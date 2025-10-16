
## -*- coding: utf-8 -*-
"""
QA Validator
Author : Lalit Kela
"""

import os
import sys
import platform
import json
import time
import traceback
import re
from datetime import datetime
from pathlib import Path
import tempfile
import pickle
import queue as _queue  # for non-blocking drain of multiprocessing.Queue

import tkinter as tk
from tkinter import ttk, filedialog, messagebox

import numpy as np
import pandas as pd
import dask.dataframe as dd

from sqlalchemy import create_engine, text
from sqlalchemy.engine import URL
import pandas_gbq

from multiprocessing import Process, Queue
from typing import Optional, Any
import multiprocessing

from cryptography.fernet import Fernet
from PIL import Image, ImageTk

# ---------------------- OS / UI helpers ----------------------
IS_WINDOWS = platform.system().lower().startswith('win')
APP_ICON_ICO = 'qa_validator.ico'
APP_ICON_PNG = 'qa_validator_icon.png'

TS_RE = re.compile(r'^\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\]\s')


def resource_path(relative):
    base = getattr(sys, '_MEIPASS', os.path.abspath(os.path.dirname(__file__)))
    return os.path.join(base, relative)


def set_app_icon(root):
    try:
        ico_path = resource_path(APP_ICON_ICO)
        if IS_WINDOWS and os.path.exists(ico_path):
            root.iconbitmap(ico_path)
            return
    except Exception:
        pass
    try:
        png_path = resource_path(APP_ICON_PNG)
        if os.path.exists(png_path):
            img = tk.PhotoImage(file=png_path)
            root.iconphoto(True, img)
            root._icon_ref = img
    except Exception:
        pass


def maximize_on_start(root):
    try:
        root.update_idletasks(); root.state('normal'); root.deiconify()
    except Exception:
        pass
    try:
        if IS_WINDOWS:
            root.state('zoomed')
        else:
            try:
                root.attributes('-zoomed', True)
            except Exception:
                sw, sh = root.winfo_screenwidth(), root.winfo_screenheight()
                root.geometry(f'{sw}x{sh}+0+0'); root.minsize(int(sw * 0.75), int(sh * 0.75))
    except Exception:
        root.geometry('1400x900+50+50')


# ---------------------- Optional secrets (Fernet) ----------------------
try:
    from cryptography.fernet import Fernet
except Exception:
    Fernet = None

_ENC_PREFIX = 'enc:fernet:'


def _get_fernet():
    if Fernet is None:
        raise RuntimeError("cryptography is not installed")
    key_path = Path.home() / '.myapp' / 'secret.key'
    key_path.parent.mkdir(parents=True, exist_ok=True)
    '''if not key_path.exists():
        key = Fernet.generate_key()
        with open(key_path, 'wb') as f:
            f.write(key)
        try:
            os.chmod(key_path, 0o600)
        except Exception:
            pass'''
    if not key_path.exists():
        raise RuntimeError("Encryption key missing — cannot decrypt existing secrets. No saved secrets vailable")
    else:
        with open(key_path, 'rb') as f:
            key = f.read()
    return Fernet(key)


def _is_encrypted(val) -> bool:
    return isinstance(val, str) and val.startswith(_ENC_PREFIX)


def _encrypt_str(plain: str) -> str:
    if not plain:
        return plain
    f = _get_fernet(); tok = f.encrypt(plain.encode('utf-8')).decode('utf-8')
    return _ENC_PREFIX + tok


def _decrypt_str(value: str) -> str:
    if not _is_encrypted(value):
        return value
    f = _get_fernet(); tok = value[len(_ENC_PREFIX):].encode('utf-8')
    return f.decrypt(tok).decode('utf-8')


def _encrypt_profile_secrets(profile: dict) -> dict:
    p = json.loads(json.dumps(profile))
    for side in ('left', 'right'):
        src = p.get(side, {})
        if src.get('kind') == 'db':
            params = src.get('params', {})
            if 'password' in params and params['password']:
                params['password'] = _encrypt_str(params['password'])
    p['__enc__'] = 'fernet'
    return p


def _decrypt_profile_secrets(profile: dict) -> dict:
    p = json.loads(json.dumps(profile))
    for side in ('left', 'right'):
        src = p.get(side, {})
        if src.get('kind') == 'db':
            params = src.get('params', {})
            pw = params.get('password')
            if _is_encrypted(pw):
                params['password'] = _decrypt_str(pw)
    return p


# ---------------------- DB Specs & Builders ----------------------
class DBSpec:
    def __init__(self, name, fields, builder, preview_wrap=None, count_wrap=None, test_sql=None):
        self.name = name
        self.fields = fields
        self.builder = builder
        self.preview_wrap = preview_wrap or (lambda q, n: f"SELECT * FROM ({q}) t LIMIT {n}")
        self.count_wrap = count_wrap or (lambda q: f"SELECT COUNT(*) AS ct FROM ({q}) t")
        self.test_sql = test_sql or "SELECT 1"


def _to_int(v):
    try:
        return int(v) if v not in (None, "") else None
    except Exception:
        return None


def build_postgres(v):
    return URL.create(
        drivername="postgresql+psycopg2",
        username=v.get('user') or None,
        password=v.get('password') or None,
        host=v.get('host') or None,
        port=_to_int(v.get('port')),
        database=v.get('database') or None,
    )


def build_mysql(v):
    return URL.create(
        drivername="mysql+pymysql",
        username=v.get('user') or None,
        password=v.get('password') or None,
        host=v.get('host') or None,
        port=_to_int(v.get('port')),
        database=v.get('database') or None,
    )


def build_mssql(v):
    driver = v.get('driver') or ('ODBC Driver 18 for SQL Server' if IS_WINDOWS else 'ODBC Driver 17 for SQL Server')
    auth_method = (v.get('auth_method') or 'SQL Authentication').strip()
    encrypt = (v.get('encrypt') or 'yes').strip().lower()
    trust = (v.get('trust_server_certificate') or 'yes').strip().lower()
    query = {
        'driver': driver,
        'Encrypt': 'yes' if encrypt in ('1', 'true', 'yes', 'y') else 'no',
        'TrustServerCertificate': 'yes' if trust in ('1', 'true', 'yes', 'y') else 'no',
    }
    if auth_method == 'Windows Integrated (Trusted_Connection)':
        query['Trusted_Connection'] = 'yes'
        return URL.create(
            drivername="mssql+pyodbc", host=v.get('host') or None, port=_to_int(v.get('port')),
            database=v.get('database') or None, query=query,
        )
    else:
        query['Trusted_Connection'] = 'no'
        return URL.create(
            drivername="mssql+pyodbc", username=v.get('user') or None, password=v.get('password') or None,
            host=v.get('host') or None, port=_to_int(v.get('port')), database=v.get('database') or None, query=query,
        )


def build_oracle(v):
    return URL.create(
        drivername="oracle+oracledb", username=v.get('user') or None, password=v.get('password') or None,
        host=v.get('host') or None, port=_to_int(v.get('port')), database=None,
        query={"service_name": v.get('service') or "orclpdb1"},
    )


def build_snowflake(v):
    query = {}
    if v.get('warehouse'): query['warehouse'] = v.get('warehouse')
    if v.get('role'): query['role'] = v.get('role')
    if v.get('schema'): query['schema'] = v.get('schema')
    auth_method = (v.get('auth_method') or 'Password').strip()
    if auth_method.lower().startswith('sso'):
        query['authenticator'] = 'externalbrowser'
    return URL.create(
        drivername='snowflake', username=v.get('user') or None,
        password=(v.get('password') or None) if auth_method == 'Password' else None,
        host=v.get('account') or None, database=v.get('database') or None, query=query,
    )


def build_redshift(v):
    return URL.create(
        drivername="redshift+redshift_connector", username=v.get('user') or None, password=v.get('password') or None,
        host=v.get('host') or None, port=_to_int(v.get('port')), database=v.get('database') or None,
    )


def build_bigquery(v):
    creds = (v.get('credentials') or '').strip()
    if creds:
        os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = creds
    project = (v.get('project') or '').strip()
    return f"bigquery://{project}" if project else "bigquery://"


DB_SPECS = {
    'Postgres': DBSpec('Postgres', [
        ('host','Host','localhost'),('port','Port','5432'),('database','Database',''),('user','User',''),('password','Password','')
    ], build_postgres, test_sql="SELECT 1"),
    'MySQL': DBSpec('MySQL', [
        ('host','Host','localhost'),('port','Port','3306'),('database','Database',''),('user','User',''),('password','Password','')
    ], build_mysql, test_sql="SELECT 1"),
    'SQL Server': DBSpec('SQL Server', [
        ('host','Host','localhost'),('port','Port','1433'),('database','Database',''),('user','User',''),('password','Password','')
    ], build_mssql, preview_wrap=lambda q,n: f"SELECT TOP {n} * FROM ({q}) t", test_sql="SELECT 1"),
    'Oracle': DBSpec('Oracle', [
        ('host','Host','localhost'),('port','Port','1521'),('service','Service/SID','orclpdb1'),('user','User',''),('password','Password','')
    ], build_oracle, preview_wrap=lambda q,n: f"SELECT * FROM ({q}) t FETCH FIRST {n} ROWS ONLY", test_sql="SELECT 1 FROM DUAL"),
    'Snowflake': DBSpec('Snowflake', [
        ('account','Account',''),('user','User',''),('password','Password',''),('database','Database',''),('schema','Schema','PUBLIC'),('warehouse','Warehouse',''),('role','Role',''),('auth_method','Auth (Password/SSO)','Password')
    ], build_snowflake, test_sql="SELECT 1"),
    'Redshift': DBSpec('Redshift', [
        ('host','Host',''),('port','Port','5439'),('database','Database',''),('user','User',''),('password','Password','')
    ], build_redshift, test_sql="SELECT 1"),
    'BigQuery': DBSpec('BigQuery', [
        ('project','Project ID',''),('location','Location','US'),('credentials','Credentials JSON Path (optional)',''),('auth_method','Auth Method','OAuth (pandas_gbq)')
    ], build_bigquery, test_sql="SELECT 1"),
}


# ---------------------- Data helpers ----------------------

def safe_dd_read_csv(path, **kwargs):
    kwargs.pop('dtype_backend', None)
    return dd.read_csv(path, **kwargs)


def normalize_col(col: str) -> str:
    if col is None: return ''
    c = str(col).strip().lower().replace('\n',' ').replace('\t',' ')
    c = ' '.join(c.split())
    normalized = ''.join(ch if ch.isalnum() else '_' for ch in c)
    while '__' in normalized:
        normalized = normalized.replace('__','_')
    return normalized.strip('_')


def normalize_columns(df: pd.DataFrame):
    mapping = {}; seen = set()
    for orig in df.columns:
        base = normalize_col(orig); name = base; i = 2
        while name in seen:
            name = f"{base}_{i}"; i += 1
        mapping[orig] = name; seen.add(name)
    df2 = df.copy(); df2.columns = [mapping[c] for c in df.columns]
    return df2, mapping


def coerce_to_string_df(df: pd.DataFrame) -> pd.DataFrame:
    def to_str(x):
        if pd.isna(x): return ''
        if isinstance(x, (np.integer, int)): return str(int(x))
        if isinstance(x, (np.floating, float)):
            vx = float(x)
            if np.isfinite(vx) and vx.is_integer(): return str(int(vx))
            return format(vx, '.15g')
        return str(x).strip()
    try:
        return df.map(to_str)
    except AttributeError:
        return df.applymap(to_str)


def column_value_diffs(left, right, cols, topn=25):
    rows = []
    for c in cols:
        vc1 = left[c].astype(str).value_counts(dropna=False)
        vc2 = right[c].astype(str).value_counts(dropna=False)
        vc1 = vc1.rename('datasource1').to_frame(); vc2 = vc2.rename('datasource2').to_frame()
        merged = vc1.join(vc2, how='outer').fillna(0).astype(int)
        merged['delta'] = merged['datasource1'] - merged['datasource2']
        merged['only_in'] = np.where((merged['datasource1']>0)&(merged['datasource2']==0),'Datasource1',
                                     np.where((merged['datasource2']>0)&(merged['datasource1']==0),'Datasource2',''))
        merged = merged.reindex(merged['delta'].abs().sort_values(ascending=False).index).head(topn)
        for idx, r in merged.iterrows():
            rows.append({'Column': c, 'Value': idx, 'datasource1': int(r['datasource1']), 'datasource2': int(r['datasource2']), 'Delta': int(r['delta']), 'OnlyIn': r['only_in']})
    return pd.DataFrame(rows)


# ---------------------- Core compare (child process) ----------------------

def _head_sample_core(data, meta):
    try:
        if meta.get('type')=='file' and hasattr(data,'compute'):
            return data.head(1000, compute=True)
        elif meta.get('type')=='db' and isinstance(data,pd.DataFrame):
            return data
        else:
            return data.head(1000) if hasattr(data,'head') else data
    except Exception:
        return data


def _load_source_core(cfg, row_limit=None, low_mem=False, log=lambda m: None):
    kind, payload = cfg
    if kind=='file':
        path = payload['path']; sep = payload.get('delimiter', ',')
        if not os.path.exists(path):
            raise Exception(f'File not found: {path}')
        log('File streaming started')
        if low_mem:
            ddf = safe_dd_read_csv(path, sep=sep, blocksize='128MB', assume_missing=True)
            count = int(ddf.shape[0].compute())
            if row_limit:
                sample = ddf.head(row_limit, compute=True); log('File streaming complete'); return sample, len(sample), {'type':'file'}
            log('File streaming complete'); return ddf, count, {'type':'file'}
        else:
            if row_limit:
                try:
                    ddf = safe_dd_read_csv(path, sep=sep, blocksize='64MB', assume_missing=True); df = ddf.head(row_limit, compute=True)
                except Exception:
                    df = pd.read_csv(path, sep=sep, nrows=row_limit)
                log('File streaming complete'); return df, len(df), {'type':'file'}
            else:
                try:
                    ddf = safe_dd_read_csv(path, sep=sep, blocksize='64MB', assume_missing=True); df = ddf.compute()
                except Exception:
                    df = pd.read_csv(path, sep=sep)
                log('File streaming complete'); return df, len(df), {'type':'file'}
    else:
        db_type = payload['db_type']; params = payload['params']; spec = DB_SPECS.get(db_type)
        log('Database connection started')
        if db_type=='BigQuery' and (params.get('auth_method','').startswith('OAuth')):
            #import pandas_gbq
            q = params.get('query'); proj = params.get('project') or None; loc = params.get('location') or 'US'
            if low_mem and row_limit:
                df = pandas_gbq.read_gbq(f"SELECT * FROM ({q}) t LIMIT {row_limit}", project_id=proj, location=loc, progress_bar_type=None, reauth = True); log('Database connection end'); return df, len(df), {'type':'db'}
            elif low_mem:
                df = pandas_gbq.read_gbq(f"SELECT * FROM ({q}) t LIMIT 5000", project_id=proj, location=loc, progress_bar_type=None, reauth = True)
                try:
                    cnt_df = pandas_gbq.read_gbq(f"SELECT COUNT(*) AS ct FROM ({q}) t", project_id=proj, location=loc, progress_bar_type=None, reauth = True); count = int(cnt_df.iloc[0,0])
                except Exception:
                    count = len(df)
                log('Database connection end'); return df, count, {'type':'db'}
            else:
                df = pandas_gbq.read_gbq(q, project_id=proj, location=loc, progress_bar_type=None, reauth = True); log('Database connection end'); return df, len(df), {'type':'db'}
        url = spec.builder(params); eng = create_engine(url); q = params.get('query')
        with eng.connect() as conn:
            try:
                cnt_df = pd.read_sql_query(text(spec.count_wrap(q)), conn); total_count = int(cnt_df.iloc[0,0])
            except Exception:
                total_count = None
            if row_limit and not low_mem:
                df = pd.read_sql_query(text(spec.preview_wrap(q, row_limit)), conn); log('Database connection end'); return df, len(df), {'type':'db'}
            elif low_mem:
                sample_df = pd.read_sql_query(text(spec.preview_wrap(q, 5000)), conn); log('Database connection end'); return sample_df, total_count, {'type':'db','url':str(url),'sql':q,'chunksize':100000}
            else:
                if not q: raise Exception('SQL query is required')
                df = pd.read_sql_query(text(q), conn); count = len(df) if total_count is None else total_count; log('Database connection end'); return df, count, {'type':'db'}


def compare_core(left_cfg, right_cfg, pk_text: str, row_limit: int, low_mem: bool, live_logger=None):
    logs = []
    def log(m):
        line = f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {m}"
        logs.append(line)
        # stream to parent if queue logger provided
        if callable(live_logger):
            try:
                live_logger(line)
            except Exception:
                pass

    results = {
        'summary': None,
        'findings': pd.DataFrame(),
        'counts': pd.DataFrame(),
        'column_map': pd.DataFrame(),
        'column_compare': pd.DataFrame(),
        'dtype_compare': pd.DataFrame(),
        'missing_keys': pd.DataFrame(),
        'cell_mismatches': pd.DataFrame(),
        'row_differences': pd.DataFrame(),
        'unmatched_rows': pd.DataFrame(),
        'column_value_diffs': pd.DataFrame(),
        'only_in_datasource1': pd.DataFrame(),
        'only_in_datasource2': pd.DataFrame(),
        '__logs__': logs,
    }

    left_df, left_count, left_meta = _load_source_core(left_cfg, row_limit=row_limit, low_mem=low_mem, log=log)
    right_df, right_count, right_meta = _load_source_core(right_cfg, row_limit=row_limit, low_mem=low_mem, log=log)

    log('Comparison started')

    left_head = _head_sample_core(left_df, left_meta)
    right_head = _head_sample_core(right_df, right_meta)

    left_norm, left_map = normalize_columns(left_head)
    right_norm, right_map = normalize_columns(right_head)

    left_order = [left_map[c] for c in left_head.columns]
    right_order = [right_map[c] for c in right_head.columns]
    all_cols = left_order + [c for c in right_order if c not in left_order]
    common_cols = [c for c in left_order if c in right_order]

    dtype_rows = []
    if common_cols:
        for c in common_cols:
            k1 = [k for k, v in left_map.items() if v == c]
            k2 = [k for k, v in right_map.items() if v == c]
            dt1 = str(left_head[k1[0]].dtype) if k1 else 'NA'
            dt2 = str(right_head[k2[0]].dtype) if k2 else 'NA'
            dtype_rows.append({'Column(normalized)': c, 'Source1 dtype': dt1, 'Source2 dtype': dt2, 'Match': dt1 == dt2})
    dtype_df = pd.DataFrame(dtype_rows)

    counts_df = pd.DataFrame([
        {'Metric':'RowCount','Source':'Datasource 1','Value': int(left_count) if left_count is not None else None},
        {'Metric':'RowCount','Source':'Datasource 2','Value': int(right_count) if right_count is not None else None},
    ])

    cols_only_left = [c for c in left_order if c not in right_order]
    cols_only_right = [c for c in right_order if c not in left_order]
    col_comp = pd.DataFrame({'Common': pd.Series(common_cols), 'OnlyInDatasource1': pd.Series(cols_only_left), 'OnlyInDatasource2': pd.Series(cols_only_right)})

    def align_and_string(df, order_cols):
        for c in order_cols:
            if c not in df.columns: df[c] = ''
        return coerce_to_string_df(df[order_cols])

    if hasattr(left_df,'compute'): left_df = left_df.head(50000, compute=True)
    if hasattr(right_df,'compute'): right_df = right_df.head(50000, compute=True)

    left_full = align_and_string(normalize_columns(left_df)[0] if isinstance(left_df, pd.DataFrame) else left_norm, all_cols)
    right_full = align_and_string(normalize_columns(right_df)[0] if isinstance(right_df, pd.DataFrame) else right_norm, all_cols)

    pk_norm = [normalize_col(c) for c in pk_text.split(',') if c.strip()] if pk_text else []
    pk_norm = [c for c in pk_norm if c in common_cols]

    try:
        lr = left_full[common_cols].merge(right_full[common_cols], how='outer', indicator=True)
        s1_minus = lr[lr['_merge']=='left_only'].drop(columns=['_merge']).copy(); s1_minus.insert(0,'_datasource','Datasource1')
        s2_minus = lr[lr['_merge']=='right_only'].drop(columns=['_merge']).copy(); s2_minus.insert(0,'_datasource','Datasource2')
        unmatched_rows = pd.concat([s1_minus, s2_minus], axis=0, ignore_index=True)
        sort_cols = pk_norm if pk_norm else common_cols
        if sort_cols: unmatched_rows = unmatched_rows.sort_values(by=sort_cols)
    except Exception:
        unmatched_rows = pd.DataFrame(); s1_minus = pd.DataFrame(); s2_minus = pd.DataFrame()

    row_differences = pd.DataFrame()
    if pk_norm:
        l_idx = left_full.set_index(pk_norm, drop=False); r_idx = right_full.set_index(pk_norm, drop=False)
        common_idx = l_idx.index.intersection(r_idx.index)
        if len(common_idx)>0:
            l_common = l_idx.loc[common_idx, common_cols]; r_common = r_idx.loc[common_idx, common_cols]
            non_key = [c for c in common_cols if c not in pk_norm]
            if non_key:
                neq = (l_common[non_key] != r_common[non_key]); diff_rows = neq.any(axis=1)
                if diff_rows.any():
                    l_diff = l_common.loc[diff_rows].copy(); r_diff = r_common.loc[diff_rows].copy()
                    l_diff.insert(0,'_datasource','Datasource1'); r_diff.insert(0,'_datasource','Datasource2')
                    row_differences = pd.concat([l_diff, r_diff], axis=0); row_differences = row_differences.sort_values(by=pk_norm+non_key)

    col_value_diffs = column_value_diffs(left_full[common_cols], right_full[common_cols], common_cols, topn=25) if common_cols else pd.DataFrame()

    findings_rows = []
    if not dtype_df.empty:
        bad = dtype_df[dtype_df['Match']==False]
        for _,r in bad.iterrows(): findings_rows.append({'Category':'Dtype mismatch','Item': r['Column(normalized)'], 'Details':'S1='+str(r['Source1 dtype'])+' S2='+str(r['Source2 dtype']), 'Count': 1})
    if not row_differences.empty:
        findings_rows.append({'Category':'Row differences','Item':'PK-aligned differences','Details':'Rows with any non-key column differing','Count': int(row_differences.shape[0]//2)})
    if not unmatched_rows.empty:
        findings_rows.append({'Category':'Unmatched rows','Item':'Present on one side only','Details':'See unmatched_rows view','Count': int(unmatched_rows.shape[0])})
    if not col_value_diffs.empty:
        agg = col_value_diffs.groupby('Column')['Delta'].apply(lambda s: int(np.sum(np.abs(s)))).reset_index().sort_values('Delta', ascending=False).head(10)
        for _,r in agg.iterrows(): findings_rows.append({'Category':'Column distribution diff','Item': r['Column'], 'Details':'Top Δ across values', 'Count': int(r['Delta'])})
    findings_df = pd.DataFrame(findings_rows)

    results['counts'] = counts_df
    results['column_map'] = pd.DataFrame([
        {'normalized': c, 'source1_cols': ', '.join([k for k,v in left_map.items() if v==c]), 'source2_cols': ', '.join([k for k,v in right_map.items() if v==c]), 'Match': ([k for k,v in left_map.items() if v==c] == [k for k,v in right_map.items() if v==c])}
        for c in all_cols
    ])
    results['column_compare'] = col_comp
    results['dtype_compare'] = dtype_df
    results['unmatched_rows'] = unmatched_rows
    results['findings'] = findings_df
    results['missing_keys'] = pd.DataFrame()
    results['cell_mismatches'] = pd.DataFrame()
    results['row_differences'] = row_differences
    results['column_value_diffs'] = col_value_diffs
    results['only_in_datasource1'] = s1_minus if 's1_minus' in locals() else pd.DataFrame()
    results['only_in_datasource2'] = s2_minus if 's2_minus' in locals() else pd.DataFrame()

    human_summary = (
        f"COUNT VALIDATION : Source1 rows: {left_count} & Source2 rows: {right_count}\n"
        f"COLUMN VALIDATION : Common columns : {len(common_cols)}; Only in DS1: {len(cols_only_left)} cols & Only in DS2: {len(cols_only_right)} cols\n"
        f"DATA VALIDATION : Total Unmatched rows for common columns: {0 if unmatched_rows is None else len(unmatched_rows)}"
    )
    results['summary'] = human_summary

    log('Comparison completed')

    return results


def run_compare_process(tmp_path, left_cfg, right_cfg, pk_text, row_limit, low_mem, log_q: Optional[Any]):
    def live_logger(line: str):
        if log_q is None:
            return
        try:
            log_q.put_nowait(line)
        except _queue.Full:
            # drop if UI is slower; we keep child non-blocking
            pass
        except Exception:
            pass
    try:
        res = compare_core(left_cfg, right_cfg, pk_text, row_limit, low_mem, live_logger=live_logger)
        with open(tmp_path, 'wb') as f:
            pickle.dump(res, f, protocol=pickle.HIGHEST_PROTOCOL)
        os._exit(0)
    except Exception as e:
        err = {'__error__': str(e), '__trace__': traceback.format_exc()}
        try:
            with open(tmp_path, 'wb') as f:
                pickle.dump(err, f, protocol=pickle.HIGHEST_PROTOCOL)
        except Exception:
            pass
        os._exit(2)


# ---------------------- Tk App ----------------------
class DataComparatorApp:
    def __init__(self, root):
        self.root = root
        root.title('QA Validator')
        root.minsize(1200, 800)
        self.cancel_event = False
        self.timeout_min_var = tk.IntVar(value=60)
        style = ttk.Style()
        #style.theme_use('default') # normal, clam, alt
        style.configure('TNotebook.Tab', padding=[10, 5], font=('Segoe UI', 10))
        style.map('TNotebook.Tab', 
            font=[('selected', ('Segoe UI', 10, 'bold'))],
            background=[('active', '#7986cb'),('selected', '#37474f'), ('!selected', '#f0f0f0')],
            foreground=[('selected', 'green'), ('!selected', 'black')])
        self.nb = ttk.Notebook(root); self.nb.pack(fill='both', expand=True)
        self.tab_home = ttk.Frame(self.nb); self.tab_config = ttk.Frame(self.nb)
        self.tab_results = ttk.Frame(self.nb); self.tab_logs = ttk.Frame(self.nb)
        self.nb.add(self.tab_home, text='Home')
        self.nb.add(self.tab_config, text='Configuration')
        self.nb.add(self.tab_results, text='Results')
        self.nb.add(self.tab_logs, text='Logs')
        self.mode_var = tk.StringVar(value='db_vs_db')
        self.left_widgets = {}; self.right_widgets = {}
        self.results = {
            'summary': None,
            'findings': pd.DataFrame(),
            'counts': pd.DataFrame(),
            'column_map': pd.DataFrame(),
            'column_compare': pd.DataFrame(),
            'dtype_compare': pd.DataFrame(),
            'missing_keys': pd.DataFrame(),
            'cell_mismatches': pd.DataFrame(),
            'unmatched_rows': pd.DataFrame(),
            'column_value_diffs': pd.DataFrame(),
            'only_in_datasource1': pd.DataFrame(),
            'only_in_datasource2': pd.DataFrame(),
            'row_differences': pd.DataFrame(),
        }
        self._build_home(); self._build_config(); self._build_results(); self._build_logs(); self._build_brand_footer()
        self._proc = None; self._proc_tmp = None; self._proc_start = None
        self._log_q: Optional[Any] = None

    # ---------- UI builders ----------
    def _build_home(self):
        f = self.tab_home
        ttk.Label(f, text='Validator : Heterogeneous Data Compare utility', font=('Segoe UI', 18, 'bold')).pack(pady=16)
        btns = ttk.Frame(f); btns.pack(pady=20)
        ttk.Button(btns, text='Database vs Database', width=22, command=lambda: self._set_mode('db_vs_db')).grid(row=0, column=0, padx=8, pady=8)
        ttk.Button(btns, text='Database vs File', width=22, command=lambda: self._set_mode('db_vs_file')).grid(row=0, column=1, padx=8, pady=8)
        ttk.Button(btns, text='File vs File', width=22, command=lambda: self._set_mode('file_vs_file')).grid(row=0, column=2, padx=8, pady=8)
        ttk.Label(f, text='Choose mode to configure sources.').pack()

    def _set_mode(self, mode):
        self.mode_var.set(mode); self.nb.select(self.tab_config); self.render_config()

    def _build_config(self):
        f = self.tab_config
        top = ttk.Frame(f); top.pack(fill='x', padx=10, pady=8)
        btns = ttk.Frame(f); btns.pack(pady=0)
        ttk.Button(btns, text='Database vs Database', width=22, command=lambda: self._set_mode('db_vs_db')).grid(row=0, column=0, padx=8, pady=8)
        ttk.Button(btns, text='Database vs File', width=22, command=lambda: self._set_mode('db_vs_file')).grid(row=0, column=1, padx=8, pady=8)
        ttk.Button(btns, text='File vs File', width=22, command=lambda: self._set_mode('file_vs_file')).grid(row=0, column=2, padx=8, pady=8)
        ttk.Label(top, text='Mode:').grid(row=0, column=0, sticky='w')
        ttk.Label(top, textvariable=self.mode_var).grid(row=0, column=1, sticky='w')
        #ttk.Label(top, text='Primary key columns (comma-separated):').grid(row=1, column=0, sticky='w', pady=(6,0))
        self.pk_entry = ttk.Entry(top, width=0)
        #self.pk_entry = ttk.Entry(top, width=50); self.pk_entry.grid(row=1, column=1, sticky='w', pady=(6,0))
        ttk.Label(top, text='Row limit for sample validation(optional):').grid(row=2, column=0, sticky='w', pady=(6,0))
        self.rowlimit_entry = ttk.Entry(top, width=20); self.rowlimit_entry.grid(row=2, column=1, sticky='w', pady=(6,0))
        ttk.Label(top, text='Low-memory sample rows (e.g., 10000):').grid(row=3, column=0, sticky='w', pady=(6,0))
        self.lowmem_sample_entry = ttk.Entry(top, width=12); self.lowmem_sample_entry.insert(0,'10000'); self.lowmem_sample_entry.grid(row=3, column=1, sticky='w')
        self.lowmem_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(top, text='Low-memory mode (It validates only sample rows from both sides)', variable=self.lowmem_var).grid(row=4, column=0, columnspan=2, sticky='w')
        ttk.Label(top, text='Timeout (min)').grid(row=0, column=4, sticky='w', padx=4)
        self.timeout_spin = ttk.Spinbox(top, from_=0, to=240, textvariable=self.timeout_min_var, width=6)
        self.timeout_spin.grid(row=0, column=5, sticky='w', padx=4)

        self.pw = ttk.Panedwindow(f, orient='horizontal'); self.pw.pack(fill='both', expand=True, padx=10, pady=10)
        self.left_frame = ttk.LabelFrame(self.pw, text='Datasource 1', padding=8)
        self.right_frame = ttk.LabelFrame(self.pw, text='Datasource 2', padding=8)
        self.pw.add(self.left_frame, weight=1); self.pw.add(self.right_frame, weight=1)

        action = ttk.Frame(f); action.pack(fill='x', padx=10, pady=6)
        self.progress = ttk.Progressbar(action, orient='horizontal', length=360, mode='determinate'); self.progress.pack(side='left', padx=6)
        
        ttk.Button(action, text='Test DS1', command=lambda: self._test_connection('left')).pack(side='left', padx=6)
        ttk.Button(action, text='Test DS2', command=lambda: self._test_connection('right')).pack(side='left', padx=6)
        ttk.Button(action, text='Test Both', command=lambda: self._test_connection('both')).pack(side='left', padx=6)

        ttk.Button(action, text='Save Profile', command=self._save_profile).pack(side='right', padx=6)
        ttk.Button(action, text='Load Profile', command=self._load_profile).pack(side='right', padx=6)
        ttk.Button(action, text='Reset', command=self.on_reset).pack(side='right', padx=6)
        ttk.Button(action, text='Stop', command=self.on_stop).pack(side='right', padx=6)
        ttk.Button(action, text='Submit', command=self.on_submit).pack(side='right', padx=6)

        self.render_config()

    def _canon_db_type(self, name: str|None, default='Postgres') -> str:
        DB_TYPE_CANON = {
            'postgresql':'Postgres','postgres':'Postgres','pg':'Postgres','mysql':'MySQL','sql server':'SQL Server','mssql':'SQL Server','ms sql server':'SQL Server','snowflake':'Snowflake','redshift':'Redshift','oracle':'Oracle','bigquery':'BigQuery','google bigquery':'BigQuery'
        }
        if not name: return default
        n = name.strip().lower(); return DB_TYPE_CANON.get(n, name)

    def render_config(self):
        for w in self.left_frame.winfo_children(): w.destroy()
        for w in self.right_frame.winfo_children(): w.destroy()
        mode = self.mode_var.get(); self.left_widgets.clear(); self.right_widgets.clear()
        if mode in ('db_vs_db','db_vs_file'): self._build_db_block(self.left_frame, self.left_widgets)
        else: self._build_file_block(self.left_frame, self.left_widgets)
        if mode=='db_vs_db': self._build_db_block(self.right_frame, self.right_widgets)
        elif mode=='db_vs_file': self._build_file_block(self.right_frame, self.right_widgets)
        else: self._build_file_block(self.right_frame, self.right_widgets)

    def _render_side(self, side: str, kind: str, db_type: str|None=None):
        frame = self.left_frame if side=='left' else self.right_frame
        for w in frame.winfo_children(): w.destroy()
        store = {}
        if kind=='db':
            db_type = self._canon_db_type(db_type, 'Postgres'); store['db_type_var'] = tk.StringVar(value=db_type); self._build_db_block(frame, store)
        else:
            self._build_file_block(frame, store)
        if side=='left': self.left_widgets = store
        else: self.right_widgets = store
        return store

    def _current_timeout_secs(self) -> int:
        try:
            m = int(self.timeout_min_var.get()); return max(0, m) * 60
        except Exception:
            return 0

    def _build_db_block(self, parent, store):
        if 'db_type_var' not in store: store['db_type_var'] = tk.StringVar(value='Postgres')
        db_type_var = store['db_type_var']
        ttk.Label(parent, text='DB Type').grid(row=0, column=0, sticky='w')
        cmb = ttk.Combobox(parent, values=list(DB_SPECS.keys()), textvariable=db_type_var, state='readonly', width=24)
        cmb.grid(row=0, column=1, sticky='w', padx=4, pady=2); store['db_type_combo'] = cmb
        if 'fields_frame' not in store:
            store['fields_frame'] = ttk.Frame(parent); store['fields_frame'].grid(row=1, column=0, columnspan=4, pady=6, sticky='nsew')
        parent.grid_rowconfigure(1, weight=1); parent.grid_columnconfigure(1, weight=1)
        fields_frame = store['fields_frame']

        def set_entry_state(ent, enabled=True):
            try: ent.configure(state='normal' if enabled else 'disabled')
            except Exception: pass

        def rebuild_fields(event=None):
            for w in fields_frame.winfo_children(): w.destroy()
            spec = DB_SPECS.get(db_type_var.get()); store['spec'] = spec
            is_sqlsrv = bool(spec and getattr(spec,'name','')=='SQL Server'); row_ptr = 0
            sqlsrv_driver_var = tk.StringVar(value='ODBC Driver 18 for SQL Server' if IS_WINDOWS else 'ODBC Driver 17 for SQL Server')
            sqlsrv_auth_var = tk.StringVar(value='SQL Authentication')
            sqlsrv_encrypt_var = tk.BooleanVar(value=True)
            sqlsrv_trust_var = tk.BooleanVar(value=True)
            if is_sqlsrv:
                ttk.Label(fields_frame, text='Driver:').grid(row=row_ptr, column=0, sticky='w', pady=2)
                drp = ttk.Combobox(fields_frame, values=['ODBC Driver 18 for SQL Server','ODBC Driver 17 for SQL Server'], textvariable=sqlsrv_driver_var, state='readonly', width=32)
                drp.grid(row=row_ptr, column=1, sticky='w', padx=4); store['driver'] = drp; store['driver_var'] = sqlsrv_driver_var; row_ptr += 1
                ttk.Label(fields_frame, text='Authentication:').grid(row=row_ptr, column=0, sticky='w', pady=2)
                auth = ttk.Combobox(fields_frame, values=['SQL Authentication','Windows Integrated (Trusted_Connection)'], textvariable=sqlsrv_auth_var, state='readonly', width=32)
                auth.grid(row=row_ptr, column=1, sticky='w', padx=4); store['auth_method'] = auth; store['auth_method_var'] = sqlsrv_auth_var; row_ptr += 1
                chk = ttk.Frame(fields_frame); chk.grid(row=row_ptr, column=0, columnspan=2, sticky='w', pady=2)
                ttk.Checkbutton(chk, text='Encrypt', variable=sqlsrv_encrypt_var).pack(side='left', padx=(0,10))
                ttk.Checkbutton(chk, text='Trust Server Certificate', variable=sqlsrv_trust_var).pack(side='left')
                store['encrypt_var'] = sqlsrv_encrypt_var; store['trust_server_certificate_var'] = sqlsrv_trust_var; row_ptr += 1
            entries = {}
            if spec and hasattr(spec,'fields'):
                for i, (key, label, default) in enumerate(spec.fields):
                    ttk.Label(fields_frame, text=label+':').grid(row=row_ptr+i, column=0, sticky='w', pady=2)
                    if key=='auth_method' and spec.name=='Snowflake':
                        ent = ttk.Combobox(fields_frame, values=['Password','SSO (externalbrowser)'], state='readonly', width=32); ent.set(default or 'Password')
                    elif key=='auth_method' and spec.name=='BigQuery':
                        ent = ttk.Combobox(fields_frame, values=['OAuth (pandas_gbq)','Service Account File (env var)'], state='readonly', width=32); ent.set(default or 'OAuth (pandas_gbq)')
                    #elif key=='password':
                    #    ent = tk.Entry(fields_frame, width=36, show='*');
                    #    if default: ent.insert(0, default)
                    elif key=='password':
                        ent = tk.Entry(fields_frame, width=36, show='*')
                        if default:
                            ent.insert(0, default)
                        ent.grid(row=row_ptr+i, column=1, sticky='w', padx=(0,0))  # Adjust padding for eye button
                        
                        def toggle_password():
                            if ent.cget('show') == '':
                                ent.config(show='*')
                                eye_btn.config(text='👁️')
                            else:
                                ent.config(show='')
                                eye_btn.config(text='🙈')
                        
                        eye_btn = tk.Button(fields_frame, text='👁️', command=toggle_password, relief='raised')
                        eye_btn.grid(row=row_ptr+i, column=1, sticky='w', padx=(250,0))
                    else:
                        ent = tk.Entry(fields_frame, width=36); 
                        if default: ent.insert(0, default)
                    ent.grid(row=row_ptr+i, column=1, sticky='w', padx=(0,0))
                    entries[key] = ent; store[key] = ent

            def on_auth_change(event=None):
                if not spec: return
                if spec.name=='SQL Server':
                    method = sqlsrv_auth_var.get(); set_entry_state(entries.get('user'), enabled=(method!='Windows Integrated (Trusted_Connection)')); set_entry_state(entries.get('password'), enabled=(method!='Windows Integrated (Trusted_Connection)'))
                if spec.name=='Snowflake':
                    am = entries.get('auth_method'); method = am.get() if isinstance(am, ttk.Combobox) else 'Password'; set_entry_state(entries.get('password'), enabled=(method!='SSO (externalbrowser)'))

            if is_sqlsrv: store['auth_method'].bind('<<ComboboxSelected>>', on_auth_change)
            if spec and spec.name=='Snowflake' and isinstance(entries.get('auth_method'), ttk.Combobox): entries['auth_method'].bind('<<ComboboxSelected>>', on_auth_change)
            on_auth_change()

            base = row_ptr + (len(spec.fields) if spec and hasattr(spec,'fields') else 0)
            ttk.Label(fields_frame, text='SQL Query:').grid(row=base, column=0, sticky='nw')
            qtxt = tk.Text(fields_frame, height=6, width=72); qtxt.grid(row=base, column=1, pady=4); store['query'] = qtxt

        def _on_db_type_changed(event=None):
            if getattr(self,'_loading_profile', False): return
            rebuild_fields()
        cmb.bind('<<ComboboxSelected>>', _on_db_type_changed)
        rebuild_fields()

    def _build_file_block(self, parent, store):
        ttk.Label(parent, text='File Path:').grid(row=0, column=0, sticky='w')
        ent = tk.Entry(parent, width=75); ent.grid(row=0, column=1, sticky='w'); store['path']=ent
        ttk.Button(parent, text='Browse', command=lambda e=ent: self._browse_file(e)).grid(row=0, column=2, padx=4)
        ttk.Label(parent, text='Delimiter:').grid(row=1, column=0, sticky='w')
        delim = ttk.Combobox(parent, values=[',','\t',';','|','^'], state='readonly', width=6); delim.grid(row=1, column=1, sticky='w'); delim.set(','); store['delimiter']=delim

    def _browse_file(self, entry_widget):
        path = filedialog.askopenfilename(filetypes=[('CSV files','*.csv'),('All','*.*')])
        if path:
            entry_widget.delete(0,'end'); entry_widget.insert(0,path)

    def _test_connection(self, which: str):
        sides = []
        if which == 'both':
            sides = [('Datasource 1', 'left', self.left_widgets), ('Datasource 2', 'right', self.right_widgets)]
        elif which == 'left':
            sides = [('Datasource 1', 'left', self.left_widgets)]
        else:
            sides = [('Datasource 2', 'right', self.right_widgets)]

        all_ok = True
        msgs = []

        for label, side_key, store in sides:
            ok, msg = self._test_one(label, side_key, store)
            msgs.append(f"{label}: {'PASS' if ok else 'FAILED'} - {msg}")
            all_ok = all_ok and ok

        # Log & popup
        for m in msgs:
            self._log(m)

        if all_ok:
            messagebox.showinfo('Connection Test', '\n'.join(msgs))
        else:
            messagebox.showerror('Connection Test', '\n'.join(msgs))


    def _test_one(self, label: str, side_key: str, store) -> tuple[bool, str]:
        try:
            # ----- FILE SOURCE -----
            if 'path' in store:
                path = store['path'].get().strip()
                delim = store['delimiter'].get() if store.get('delimiter') else ','
                if not path:
                    return False, 'No file path set'
                if not os.path.exists(path):
                    return False, f'File not found: {path}'
                try:
                    pd.read_csv(path, sep=delim, nrows=5)
                except Exception as e:
                    return False, f'Failed to read file (delimiter={delim}): {e}'
                return True, 'File reachable and readable'

            # ----- DB SOURCE -----
            dbt = store.get('db_type_var').get()
            spec = DB_SPECS.get(dbt)
            if not spec:
                return False, f'Unknown DB type: {dbt}'

            # Collect fields like _collect_source (but no query required)
            vals = {}
            for key, _, _ in spec.fields:
                w = store.get(key)
                vals[key] = (w.get().strip() if isinstance(w, (tk.Entry, ttk.Combobox)) else '')

            # BigQuery special-case
            if dbt == 'BigQuery':
                try:
                    import pandas_gbq
                except Exception as e:
                    return False, f'pandas_gbq not available: {e}'

                proj = vals.get('project') or None
                loc = vals.get('location') or 'US'
                try:
                    # Disable tqdm progress in EXE (no console)
                    df = pandas_gbq.read_gbq("SELECT 1", project_id=proj, location=loc, progress_bar_type=None, reauth = True)
                    if df is None or df.empty:
                        return False, 'Connected but no rows from SELECT 1'
                    return True, 'BigQuery connection OK'
                except Exception as e:
                    return False, f'BigQuery test failed: {e}'

            # Other DBs via SQLAlchemy
            try:
                url = spec.builder(vals)
            except Exception as e:
                return False, f'Invalid connection parameters: {e}'

            try:
                eng = create_engine(url)
                with eng.connect() as conn:
                    tsql = getattr(spec, 'test_sql', None) or "SELECT 1"
                    _ = pd.read_sql_query(text(tsql), conn)
                return True, f'{dbt} connection OK'
            except Exception as e:
                return False, f'{dbt} test failed: {e}'

        except Exception as e:
            return False, f'Unexpected error: {e}'


    # ---------- Submit / Stop with process, timeout, and realtime logs ----------
    def on_submit(self):
        self._log('Request submitted by user')
        try:
            left_cfg = self._gather_store(self.left_widgets)
            right_cfg = self._gather_store(self.right_widgets)
        except Exception as e:
            messagebox.showwarning('Invalid input', str(e)); return
        low_mem = bool(self.lowmem_var.get())
        row_limit = None
        txt = self.rowlimit_entry.get().strip()
        if txt:
            try: row_limit = int(txt)
            except Exception: row_limit = None
        pk_text = self.pk_entry.get().strip()

        tmp_dir = Path(tempfile.gettempdir()) / 'qa_validator'; tmp_dir.mkdir(exist_ok=True)
        tmp_path = str(tmp_dir / f'results_{int(time.time())}.pkl')

        self._proc_tmp = tmp_path; self._proc_start = time.time()
        self._log_q = Queue(maxsize=1000)
        self._proc = Process(target=run_compare_process, args=(tmp_path, left_cfg, right_cfg, pk_text, row_limit, low_mem, self._log_q))
        self._proc.daemon = True; self._proc.start()
        self.cancel_event = False; self.progress['value'] = 5
        self._poll_compare()

    def _drain_log_queue(self):
        q = self._log_q
        if q is None: return
        try:
            while True:
                line = q.get_nowait()
                self._log(line)  # line already has timestamp; _log won't add another
        except _queue.Empty:
            return
        except Exception:
            return

    def _poll_compare(self):
        if self._proc is None:
            return
        # always drain any pending logs regardless of state
        self._drain_log_queue()

        timeout = self._current_timeout_secs(); elapsed = time.time() - (self._proc_start or time.time())

        if self.cancel_event:
            try:
                if self._proc.is_alive(): self._proc.terminate(); self._proc.join(3)
            except Exception: pass
            # drain remaining logs after termination
            self._drain_log_queue()
            self._log('Operation cancelled by user'); messagebox.showinfo('Cancelled','Operation cancelled')
            self.progress['value'] = 0; self._proc = None; self._log_q = None
            return

        if timeout > 0 and elapsed > timeout:
            try:
                if self._proc.is_alive(): self._proc.terminate(); self._proc.join(3)
            except Exception: pass
            self._drain_log_queue()
            self._log(f'Timeout after {int(timeout/60)} min; compare process terminated')
            messagebox.showwarning('Timeout', f'Compare exceeded {int(timeout/60)} minutes and was terminated.')
            self.progress['value'] = 0; self._proc = None; self._log_q = None
            return

        if self._proc.is_alive():
            val = self.progress['value']; self.progress['value'] = min(60, (val + 3))
            self.root.after(500, self._poll_compare)  # faster polling helps logs feel live
            return

        # finished: final drain before loading results
        self._drain_log_queue()
        self.progress['value'] = 95; res_path = self._proc_tmp; self._proc = None
        try:
            if res_path and os.path.exists(res_path):
                with open(res_path, 'rb') as f: obj = pickle.load(f)
                try: os.remove(res_path)
                except Exception: pass
            else:
                obj = {'__error__': 'No results file found'}
        except Exception as e:
            obj = {'__error__': f'Failed to read results: {e}'}

        if isinstance(obj, dict) and obj.get('__error__'):
            self._log('Error during compare: ' + obj['__error__'])
            if obj.get('__trace__'): self._log(obj['__trace__'])
            messagebox.showerror('Error', obj['__error__'])
            self.progress['value'] = 0; self._log_q = None
            return

        for k in self.results.keys():
            if k in obj: self.results[k] = obj[k]
        if obj.get('__logs__'):
            # Optional: replay archive (may duplicate live lines). Safe to skip.
            pass
        if obj.get('summary'):
            #self._log('Comparison completed'); 
            messagebox.showinfo('Comparison completed', obj['summary'])
        self.progress['value'] = 100; self._display_results(); self.progress['value'] = 0
        self._log_q = None

    def on_stop(self):
        self._log('Request stopped by user'); self.cancel_event = True

    def _gather_store(self, store):
        if 'path' in store:
            path = store['path'].get().strip()
            if not path:
                if isinstance(store['path'], tk.Entry): store['path'].config(highlightbackground='red', highlightcolor='red', highlightthickness=2)
                raise Exception('File path is required')
            delim = store['delimiter'].get() if store.get('delimiter') else ','
            return ('file', {'path': path, 'delimiter': delim})
        else:
            dbt = store.get('db_type_var').get(); spec = DB_SPECS.get(dbt); vals = {}
            for key,_,_ in spec.fields:
                w = store.get(key); val = w.get().strip() if isinstance(w,(tk.Entry,ttk.Combobox)) else ''
                if spec.name=='SQL Server':
                    auth = store.get('auth_method'); auth_val = auth.get() if isinstance(auth, ttk.Combobox) else 'SQL Authentication'
                    if key in ('user','password') and auth_val=='Windows Integrated (Trusted_Connection)':
                        pass
                    else:
                        if not val and key not in ('password',):
                            if isinstance(w, tk.Entry): w.config(highlightbackground='red', highlightcolor='red', highlightthickness=2)
                            raise Exception(f'{spec.name} field {key} is required')
                else:
                    if not val and key not in ('password','role','warehouse','schema','dataset','credentials','auth_method','location'):
                        if isinstance(w, tk.Entry): w.config(highlightbackground='red', highlightcolor='red', highlightthickness=2)
                        raise Exception(f'{spec.name} field {key} is required')
                vals[key] = val
            query_widget = store.get('query');
            if query_widget is None: raise Exception("Query widget not found in store")
            query = query_widget.get('1.0','end').strip();
            if not query: raise Exception('SQL query is required')
            vals['query'] = query
            return ('db', {'db_type': dbt, 'params': vals})

    # ---------- Results UI ----------
    def _build_results(self):
        f = self.tab_results
        top = ttk.Frame(f); top.pack(fill='x', padx=6, pady=6)
        self.lbl_summary = ttk.Label(top, text='No results yet'); self.lbl_summary.pack(anchor='w')
        row1 = ttk.Frame(f); row1.pack(fill='x', padx=6, pady=(0,6))
        ttk.Label(row1, text='View:').pack(side='left')
        self.view_var = tk.StringVar(value='counts')
        self.view_combo = ttk.Combobox(row1, state='readonly', width=48, textvariable=self.view_var, values=['counts','column_map','column_compare','dtype_compare','unmatched_rows','only_in_datasource1','only_in_datasource2','findings','column_value_diffs'])
        self.view_combo.pack(side='left', padx=6); self.view_combo.bind('<<ComboboxSelected>>', lambda e: self._display_results())
        self.filter_col_var = tk.StringVar(value='(all)')
        self.filter_col_combo = ttk.Combobox(row1, state='readonly', width=32, textvariable=self.filter_col_var, values=['(all)'])
        self.filter_col_combo.pack(side='left'); self.filter_col_combo.bind('<<ComboboxSelected>>', lambda e: self._display_results())

        table = ttk.Frame(f); table.pack(fill='both', expand=True, padx=6, pady=6)
        self.tree = ttk.Treeview(table, show='headings')
        self.sort_state = {}; self._df_override = None; self._current_cols = []
        vsb = ttk.Scrollbar(table, orient='vertical', command=self.tree.yview)
        hsb = ttk.Scrollbar(table, orient='horizontal', command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        vsb.pack(side='right', fill='y'); hsb.pack(side='bottom', fill='x'); self.tree.pack(side='left', fill='both', expand=True)
        self.tree.tag_configure('s1', background='#FFE8A1'); self.tree.tag_configure('s2', background='#FFB3B3')

        btns = ttk.Frame(f); btns.pack(fill='x', padx=6, pady=6)
        ttk.Button(btns, text='Export current view CSV', command=self._export_current_view).pack(side='right', padx=6)
        ttk.Button(btns, text='Export ALL CSVs (./results/)', command=self._export_all).pack(side='right')

    def _display_results(self):
        view = self.view_var.get(); df = self.results.get(view, pd.DataFrame())
        if isinstance(getattr(self,'_df_override', None), pd.DataFrame): df = self._df_override; self._df_override = None
        if view in ('column_value_diffs','row_differences') and isinstance(df,pd.DataFrame) and not df.empty:
            cols = sorted(list(set(df['Column']))) if 'Column' in df.columns else []
            self.filter_col_combo['values'] = ['(all)'] + cols
        else:
            self.filter_col_combo['values'] = ['(all)']
        filt = self.filter_col_var.get()
        if view in ('column_value_diffs','row_differences') and 'Column' in df.columns and filt and filt!='(all)' and not df.empty:
            df = df[df['Column']==filt]
        for item in self.tree.get_children(): self.tree.delete(item)
        if df is None or (isinstance(df,pd.DataFrame) and df.empty):
            self.lbl_summary.config(text=self.results.get('summary','No data for view: '+view)); self.tree['columns'] = []; return
        cols = list(df.columns); self.tree['columns'] = cols; self._current_cols = cols[:]
        st = self.sort_state.get(view, {'col': None, 'ascending': True}); self._apply_tree_headings(cols, sort_col=st.get('col'), ascending=st.get('ascending', True))
        DEFAULT_COL_WIDTH = 160
        for c in cols: self.tree.column(c, width=DEFAULT_COL_WIDTH, minwidth=100, stretch=False, anchor='w')
        head = df.head(1000)
        if view in ('row_differences','unmatched_rows') and '_datasource' in df.columns:
            for _,row in head.iterrows():
                vals = [row.get(c,'') for c in cols]; tag = 's1' if row.get('_datasource','')=='Datasource1' else ('s2' if row.get('_datasource','')=='Datasource2' else '')
                self.tree.insert('', 'end', values=vals, tags=(tag,))
        else:
            for _,row in head.iterrows():
                vals = [row.get(c,'') for c in cols]; self.tree.insert('', 'end', values=vals)
        note = f'View: {view} \n Showing first {min(1000,len(df))} of {len(df)} rows'
        if self.results.get('summary'): note = self.results['summary'] + ' \n\n ' + note
        st = self.sort_state.get(view)
        if st and st.get('col'): note += f"\n\n SORTED BY: {st['col']} ({'asc' if st['ascending'] else 'desc'}) , CLICK ON COLUMN HEADER TO SORT THE DATA"
        self.lbl_summary.config(text=note)

    def _export_current_view(self):
        view = self.view_var.get(); df = self.results.get(view, pd.DataFrame())
        if df is None or df.empty: messagebox.showwarning('No data', f'No data in view: {view}'); return
        os.makedirs('results', exist_ok=True); ts = datetime.now().strftime('%Y-%m-%d_%H-%M-%S'); fname = f'results/{view}_{ts}.csv'
        try: df.to_csv(fname, index=False); self._log(f'Exported {view} to {fname}'); messagebox.showinfo('Exported', f'Exported to {fname}')
        except Exception as e: self._log(f'Failed to export CSV: {e}'); messagebox.showerror('Export failed', str(e))

    def _export_all(self):
        os.makedirs('results', exist_ok=True); ts = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
        try:
            for k,df in self.results.items():
                if isinstance(df,pd.DataFrame) and not df.empty:
                    fname = f'results/{k}_{ts}.csv'; df.to_csv(fname, index=False)
            self._log('Exported all non-empty views to ./results/'); messagebox.showinfo('Exported','Exported all non-empty views to ./results/')
        except Exception as e:
            self._log(f'Failed to export all CSVs: {e}'); messagebox.showerror('Export failed', str(e))

    # ---------- Logs & Reset ----------
    def _build_logs(self):
        self.log_text = tk.Text(self.tab_logs, wrap='word'); self.log_text.pack(fill='both', expand=True)

    def _log(self, msg):
        if isinstance(msg, str) and TS_RE.match(msg): line = msg
        else: line = f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}"
        try: self.log_text.insert('end', line+'\n'); self.log_text.see('end')
        except Exception: pass

    def on_reset(self):
        self.cancel_event = True
        for d in (self.left_widgets, self.right_widgets):
            for k,w in d.items():
                try:
                    if isinstance(w, tk.Entry): w.delete(0,'end'); w.config(highlightthickness=0)
                    elif isinstance(w, ttk.Combobox): w.set('')
                    elif isinstance(w, tk.Text): w.delete('1.0','end')
                except Exception: pass
        for ent in (self.pk_entry, self.rowlimit_entry, self.lowmem_sample_entry): ent.delete(0,'end')
        self.lowmem_sample_entry.insert(0,'10000'); self.lowmem_var.set(False)
        for k in list(self.results.keys()): self.results[k] = (pd.DataFrame() if isinstance(self.results[k], pd.DataFrame) else None)
        self.view_var.set('findings'); self.filter_col_var.set('(all)')
        self._display_results(); self._log('Reset performed')

    def _sort_df_for_view(self, df: pd.DataFrame, col: str, ascending: bool) -> pd.DataFrame:
        if df is None or df.empty or col not in df.columns: return df
        ser = df[col].astype(str)
        num = pd.to_numeric(ser.str.replace(',',''), errors='coerce')
        if num.notna().mean() >= 0.9: return df.loc[num.sort_values(ascending=ascending).index]
        dt = pd.to_datetime(ser, errors='coerce', cache=True)
        if dt.notna().mean() >= 0.9: return df.loc[dt.sort_values(ascending=ascending).index]
        key = ser.str.lower(); return df.loc[key.sort_values(ascending=ascending, kind='mergesort').index]

    def _apply_tree_headings(self, cols, sort_col=None, ascending=True):
        ARROW_UP=' ▲'; ARROW_DOWN=' ▼'
        for c in cols:
            label = f"{c}{ARROW_UP if sort_col==c and ascending else (ARROW_DOWN if sort_col==c else '')}"
            self.tree.heading(c, text=label, command=lambda c=c: self._on_tree_heading_click(c))

    def _on_tree_heading_click(self, col):
        view = self.view_var.get(); base_df = self.results.get(view, pd.DataFrame())
        filt = self.filter_col_var.get() if hasattr(self,'filter_col_var') else '(all)'
        if view in ('column_value_diffs','row_differences') and 'Column' in base_df.columns and filt and filt!='(all)': base_df = base_df[base_df['Column']==filt]
        st = self.sort_state.get(view, {'col': None, 'ascending': True}); ascending = True if st.get('col') != col else not st.get('ascending', True)
        self.sort_state[view] = {'col': col, 'ascending': ascending}
        df_sorted = self._sort_df_for_view(base_df.copy(), col, ascending); self._df_override = df_sorted; self._display_results()

    def _save_profile(self):
        profile = {
            'mode': self.mode_var.get(), 'pk': self.pk_entry.get().strip(), 'row_limit': self.rowlimit_entry.get().strip(), 'lowmem': bool(self.lowmem_var.get()), 'lowmem_sample': self.lowmem_sample_entry.get().strip(), 'timeout_min': int(self.timeout_min_var.get() or 0), 'left': self._collect_source(self.left_widgets), 'right': self._collect_source(self.right_widgets)
        }
        include_pw = messagebox.askyesno('Save Profile', 'Include passwords/secret fields in profile?')
        if include_pw:
            try: profile = _encrypt_profile_secrets(profile)
            except Exception as e:
                self._log(f'Encryption unavailable; stripping passwords. ({e})')
                for side in ('left','right'):
                    src = profile.get(side, {})
                    if src.get('kind')=='db':
                        params = src.get('params', {})
                        if 'password' in params: params['password'] = ''
        else:
            for side in ('left','right'):
                src = profile.get(side, {})
                if src.get('kind')=='db':
                    params = src.get('params', {})
                    if 'password' in params: params['password'] = ''
        os.makedirs('profiles', exist_ok=True)
        fname = filedialog.asksaveasfilename(defaultextension='.json', initialdir='profiles', filetypes=[('JSON','*.json')])
        if not fname: return
        with open(fname, 'w', encoding='utf-8') as f: json.dump(profile, f, indent=2)
        self._log(f'Saved profile to {fname}'); messagebox.showinfo('Saved', f'Profile saved to {fname}')

    def _collect_source(self, store):
        if 'path' in store:
            return {'kind':'file','path':store['path'].get().strip(),'delimiter': store['delimiter'].get() if store.get('delimiter') else ','}
        else:
            dbt = store.get('db_type_var').get(); spec = DB_SPECS.get(dbt); vals = {}
            for key,_,_ in spec.fields:
                w = store.get(key); vals[key] = w.get().strip() if isinstance(w,(tk.Entry,ttk.Combobox)) else ''
            vals['query'] = store.get('query').get('1.0','end').strip();
            return {'kind':'db','db_type':dbt,'params':vals}

    def _load_profile(self):
        fname = filedialog.askopenfilename(initialdir='profiles', filetypes=[('JSON','*.json')])
        if not fname: return
        try:
            with open(fname, 'r', encoding='utf-8') as f: profile = json.load(f)
            try: profile = _decrypt_profile_secrets(profile)
            except Exception: pass
            self._loading_profile = True
            self.mode_var.set(profile.get('mode','db_vs_db'))
            self.pk_entry.delete(0,'end'); self.pk_entry.insert(0, profile.get('pk',''))
            self.rowlimit_entry.delete(0,'end'); self.rowlimit_entry.insert(0, profile.get('row_limit',''))
            self.lowmem_var.set(bool(profile.get('lowmem', False)))
            self.lowmem_sample_entry.delete(0,'end'); self.lowmem_sample_entry.insert(0, profile.get('lowmem_sample','10000'))
            self.timeout_min_var.set(int(profile.get('timeout_min', 60)))
            self.render_config()
            left_saved = profile.get('left',{}) or {}; right_saved = profile.get('right',{}) or {}
            self._apply_loaded_source('left', left_saved); self._apply_loaded_source('right', right_saved)
            self._log(f'Loaded profile from {fname}'); messagebox.showinfo('Loaded', f'Profile loaded from {fname}')
        except Exception as e:
            messagebox.showerror('Load failed', str(e))
        finally:
            self._loading_profile = False

    def _apply_loaded_source(self, side: str, saved: dict):
        mode = self.mode_var.get(); kind = ('db' if (side=='left' and mode in ('db_vs_db','db_vs_file')) or (side=='right' and mode=='db_vs_db') else 'file')
        if kind=='db':
            dbt_saved = saved.get('db_type','Postgres'); dbt = self._canon_db_type(dbt_saved,'Postgres'); store = self._render_side(side,'db',db_type=dbt)
            params = saved.get('params',{}) or {}; spec = DB_SPECS.get(dbt)
            if spec and hasattr(spec,'fields'):
                for fld in spec.fields:
                    key = fld[0]; val = params.get(key); w = store.get(key)
                    if w is not None and val is not None:
                        if isinstance(w, ttk.Combobox): w.set(val)
                        elif isinstance(w, tk.Entry): w.delete(0,'end'); w.insert(0,val)
            if dbt=='Snowflake':
                auth_val = params.get('auth_method') or 'Password'; auth_val = 'SSO (externalbrowser)' if str(auth_val).upper().startswith('SSO') else 'Password'
                if 'auth_method' in store:
                    try: store['auth_method'].set(auth_val)
                    except Exception: pass
                pwd = store.get('password')
                if pwd:
                    try: pwd.configure(state=('disabled' if auth_val=='SSO (externalbrowser)' else 'normal'))
                    except Exception: pass
            if dbt=='SQL Server':
                am_var = store.get('auth_method_var'); v = params.get('auth_method','SQL Authentication')
                if am_var: am_var.set(v)
                for k in ('user','password'):
                    if k in store:
                        try: store[k].configure(state=('disabled' if v=='Windows Integrated (Trusted_Connection)' else 'normal'))
                        except Exception: pass
            q = params.get('query', saved.get('query',''))
            if isinstance(store.get('query'), tk.Text): store['query'].delete('1.0','end'); store['query'].insert('1.0', q)
        else:
            store = self._render_side(side,'file')
            if 'path' in store: store['path'].delete(0,'end'); store['path'].insert(0, saved.get('path',''))
            if 'delimiter' in store: store['delimiter'].set(saved.get('delimiter',','))

    def _build_brand_footer(self):
        bar = ttk.Frame(self.root); bar.pack(side='bottom', fill='x')
        ttk.Separator(bar, orient='horizontal').pack(fill='x', side='top')
        inner = ttk.Frame(bar, padding=(8,4)); inner.pack(fill='x')
        left = ttk.Frame(inner); left.pack(side='left', anchor='w')
        try:
            #from PIL import Image, ImageTk
            #from PIL import Image
            path = resource_path('qa_validator.png'); 
            img = Image.open(path).resize((250,25)); self._brand_logo_small = ImageTk.PhotoImage(img)
            ttk.Label(left, image=self._brand_logo_small).pack(side='left', padx=(0,6))
        except Exception: pass
        ttk.Label(left, text='QA Validator • Developed by Lalit Kela', font=('Segoe UI', 9)).pack(side='left')


if __name__ == '__main__':
    #root = tk.Tk(); app = DataComparatorApp(root); set_app_icon(root); maximize_on_start(root); root.mainloop()
    # Required for PyInstaller + multiprocessing on Windows
    import multiprocessing, sys
    multiprocessing.freeze_support()
    try:
        # Ensures child uses the frozen EXE correctly
        multiprocessing.set_executable(sys.executable)
    except Exception:
        pass

    root = tk.Tk()
    app = DataComparatorApp(root)
    set_app_icon(root)
    maximize_on_start(root)
    root.mainloop()

