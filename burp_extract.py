import sqlite3
import sys
import json
import csv
import os
import gzip
import zlib

BURP_FILE = r'C:\Users\LuisDelRio\Burp\2026-04-10-android-bleach.burp'

def try_decompress(data):
    if data is None:
        return b''
    if isinstance(data, str):
        return data.encode()
    try:
        return gzip.decompress(data)
    except Exception:
        pass
    try:
        return zlib.decompress(data)
    except Exception:
        pass
    return data

conn = sqlite3.connect(BURP_FILE)

# List tables
tables = conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
print('=== TABLES ===')
for t in tables:
    print(' ', t[0])

# Row counts
print('\n=== ROW COUNTS ===')
for t in tables:
    try:
        count = conn.execute(f"SELECT COUNT(*) FROM [{t[0]}]").fetchone()[0]
        print(f'  {t[0]}: {count}')
    except Exception as e:
        print(f'  {t[0]}: ERROR {e}')

# Schema for each table
print('\n=== SCHEMAS ===')
for t in tables:
    try:
        cols = conn.execute(f"PRAGMA table_info([{t[0]}])").fetchall()
        print(f'\n  [{t[0]}]')
        for c in cols:
            print(f'    {c[1]} ({c[2]})')
    except Exception as e:
        print(f'  {t[0]}: ERROR {e}')

conn.close()
