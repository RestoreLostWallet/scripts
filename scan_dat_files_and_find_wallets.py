import os
import re
import argparse
import math
import sqlite3
from tqdm import tqdm

# Attempt to import Berkeley DB library
try:
    import bsddb3 as bsddb
except ImportError:
    try:
        import bsddb
    except ImportError:
        bsddb = None

# Regex patterns
WIF_REGEX = re.compile(rb"\b[5KL][1-9A-HJ-NP-Za-km-z]{50}\b")
BTC_ADDRESS_REGEX = re.compile(rb"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b")

# Keyword lists
CORE_KEYWORDS = [b"version", b"minversion", b"name", b"bestblock", b"tx", b"txid", b"key",
    b"wkey", b"defaultkey", b"pool", b"poolmeta", b"poolsize", b"keypool",
    b"keymeta", b"hdchain", b"hdseed", b"hdmasterkey", b"cscript", b"script",
    b"watchonly", b"address", b"label", b"orderposnext", b"keybirth",
    b"mintxfee", b"purpose", b"descriptor"]
ENC_KEYWORDS = [b"ckey", b"mkey"]
REQUIRED_KEYWORDS = [b"version", b"minversion"]
LEGACY_KEY = b"defaultkey"
HD_KEY = b"hdseed"
DESC_KEY = b"descriptor"

# Scoring weights
WEIGHTS = {
    'db_header': 15, 'db_lib': 15, 'enc': 10, 'kw': 6,
    'priv': 10, 'addr': 4, 'struct': 15, 'fmt': 10,
    'sqlite': 20, 'size_bonus': 5, 'req': 20, 'req_pen': 20
}

# Helpers

def is_sqlite(path):
    try:
        with open(path, 'rb') as f:
            return f.read(16).startswith(b"SQLite format 3\0")
    except:
        return False


def extract_sqlite_info(path):
    info = {'tables': [], 'user_version': None, 'app_id': None}
    try:
        conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        cur = conn.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table';")
        info['tables'] = [r[0] for r in cur.fetchall()]
        cur.execute("PRAGMA user_version;")
        info['user_version'] = cur.fetchone()[0]
        cur.execute("PRAGMA application_id;")
        info['app_id'] = cur.fetchone()[0]
        conn.close()
    except:
        pass
    return info


def check_db_structure(path):
    if not bsddb:
        return 0, False
    try:
        db = bsddb.db.DB()
        db.open(path, None, bsddb.db.DB_BTREE, bsddb.db.DB_RDONLY)
        cur = db.cursor()
        cnt, rec = 0, cur.first()
        while rec and cnt < 1000:
            cnt += 1
            rec = cur.next()
        cur.close(); db.close()
        return cnt, cnt > 0
    except:
        return 0, False


def format_size(n):
    for u in ['B','KB','MB','GB','TB']:
        if n < 1024:
            return f"{n:.2f}{u}"
        n /= 1024
    return f"{n:.2f}PB"


def size_mult(n):
    """
    Map file size to a multiplier using thresholds:
      <=10MB → 1.0
      <=50MB → 0.7
      <=100MB → 0.5
      <=1000MB → 0.2
      >=2000MB → 0.1
    Log-linear interpolation between thresholds.
    """
    size_mb = n / (1024 * 1024)
    thresholds = [10, 50, 100, 1000, 2000]
    multipliers = [1.0, 0.7, 0.5, 0.2, 0.1]
    if size_mb <= thresholds[0]:
        return multipliers[0]
    if size_mb >= thresholds[-1]:
        return multipliers[-1]
    for i in range(len(thresholds) - 1):
        low_s, high_s = thresholds[i], thresholds[i+1]
        if low_s < size_mb < high_s:
            low_m, high_m = multipliers[i], multipliers[i+1]
            t = (math.log(size_mb) - math.log(low_s)) / (math.log(high_s) - math.log(low_s))
            return low_m + t * (high_m - low_m)
    return multipliers[0]
    if size_mb >= 50:
        return 0.7
    # linear interpolation between 10MB (1.0) and 50MB (0.7)
    return 1.0 - (size_mb - 10) * (0.3 / (50 - 10))


def analyze_file(path):
    f = { 'format':'unknown','version':None,'minversion':None,
          'sqlite_tables':[], 'user_version':None, 'app_id':None,
          'db_header':False,'db_lib':False,'enc':False,
          'kw_count':0,'priv_count':0,'addr_count':0,
          'struct_ok':False,'struct_cnt':0,'size':0,
          'kws':[],'keys':[],'addrs':[],'req_ok':[],'req_miss':[] }
    try:
        f['size'] = os.path.getsize(path)
        data = open(path, 'rb').read()
    except:
        return f
    # SQLite vs BDB
    if is_sqlite(path):
        f['format'] = 'sqlite'
        info = extract_sqlite_info(path)
        f['sqlite_tables'] = info['tables']
        f['user_version'] = info['user_version']
        f['app_id'] = info['app_id']
        f['struct_cnt'] = len(info['tables'])
        # consider structure ok if any wallets table detected
        if f['struct_cnt'] > 0:
            f['struct_ok'] = True
    else:
        cnt, ok = check_db_structure(path)
        f['struct_cnt'] = cnt; f['struct_ok'] = ok
        if cnt > 0:
            f['db_header'] = True; f['db_lib'] = bsddb is not None
    # Encryption
    for kw in ENC_KEYWORDS:
        if kw in data:
            f['enc'] = True; break
    # Keywords
    for kw in CORE_KEYWORDS:
        c = data.count(kw)
        if c > 0:
            f['kw_count'] += c
            f['kws'].append(kw.decode())
    # Required
    for r in REQUIRED_KEYWORDS:
        if r in data:
            f['req_ok'].append(r.decode())
        else:
            f['req_miss'].append(r.decode())
    # Format detection for BDB
    if f['format'] != 'sqlite':
        if LEGACY_KEY in data: f['format'] = 'legacy'
        elif HD_KEY in data: f['format'] = 'hd'
        elif DESC_KEY in data: f['format'] = 'descriptor'
        m = re.search(rb"version\W*(\d+)", data)
        if m: f['version'] = int(m.group(1))
        m = re.search(rb"minversion\W*(\d+)", data)
        if m: f['minversion'] = int(m.group(1))
    else:
        f['version'] = f['user_version']
    # Private keys
    keys = WIF_REGEX.findall(data)
    f['priv_count'] = len(keys)
    f['keys'] = list({k.decode() for k in keys})
    # Addresses
    addrs = BTC_ADDRESS_REGEX.findall(data)
    f['addr_count'] = len(addrs)
    f['addrs'] = list({a.decode() for a in addrs})
    return f


def compute_probability(f):
    """Compute a weighted probability, with a fallback for keywords."""
    s = 0
    # Format and DB presence
    if f['format'] == 'sqlite': s += WEIGHTS['sqlite']
    if f['db_header']: s += WEIGHTS['db_header']
    if f['db_lib']: s += WEIGHTS['db_lib']
    if f['enc']: s += WEIGHTS['enc']
    # Keywords (weighted)
    s += min(len(f['kws']), 10) * WEIGHTS['kw']
    # Private keys and addresses
    if f['priv_count'] > 0: s += WEIGHTS['priv']
    if f['addr_count'] > 0: s += WEIGHTS['addr']
    # Structure and format bonus
    if f['struct_ok']: s += WEIGHTS['struct']
    if f['format'] not in ('unknown', 'sqlite'): s += WEIGHTS['fmt']
    # Size bonus
    if f['size'] > 1024: s += WEIGHTS['size_bonus']
    # Required keywords
    s += len(f['req_ok']) * WEIGHTS['req']
    s -= len(f['req_miss']) * WEIGHTS['req_pen']
    # Clamp pre-multiplier
    s = max(min(s, 100), 0)
    # If no required keywords, apply heavy reduction
    if not f['req_ok']:
        s *= 0.1
    # If zero score but keywords found, fallback to keyword count
    if s == 0 and f['kws']:
        s = float(len(f['kws']))
    # Apply size multiplier
    s *= size_mult(f['size'])
    # Final clamp
    return max(min(s, 100), 0)


def scan_dir(root, output):
    files = [os.path.join(dp, fn) for dp, _, fl in os.walk(root) for fn in fl if fn.lower().endswith('.dat')]
    results = []
    max_prob = 0.0  # track maximum probability
    pbar = tqdm(files, desc="Scanning .dat files", unit="file")
    for path in pbar:
        f = analyze_file(path)
        pr = compute_probability(f)
        sz = format_size(f['size'])
        pbar.write(f"{pr:.1f}%")
        pbar.write(f"  Path: {path}")
        pbar.write(f"  Format: {f['format']}, ver={f['version']}, minver={f['minversion']}, Enc={f['enc']}")
        if f['format'] == 'sqlite':
            pbar.write(f"  Tables: {', '.join(f['sqlite_tables'])}")
        pbar.write(f"  Struct: {'OK' if f['struct_ok'] else 'Bad'} ({f['struct_cnt']}), ReqOK={len(f['req_ok'])}/{len(REQUIRED_KEYWORDS)}")
        if f['req_miss']:
            pbar.write(f"  Req Missing: {', '.join(f['req_miss'])}")
        if f['kws']:
            pbar.write(f"  Keywords({len(f['kws'])}): {', '.join(f['kws'])}")
        if f['keys']:
            pbar.write(f"  Priv Keys({f['priv_count']}): {', '.join(f['keys'])}")
        if f['addrs']:
            pbar.write(f"  Addresses({f['addr_count']}): {', '.join(f['addrs'])}")
        pbar.write(f"  Size={sz}\n")
        results.append({'path': path, 'probability': pr, 'features': f})
        # update maximum seen probability
        if pr > max_prob:
            max_prob = pr
        pbar.set_postfix({'max_probability': f"{max_prob:.1f}%"})
        # Sort by probability and write text-based results
    results.sort(key=lambda x: x['probability'], reverse=True)
    txtf = output + '.txt'
        # Write sorted text-based results
    txtf = output + '.txt'
    with open(txtf, 'w') as tf:
        for it in results:
            f = it['features']
            tf.write(f"{it['probability']:.1f}%\n")
            tf.write(f"  Path: {it['path']}\n")
            tf.write(f"  Format: {f['format']}, ver={f['version']}, minver={f['minversion']}, Enc={f['enc']}\n")
            if f['format'] == 'sqlite':
                tf.write(f"  Tables: {', '.join(f['sqlite_tables'])}\n")
            tf.write(f"  Struct: {'OK' if f['struct_ok'] else 'Bad'} ({f['struct_cnt']}), ReqOK={len(f['req_ok'])}/{len(REQUIRED_KEYWORDS)}\n")
            if f['req_miss']:
                tf.write(f"  Req Missing: {', '.join(f['req_miss'])}\n")
            if f['kws']:
                tf.write(f"  Keywords({len(f['kws'])}): {', '.join(f['kws'])}\n")
            if f['keys']:
                tf.write(f"  Priv Keys({f['priv_count']}): {', '.join(f['keys'])}\n")
            if f['addrs']:
                tf.write(f"  Addresses({f['addr_count']}): {', '.join(f['addrs'])}\n")
            tf.write(f"  Size={format_size(f['size'])}\n")
            # blank line between entries
            tf.write("\n")
    # Finished writing to text file
    print(f"\nScan complete. Results saved to {txtf}")

def main():
    parser = argparse.ArgumentParser(description='Scan .dat and SQLite wallet files')
    parser.add_argument('directory', help='Directory to scan')
    parser.add_argument('--output', default='wallet_scan_results', help='Output file prefix')
    args = parser.parse_args()
    scan_dir(args.directory, args.output)

if __name__ == '__main__':
    main()
