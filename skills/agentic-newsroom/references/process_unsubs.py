#!/usr/bin/env python3
"""Process unsubscribe clicks from the site access log (watermark-persisted).

Companion to the agentic-newsroom curator: each run counts only access-log
lines newer than the persisted watermark, moves matching subscribers out of
the store, and records expired tokens so re-clicks are no-ops. The curator
runs it once per cycle; the store schema is:

  subscribers.json: {"subscribers": [{email, token (hex), added_at, source},
                                     ...], "expired_tokens": [...]}

Config: reads the `unsub` key of newsroom.json (see newsroom.json.example):
  log_ssh    ssh alias of the site host (omit to grep a local log_file)
  log_file   path to the vhost access log on that host (read via sudo)
  unsub_pct  URL substring that identifies an unsubscribe hit
  watermark  path of the last-processed-timestamp file
  store      path of the subscriber store

Watermark rule: verify the matcher against a real log line BEFORE the first
watermark-advancing run - a 0-hit run with a bad matcher still advances the
watermark and swallows those events forever. Backup the store and the
watermark before the first run.

stdlib only. Run by the news curator each cycle.
"""
import json, subprocess, re, os, argparse, tempfile
from datetime import datetime

MARK_FORMAT = '%d/%b/%Y:%H:%M:%S %z'  # nginx log time


def expand(p):
    return os.path.expanduser(p)


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('--config', default='newsroom.json')
    args = ap.parse_args()
    cfg = json.load(open(expand(args.config))).get('unsub', {})
    mark = expand(cfg['watermark'])
    subs_path = expand(cfg['store'])
    log_file = cfg['log_file']
    needle = cfg['unsub_path']
    ssh = cfg.get('log_ssh')
    if ssh:
        remote = (f"sudo grep -h {needle!r} {log_file} 2>/dev/null || true")
        r = subprocess.run(
            ['ssh', '-o', 'ConnectTimeout=12', '-o', 'BatchMode=yes', ssh, remote],
            capture_output=True, text=True, timeout=90)
    else:
        r = subprocess.run(
            ['bash', '-c',
             f"grep -h {needle!r} {log_file} 2>/dev/null || true"],
            capture_output=True, text=True, timeout=90)
    lines = r.stdout.splitlines()

    def parse(ts):
        try:
            return datetime.strptime(ts, MARK_FORMAT)
        except Exception:
            return None

    wm = open(mark).read().strip() if os.path.exists(mark) else ''
    wmdt = parse(wm) if wm else None
    store = json.load(open(subs_path))
    subs = store.get('subscribers', [])
    expired = set(store.get('expired_tokens', []))
    by_token = {s.get('token'): s for s in subs}
    new_wm = wmdt
    hits = 0
    removed = []
    for line in lines:
        m = re.search(r'\[([^\]]+)\]', line)
        if not m:
            continue
        t = parse(m.group(1))
        if not t:
            continue
        if wmdt and t <= wmdt:
            continue
        if not new_wm or t > new_wm:
            new_wm = t
        im = re.search(r'[?&]u=([A-Za-z0-9_-]+)', line)
        if not im:
            continue
        tok = im.group(1)
        if tok in by_token and tok not in expired:
            sub = by_token[tok]
            subs.remove(sub)
            expired.add(tok)
            removed.append(sub.get('email', ''))
        hits += 1
    store['subscribers'] = subs
    store['expired_tokens'] = sorted(expired)
    st = os.stat(subs_path) if os.path.exists(subs_path) else None
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(subs_path) or '.')
    with os.fdopen(fd, 'w') as f:
        json.dump(store, f, indent=1)
    os.chmod(tmp, 0o600)
    os.replace(tmp, subs_path)
    if new_wm:
        open(mark, 'w').write(new_wm.strftime(MARK_FORMAT))
    print(f'unsub processing: {hits} hits, {len(removed)} removed '
          f'({", ".join(removed) or "none"}), {len(subs)} subscribers remain')


if __name__ == '__main__':
    main()