#!/usr/bin/env python3
"""Generic agentic-newsroom builder: render + deploy news pages from curated state.

Companion to the agentic-newsroom curator automation (see SKILL.md). Reads a
small JSON config, renders the primary page (newest N stories), the archive
page (everything older), and an RSS feed, then ships them to the configured
static site. Maintains the state's archive key: entries older than
archive_hours move from articles into archive (deduped, atomic, nothing
deleted) - the curator never prunes.

State schema: {\"articles\": [...], \"archive\": [...]}, entry:
{id, added_at (ISO UTC Z), source, title, url, category, summary}.

Usage:
  build_news.py --config newsroom.json [--dry-run] [--state PATH]

Config keys (newsroom.json; see newsroom.json.example):
  state            path to the state file (required)
  site_url         site base URL (required)
  page_prefix      page prefix, default /news/
  primary_count    page cap, default 10
  rss_count        RSS cap, default 15
  archive_hours    entries older than this move to the archive key, default 36
  brand            {name, copyright, [nav: [[label, href], ...]]}
  copy             {page_title, page_lede, archive_title, archive_lede,
                    archive_note} (optional; sensible defaults)
  deploy           {ssh: host alias or null, sudo: true, web_root} (optional;
                   null ssh = write to --out-dir and ship nothing)
  verify           {scheme: https, insecure: true} for the post-ship curl
  map              {path: /etc/nginx/go-targets.map} (optional) - nginx
                   arg-id -> target map for /news/go click-throughs
  rss              {file: rss.xml} (optional; omit to disable RSS)
  counts_cmd       optional command string; its last stdout line must be JSON
                   {\"visits\": int, \"clicks\": {id: int}}; absent = render 0

Deploy target layout: <web_root><page_prefix>index.html, .../history/index.html,
.../rss.xml. The go-map covers ALL live stories (primary + archive) so every
published link resolves; its first line is a static header so nginx reloads
only on a real id change.

stdlib only: json, html, subprocess, datetime, os, tempfile, urllib.
"""
import json, html, subprocess, datetime, os, sys, argparse, tempfile, urllib.request

DEFAULT_CONFIG = {
    'state': '~/.openclaw/news/state.json',
    'site_url': 'https://example.com',
    'page_prefix': '/news/',
    'primary_count': 10,
    'rss_count': 15,
    'archive_hours': 36,
    'brand': {'name': 'Agentic Newsroom', 'copyright': '(c) 2026'},
    'copy': {},
    'deploy': {'ssh': None, 'sudo': True, 'web_root': '/var/www/example.com'},
    'map': None,
    'rss_file': 'rss.xml',
    'counts_cmd': None,
}

TEMPLATE = '''<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>__PAGETITLE__</title>
  <meta name="description" content="__PAGEDESC__">
  <meta name="theme-color" content="#1a2233">
  <link rel="canonical" href="__PAGECANON__">
<link rel="alternate" type="application/rss+xml" title="__RSSFEEDTITLE__" href="__RSSPATH__">
  <meta property="og:title" content="__PAGETITLE__">
  <meta property="og:description" content="__PAGEDESC__">
  <meta property="og:url" content="__PAGECANON__">
  <meta property="og:type" content="website">
  <meta property="og:site_name" content="__SITE__">
  <meta name="twitter:card" content="summary">
  <link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 16 16'%3E%3Crect width='16' height='16' fill='%231a2233'/%3E%3Crect x='11' y='3' width='3' height='3' fill='%23c9a96a'/%3E%3C/svg%3E">
  <style>
    :root { --fg:#1a2233; --sub:#5a6478; --rule:#e9ecf1; --ink:#8a6a2b;
            --bg:#f6f7f9; --card:#fff; --max:64ch; }
    *, *::before, *::after { box-sizing: border-box; }
    body { margin:0; font:17px/1.6 -apple-system, BlinkMacSystemFont, "Segoe UI",
           Inter, Arial, sans-serif; color:var(--fg); background:var(--bg);
           -webkit-font-smoothing:antialiased; }
    a { color:var(--ink); text-decoration:underline; text-underline-offset:2px; }
    a:hover, a:focus { color:var(--fg); }
    .wrap { max-width:var(--max); margin:0 auto; padding:0 1.25rem; }
    header { border-bottom:1px solid var(--rule,#e9ecf1); background:#fff; }
    header .wrap { display:flex; align-items:baseline; justify-content:space-between;
                   padding-top:1.5rem; padding-bottom:1.5rem; flex-wrap:wrap; gap:1rem; }
    .wordmark { font-family:Georgia, "Times New Roman", serif; font-weight:600;
                font-size:1.35rem; letter-spacing:.12em; color:var(--fg);
                text-decoration:none; }
    nav ul { list-style:none; margin:0; padding:0; display:flex; flex-wrap:wrap;
             gap:1.25rem; font-size:.9rem; }
    nav a { color:var(--sub); text-decoration:none; }
    main { padding:3.5rem 0 5rem; }
    h1 { font-family:Georgia, "Times New Roman", serif; font-weight:600;
         font-size:2.4rem; line-height:1.15; margin:0 0 1.25rem; max-width:24ch; }
    .lede { font-size:1.2rem; line-height:1.55; color:#2f3a4f; margin:0 0 1rem;
            max-width:56ch; }
    .wire-note { color:var(--sub); font-size:.85rem; margin:0 0 2rem; }
    .news-item { padding:1.15rem 0; border-bottom:1px solid var(--rule,#e9ecf1); }
    .news-item:first-of-type { border-top:1px solid var(--rule,#e9ecf1); }
    .news-item .cat { font-size:.72rem; letter-spacing:.08em; text-transform:uppercase;
                      color:var(--ink); margin-bottom:.3rem; }
    .news-item h2 { font-family:Georgia, "Times New Roman", serif; font-size:1.15rem;
                    font-weight:600; line-height:1.3; margin:0 0 .4rem; }
    .news-item h2 a { color:var(--fg); text-decoration:none; }
    .news-item .sum { margin:0 0 .45rem; color:#2f3a4f; font-size:.95rem; }
    .news-item .meta { margin:0; color:var(--sub); font-size:.8rem; }
    footer { border-top:1px solid var(--rule,#e9ecf1); background:#fff;
             padding:1.75rem 0; color:var(--sub); font-size:.85rem; }
    @media (max-width:540px) { h1 { font-size:2rem; } }
  </style>
</head>
<body>
  <header>
    <div class="wrap">
      <a class="wordmark" href="__SITEHOME__">__SITE__</a>
      __NAV__
    </div>
  </header>
  <main>
    <div class="wrap">
__HEADBLOCK__
<!--ARTICLES-->
    </div>
  </main>
  <footer>
    <div class="wrap">
      <span>__FOOTER__</span>
    </div>
  </footer>
  <script>
  (function () {
    var els = document.querySelectorAll('time[data-curated]');
    for (var i = 0; i < els.length; i++) {
      try {
        var t = new Date(els[i].getAttribute('data-curated'));
        if (!isNaN(t.getTime())) {
          els[i].textContent = t.toLocaleTimeString([], {
            hour: 'numeric', minute: '2-digit', timeZoneName: 'short'
          });
        }
      } catch (e) {}
    }
  })();
  </script>
</body>
</html>'''


def esc(s, q=False):
    return html.escape(str(s), quote=q)


def cfg_get(cfg, path, default=None):
    cur = cfg
    for part in path.split('.'):
        if not isinstance(cur, dict) or part not in cur:
            return default
        cur = cur[part]
    return cur


def link_ok(url):
    try:
        req = urllib.request.Request(url, headers={
            'User-Agent': 'Mozilla/5.0 (compatible; newsroom-linkcheck/1.0)'})
        r = urllib.request.urlopen(req, timeout=10)
        return True, r.status
    except Exception as e:
        return False, str(e)[:60]


def get_counts(cfg):
    cmd = cfg.get('counts_cmd')
    if not cmd:
        return {'visits': 0, 'clicks': {}}
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True,
                           timeout=90)
        return json.loads(r.stdout.strip().splitlines()[-1])
    except Exception as e:
        print('counts pull failed (rendering without):', str(e)[:80])
        return {'visits': 0, 'clicks': {}}


def render_rows(articles, clicks, cfg):
    show_counts = bool(cfg.get('counts_cmd'))
    rows = []
    for a in articles:
        d = datetime.datetime.fromisoformat(a['added_at'].replace('Z', '+00:00'))
        reads = int(clicks.get(a['id'], 0))
        href = cfg['page_prefix'] + 'go?id=' + esc(a['id'], True)
        cnt = ' &middot; read %d times' % reads if show_counts else ''
        rows.append(f'''<article class="news-item">
  <div class="cat">{esc(a["category"])}</div>
  <h2><a href="{href}" rel="noopener">{esc(a["title"])}</a></h2>
  <p class="sum">{esc(a["summary"])}</p>
  <p class="meta">{esc(a["source"])} &middot; {d.strftime("%b %d")} &middot; curated <time data-curated="{d.strftime("%Y-%m-%dT%H:%M:%SZ")}" title="{d.strftime("%H:%M")} UTC">{d.strftime("%H:%M")} UTC</time>{cnt}</p>
</article>''')
    return '\n'.join(rows)


def page_from(template, cfg, page_title, page_desc, head_block, body, home='/'):
    canon = cfg['site_url'] + cfg['page_prefix'].rstrip('/') + '/'
    brand = cfg.get('brand', {})
    nav = ''
    items = brand.get('nav') or []
    if items:
        lis = ''.join(f'<li><a href="{esc(u)}">{esc(l)}</a></li>' for l, u in items)
        nav = '<nav aria-label="Primary"><ul>' + lis + '</ul></nav>'
    rss_path = cfg['page_prefix'] + cfg.get('rss_file', 'rss.xml') \
        if cfg.get('rss_file') else ''
    p = template
    for k, v in [('__PAGETITLE__', esc(page_title)), ('__PAGEDESC__', esc(page_desc)),
                 ('__PAGECANON__', esc(canon)),
                 ('__RSSFEEDTITLE__', esc(cfg['brand'].get('name', '') + ' news feed')),
                 ('__RSSPATH__', esc(rss_path)),
                 ('__SITE__', esc(brand.get('name', ''))),
                 ('__SITEHOME__', esc(home)), ('__NAV__', nav),
                 ('__FOOTER__', esc(brand.get('copyright', '')))]:
        p = p.replace(k, v)
    return p.replace('__HEADBLOCK__', head_block)


def ship_map(kept, cfg, outdir):
    """Regenerate the go-map and reload nginx only when content changed."""
    if not cfg.get('map'):
        return
    lines = ''.join(f"{a['id']} {a['url']};\n" for a in kept)
    mapf = os.path.join(outdir, 'targets.map')
    open(mapf, 'w').write('# newsroom go-map - regenerated by build_news.py\n' + lines)
    rpath = cfg['map']['path']
    ssh = cfg['deploy'].get('ssh')
    if not ssh:
        same = bool(os.path.exists(rpath)) and __import__('filecmp').cmp(
            mapf, rpath, shallow=False)
        if not same:
            write_local(mapf, rpath)
            print('local map updated:', rpath)
        else:
            print('redirect map unchanged')
        return
    subprocess.run(['scp', '-o', 'ConnectTimeout=12', '-o', 'BatchMode=yes',
                    mapf, ssh + ':/tmp/'], check=True, timeout=60)
    r = subprocess.run(['ssh', '-o', 'ConnectTimeout=12', '-o', 'BatchMode=yes', ssh,
                        'sudo cmp -s /tmp/targets.map %s && echo SAME || echo CHANGED'
                        % rpath], capture_output=True, text=True, timeout=60)
    if 'CHANGED' in r.stdout:
        subprocess.run(['ssh', '-o', 'ConnectTimeout=12', '-o', 'BatchMode=yes', ssh,
                        'sudo cp /tmp/targets.map %s && sudo nginx -t && '
                        'sudo systemctl reload nginx && echo MAP-RELOADED' % rpath],
                       check=True, timeout=90)
        print('redirect map updated + nginx reloaded')
    else:
        print('redirect map unchanged')


def write_local(src, dst):
    open(dst, 'w').write(open(src).read())
    return True


def expand(p):
    return os.path.expanduser(p)


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('--config', default='newsroom.json')
    ap.add_argument('--state', default=None, help='override config state path')
    ap.add_argument('--dry-run', action='store_true',
                    help='validate + render only: no state write, no deploy')
    ap.add_argument('--out', default=None, help='output dir when no deploy ssh')
    args = ap.parse_args()

    with open(expand(args.config)) as f:
        loaded = json.load(f)
    cfg = {**DEFAULT_CONFIG, **loaded}
    for key in ('primary_count', 'rss_count', 'archive_hours'):
        cfg[key] = int(cfg.get(key, DEFAULT_CONFIG[key]))
    state_path = expand(args.state or cfg['state'])
    page_prefix = cfg['page_prefix']
    if not page_prefix.endswith('/'):
        page_prefix += '/'
    cfg['page_prefix'] = page_prefix

    data = json.load(open(state_path))
    now = datetime.datetime.now(datetime.timezone.utc)
    fresh, old = [], []
    for a in data.get('articles', []):
        try:
            added = datetime.datetime.fromisoformat(a['added_at'].replace('Z', '+00:00'))
        except Exception:
            continue
        if (now - added).total_seconds() <= cfg['archive_hours'] * 3600:
            fresh.append(a)
        else:
            old.append(a)
    if old:
        archive = list(data.get('archive', []))
        seen = {x.get('id') for x in archive}
        moved = [a for a in old if a.get('id') and a['id'] not in seen]
        if moved:
            data['archive'] = sorted(moved + archive,
                                     key=lambda a: a.get('added_at', ''), reverse=True)
            data['articles'] = fresh
            if args.dry_run:
                print('dry-run: would archive %d entries (articles -> archive)'
                      % len(moved))
            else:
                st = os.stat(state_path)
                fd, tmp = tempfile.mkstemp(dir=os.path.dirname(state_path) or '.')
                os.close(fd)
                json.dump(data, open(tmp, 'w'), indent=2)
                os.chmod(tmp, st.st_mode & 0o777)
                os.replace(tmp, state_path)
                print('archived %d entries (articles -> archive)' % len(moved))

    pool = {}
    for a in data.get('archive', []):
        pool.setdefault(a.get('id') or a.get('url'), a)
    for a in data.get('articles', []):
        pool[a.get('id') or a.get('url')] = a
    newest = sorted(pool.values(), key=lambda a: a.get('added_at', ''), reverse=True)

    kept = []
    for a in newest:
        ok, info = link_ok(a['url'])
        if ok:
            kept.append(a)
        else:
            print('dropped dead link:', a['id'], '->', str(info)[:60])

    counts = get_counts(cfg)
    if not kept:
        print('no valid articles - pages and map left as-is')
        return

    primary = kept[:cfg['primary_count']]
    history = kept[cfg['primary_count']:]
    is_remote = bool(cfg['deploy'].get('ssh'))
    outdir = args.out or tempfile.mkdtemp(prefix='newsroom-build-')
    os.makedirs(outdir, exist_ok=True)

    copy = cfg.get('copy', {})
    brand = cfg.get('brand', {})
    site = brand.get('name', 'Agentic Newsroom')
    open_count = ('Opened <strong>%d</strong> times.' % int(counts.get('visits', 0))) \
        if cfg.get('counts_cmd') else ''
    head_primary = (f'      <h1>{esc(copy.get("page_title", "News."))}</h1>\n'
                    f'      <p class="lede">{esc(copy.get("page_lede", ""))}</p>\n'
                    f'      <p class="wire-note">Refreshed continuously; the newest stories '
                    f'here, older ones in the '
                    f'<a href="{page_prefix}history/">archive</a>. {open_count}</p>')
    note_hist = cfg.get('copy', {}).get('archive_note', 'Stories move here as newer '
                        'ones arrive; nothing is deleted.')
    head_hist = (f'      <h1>{esc(copy.get("archive_title", "News archive."))}</h1>\n'
                 f'      <p class="lede">{esc(copy.get("archive_lede", ""))} '
                 f'Older stories from the newsroom &mdash; the newest '
                 f'{cfg["primary_count"]} live on the '
                 f'<a href="{page_prefix}">main page</a>.</p>\n'
                 f'      <p class="wire-note">{esc(note_hist)}</p>')
    empty_primary = '<p class="wire-note">The newsroom is warming up.</p>'

    page = page_from(TEMPLATE, cfg,
                     copy.get('page_title', site + ' News'),
                     copy.get('page_lede', ''),
                     head_primary, '')
    page = page.replace('<!--ARTICLES-->', render_rows(primary, counts.get('clicks', {}), cfg)
                        or empty_primary)
    hist_body = render_rows(history, counts.get('clicks', {}), cfg) if history else \
        ('<p class="wire-note">No archived stories yet &mdash; the newest stories '
         'live on the <a href="%s">main page</a>.</p>' % page_prefix)
    hist = page_from(TEMPLATE, cfg,
                     copy.get('archive_title', site + ' News Archive'),
                     copy.get('archive_desc', 'Older stories from the ' + site +
                              ' agentic newsroom.'), head_hist, '')
    hist = hist.replace('<!--ARTICLES-->', hist_body)
    p1 = os.path.join(outdir, 'index.html')
    p2 = os.path.join(outdir, 'history.html')
    open(p1, 'w').write(page)
    open(p2, 'w').write(hist)
    rssf = None
    if cfg.get('rss_file'):
        import email.utils
        items = []
        for a in kept[:cfg['rss_count']]:
            d = datetime.datetime.fromisoformat(a['added_at'].replace('Z', '+00:00'))
            link = cfg['site_url'] + page_prefix + 'go?id=' + esc(a['id'], True)
            items.append('<item>\n  <title>' + esc(a['title']) + '</title>\n  <link>'
                         + link + '</link>\n  <description>' + esc(a['summary'])
                         + '</description>\n  <guid>' + link + '</guid>\n  <pubDate>'
                         + email.utils.format_datetime(
                             d.replace(tzinfo=datetime.timezone.utc))
                         + '</pubDate>\n</item>')
        now_rfc = email.utils.format_datetime(
            datetime.datetime.now(datetime.timezone.utc))
        rss = ('<?xml version="1.0" encoding="UTF-8"?>\n<rss version="2.0">\n'
               '<channel>\n<title>' + esc(site + ' News') + '</title>\n<link>'
               + cfg['site_url'] + page_prefix + '</link>\n<description>'
               + esc(copy.get('page_lede', '')) + '</description>\n<language>en</language>\n'
               '<lastBuildDate>' + now_rfc + '</lastBuildDate>\n'
               + '\n'.join(items) + '\n</channel>\n</rss>\n')
        rssf = os.path.join(outdir, cfg['rss_file'])
        open(rssf, 'w').write(rss)

    ssh = cfg['deploy'].get('ssh')
    if args.dry_run or not ssh:
        if not args.dry_run:
            ship_map(kept, cfg, outdir)
        print('dry-run/local: rendered %d primary, %d history -> %s%s'
              % (len(primary), len(history), outdir,
                 ' (not shipped; configure deploy.ssh or drop --dry-run to ship)'
                 if args.dry_run else ' (local out dir)'))
        return
    web = cfg['deploy']['web_root'].rstrip('/')
    base = web + page_prefix.rstrip('/')
    sudo = 'sudo ' if cfg['deploy'].get('sudo', True) else ''
    owner = cfg['deploy'].get('owner', 'www-data:www-data')
    subprocess.run(['scp', '-o', 'ConnectTimeout=12', '-o', 'BatchMode=yes',
                    p1, ssh + ':/tmp/newsroom-index.html',
                    p2, ssh + ':/tmp/newsroom-history.html'], check=True, timeout=90)
    if rssf:
        subprocess.run(['scp', '-o', 'ConnectTimeout=12', '-o', 'BatchMode=yes',
                        rssf, ssh + ':/tmp/newsroom-rss.xml'], check=True, timeout=90)
    cmd = ('%smkdir -p %s %s/history && %scp /tmp/newsroom-index.html %s/index.html && '
           '%scp /tmp/newsroom-history.html %s/history/index.html'
           % (sudo, base, base, sudo, base, sudo, base))
    if rssf:
        cmd += ' && %scp /tmp/newsroom-rss.xml %s/%s' % (sudo, base, cfg['rss_file'])
    if sudo:
        cmd += (f' && {sudo}chown -R {owner} {base} && '
                f'{sudo}chmod 755 {base} {base}/history && '
                f'{sudo}chmod 640 {base}/index.html {base}/history/index.html')
        if rssf:
            cmd += f' {base}/{cfg["rss_file"]}'
    subprocess.run(['ssh', '-o', 'ConnectTimeout=12', '-o', 'BatchMode=yes', ssh, cmd],
                   check=True, timeout=90)
    ship_map(kept, cfg, outdir)
    for label, url in [('news', cfg['site_url'] + page_prefix),
                       ('history', cfg['site_url'] + page_prefix + 'history/')]:
        r = subprocess.run(['ssh', '-o', 'ConnectTimeout=12', '-o', 'BatchMode=yes',
                            ssh, "curl -sk -o /dev/null -w '%{http_code}' " + url],
                           capture_output=True, text=True, timeout=90)
        print('deployed; %s HTTP %s' % (label, r.stdout.strip()))
    print('primary:', len(primary), '| history:', len(history))


if __name__ == '__main__':
    main()