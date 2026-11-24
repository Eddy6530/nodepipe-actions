# -*- coding: utf-8 -*-
"""GitHub Actions 版节点管线：采集聚合渲染 + 推 Gist（无验证，海外视角）

定位：云端定时保鲜通道。海外 runner 不做探活验证（视角失真，见交接文档坑 1），
死节点由手机 Clash 的"自动选择"url-test 组兜底（每 15 分钟自动测活）。
本地管线（带三重验证+终检）按需跑，后跑者覆盖先跑者，手机订阅 URL 恒定。
"""
import ast
import base64
import html as htmllib
import io
import json
import os
import re
import time
import urllib.parse
import urllib.request as uq
from concurrent.futures import ThreadPoolExecutor

import yaml

REPO_DIR = os.path.dirname(os.path.abspath(__file__))
SOURCES_PATH = os.path.join(REPO_DIR, 'sources_public.json')
GIST_TOKEN = os.environ.get('GIST_TOKEN', '')
GITHUB_TOKEN = os.environ.get('GITHUB_TOKEN', '')
GIST_ID = '6822f56e79031dede79a63244f1c3c4f'
UA = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
KNOWN_TYPES = {'vless', 'vmess', 'ss', 'trojan', 'hysteria2', 'anytls', 'tuic'}
URI_SCHEMES = ('vless://', 'vmess://', 'trojan://', 'ss://', 'hysteria2://', 'hy2://',
               'anytls://', 'tuic://')
CAP_PER_SOURCE = 200
MAX_RENDER = 400


# ---------------- fetch（Actions 海外直连优先，镜像链兜底） ----------------
def fetch(url, timeout=15):
    cands = [url]
    m = re.match(r'https://raw\.githubusercontent\.com/([^/]+)/([^/]+)/([^/]+)/(.+)', url)
    if m:
        o, b, br, p = m.groups()
        # Actions 在海外：raw 直连通常通，直连排第一，镜像只做兜底
        cands = [url]
        if br in ('main', 'master'):
            cands.append('https://fastly.jsdelivr.net/gh/%s/%s@%s/%s' % (o, b, br, p))
            cands.append('https://testingcf.jsdelivr.net/gh/%s/%s@%s/%s' % (o, b, br, p))
        cands.append('https://gh-proxy.com/' + url)
    for c in cands:
        try:
            req = uq.Request(c, headers=UA)
            return uq.urlopen(req, timeout=timeout).read().decode('utf-8', 'ignore')
        except Exception:
            continue
    return None


# ---------------- URI -> node（照抄本地 collect.py） ----------------
def b64d(s):
    s = urllib.parse.unquote(s.strip()).replace('-', '+').replace('_', '/')
    s += '=' * (-len(s) % 4)
    return base64.b64decode(s)


def split_uri(uri):
    sch, body = uri.split('://', 1)
    frag = ''
    if '#' in body:
        body, frag = body.split('#', 1)
    frag = htmllib.unescape(urllib.parse.unquote(frag)).strip()
    userinfo, hostport = body.rsplit('@', 1)
    qd = {}
    if '?' in hostport:
        hostport, qs = hostport.split('?', 1)
        qd = urllib.parse.parse_qs(qs, keep_blank_values=True)
    if hostport.startswith('['):
        host = hostport[1:hostport.index(']')]
        port = hostport.split(']:', 1)[1]
    else:
        host, port = hostport.rsplit(':', 1)
    g = lambda k, d=None: qd[k][0] if k in qd else d
    return sch, userinfo, host, int(port), g, frag


def wsgrpc(p, net, host, path):
    net = (net or 'tcp').lower()
    if net == 'ws':
        p['network'] = 'ws'
        wo = {}
        if path:
            wo['path'] = path
        if host:
            wo['headers'] = {'Host': host}
        if wo:
            p['ws-opts'] = wo
    elif net == 'grpc':
        p['network'] = 'grpc'
        p['grpc-opts'] = {'grpc-service-name': path or ''}


def parse_vmess(uri):
    o = json.loads(b64d(uri[8:]).decode('utf-8', 'ignore'))
    p = {'type': 'vmess', 'server': o.get('add'), 'port': int(o.get('port') or 0),
         'uuid': o.get('id'), 'alterId': int(o.get('aid') or 0),
         'cipher': o.get('scy') or 'auto', 'name': o.get('ps') or ''}
    if str(o.get('tls', '')).lower() == 'tls':
        p['tls'] = True
    if o.get('sni'):
        p['servername'] = o['sni']
    elif o.get('host') and (o.get('net') or '') == 'ws':
        p['servername'] = o['host']
    wsgrpc(p, o.get('net'), o.get('host'), o.get('path'))
    return p


def parse_vless(uri):
    _, userinfo, host, port, g, frag = split_uri(uri)
    p = {'type': 'vless', 'server': host, 'port': port, 'uuid': userinfo, 'name': frag}
    sec = (g('security') or 'none').lower()
    if sec in ('tls', 'reality'):
        p['tls'] = True
    if g('sni'):
        p['servername'] = g('sni')
    if g('fp'):
        p['client-fingerprint'] = g('fp')
    if sec == 'reality':
        p['reality-opts'] = {'public-key': g('pbk'), 'short-id': g('sid')}
    if g('flow'):
        p['flow'] = g('flow')
    if (g('insecure') or '0') == '1':
        p['skip-cert-verify'] = True
    wsgrpc(p, g('type'), g('host'), g('path'))
    return p


def parse_trojan(uri):
    _, userinfo, host, port, g, frag = split_uri(uri)
    p = {'type': 'trojan', 'server': host, 'port': port,
         'password': urllib.parse.unquote(userinfo), 'name': frag}
    if g('sni'):
        p['sni'] = g('sni')
    if g('fp'):
        p['client-fingerprint'] = g('fp')
    if (g('insecure') or '0') == '1':
        p['skip-cert-verify'] = True
    wsgrpc(p, g('type'), g('host'), g('path'))
    return p


def parse_anytls(uri):
    _, userinfo, host, port, g, frag = split_uri(uri)
    p = {'type': 'anytls', 'server': host, 'port': port,
         'password': urllib.parse.unquote(userinfo), 'name': frag}
    if g('sni'):
        p['sni'] = g('sni')
    if g('fp'):
        p['client-fingerprint'] = g('fp')
    if (g('insecure') or '0') == '1':
        p['skip-cert-verify'] = True
    return p


def parse_hy2(uri):
    _, userinfo, host, port, g, frag = split_uri(uri)
    p = {'type': 'hysteria2', 'server': host, 'port': port,
         'password': urllib.parse.unquote(userinfo), 'name': frag}
    if g('sni'):
        p['sni'] = g('sni')
    if g('pinSHA256'):
        p['fingerprint'] = g('pinSHA256')
    if g('fp'):
        p['client-fingerprint'] = g('fp')
    if (g('insecure') or '0') == '1':
        p['skip-cert-verify'] = True
    if g('obfs'):
        p['obfs'] = g('obfs')
        p['obfs-password'] = g('obfs-password', '')
    return p


def parse_tuic(uri):
    _, userinfo, host, port, g, frag = split_uri(uri)
    uuid, _, pw = userinfo.partition(':')
    p = {'type': 'tuic', 'server': host, 'port': port, 'uuid': uuid,
         'password': urllib.parse.unquote(pw), 'name': frag}
    if g('sni'):
        p['sni'] = g('sni')
    if g('congestion_control'):
        p['congestion-controller'] = g('congestion_control')
    v = g('alpn')
    if v:
        p['alpn'] = v.split(',')
    return p


def parse_ss(uri):
    body = uri[5:]
    frag = ''
    if '#' in body:
        body, frag = body.split('#', 1)
    frag = htmllib.unescape(urllib.parse.unquote(frag)).strip()
    if '@' in body:
        userinfo, hostport = body.rsplit('@', 1)
        hostport = hostport.split('?', 1)[0]
        host, port = hostport.rsplit(':', 1)
        u = urllib.parse.unquote(userinfo)
        if ':' in u:
            method, pw = u.split(':', 1)
        else:
            raw = b64d(userinfo).decode('utf-8', 'ignore')
            method, pw = raw.split(':', 1)
    else:
        raw = b64d(body).decode('utf-8', 'ignore')
        cred, hostport = raw.rsplit('@', 1)
        method, pw = cred.split(':', 1)
        host, port = hostport.rsplit(':', 1)
    return {'type': 'ss', 'server': host, 'port': int(port),
            'cipher': method, 'password': pw, 'name': frag}


URI_PARSERS = {'vmess': parse_vmess, 'vless': parse_vless, 'trojan': parse_trojan,
               'ss': parse_ss, 'hysteria2': parse_hy2, 'hy2': parse_hy2,
               'anytls': parse_anytls, 'tuic': parse_tuic}


def sanitize(p):
    if p.get('type') not in KNOWN_TYPES:
        return None
    for f in ('port', 'alterId'):
        v = p.get(f)
        if isinstance(v, str):
            try:
                p[f] = int(v)
            except Exception:
                return None
    v = p.get('alpn')
    if isinstance(v, str):
        s = v.strip()
        if s.startswith('[') and s.endswith(']'):
            try:
                lv = ast.literal_eval(s)
                p['alpn'] = [str(x) for x in lv] if isinstance(lv, list) else [s]
            except Exception:
                p['alpn'] = [s]
        else:
            p['alpn'] = [s]
    if not p.get('server') or not p.get('port'):
        return None
    if re.match(r'^(127\.|0\.0\.0\.0$|198\.18\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|localhost)', str(p['server'])):
        return None
    return p


def extract_uris(text):
    text = htmllib.unescape(text)
    out = []
    for m in re.finditer(r'(?:vless|vmess|trojan|ss|hysteria2|hy2|anytls|tuic)://[^\s<>"\'\)\]]+', text):
        out.append(m.group(0).rstrip('.,;'))
    for m in re.finditer(r'[A-Za-z0-9+/=]{80,}', text):
        try:
            dec = base64.b64decode(m.group(0) + '=' * (-len(m.group(0)) % 4)).decode('utf-8', 'ignore')
            out.extend(l.strip() for l in dec.splitlines() if l.strip().startswith(URI_SCHEMES))
        except Exception:
            pass
    return out


def parse_text(src_id, text, acc, seen, stats):
    parsed = failed = 0
    nodes = []
    text = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', text)
    uris = extract_uris(text)
    if uris:
        for l in uris[:CAP_PER_SOURCE]:
            sch = l.split('://', 1)[0].lower()
            fn = URI_PARSERS.get(sch)
            if not fn:
                failed += 1
                continue
            try:
                n = sanitize(fn(l))
                if n:
                    nodes.append(n)
                    parsed += 1
                else:
                    failed += 1
            except Exception:
                failed += 1
    else:
        dl = [l.strip() for l in text.replace('\ufeff', '').split('\n') if l.strip()]
        if len(dl) > 20 and all(re.fullmatch(r'\d{1,3}', l) and int(l) <= 255 for l in dl[:50]):
            try:
                text = bytes(int(l) for l in dl).decode('utf-8', 'ignore')
                text = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', text)
            except Exception:
                pass
        sq = ''.join(text.split())
        if re.fullmatch(r'[A-Za-z0-9+/=]{40,}', sq):
            try:
                text = base64.b64decode(sq + '=' * (-len(sq) % 4)).decode('utf-8', 'ignore')
                text = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', text)
            except Exception:
                pass
        try:
            d = yaml.safe_load(text)
            if not isinstance(d, dict):
                return 0, 1
            for p in (d.get('proxies') or [])[:CAP_PER_SOURCE]:
                n = sanitize(dict(p))
                if n:
                    nodes.append(n)
                    parsed += 1
                else:
                    failed += 1
        except Exception as e:
            stats['parse_error:' + src_id] = str(e)[:60]
            return 0, 1
    for n in nodes:
        key = (n['type'], n.get('server'), n.get('port'),
               n.get('uuid') or n.get('password'))
        if key in seen:
            continue
        seen.add(key)
        n['src'] = src_id
        acc.append(n)
    return parsed, failed


# ---------------- rolling 滚动命名仓库 ----------------
def work_rolling(job):
    sid, repo, letter = job
    d = None
    hdr = dict(UA)
    if GITHUB_TOKEN:
        hdr['Authorization'] = 'Bearer ' + GITHUB_TOKEN
    for base in ('https://api.github.com',
                 'https://gh-proxy.com/https://api.github.com'):
        try:
            req = uq.Request(base + '/repos/' + repo + '/contents/', headers=hdr)
            d = json.loads(uq.urlopen(req, timeout=30).read().decode())
            break
        except Exception:
            continue
    if not isinstance(d, list):
        return sid, None
    today = time.strftime('%d')
    cands = [f for f in d if f.get('type') == 'file' and today in f['name'] and letter in f['name'].upper()]
    if not cands:
        print('ROLLING %s: 当天(%s)无命中文件' % (sid, today))
        return sid, None
    cands.sort(key=lambda f: f.get('size') or 0, reverse=True)
    raw = cands[0].get('download_url') or ('https://raw.githubusercontent.com/' + repo + '/main/' + cands[0]['name'])
    print('ROLLING %s -> %s (%d B)' % (sid, cands[0]['name'], cands[0].get('size') or 0))
    return sid, fetch(raw)


# ---------------- Telegram（Actions 海外直连 t.me，本地代理离线时做不到） ----------------
def fetch_tg(ch):
    try:
        req = uq.Request('https://t.me/s/' + ch, headers=UA)
        return uq.urlopen(req, timeout=15).read().decode('utf-8', 'ignore')
    except Exception:
        return None


def discover_telegram(texts, known):
    found = set()
    for t in texts:
        for m in re.finditer(r't\.me/([A-Za-z0-9_]{4,32})', t):
            ch = m.group(1)
            if ch not in known and not ch.endswith('bot') and ch.lower() not in ('share', 'joinchat'):
                found.add(ch)
    return sorted(found)[:4]


# ---------------- 渲染 ----------------
def q(s):
    return '"' + str(s).replace('\\', '\\\\').replace('"', '\\"') + '"'


def emit(p):
    parts = []
    for k, v in p.items():
        if v in (None, ''):
            continue
        if isinstance(v, bool):
            parts.append('%s: %s' % (k, 'true' if v else 'false'))
        elif isinstance(v, int):
            parts.append('%s: %d' % (k, v))
        elif isinstance(v, list):
            parts.append('%s: [%s]' % (k, ', '.join(q(x) for x in v)))
        elif isinstance(v, dict):
            inner = ', '.join('%s: %s' % (ik, q(iv) if isinstance(iv, str) else iv)
                              for ik, iv in v.items() if iv not in (None, ''))
            if inner:
                parts.append('%s: {%s}' % (k, inner))
        else:
            parts.append('%s: %s' % (k, q(v)))
    return '  - {' + ', '.join(parts) + '}'


def render(acc):
    ts = time.strftime('%Y-%m-%d %H:%M', time.gmtime())
    names = {}
    for n in acc:
        base = (n.get('name') or n.get('server') or n['type']).strip()
        if base in names:
            names[base] += 1
            n['name'] = '[%s] %s #%d' % (n['src'], base, names[base])
        else:
            names[base] = 1
            n['name'] = '[%s] %s' % (n['src'], base)
    render_nodes = acc[:MAX_RENDER]
    out = []
    out.append('# [GitHub Actions] 云端聚合版 · 生成于 %s UTC' % ts)
    out.append('# 本版本未做国内视角验证（Actions runner 在海外），死节点由手机端"自动选择"组自动避开')
    out.append('# 共 %d 个节点（去重清洗后）。本地验证版会覆盖本版本（本地跑完即推）' % len(render_nodes))
    out.append('mixed-port: 7890')
    out.append('allow-lan: false')
    out.append('mode: rule')
    out.append('log-level: info')
    out.append('unified-delay: true')
    out.append('tcp-concurrent: true')
    out.append('profile: {store-selected: true, store-fake-ip: true}')
    out.append('geox-url:')
    out.append('  geoip: "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geoip.dat"')
    out.append('  geosite: "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geosite.dat"')
    out.append('  mmdb: "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/country.mmdb"')
    out.append('dns:')
    out.append('  enable: true')
    out.append('  ipv6: false')
    out.append('  enhanced-mode: fake-ip')
    out.append('  fake-ip-range: 198.18.0.1/16')
    out.append('  fake-ip-filter: ["*.lan", "*.local", "+.msftconnecttest.com", "+.msftncsi.com"]')
    out.append('  default-nameserver: ["223.5.5.5", "119.29.29.29"]')
    out.append('  proxy-server-nameserver: ["https://223.5.5.5/dns-query", "https://doh.pub/dns-query"]')
    out.append('  nameserver: ["https://223.5.5.5/dns-query", "https://doh.pub/dns-query"]')
    out.append('proxies:')
    out += [emit({k: v for k, v in n.items() if k != 'src'}) for n in render_nodes]
    names_list = [n['name'] for n in render_nodes]
    out.append('proxy-groups:')
    out.append('  - name: "自动选择"')
    out.append('    type: url-test')
    out.append('    proxies: [' + ', '.join(q(n) for n in names_list) + ']')
    out.append('    url: "http://www.gstatic.com/generate_204"')
    out.append('    interval: 86400')
    out.append('    tolerance: 50')
    out.append('    lazy: true')
    out.append('  - name: "节点选择"')
    out.append('    type: select')
    out.append('    proxies: ["自动选择", "DIRECT"]')
    out.append('rules:')
    for cidr in ('192.168.0.0/16', '10.0.0.0/8', '172.16.0.0/12', '127.0.0.0/8'):
        out.append('  - "IP-CIDR,%s,DIRECT,no-resolve"' % cidr)
    out.append('  - "GEOSITE,cn,DIRECT"')
    out.append('  - "GEOIP,CN,DIRECT"')
    out.append('  - "MATCH,节点选择"')
    return '\n'.join(out) + '\n', len(render_nodes)


# ---------------- Gist 推送 ----------------
def push_gist(yaml_text):
    body = json.dumps({
        'description': 'free nodes daily (TeleAgent nodepipe, auto-updated)',
        'public': False,
        'files': {'free_nodes.yaml': {'content': yaml_text}},
    }).encode()
    headers = {'Authorization': 'Bearer ' + GIST_TOKEN, 'Accept': 'application/vnd.github+json',
               'User-Agent': 'nodepipe-actions', 'Content-Type': 'application/json'}
    req = uq.Request('https://api.github.com/gists/' + GIST_ID, data=body,
                     headers=headers, method='PATCH')
    resp = json.loads(uq.urlopen(req, timeout=30).read().decode())
    print('PUSH_GIST updated gist %s' % resp['id'])


def main():
    cfg = json.load(io.open(SOURCES_PATH, encoding='utf-8'))
    acc, seen, stats = [], set(), {}
    texts_all = []
    jobs, jobs_roll = [], []
    for s in cfg.get('github_raw', []):
        if not s.get('enabled', True):
            continue
        kind = s.get('kind', 'auto')
        if kind.startswith('rolling'):
            jobs_roll.append((s['id'], s.get('repo') or s.get('url'), kind))
        else:
            jobs.append((s['id'], s['url'], kind))
    _now = time.localtime()
    jobs = [(sid, url.replace('{date}', time.strftime('%d', _now))
                     .replace('{ymd}', time.strftime('%Y%m%d', _now))
                     .replace('{Y}', time.strftime('%Y', _now))
                     .replace('{m}', time.strftime('%m', _now)), kind) for sid, url, kind in jobs]
    tgc = cfg.get('telegram_channels', {})
    tg_jobs = [('tg-' + ch, 'https://t.me/s/' + ch, 'tg') for ch in (tgc.get('seeds') or [])[:tgc.get('fetch_max', 12)]]

    def work(job):
        sid, url, kind = job
        return sid, fetch(url)

    with ThreadPoolExecutor(16) as ex:
        for sid, t in ex.map(work, jobs + tg_jobs):
            st = {'ok': bool(t), 'bytes': len(t) if t else 0}
            stats['src:' + sid] = st
            if t:
                texts_all.append(t)
                p, f = parse_text(sid, t, acc, seen, stats)
                st['parsed'], st['failed'] = p, f
    for job in jobs_roll:
        sid, t = work_rolling(job)
        st = {'ok': bool(t), 'bytes': len(t) if t else 0}
        stats['src:' + sid] = st
        if t:
            texts_all.append(t)
            p, f = parse_text(sid, t, acc, seen, stats)
            st['parsed'], st['failed'] = p, f

    if tgc.get('discover', True):
        known = set(tgc.get('seeds') or [])
        found = discover_telegram(texts_all, known)
        if found:
            print('TG_DISCOVERED', found)

    for k, v in sorted(stats.items()):
        print('  %s %s' % (k, v))
    print('COLLECT total=%d' % len(acc))
    if not acc:
        print('PIPELINE empty pool - skip push')
        return 4
    yaml_text, n = render(acc)
    if not GIST_TOKEN:
        print('PUSH_GIST skip: GIST_TOKEN 未设置（Secrets 里加 GIST_TOKEN= 本地 sources.json 的 gist.token）')
        io.open('actions_render_preview.yaml', 'w', encoding='utf-8', newline='\n').write(yaml_text)
        return 0
    push_gist(yaml_text)
    print('PIPELINE ALL_DONE rendered=%d' % n)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
