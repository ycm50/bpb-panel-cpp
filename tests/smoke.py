import json, sys, urllib.request

base = sys.argv[1] if len(sys.argv) > 1 else 'http://127.0.0.1:18099/securepath'
results = []

def ok(name, cond, extra=''):
    results.append((('PASS' if cond else 'FAIL'), name, extra))

def get(path, headers=None, data=None, method=None):
    req = urllib.request.Request(base + path, headers=headers or {}, data=data, method=method)
    try:
        with urllib.request.urlopen(req, timeout=25) as r:
            return r.status, r.read(), r.headers
    except urllib.error.HTTPError as e:
        return e.code, e.read(), e.headers
    except Exception as e:
        return 0, str(e).encode(), {}

st, body, _ = get('/login')
ok('login html', st == 200 and b'BPB Panel' in body, f'{st} {len(body)}')

st, body, _ = get('/panel/settings')
cookie = ''
if st == 401:
    st2, _, _ = get('/panel/reset-password', {'Content-Type': 'application/json'}, b'{"username":"admin","password":"pw12345"}', 'POST')
    req = urllib.request.Request(base + '/login/authenticate', data=b'{"username":"admin","password":"pw12345"}',
                                 headers={'Content-Type': 'application/json'}, method='POST')
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            cookie = (r.headers.get('Set-Cookie') or '').split(';')[0]
    except Exception:
        pass
    st, body, _ = get('/panel/settings', {'Cookie': cookie} if cookie else None)
try:
    j = json.loads(body or b'{}')
except Exception:
    j = {}
ok('panel settings', st == 200 and j.get('success'), f"{len(j.get('body',{}).get('proxySettings',{}))} keys" if j.get('success') else str(st))

for kind, app in [('raw','xray'),('normal','xray'),('fragment','xray'),('normal','sing-box'),('normal','clash'),
                  ('warp','clash'),('warp','wireguard'),('warp-pro','amnezia')]:
    st, body, hdrs = get(f'/sub/{kind}?app={app}')
    ct = (hdrs.get('Content-Type') or '')
    ok(f'sub {kind}/{app}', st == 200, f'{st} {len(body)}B')

st, body, _ = get('/sub/share-settings')
ok('share-settings', st == 200 and b'customDomain' not in body, f'{st} {len(body)}B')

st, body, _ = get('/dns-query?name=example.com&type=A', {'Accept': 'application/dns-json'})
ok('doh', st == 200 and b'Answer' in body, f'{st} {len(body)}B')

data = ('http://127.0.0.1:18099/securepath/sub/normal?app=xray').encode()
st, body, _ = get('/qrcode?data=' + urllib.parse.quote(data.decode()), data=b'', method='POST')
ok('qrcode', st == 200 and body[:4] == b'\x89PNG', f'{st} {len(body)}B')

for r in results:
    print(f'{r[0]:5} {r[1]:24} {r[2]}')
failed = sum(1 for r in results if r[0] == 'FAIL')
print(f'--- {len(results)-failed}/{len(results)} passed')
sys.exit(1 if failed else 0)