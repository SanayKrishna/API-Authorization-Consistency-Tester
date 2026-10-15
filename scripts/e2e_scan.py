import json, urllib.request, time
toks = json.loads(urllib.request.urlopen('http://127.0.0.1:8001/demo/tokens').read())
print('tokens ok:', sorted(toks.keys()))
pol = json.load(open('examples/sample_policy.json'))
tmap = {'admin': toks['admin']['token'], 'alice': toks['alice']['token'],
        'bob-as-alice-target': toks['alice']['token'], 'readonly': toks['readonly']['token']}
for ident in pol['identities']:
    n = ident['name']
    if n in tmap:
        ident['token'] = tmap[n]
payload = {'target_base_url': 'http://127.0.0.1:8001', 'endpoints': pol['endpoints'],
           'identities': pol['identities'],
           'options': {'include_destructive': True, 'timeout_secs': 10, 'max_concurrency': 5, 'rate_delay_secs': 0.01},
           'confirm_target': True}
req = urllib.request.Request('http://127.0.0.1:8000/api/scans', data=json.dumps(payload).encode(),
                             headers={'Content-Type': 'application/json'}, method='POST')
resp = json.loads(urllib.request.urlopen(req).read())
print('scan created:', resp)
sid = resp['scan_id']
s = {}
for i in range(30):
    time.sleep(2)
    s = json.loads(urllib.request.urlopen(f'http://127.0.0.1:8000/api/scans/{sid}').read())
    print(f"poll {i}: status={s['status']} progress={s['progress']} summary={s['summary']}")
    if s['status'] == 'completed':
        break
print('findings:', len(s.get('findings', [])))
cats = {}
for f in s.get('findings', []):
    cats[f['category']] = cats.get(f['category'], 0) + 1
print('by_category:', cats)
print('by_severity:', s['summary'].get('by_severity'))
# reports
rj = urllib.request.urlopen(f'http://127.0.0.1:8000/api/scans/{sid}/report.json').read()
print('report.json bytes:', len(rj))
rc = urllib.request.urlopen(f'http://127.0.0.1:8000/api/scans/{sid}/report.csv').read()
print('report.csv lines:', rc.decode()[:500])
rh = urllib.request.urlopen(f'http://127.0.0.1:8000/api/scans/{sid}/report.html').read()
print('report.html bytes:', len(rh))
open(f'reports/example-scan.json', 'wb').write(rj)
open(f'reports/example-findings.csv', 'wb').write(rc)
open(f'reports/example-report.html', 'wb').write(rh)
# results csv
import urllib.parse
rc2 = urllib.request.urlopen(f'http://127.0.0.1:8000/api/scans/{sid}/report.csv?kind=results').read()
open(f'reports/example-results.csv', 'wb').write(rc2)
print('saved examples')
# second scan for diff
req2 = urllib.request.Request('http://127.0.0.1:8000/api/scans', data=json.dumps(payload).encode(),
                              headers={'Content-Type': 'application/json'}, method='POST')
resp2 = json.loads(urllib.request.urlopen(req2).read())
sid2 = resp2['scan_id']
print('second scan:', sid2)
for i in range(30):
    time.sleep(2)
    s2 = json.loads(urllib.request.urlopen(f'http://127.0.0.1:8000/api/scans/{sid2}').read())
    if s2['status'] == 'completed':
        break
print('second done')
diff = json.loads(urllib.request.urlopen(f'http://127.0.0.1:8000/api/scans/{sid2}/diff?against={sid}').read())
print('diff:', {k: diff[k] for k in ('new', 'resolved', 'unchanged')})
