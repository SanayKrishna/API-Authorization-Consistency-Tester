import json, glob, os
p = 'reports/example-scan.json'
d = json.load(open(p))
print('total', d['summary']['total'], 'failed', d['summary']['failed'])
for f in d['findings'][:30]:
    print(f"{f['severity']:13} {f['category']:20} {f['endpoint_id']:12} {f['method']:6} {f['path']:30} exp={f['expected'][:60]} act={f['actual'][:60]}")
print('--- results fail sample ---')
for r in d['results']:
    if r['verdict'] == 'fail':
        print(r['test_id'], 'exp', r['expected'], 'status', r['actual_status'], 'err', r['error'][:100], 'body', r['body_excerpt'][:120])
        if sum(1 for _ in [1]) > 0:
            pass
        # limit
        break
# print all fails grouped
from collections import Counter
print(Counter((r['endpoint_id'], r['expected'], r['actual_status']) for r in d['results'] if r['verdict'] == 'fail'))
print(Counter((r['endpoint_id'], r['expected'], r['actual_status']) for r in d['results'] if r['verdict'] == 'inconclusive'))
