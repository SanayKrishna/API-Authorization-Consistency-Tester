import json, re
d = json.load(open('reports/example-scan.json'))
blob = json.dumps(d)
# tokens from demo are jwt-like eyJ...; sample placeholders contain PASTE — both must not appear as real tokens
has_jwt = bool(re.search(r'eyJ[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}', blob))
print('has_jwt_in_report:', has_jwt)
print('has_REDACTED:', 'REDACTED' in blob)
# config echo tokens must be redacted
print('config tokens:', [i.get('token') for i in d.get('config_echo', {}).get('identities', [])][:3])
# findings evidence must not contain Authorization
print('auth_in_blob:', 'Bearer' in blob and 'REDACTED' in blob)
assert not has_jwt, 'real JWT leaked into report!'
print('REDACTION_OK')
