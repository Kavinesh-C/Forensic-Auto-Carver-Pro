import urllib.request
import sys

url = 'http://localhost:8080/diag'
try:
    resp = urllib.request.urlopen(url, timeout=10)
    body = resp.read().decode('utf-8', errors='replace')
    print('STATUS', getattr(resp, 'status', 'unknown'))
    print('HEADERS')
    for k,v in resp.getheaders():
        print(f'{k}: {v}')
    print('\nBODY:\n')
    print(body)
except Exception as e:
    print('ERROR', repr(e))
    # If it's an HTTPError, attempt to show the body
    try:
        import urllib.error
        if isinstance(e, urllib.error.HTTPError):
            print('HTTPERROR BODY:')
            try:
                print(e.read().decode('utf-8','replace'))
            except Exception:
                pass
    except Exception:
        pass
