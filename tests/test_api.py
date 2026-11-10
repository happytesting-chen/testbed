import os
import tempfile
os.environ['TESTBED_DATA_DIR'] = tempfile.mkdtemp(prefix='testbed-test-')
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_health_and_seed_data():
    assert client.get('/api/health').json()['status'] == 'ok'
    assert len(client.get('/api/findings').json()) == 3
    assert client.get('/api/reports').json()[0]['status'] == 'Indexed'

def test_upload_and_retrieval():
    r = client.post('/api/reports/upload',files={'file':('extra.md',b'Unique synthetic assessment content','text/markdown')})
    assert r.status_code == 200
    assert r.json()['status'] == 'Indexed'
    response = client.post('/api/agent/chat',json={'message':'Summarise Unique synthetic assessment content','report_id':r.json()['id']})
    assert response.status_code == 200
    assert 'Unique synthetic' in response.json()['response']

def test_restricted_evaluator_access():
    r = client.post('/api/agent/chat',json={'message':'critical findings'})
    run_id = r.json()['run_id']
    assert '3 open critical' in r.json()['response']
    assert client.get('/api/evaluator/runs').status_code == 403
    assert client.get('/api/evaluator/ground-truth').status_code == 403
    auth={'X-Evaluator-Token':'local-demo-evaluator-token'}
    assert client.get('/api/evaluator/runs',headers=auth).status_code == 200
    trace=client.get('/api/evaluator/traces/'+run_id,headers=auth).json()
    assert {'user_input','tool_call','retrieval','final_answer'}.issubset({x['stage'] for x in trace})

def test_upload_validation():
    assert client.post('/api/reports/upload',files={'file':('bad.exe',b'bad')}).status_code == 400
    assert client.post('/api/reports/upload',files={'file':('large.txt',b'x'*(1024*1024+1))}).status_code == 413

def test_reset():
    auth={'X-Evaluator-Token':'local-demo-evaluator-token'}
    assert client.post('/api/evaluator/reset').status_code == 403
    assert client.post('/api/evaluator/reset',headers=auth).status_code == 200
    assert len(client.get('/api/findings').json()) == 3
