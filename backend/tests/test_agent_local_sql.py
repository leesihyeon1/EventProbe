"""Local SQL workflow against an actual SQLite query, with no model/network access."""
import asyncio
import sqlite3
from urllib.parse import parse_qs

import httpx
import pytest

from core.agent import AgentManager
from core.agent_models import Action, RunSpec
from core.agent_store import Store
from core import agent as module


def execute(tmp_path, monkeypatch, handler, **settings):
    async def forbidden_model(*args, **kwargs):
        pytest.fail('Local SQL workflow must never call the external model')
    monkeypatch.setattr(module, 'choose_action', forbidden_model)

    async def scenario():
        manager = AgentManager(Store(tmp_path / 'runs.db'), transport=httpx.MockTransport(handler))
        spec = RunSpec(max_ai_calls=0, **{'goal': 'SQL injection', **settings})
        rid = manager.create(spec)
        await manager.tasks[rid]
        return manager.snapshot(rid)
    return asyncio.run(scenario())


@pytest.mark.parametrize('parameterized', [False, True])
@pytest.mark.parametrize('numeric', [False, True])
def test_local_query_finishes_without_model(tmp_path, monkeypatch, parameterized, numeric):
    with sqlite3.connect(':memory:') as db:
        db.execute('CREATE TABLE items (id INTEGER, name TEXT, details TEXT)')
        db.execute('INSERT INTO items VALUES (1, ?, ?)', ('alpha', 'A' * 120))
        def handler(request):
            value = request.url.params['input']
            try:
                column = 'id' if numeric else 'name'
                if parameterized:
                    rows = db.execute(f'SELECT details FROM items WHERE {column}=?', (value,)).fetchall()
                else:
                    expression = value if numeric else f"'{value}'"
                    rows = db.execute(f'SELECT details FROM items WHERE {column}={expression}').fetchall()
                return httpx.Response(200, text=''.join(r[0] for r in rows))
            except sqlite3.Error:
                return httpx.Response(500, text='query error')
        run = execute(tmp_path, monkeypatch, handler,
                      request={'url': 'https://fixture.test/?input=' + ('1' if numeric else 'alpha')})
    assert run['state'] == 'completed', run['data'].get('reason')
    assert run['data']['ai_calls'] == 0
    assert run['data']['requests'] <= 24
    assert run['conclusion']['verdict'] == ('inconclusive' if parameterized else 'suspicious')
    assert run['conclusion']['counts']['confirmed'] == 0


@pytest.mark.parametrize('parameterized', [False, True])
def test_discovered_login_refreshes_csrf_and_isolates_cookies(tmp_path, monkeypatch, parameterized):
    requests, issued, used = [], set(), set()
    with sqlite3.connect(':memory:') as db:
        db.execute('CREATE TABLE users (name TEXT, password TEXT)')
        db.execute("INSERT INTO users VALUES ('admin', 'secret')")
        def handler(request):
            requests.append(request)
            assert 'logged_in=yes' not in request.headers.get('cookie', '')
            if request.method == 'GET':
                token = str(len(requests))
                issued.add(token)
                return httpx.Response(200, headers={'content-type': 'text/html'}, text=(
                    '<form method="post" action="/login"><input name="user">'
                    '<input type="password" name="password" value="test">'
                    f'<input type="hidden" name="csrf_token" value="{token}"></form>'))
            assert request.url.path == '/login'
            fields = parse_qs(request.content.decode(), keep_blank_values=True)
            token = fields['csrf_token'][0]
            assert token in issued and token not in used
            used.add(token)
            user, password = fields['user'][0], fields['password'][0]
            try:
                if parameterized:
                    rows = db.execute('SELECT name FROM users WHERE name=? AND password=?', (user, password)).fetchall()
                else:
                    rows = db.execute(f"SELECT name FROM users WHERE name='{user}' AND password='{password}'").fetchall()
            except sqlite3.Error:
                return httpx.Response(500, text='query error')
            return httpx.Response(200, text=('Welcome ' + 'A' * 150) if rows else 'Login failed',
                                  headers={'set-cookie': 'logged_in=yes; Path=/'} if rows else {})
        run = execute(tmp_path, monkeypatch, handler, allow_write_methods=True,
                      request={'url': 'https://fixture.test/login?RetURL=home'})
    actions = [e['data'] for e in run['events'] if e['kind'] == 'action' and e['data']['kind'] == 'confirm']
    assert actions[0]['location'] == 'body' and actions[0]['param'] == 'user'
    assert len(used) == 7
    assert run['data']['requests'] == len(requests) == 15
    assert run['conclusion']['verdict'] == ('inconclusive' if parameterized else 'suspicious')
    assert run['conclusion']['completion'] == 'partial'  # Remaining fields exceed the explicit budget.
    assert run['data']['ai_calls'] == 0


def test_generic_goal_checks_observed_asp_login_form_without_model(tmp_path, monkeypatch):
    requests = []
    with sqlite3.connect(':memory:') as db:
        db.execute('CREATE TABLE users (name TEXT, password TEXT)')
        db.execute("INSERT INTO users VALUES ('admin', 'secret')")

        def handler(request):
            requests.append(request)
            if request.method == 'GET':
                return httpx.Response(200, headers={'content-type': 'text/html'}, text=(
                    '<form method="post" action="/Login.asp?RetURL=%2FDefault.asp">'
                    '<input name="tfUName"><input type="password" name="tfUPass" value="test"></form>'))
            fields = parse_qs(request.content.decode(), keep_blank_values=True)
            try:
                rows = db.execute(f"SELECT name FROM users WHERE name='{fields['tfUName'][0]}' "
                                  f"AND password='{fields['tfUPass'][0]}'").fetchall()
            except sqlite3.Error:
                rows = []
            return httpx.Response(200, text='Welcome ' + 'A' * 150 if rows else 'Login failed',
                                  headers={'set-cookie': 'logged_in=yes; Path=/'} if rows else {})

        run = execute(tmp_path, monkeypatch, handler,
                      goal='대상에서 취약 신호를 확인하고 근거가 있는 후속 테스트를 진행해줘.',
                      allow_write_methods=True, target_scope='same_origin',
                      request={'url': 'https://fixture.test/Login.asp?RetURL=%2FDefault.asp'})
    confirms = [e['data'] for e in run['events'] if e['kind'] == 'action' and e['data']['kind'] == 'confirm']
    assert confirms and confirms[0]['confirmation_profile'] == 'sql_login'
    assert confirms[0]['param'] == 'tfUName' and confirms[0]['category'] == 'auth'
    assert any(r.method == 'POST' for r in requests)
    assert run['data']['ai_calls'] == 0
    assert any(e['kind'] == 'verification' for e in run['events'])


@pytest.mark.parametrize('settings', [
    {}, {'allow_write_methods': True, 'target_scope': 'request_only'},
    {'allow_write_methods': True, 'denied_path_prefixes': ['/login']},
    {'allow_write_methods': True, 'allowed_methods': ['GET']},
])
def test_discovery_never_bypasses_write_or_path_policy(tmp_path, monkeypatch, settings):
    requests = []
    def handler(request):
        requests.append(request)
        return httpx.Response(200, headers={'content-type': 'text/html'}, text='<form method="post" action="/login"><input name="user"><input name="password" type="password"></form>')
    run = execute(tmp_path, monkeypatch, handler, request={'url': 'https://fixture.test/'}, **settings)
    assert len(requests) == 1 and requests[0].method == 'GET'
    assert run['conclusion']['completion'] == 'partial'


def test_reflection_is_not_sql_evidence(tmp_path, monkeypatch):
    run = execute(tmp_path, monkeypatch, lambda r: httpx.Response(200, text=str(r.url.params.get('q', '')) * 50),
                  request={'url': 'https://fixture.test/?q=alpha'})
    assert run['state'] == 'completed'
    assert run['conclusion']['verdict'] == 'inconclusive'


def test_small_budget_does_not_start_unfinishable_check(tmp_path, monkeypatch):
    run = execute(tmp_path, monkeypatch, lambda r: httpx.Response(200, text='fixture'),
                  request={'url': 'https://fixture.test/?q=alpha'}, max_requests=7)
    assert run['data']['requests'] == 1
    assert run['state'] == 'limited'
    assert run['conclusion']['requested_checks'][0]['status'] == 'not_tested'


def test_sql_profile_cannot_lower_other_categories_request_cost():
    with pytest.raises(ValueError):
        Action(kind='confirm', hypothesis='fixture', category='ssti', confirmation_profile='sql_string')


def test_off_origin_form_is_never_submitted(tmp_path, monkeypatch):
    requests = []
    def handler(request):
        requests.append(request)
        return httpx.Response(200, headers={'content-type': 'text/html'}, text='<form method="post" action="https://outside.test/login"><input name="user"></form>')
    run = execute(tmp_path, monkeypatch, handler, allow_write_methods=True,
                  request={'url': 'https://fixture.test/'})
    assert len(requests) == 1
    assert run['state'] == 'paused'


def test_ambiguous_post_is_not_retried(tmp_path, monkeypatch):
    posts = []
    def handler(request):
        if request.method == 'POST':
            posts.append(request)
            raise httpx.ReadTimeout('submission outcome unknown', request=request)
        return httpx.Response(200, headers={'content-type': 'text/html'}, text='<form method="post" action="/login"><input name="user"></form>')
    run = execute(tmp_path, monkeypatch, handler, allow_write_methods=True,
                  request={'url': 'https://fixture.test/'})
    assert len(posts) == 1
    assert run['conclusion']['completion'] == 'partial'
    assert len(module.ambiguous_writes(run['events'])) == 1


def test_rotating_token_does_not_create_duplicate_form(tmp_path):
    spec = RunSpec(goal='SQL injection', allow_write_methods=True,
                   request={'url': 'https://fixture.test/'})
    manager = AgentManager(Store(tmp_path / 'runs.db'))
    data = {'endpoints': {'seed': spec.request.model_dump()}}
    for token in ('one', 'two'):
        manager._record_discovery('fixture', data, spec.request.model_dump(), {
            'id': token, 'response': {'headers': {'content-type': 'text/html'}, 'body':
                '<form method="post" action="/login"><input name="user">'
                f'<input name="csrf_token" value="{token}"></form>'}}, 'step', spec)
    assert len(data['endpoints']) == 2
    assert len(data['form_sources']) == 1


@pytest.mark.parametrize('parameterized', [False, True])
@pytest.mark.parametrize('marker_configured', [False, True])
def test_crawls_linked_login_form_and_checks_auth_bypass(tmp_path, monkeypatch, parameterized, marker_configured):
    requests = []
    marker = 'PRIVATE_DASHBOARD_72641'
    with sqlite3.connect(':memory:') as db:
        db.execute('CREATE TABLE users (name TEXT, password TEXT)')
        db.execute("INSERT INTO users VALUES ('admin', 'secret')")

        def handler(request):
            requests.append(request)
            if request.url.path == '/':
                return httpx.Response(200, headers={'content-type': 'text/html'},
                                      text='<a href="/login">Login</a>')
            if request.method == 'GET':
                return httpx.Response(200, headers={'content-type': 'text/html'}, text=(
                    '<form method="POST" action="/session"><input name="user">'
                    '<input type="password" name="password" value="test"></form>'))
            fields = parse_qs(request.content.decode(), keep_blank_values=True)
            user, password = fields['user'][0], fields['password'][0]
            try:
                if parameterized:
                    rows = db.execute('SELECT name FROM users WHERE name=? AND password=?',
                                      (user, password)).fetchall()
                else:
                    rows = db.execute(f"SELECT name FROM users WHERE name='{user}' AND password='{password}'").fetchall()
            except sqlite3.Error:
                return httpx.Response(500, text='query error')
            return httpx.Response(200, text=marker if rows else 'Login failed',
                                  headers={'set-cookie': 'session=granted; Path=/'} if rows else {})

        run = execute(tmp_path, monkeypatch, handler, goal='로그인 인증 우회',
                      request={'url': 'https://fixture.test/'},
                      allow_write_methods=True, protected_marker=marker if marker_configured else '')
    assert any(r.method == 'GET' and r.url.path == '/login' for r in requests)
    assert any(r.method == 'POST' and r.url.path == '/session' for r in requests)
    assert any(e['kind'] == 'action' and e['data'].get('category') == 'auth' for e in run['events'])
    assert run['data']['ai_calls'] == 0
    assert run['conclusion']['verdict'] == ('inconclusive' if parameterized else
                                           'confirmed' if marker_configured else 'suspicious')
    assert run['conclusion']['requested_checks'] == [{'category': 'auth', 'status': 'tested'}]
