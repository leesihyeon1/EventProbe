from core.analyzer import analyze_response, generate_summary


def test_error_leak_alone_not_critical():
    result = analyze_response(200, {}, 'You have an error in your SQL syntax', 100)
    assert result['error_leaks']
    assert result['risk_level'] == 'high'


def test_reflection_does_not_confirm_browser_execution():
    result = analyze_response(200, {'content-type': 'text/html'},
                              '<svg onload=alert(1)>', 50,
                              payload='<svg onload=alert(1)>', category='xss')
    assert result['attack_outcome'] == 'suspicious'
    assert result['next_action']['browser']
    assert result['score'] != result['attack_confidence']


def test_invalid_request_defers_execution_but_keeps_observed_leak(monkeypatch):
    from core import analyzer
    monkeypatch.setattr(analyzer.test_validity, 'assess', lambda **kw: {
        'ok': False, 'warnings': [{'severity': 'block', 'code': 'challenge',
                                   'why': 'challenge page', 'fix': 'retry'}]})
    result = analyze_response(200, {}, 'uid=1000(user) gid=1000(user)', 100,
                              payload=';id', category='cmdi')
    assert result['attack_outcome'] != 'success'
    leak = analyze_response(200, {}, '[core]\nrepositoryformatversion = 0', 100,
                            url='https://example.test/.git/config')
    assert any(f['verdict'] == '성공' for f in leak['findings'])


def test_attack_and_hygiene_are_independent_and_summary_counts_outcomes():
    result = analyze_response(200, {'content-type': 'text/html'}, '<html>normal</html>', 100,
                              category='sqli', payload='test')
    assert result['attack_risk_level'] == 'low'
    assert result['overall_risk_level'] == result['hygiene_risk_level']
    summary = generate_summary([{'analysis': result}])
    assert summary['outcome_counts']['inconclusive'] == 1
