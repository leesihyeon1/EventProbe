from core.triage_campaigns import summarize_campaigns


def events(action='allowed'):
    return [dict(id=str(i),host='example.test',source=f'192.0.2.{i%3+1}',window='100',path=f'/path{i}',method='GET',category='sqli',signature='',action=action,priority='review',status=200,reasons=[]) for i in range(12)]


def test_wide_and_distributed_observations_with_bounded_representatives():
    r=summarize_campaigns(events())
    target=next(c for c in r['campaigns'] if c['axis']=='target')
    assert target['path_count']==12 and target['source_count']==3
    assert len(target['representative_ids'])==3
    assert len(target['signals'])==2
    assert '판별할 수 없음' in target['ai_attribution']


def test_blocked_scan_retains_visibility_without_replay_recommendation():
    target=summarize_campaigns(events('blocked'))['campaigns'][0]
    assert target['record_count']==12 and target['representative_ids']==[]


def test_unknown_time_is_not_campaign_evidence():
    data=events()
    for e in data:e['window']='unknown'
    r=summarize_campaigns(data)
    assert r['campaigns']==[] and r['unknown_time_events']==12


def test_repeated_single_path_does_not_claim_broad_scan():
    data=events()
    for e in data:e['path']='/same'
    assert summarize_campaigns(data)['campaigns']==[]


def test_time_windows_remain_separate():
    data=events()
    for i,e in enumerate(data):e['window']=str(i)
    assert summarize_campaigns(data)['campaigns']==[]
