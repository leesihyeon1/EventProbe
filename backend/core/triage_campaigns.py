"""Observed scan patterns, not attribution or proof of AI usage."""
from collections import defaultdict,Counter
from datetime import datetime,timezone,timedelta
from urllib.parse import urlsplit

_KST=timezone(timedelta(hours=9))


def _window_span_label(windows):
    """15분 버킷 인덱스 집합 → 읽기 쉬운 시간 범위(KST). 실패 시 ''."""
    nums=sorted(int(w) for w in windows if str(w).isdigit())
    if not nums:return ''
    try:
        start=datetime.fromtimestamp(nums[0]*900,_KST);end=datetime.fromtimestamp((nums[-1]+1)*900,_KST)
        if start.date()==end.date():
            return f"{start.strftime('%m-%d %H:%M')}~{end.strftime('%H:%M')} KST"
        return f"{start.strftime('%m-%d %H:%M')}~{end.strftime('%m-%d %H:%M')} KST"
    except (ValueError,OverflowError,OSError):
        return ''


def summarize_campaigns(events):
    # (axis, entity) 로만 묶어 인접 15분 버킷 분할을 합친다. 시간 범위는 버킷들의 실제 범위로 표기한다.
    buckets=defaultdict(list)
    for e in events:
        if e.get('window')=='unknown' or not e.get('host') or 'HOST_CONFLICT' in e.get('reasons',[]):continue
        buckets[('target',e['host'])].append(e)
        if e.get('source'):buckets[('source',e['source'])].append(e)
    campaigns=[]
    for (axis,entity),items in buckets.items():
        windows={e['window'] for e in items if e.get('window') not in (None,'unknown')}
        paths={urlsplit(e['path']).path for e in items}
        hosts={e['host'] for e in items};sources={e['source'] for e in items if e.get('source')}
        types={e.get('category') or e.get('signature') for e in items}-{'' ,None}
        signals=[]
        if len(paths)>=5 and len(items)>=10:signals.append('넓은 경로 탐색')
        if axis=='target' and len(sources)>=3 and len(paths)>=5:signals.append('여러 출발지의 동시 탐색 후보')
        if axis=='source' and len(hosts)>=3:signals.append('여러 자산에 대한 탐색')
        if len(types)>=3 and len(items)>=10:signals.append('다양한 공격 유형 탐색')
        if not signals:continue
        actions=Counter(e['action'] for e in items)
        # Retain distinct payloads in evidence; select bounded representative requests only.
        candidates=[e for e in items if e['action']!='blocked' and e['method']=='GET' and (e['priority']=='review' or e['action']=='allowed')]
        candidates.sort(key=lambda e:(e['priority']!='review',e.get('status') is None,e['id']))
        representatives=[];seen=set()
        for e in candidates:
            key=(e['host'],e.get('category') or e.get('signature'),e['path'],e.get('status'))
            if key in seen:continue
            seen.add(key);representatives.append(e['id'])
            if len(representatives)==3:break
        all_blocked=actions['blocked']==len(items)
        response=('차단 유지 여부와 같은 시간대 허용 로그를 확인하세요. 기본 재요청 대상은 없습니다.' if all_blocked else
                  '허용·불명 이벤트의 응답 본문과 대상 서비스 영향을 확인하고 대표 요청부터 검증하세요. 동일 범위의 WAF 규칙·속도 제한 적용 여부를 운영자가 검토하세요.')
        win_nums=sorted(int(w) for w in windows if str(w).isdigit())
        campaigns.append(dict(axis=axis,entity=entity,window=str(win_nums[0]) if win_nums else '',
             window_label=_window_span_label(windows),window_count=len(windows),
             record_count=len(items),path_count=len(paths),
             source_count=len(sources),host_count=len(hosts),type_count=len(types),actions=dict(actions),signals=signals,
             representative_ids=representatives,event_ids=[e['id'] for e in items],response=response,
             ai_attribution='로그만으로 AI 사용 여부를 판별할 수 없음'))
    return {'campaigns':campaigns,'unknown_time_events':sum(e.get('window')=='unknown' for e in events),
            'policy':{'window_seconds':900,'wide_scan_min_records':10,'wide_scan_min_paths':5,'distributed_min_sources':3,'representative_limit':3},
            'limitations':'입력 파일의 관측 범위에 한정된 상관 후보입니다. 고정 15분 경계·수집 누락·NAT/프록시·중복 장비 로그가 결과에 영향을 줍니다. 같은 행위를 AI 사용의 증거로 판단하지 않습니다.'}
