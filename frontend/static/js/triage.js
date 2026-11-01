/* Session-only triage: untrusted log values are always rendered as text. */
(() => {
  const el = id => document.getElementById(id);
  let result = null, busy = false, analyzedText = null;
  const technologyProfiles={};
  const selected=new Set(), origins={};
  let shownResult=null;
  const labels = {review:'검토 필요',information:'정보 보완',low:'재요청 저우선'};
  const reasons = {DEVICE_BLOCKED:'장비 차단 기록',SIMPLE_NOT_FOUND:'단순 조회 · 404/410',ATTACK_REVIEW:'공격 유형/민감파일 검토',INSUFFICIENT_EVIDENCE:'판단 근거 부족',HOST_CONFLICT:'호스트 불일치',HOST_MISSING:'호스트 없음',PCAP_NOT_INSPECTED:'PCAP 미분석 · 대상 확인 필요',INVENTORY_STALE:'자산 정보 갱신 필요',IMPORTANT_ASSET:'중요 운영 자산',MIXED_ALLOWED_BLOCKED:'같은 시간대 허용·차단 혼재'};
  function node(tag,text,cls) { const n=document.createElement(tag); n.textContent=text; if(cls)n.className=cls; return n; }

  async function triageApi(path, body) {
    return _asJson(await fetch('/api/triage'+path, body===undefined?{}:{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)}),'검증 준비');
  }

  function render() {
    el('triageSummary').replaceChildren(); el('triageResults').replaceChildren();
    el('triageImport').open=!result;
    el('triageAssessment').hidden=!result;el('triageHandoff').hidden=!result;el('triageTechnology').hidden=!result;
    if(!result)return;
    if(shownResult!==result){selected.clear();for(const key of Object.keys(origins))delete origins[key];for(const key of Object.keys(technologyProfiles))delete technologyProfiles[key];shownResult=result;renderOrigins();for(const e of result.events)if(e.priority==='review'&&!e.screening?.screened&&e.method==='GET'&&TriageWorkflow.inferredOrigin(e))selected.add(e.id);}
    renderAssessment();renderTechnology();updateSelection();
    const s=result.summary;
    for(const [k,title] of Object.entries({records:'입력',parsed:'분석 성공',errors:'분석 실패',unsupported:'HTTP 요청 없음',groups:'대상 묶음',review:'검토 필요',information:'정보 보완',low:'재요청 저우선'})) el('triageSummary').append(node('div',`${title} ${s[k]??0}`));
    const screenedCount=result.events.filter(e=>e.screening?.screened).length;
    el('triageSummary').append(node('div',`우선 확인 ${result.events.length-screenedCount} · 낮은 우선순위 ${screenedCount}`));
    const filter=el('triageFilter').value;
    const screenFilter=el('triageScreenFilter').value;
    const table=node('table','','triage-table');const head=node('thead','');const tr=node('tr','');
    for(const title of ['검증','대상 / 요청','어떤 이벤트인가','장비 처리 / 응답','분석 판단','로그 수'])tr.append(node('th',title));head.append(tr);table.append(head);
    const body=node('tbody','');
    const visible=TriageWorkflow.rows(result.events).filter(e=>(!filter||e.priority===filter)&&(screenFilter==='all'||(screenFilter==='screened'?Boolean(e.screening?.screened):!e.screening?.screened)));
    for(const row of visible){
      const line=node('tr','');line.dataset.priority=row.priority;
      const checkCell=node('td','');const check=node('input','');check.type='checkbox';check.disabled=row.method!=='GET';check.checked=row.items.every(e=>selected.has(e.id));check.indeterminate=!check.checked&&row.items.some(e=>selected.has(e.id));check.setAttribute('aria-label',`${row.host} ${row.path} 검증 선택`);
      check.onchange=()=>{for(const e of row.items){if(check.checked)selected.add(e.id);else selected.delete(e.id);}updateSelection();};checkCell.append(check);
      const target=node('td','');target.append(node('strong',row.host||row.destination||'대상 확인 필요'),node('div',row.path?`${row.method} ${row.path}`:'HTTP 요청 경로 없음','triage-path'));
      const origin=TriageWorkflow.inferredOrigin(row);target.append(node('small',origin?`접속 주소: ${origin} (로그 기준)`:'접속 주소 확인 필요'));
      const detail=node('details','');detail.append(node('summary','원문과 상세 근거'));detail.append(node('pre',JSON.stringify(row.items,null,2)));target.append(detail);
      const attack=node('td','');
      attack.append(node('strong',row.assessment?.title||row.signature||row.category||'탐지명 없음'));
      if(row.assessment){attack.append(node('p',`공격 중요도: ${{high:'높음',medium:'주의',unknown:'판단 보류'}[row.assessment.importance]}`),node('p',`예상 영향: ${row.assessment.impact}`),node('small',row.assessment.evidence.join(' · ')));}
      const outcome=node('td',`${({blocked:'차단',allowed:'허용',unknown:'불명'})[row.action]||'불명'} / ${row.status??'응답 코드 없음'}`);
      const decision=node('td','');decision.append(node('strong',labels[row.priority]));
      const why=row.priority==='low'?(row.action==='blocked'?'장비가 차단한 기록입니다. 기본 검증 대상에서 제외합니다.':'단순 미존재 조회로 재요청 우선순위가 낮습니다.'):row.priority==='review'?'공격 징후 또는 중요 자산 관련 이벤트입니다. 응답과 재현 여부를 검증하세요.':'성공·차단 판단 근거가 부족합니다. 장비/응답 정보를 확인하세요.';
      decision.append(node('p',why),node('small',row.reasons.map(r=>reasons[r]||r).join(' · ')));
      if(row.screening?.code)decision.append(node('p',`${row.screening.screened?'낮은 우선순위':'기술 일치'}: ${row.screening.explanation}`,'triage-screening-note'));
      if(row.technologies?.length)decision.append(node('small',`확인된 기술: ${row.technologies.join(', ')}`));
      if(row.assessment)decision.append(node('p',row.assessment.outcome),node('p',row.assessment.next_action));
      const latest=row.items.find(e=>e.latest_verification)?.latest_verification;if(latest)decision.append(node('p',`검증 응답: ${latest.statuses.map(c=>c||'무응답').join(', ')}`,'triage-verification'));
      line.append(checkCell,target,attack,outcome,decision,node('td',String(row.items.length)));body.append(line);
    }
    table.append(body);const wrap=node('div','','triage-table-wrap');wrap.append(table);el('triageResults').append(wrap);
    if(!visible.length)el('triageResults').append(node('p','이 조건에 해당하는 이벤트가 없습니다. 전체 기록을 선택하면 원본 이벤트를 확인할 수 있습니다.'));
    if(result.unsupported?.length) {
      const skipped=node('details','');skipped.append(node('summary',`HTTP 요청이 없어 검증에서 제외한 레코드 ${result.unsupported.length}건`));
      for(const e of result.unsupported)skipped.append(node('p',`${e.line}번: ${e.reason}`));
      el('triageResults').append(skipped);
    }
    if(result.errors.length) {
      const errors=node('details','');errors.append(node('summary',`분석하지 못한 레코드 ${result.errors.length}건`));
      for(const e of result.errors)errors.append(node('p',`${e.line}번: ${e.reason}`));
      el('triageResults').append(errors);
    }
  }

  function updateSelection(){el('triageSelectedCount').textContent=`검증할 로그 ${selected.size}건 선택 (같은 URL은 1회 전달)`;el('triageSendBulk').disabled=!selected.size;}
  function renderTechnology(){
    const box=el('triageTechnology');box.replaceChildren(node('h2','대상 웹 기술 확인'));
    box.append(node('p','작업공간 인벤토리에 등록된 대상만 직접 확인합니다. 버튼을 누르면 해당 origin에 GET / 요청 1회가 전송되며 리다이렉트와 응답 본문은 수집하지 않습니다. 기술 지문이 보이지 않는다고 해당 기술이 없다는 뜻은 아닙니다.'));
    const assets=new Map();
    for(const e of result.events)if(e.inventory?.origin)assets.set(e.inventory.origin,e.inventory);
    if(!assets.size){box.append(node('p','일치하는 등록 자산이 없습니다. 운영 자산 인벤토리에 정확한 origin을 등록하면 기술 확인 버튼을 사용할 수 있습니다.'));return;}
    for(const [origin,asset] of assets){
      const row=node('div','','triage-technology-row');
      const cached=technologyProfiles[origin];
      row.append(node('strong',origin),node('span',`인벤토리 기술: ${asset.stack||'미기록'}${asset.stale?' (정보 오래됨)':''}`));
      if(cached)row.append(node('span',`응답 헤더 기술: ${cached.technologies.join(', ')||'식별되지 않음'} · HTTP ${cached.status}`));
      const button=node('button','웹 기술 확인','btn btn-secondary');button.disabled=busy;
      button.onclick=async()=>{
        if(busy)return;busy=true;button.disabled=true;el('triageStatus').textContent=`${origin} 기술 확인 중…`;
        try{
          const profile=await triageApi('/technology-probe',{origin});technologyProfiles[origin]=profile;
          for(const e of result.events.filter(item=>item.inventory?.origin===origin)){
            e.technologies=[...new Set([...(e.technologies||[]),...profile.technologies])];
            const match=TriageWorkflow.technologyMatch(e);
            if(match&&e.screening?.code!=='IPS_BLOCKED'&&!e.reasons?.includes('MIXED_ALLOWED_BLOCKED')&&!e.reasons?.includes('IMPORTANT_ASSET'))
              e.screening={screened:false,code:'TECH_MATCH',explanation:`관측된 웹 기술과 요청 경로가 일치합니다: ${match}. 실제 취약 여부는 별도 확인이 필요합니다.`};
          }
          render();el('triageStatus').textContent=`${origin} 기술 확인 완료 · HTTP ${profile.status}. 요청 1건.`;
        }catch(error){el('triageStatus').textContent=error.message;}
        finally{busy=false;renderTechnology();}
      };
      row.append(button);box.append(row);
    }
  }
  function renderOrigins(){
    el('triageOrigins').replaceChildren();
    for(const host of new Set(result.events.filter(e=>e.method==='GET'&&!TriageWorkflow.inferredOrigin(e)).map(e=>e.host))){
      const label=node('label',`${host||'대상 불명'} → 실제 접속 주소`);
      const input=node('input','');input.type='url';input.placeholder='https://example.com (프로토콜·포트 확인)';input.setAttribute('aria-label',`${host} 접속 주소`);
      input.oninput=()=>{origins[host]=input.value.trim();};label.append(input);el('triageOrigins').append(label);
    }
  }
  window.addEventListener('triage-bulk-complete',event=>{
    if(!result)return;
    for(const link of event.detail.source.events){
      const item=result.events.find(e=>e.id===link.event_id);const target=event.detail.targets.find(t=>t.url===link.url);
      if(item&&target)item.latest_verification={at:new Date().toISOString(),url:link.url,statuses:(target.results||[]).map(r=>r.status_code||0)};
    }
    render();
  });
  function campaignPanel(){
    const scan=result.scan_analysis;const panel=node('section','','triage-campaigns');
    panel.append(node('h2','대량 탐색 행위와 대응 우선순위'));
    if(!scan){panel.append(node('p','최신 로그 분석을 실행하면 스캔 행위를 묶어 확인할 수 있습니다.'));return panel;}
    if(!scan.campaigns.length)panel.append(node('p','현재 입력에서 설정 기준을 넘는 대량 탐색 묶음은 없습니다. 탐지가 없다는 것이 정상 통신을 의미하지는 않습니다.'));
    for(const c of scan.campaigns){
      const card=node('article','','triage-assessment');
      card.append(node('h3',`${c.axis==='target'?'대상':'출발지'} ${c.entity} · ${c.signals.join(' / ')}`));
      card.append(node('p',`${new Date(Number(c.window)*900000).toLocaleString()}부터 15분 · 로그 ${c.record_count} · 경로 ${c.path_count} · 출발지 ${c.source_count} · 자산 ${c.host_count}`));
      card.append(node('p',`차단 ${c.actions.blocked||0} / 허용 ${c.actions.allowed||0} / 불명 ${c.actions.unknown||0}`));
      card.append(node('p',c.response));
      const button=node('button',`대표 검증 후보 ${c.representative_ids.length}건 선택`,'btn btn-primary');button.disabled=!c.representative_ids.length;
      button.onclick=()=>{selected.clear();for(const id of c.representative_ids)selected.add(id);el('triageFilter').value='';render();el('triageHandoff').scrollIntoView({block:'start'});};card.append(button);
      const details=node('details','');details.append(node('summary','판단 기준과 한계'),node('p',c.ai_attribution+' · '+scan.limitations));card.append(details);panel.append(card);
    }
    panel.append(node('p',`시간 정보가 부족해 시간대 상관분석에서 제외된 이벤트 ${scan.unknown_time_events}건. 출발지와 대상 묶음은 중복될 수 있습니다.`));
    return panel;
  }
  const chartColors=['#6366f1','#06b6d4','#f59e0b','#ef4444','#22c55e','#a855f7','#f97316','#64748b','#14b8a6','#eab308','#ec4899'];
  function chartTitle(title,description){const box=node('div','');box.append(node('h3',title),node('p',description));return box;}
  function countRows(items,total){
    const list=node('div','','triage-stat-rows');
    for(const [index,item] of items.entries()){
      const row=node('div','','triage-stat-row');
      const percent=total?item.count/total*100:0;
      row.append(node('span',item.label),node('strong',`${item.count}건 · ${percent.toFixed(1)}%`));
      const track=node('div','','triage-stat-track');const fill=node('div','','triage-stat-fill');fill.style.width=`${percent}%`;fill.style.background=chartColors[index%chartColors.length];track.append(fill);row.append(track);list.append(row);
    }
    if(!items.length)list.append(node('p','집계할 기록이 없습니다.'));
    return list;
  }
  function donut(items,total){
    const wrap=node('div','','triage-donut-wrap');const pie=node('div','','triage-donut');
    let start=0;const sectors=[];
    for(const [index,item] of items.entries()){
      const end=start+(total?item.count/total*100:0);
      sectors.push(`${chartColors[index%chartColors.length]} ${start}% ${end}%`);start=end;
    }
    pie.style.background=sectors.length?`conic-gradient(${sectors.join(',')})`:'var(--border)';
    pie.setAttribute('role','img');pie.setAttribute('aria-label',items.map(i=>`${i.label} ${i.count}건`).join(', ')||'집계 기록 없음');
    pie.append(node('span',`${total}건`));wrap.append(pie,countRows(items,total));return wrap;
  }
  function statisticsPanel(){
    const s=result.statistics;const section=node('section','','triage-statistics');
    section.append(node('h2','발생 이벤트 통계'));
    if(!s){section.append(node('p','저장 당시 생성된 통계가 없습니다. 원문을 다시 분석하면 통계를 볼 수 있습니다.'));return section;}
    const grid=node('div','','triage-stat-grid');
    const names=node('article','','triage-stat-card');names.append(chartTitle('탐지명별 비율','evtname 우선 · 없으면 장비 탐지명 · 상위 10개와 기타'),donut(s.event_names,s.total));grid.append(names);
    const families=node('article','','triage-stat-card');families.append(chartTitle('이벤트 계열','정보 수집성 · 웹 · 애플리케이션 · 네트워크 · 기타'),countRows(s.families,s.total));grid.append(families);
    const targets=node('article','','triage-stat-card');targets.append(chartTitle('대상별 이벤트','HTTP Host 우선 · 없으면 DST · 상위 10개와 기타'),countRows(s.targets,s.total));grid.append(targets);
    const devices=node('article','','triage-stat-card');devices.append(chartTitle('장비별 처리와 응답','명시된 장비 종류별 로그 비율 · 응답 코드는 장비 기록값'));
    for(const d of s.devices){
      const detail=node('div','','triage-device-stat');detail.append(node('h4',`${d.name} · ${d.records}건`));
      const actionItems=[['차단',d.actions.blocked||0],['허용',d.actions.allowed||0],['불명',d.actions.unknown||0]].map(([label,count])=>({label,count}));
      detail.append(node('p','장비 동작'),countRows(actionItems,d.records));
      if(d.name==='WAF'||d.name==='IDS'){
        detail.append(node('p','HTTP 응답 코드'),countRows(d.http_status,d.status_eligible));
        if(d.response_result.length)detail.append(node('p','장비 응답 판정'),countRows(d.response_result,d.response_result.reduce((sum,item)=>sum+item.count,0)));
      }
      devices.append(detail);
    }
    grid.append(devices);section.append(grid);
    const correlations=node('div','','triage-stat-correlations');correlations.append(node('h3','상관 분석 후보'));
    if(s.correlations.length)for(const c of s.correlations)correlations.append(node('p',`${c.label} · ${c.source||c.target}`));
    else correlations.append(node('p','현재 입력에서 여러 대상·출발지·공격 계열을 잇는 후보는 없습니다.'));
    section.append(correlations,node('p',s.note));
    return section;
  }
  function renderAssessment(){
    const box=el('triageAssessment');box.replaceChildren();const o=TriageWorkflow.overview(result);
    box.append(statisticsPanel());
    box.append(node('h2','공격 핵심 요약'));
    const summary=result.attack_summary;
    if(summary){
      box.append(node('p',`공격 중요도 높음 ${summary.high}건 · 공격 유형·대상별 ${summary.groups.length}개 묶음. 중요도와 장비 처리 결과를 함께 확인하세요.`,'triage-conclusion'));
      const list=node('div','','triage-attack-list');
      for(const [index,g] of summary.groups.slice(0,5).entries()){
        const card=node('article','','triage-attack-card');card.dataset.importance=g.importance;
        card.append(node('h3',`${index+1}. ${g.title} · ${g.host||'대상 불명'}`));
        card.append(node('strong',`중요도 ${{high:'높음',medium:'주의',unknown:'판단 보류'}[g.importance]} · ${g.rank===0?'우선 조사':'근거 확인'}`));
        card.append(node('p',`예상 영향: ${g.impact}`));
        card.append(node('p',`로그 ${g.record_count}건 · 출발지 ${g.source_count}개 · 경로 ${g.path_count}개 · 차단 ${g.actions.blocked||0} / 허용 ${g.actions.allowed||0} / 불명 ${g.actions.unknown||0}`));
        if(g.occurrence_records)card.append(node('small',`횟수 필드가 있는 ${g.occurrence_records}개 로그의 장비 보고 횟수 합계: ${g.reported_occurrences}`));
        card.append(node('p',`대표 경로: ${g.paths.join(', ')}`));
        if(g.sources.length)card.append(node('p',`출발지 예시: ${g.sources.join(', ')}`));
        card.append(node('p',`대표 이벤트 판단 근거: ${g.evidence.join(' · ')}`),node('p',`다음 확인: ${g.next_action}`));
        list.append(card);
      }
      box.append(list);
      if(summary.groups.length>5)box.append(node('p',`우선 확인할 5개 묶음을 표시했습니다. 전체 ${summary.groups.length}개 묶음의 이벤트는 아래 분석표에서 확인하세요.`));
      box.append(node('p',summary.limitation));
    }else box.append(node('p','이 저장 기록에는 공격 핵심 요약이 없습니다. 원문 로그를 다시 분석하면 새 요약을 볼 수 있습니다.'));
    box.append(node('p',o.conclusion,'triage-conclusion'));
    const actions=node('div','','triage-recommendations');
    for(const [title,body] of [
      ['먼저 확인',`${result.summary.review}건의 검토 필요 이벤트를 우선 확인하세요. 허용·차단 혼재와 중요 자산은 상세 근거를 확인합니다.`],
      ['보완할 근거',`${result.summary.information}건은 정보 보완이 필요합니다. 상태 코드·장비 동작·자산 소유자와 실제 접속 주소를 확인하세요.`],
      ['재검증 줄이기',`${result.summary.low}건은 재요청 저우선입니다. 차단 기록을 검토하고 필요한 예외만 선택하세요. 저우선은 안전 판정이 아닙니다.`]
    ]){const item=node('div','');item.append(node('h3',title),node('p',body));actions.append(item);}
    const verified=result.events.filter(e=>e.latest_verification);
    if(verified.length)box.append(node('p',`선택 검증 결과가 연결된 이벤트 ${verified.length}건. 이벤트 상세의 최신 응답 코드와 일괄 테스트 결과를 함께 확인하세요.`));
    box.append(actions,node('p',`장비 기록: 차단 ${o.blocked} · 허용 ${o.allowed} · 불명 ${o.unknown} / HTTP 요청 없는 로그 ${result.summary.unsupported||0}건은 별도 확인`));
    box.append(campaignPanel());
  }
  el('triageSelectReview').onclick=()=>{for(const e of result?.events||[])if(e.priority==='review'&&!e.screening?.screened&&e.method==='GET')selected.add(e.id);render();};
  el('triageSelectNone').onclick=()=>{selected.clear();render();};
  el('triageSendBulk').onclick=()=>{
    const transfer=TriageWorkflow.targets(result.events,selected,origins);
    if(transfer.errors.length){el('triageHandoffStatus').textContent=transfer.errors.join(' / ');return;}
    if(!transfer.urls.length)return;
    if(!state.payloads){el('triageHandoffStatus').textContent='일괄 테스트 구성을 불러오는 중입니다. 잠시 후 다시 시도하세요.';return;}
    switchView('bulk');switchModalTab('multi');switchMultiPayloadMode('custom');
    el('multiUrls').value=transfer.urls.join('\n');el('multiMethod').value='GET';el('multiCustomPayloads').value='';el('multiTargetParam').value='';el('multiInjectIn').value='params';el('multiConcurrency').value='1';
    window.triageBulkContext={events:transfer.links,urls:transfer.urls,created:new Date().toISOString()};
    let banner=el('triageBulkBanner');if(!banner){banner=node('section','','triage-assessment');banner.id='triageBulkBanner';el('mtab-multi').prepend(banner);}
    banner.replaceChildren(node('h3',`이벤트 분석에서 선택한 ${transfer.links.length}건 → URL ${transfer.urls.length}개`),node('p','기본 준비는 GET 단순 요청 · 동시 1개입니다. 기존 요청 헤더와 기본 헤더 설정을 확인한 뒤 아래 테스트 시작 버튼을 누르세요. 요청 재현은 과거 침해 성공을 확정하지 않습니다.'));
    const back=node('button','이벤트 판단으로 돌아가기','btn btn-secondary');back.onclick=()=>switchView('triage');banner.append(back);
    banner.scrollIntoView({block:'start'});
  };

  async function loadLogFiles(files) {
    if(busy){el('triageStatus').textContent='현재 작업이 끝난 뒤 파일을 넣어주세요.';return;}
    if(!files?.length)return;
    if(files.length!==1){el('triageStatus').textContent='로그 파일은 한 번에 1개씩 넣어주세요.';return;}
    const file=files[0];
    if(file.size>2000000){el('triageStatus').textContent='파일이 너무 큽니다. 2MB 이하 파일을 넣어주세요.';return;}
    if(!/\.(csv|log|txt|json|jsonl|ndjson)$/i.test(file.name)){el('triageStatus').textContent='CSV, LOG, TXT, JSON, JSONL, NDJSON 파일을 넣어주세요.';return;}
    busy=true;el('triageAnalyze').disabled=true;el('triageFile').disabled=true;
    try {
      const text=await file.text();
      if(!text.trim())throw new Error('빈 파일입니다. 로그가 포함된 파일을 넣어주세요.');
      el('triageInput').value=text;
      result=null;analyzedText=null;selected.clear();
      el('triageSave').disabled=true;el('triageExport').disabled=true;
      render();el('triageImport').open=true;
      el('triageStatus').textContent=`${file.name} 불러오기 완료 · ‘로그 분석’을 눌러 시작하세요.`;
    }catch(error){el('triageStatus').textContent='파일을 불러오지 못했습니다. '+error.message;}
    finally{busy=false;el('triageAnalyze').disabled=false;el('triageFile').disabled=false;el('triageFile').value='';}
  }
  el('triageFile').onchange=ev=>loadLogFiles(ev.target.files);
  const dropArea=el('triageImport');let dragDepth=0;
  const isFileDrag=ev=>Array.from(ev.dataTransfer?.types||[]).includes('Files');
  dropArea.addEventListener('dragenter',ev=>{
    if(!isFileDrag(ev))return;ev.preventDefault();dragDepth++;
    dropArea.open=true;dropArea.classList.add('triage-drag-active');
  });
  dropArea.addEventListener('dragover',ev=>{
    if(!isFileDrag(ev))return;ev.preventDefault();ev.dataTransfer.dropEffect=busy?'none':'copy';
  });
  dropArea.addEventListener('dragleave',ev=>{
    if(!isFileDrag(ev))return;dragDepth=Math.max(0,dragDepth-1);
    if(!dragDepth)dropArea.classList.remove('triage-drag-active');
  });
  dropArea.addEventListener('drop',ev=>{
    if(!isFileDrag(ev))return;ev.preventDefault();ev.stopPropagation();dragDepth=0;
    dropArea.classList.remove('triage-drag-active');loadLogFiles(ev.dataTransfer.files);
  });
  el('triageAnalyze').onclick=async()=>{
    if(busy)return; busy=true; el('triageAnalyze').disabled=true;
    el('triageExport').disabled=true;el('triageSave').disabled=true;analyzedText=null; result=null;render();
    el('triageStatus').textContent='로그 분석 중…';
    try {
      const text=el('triageInput').value;
      if(new TextEncoder().encode(text).length>2000000)throw new Error('입력은 2MB 이하로 제한됩니다.');
      const response=await fetch('/api/triage/analyze',{method:'POST',headers:{'Content-Type':'text/plain; charset=utf-8'},body:text});
      result=await _asJson(response,'로그 분석');analyzedText=text;el('triageSave').disabled=false; render(); el('triageExport').disabled=false;
      el('triageStatus').textContent='분석 완료 · 대상 요청 0건 · 저우선은 안전 판정이 아닙니다. 이벤트 상세에서 자산 대조와 선택 검증을 준비할 수 있습니다.';
    } catch(e) {el('triageStatus').textContent=e.message;}
    finally {busy=false;el('triageAnalyze').disabled=false;}
  };

  async function textPost(path,text) {
    if(new TextEncoder().encode(text).length>2000000)throw new Error('입력은 2MB 이하로 제한됩니다.');
    return _asJson(await fetch('/api/triage'+path,{method:'POST',headers:{'Content-Type':'text/plain; charset=utf-8'},body:text}),'기록 관리');
  }
  async function refreshHistory() {
    const r=await triageApi('/batches');el('triageHistory').replaceChildren();
    if(!r.batches.length)el('triageHistory').append(node('p','저장 기록이 없습니다.'));
    for(const b of r.batches) {
      const row=node('p',`${new Date(b.created*1000).toLocaleString()} · ${b.summary.records}건 · 만료 ${new Date(b.expires*1000).toLocaleString()} `);
      const load=node('button','불러오기','btn btn-secondary');
      load.onclick=async()=>{if(busy)return;busy=true;try{result=await triageApi('/batches/'+b.id);analyzedText=null;el('triageSave').disabled=true;el('triageExport').disabled=false;render();el('triageStatus').textContent='저장 당시 분석 결과를 불러왔습니다. 현재 인벤토리와 다를 수 있습니다.';}catch(err){el('triageStatus').textContent=err.message;}finally{busy=false;}};
      const del=node('button','삭제','btn btn-secondary');del.onclick=async()=>{if(!confirm('이 기록의 원문과 분석 결과를 삭제할까요?'))return;try{await _asJson(await fetch('/api/triage/batches/'+b.id,{method:'DELETE'}),'삭제');await refreshHistory();}catch(err){el('triageStatus').textContent=err.message;}};
      row.append(load,del);el('triageHistory').append(row);
    }
  }
  el('triageSave').onclick=async()=>{
    if(analyzedText===null||busy)return;const button=el('triageSave');button.disabled=true;
    try{const saved=await textPost('/batches?days='+encodeURIComponent(el('triageRetention').value),analyzedText);el('triageStatus').textContent=saved.duplicate?'같은 원문이 이미 저장되어 있습니다. 보존 기한은 연장하지 않았습니다.':`저장 완료 · 기존 기록과 겹치는 이벤트 ${saved.overlap_events}건 (원본은 유지)`;await refreshHistory();}catch(err){el('triageStatus').textContent=err.message;}finally{button.disabled=analyzedText===null;}
  };
  async function refreshInventory() {
    const r=await triageApi('/inventory');el('triageInventoryList').replaceChildren();
    if(!r.assets.length)el('triageInventoryList').append(node('p','등록한 운영 자산이 없습니다.'));
    for(const a of r.assets) {
      const row=node('p',`${a.origin} · ${a.service} · ${a.importance} · 확인 ${new Date(a.verified_at*1000).toLocaleString()} `);
      const del=node('button','삭제','btn btn-secondary');del.onclick=async()=>{if(!confirm('이 자산 정보를 삭제할까요?'))return;try{await _asJson(await fetch('/api/triage/inventory?origin='+encodeURIComponent(a.origin),{method:'DELETE'}),'자산 삭제');await refreshInventory();}catch(err){el('triageStatus').textContent=err.message;}};
      row.append(del);el('triageInventoryList').append(row);
    }
  }
  el('triageHistoryRefresh').onclick=()=>refreshHistory().catch(err=>{el('triageStatus').textContent=err.message;});
  el('triageInventoryRefresh').onclick=()=>refreshInventory().catch(err=>{el('triageStatus').textContent=err.message;});
  el('triageInventoryImport').onclick=async()=>{const button=el('triageInventoryImport');button.disabled=true;try{const r=await textPost('/inventory',el('triageInventoryInput').value);el('triageStatus').textContent=`자산 ${r.imported}건 반영. 로그를 다시 분석하면 최신 정보를 적용합니다.`;await refreshInventory();}catch(err){el('triageStatus').textContent=err.message;}finally{button.disabled=false;}};

  el('triageFilter').onchange=render;
  el('triageScreenFilter').onchange=render;
  el('triageClear').onclick=()=>{if(busy)return;result=null;analyzedText=null;el('triageSave').disabled=true;el('triageInput').value='';el('triageFile').value='';el('triageStatus').textContent='';el('triageExport').disabled=true;render();};
  el('triageExport').onclick=()=>{
    if(!result)return;
    const url=URL.createObjectURL(new Blob([JSON.stringify(result,null,2)],{type:'application/json'}));
    const a=node('a','');a.href=url;a.download='event-analysis.json';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);
  };
})();
