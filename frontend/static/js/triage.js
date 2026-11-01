/* Session-only triage: untrusted log values are always rendered as text. */
(() => {
  const el = id => document.getElementById(id);
  let result = null, busy = false, analyzedText = null;
  const technologyProfiles={};
  let probeController=null;
  const selected=new Set(), origins={};
  let shownResult=null;
  const labels = {review:'검토 필요',information:'정보 보완',low:'재요청 저우선'};
  const reasons = {DEVICE_BLOCKED:'장비 차단 기록',SIMPLE_NOT_FOUND:'단순 조회 · 404/410',ATTACK_REVIEW:'공격 유형/민감파일 검토',INSUFFICIENT_EVIDENCE:'판단 근거 부족',HOST_CONFLICT:'호스트 불일치',HOST_MISSING:'호스트 없음',PCAP_NOT_INSPECTED:'PCAP 미분석 · 대상 확인 필요',INVENTORY_STALE:'자산 정보 갱신 필요',IMPORTANT_ASSET:'중요 운영 자산',MIXED_ALLOWED_BLOCKED:'같은 시간대 허용·차단 혼재'};
  function node(tag,text,cls) { const n=document.createElement(tag); n.textContent=text; if(cls)n.className=cls; return n; }

  async function triageApi(path, body, signal) {
    return _asJson(await fetch('/api/triage'+path, body===undefined?{}:{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body),signal}),'검증 준비');
  }

  let listPage=0;
  function filters(){return {ips:el('triageExcludeIps').checked,scan:el('triageExcludeScan').checked};}
  function currentQueue(){return TriageWorkflow.queue(result?.events||[],origins,filters());}
  function selectReady(){selected.clear();for(const e of currentQueue().ready)if(TriageWorkflow.recommended(e))selected.add(e.id);}
  function render() {
    const present=!!result;
    el('triageEmpty').hidden=present;el('triageImport').open=!present;
    for(const id of ['triageAssessment','triageFilterSection','triageHandoff','triageTechnologyDetails'])el(id).hidden=!present;
    el('triageResults').replaceChildren();el('triageSummary').replaceChildren();
    if(!result)return;
    if(shownResult!==result){
      for(const key of Object.keys(origins))delete origins[key];
      for(const key of Object.keys(technologyProfiles))delete technologyProfiles[key];
      Object.assign(technologyProfiles,result.technology_profiles||{});
      shownResult=result;listPage=0;el('triageScreenFilter').value='recommended';el('triageHandoffStatus').textContent='';renderOrigins();selectReady();
    }
    const q=currentQueue();const readyIds=new Set(q.ready.map(e=>e.id));
    for(const id of selected)if(!readyIds.has(id))selected.delete(id);
    renderAssessment();renderTechnology();
    el('triageIpsCount').textContent=result.events.filter(e=>TriageWorkflow.noiseKind(e)==='ips').length+'건';
    el('triageScanCount').textContent=result.events.filter(e=>TriageWorkflow.noiseKind(e)==='scan').length+'건';
    for(const [title,n] of [['분석 이벤트',result.events.length],['노이즈 제외',q.excluded.length],['정보 보완',q.unresolved.length],['권장 검증 후보',q.ready.filter(e=>TriageWorkflow.recommended(e)).length]]){
      const item=node('div','');item.append(node('span',title),node('strong',`${n}건`));el('triageSummary').append(item);
    }
    updateSelection();
    const mode=el('triageScreenFilter').value;
    const subset=mode==='all'?result.events:mode==='recommended'?q.ready.filter(e=>TriageWorkflow.recommended(e)):(q[mode]||[]);
    const rows=TriageWorkflow.rows(subset);listPage=Math.min(listPage,Math.max(0,Math.ceil(rows.length/50)-1));
    const table=node('table','','triage-table');const head=node('thead','');const tr=node('tr','');
    for(const title of ['선택','대상 · 요청','탐지 내용','장비 · 응답','분류 근거','로그'])tr.append(node('th',title));head.append(tr);table.append(head);
    const body=node('tbody','');
    const excludedIds=new Set(q.excluded.map(e=>e.id));
    for(const row of rows.slice(listPage*50,(listPage+1)*50)){
      const line=node('tr','');const pick=node('td','');const check=node('input','');check.type='checkbox';
      const eligible=row.items.filter(e=>readyIds.has(e.id));check.disabled=!eligible.length;
      check.checked=eligible.length>0&&eligible.every(e=>selected.has(e.id));check.indeterminate=!check.checked&&eligible.some(e=>selected.has(e.id));
      check.setAttribute('aria-label',`${row.host||row.destination||'대상 불명'} ${row.path||''} 선택`);
      check.onchange=()=>{for(const e of eligible){if(check.checked)selected.add(e.id);else selected.delete(e.id);}updateSelection();};pick.append(check);
      const target=node('td','');target.append(node('strong',row.host||row.destination||'대상 불명'),node('div',row.path?`${row.method} ${row.path}`:'HTTP 요청 정보 없음','triage-path'));
      const detail=node('details','');detail.append(node('summary','원본 / 상세'));detail.ontoggle=()=>{if(detail.open&&detail.children.length===1)detail.append(node('pre',JSON.stringify(row.items,null,2)));};target.append(detail);
      const attack=node('td',row.event_name||row.signature||row.assessment?.title||row.category||'미분류');
      const outcome=node('td',`${row.device||'장비 불명'} · ${{blocked:'차단',allowed:'허용',unknown:'불명'}[row.action]||'불명'}`);outcome.append(node('div',row.status?`HTTP ${row.status}`:'응답 미기록'));
      const reason=node('td','');const excluded=excludedIds.has(row.id);
      reason.append(node('span',excluded?'노이즈 제외':readyIds.has(row.id)?'검증 가능':'정보 보완',`triage-badge ${excluded?'muted':'active'}`));
      reason.append(node('div',excluded?row.screening.explanation:row.queue_reason||row.screening?.explanation||row.assessment?.next_action||'요청 응답과 재현 여부를 확인하세요.'));
      const latest=row.items.find(e=>e.latest_verification)?.latest_verification;
      if(latest)reason.append(node('small',`최근 검증: ${latest.statuses.map(c=>c||'무응답').join(', ')}`));
      line.append(pick,target,attack,outcome,reason,node('td',String(row.items.length)));body.append(line);
    }
    table.append(body);const wrap=node('div','','triage-table-wrap');wrap.append(table);el('triageResults').append(wrap);
    if(!rows.length)el('triageResults').append(node('p',['ready','recommended'].includes(mode)?'현재 조건의 검증 후보가 없습니다. 차단 기록은 자동 선택하지 않습니다. 전체 기록 또는 정보 보완 목록을 확인하세요.':'이 분류에 해당하는 이벤트가 없습니다.','triage-empty-row'));
    if(rows.length>50){const pager=node('div','','triage-actions');for(const [label,delta] of [['이전',-1],['다음',1]]){const b=node('button',label,'btn btn-secondary');b.disabled=listPage+delta<0||(listPage+delta)*50>=rows.length;b.onclick=()=>{listPage+=delta;render();};pager.append(b);}pager.append(node('span',`${listPage+1} / ${Math.ceil(rows.length/50)} 페이지 · 묶음 ${rows.length}개`));el('triageResults').append(pager);}
    for(const [key,title] of [['unsupported','HTTP 요청 없는 로그'],['errors','파싱 실패']])if(result[key]?.length){const d=node('details','');d.append(node('summary',`${title} ${result[key].length}건`));d.ontoggle=()=>{if(d.open&&d.children.length===1)d.append(node('pre',JSON.stringify(result[key],null,2)));};el('triageResults').append(d);}
  }
  function updateSelection(){
    const q=currentQueue();const transfer=TriageWorkflow.targets(q.ready,selected,origins);
    el('triageUrlList').value=transfer.urls.join('\n');
    el('triageSelectedCount').textContent=`URL ${transfer.urls.length}개`;
    el('triageQueueNote').textContent=transfer.urls.length?`선택 로그 ${transfer.links.length}건 → 중복 URL을 합친 ${transfer.urls.length}개 요청. 아래 목록이 그대로 복사·전달됩니다.`:'현재 선택된 검증 URL이 없습니다. 노이즈 제외 결과와 정보 보완 목록을 확인하세요.';
    for(const id of ['triageSendBulk','triageCopyUrls'])el(id).disabled=busy||!transfer.urls.length||!!transfer.errors.length;
    return transfer;
  }
  function applyTechnology(origin,profile){
    technologyProfiles[origin]={...profile,checked_at:new Date().toISOString()};
    result.technology_profiles={...technologyProfiles};
    if(profile.error)return;
    for(const e of result.events.filter(item=>item.inventory?.origin===origin)){
      e.technologies=[...new Set([...(e.technologies||[]),...profile.technologies])];
      const match=TriageWorkflow.technologyMatch(e);
      if(match&&!['IPS_BLOCKED','SIMPLE_SCAN_4XX','ORIGIN_NOT_FOUND_SCAN'].includes(e.screening?.code)&&!e.reasons?.includes('MIXED_ALLOWED_BLOCKED')&&!e.reasons?.includes('IMPORTANT_ASSET')){
        e.screening={screened:false,code:'TECH_MATCH',explanation:`관측된 웹 기술과 요청 경로가 일치합니다: ${match}. 실제 취약 여부는 별도 확인이 필요합니다.`};
        // Technology evidence is shown without changing the operator's selection.
      }
    }
  }
  function isInternalHost(origin){
    try{const h=new URL(origin).hostname.toLowerCase();
      return h==='localhost'||/^(10\.|127\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(h)||/\.(local|internal|lan|corp|intra)$/.test(h);
    }catch{return false;}
  }
  async function probeTechnology(origin,asset,button){
    if(busy)return;
    if(!asset&&typeof confirm==='function'&&!confirm(`${origin} 에 GET / 요청 1회(헤더만)를 보냅니다.${isInternalHost(origin)?'\n내부망 주소로 보입니다 — 인가된 대상인지 확인하세요.':''}\n계속할까요?`))return;
    busy=true;if(button)button.disabled=true;el('triageStatus').textContent=`${origin} 기술 확인 중…`;
    try{
      const profile=await triageApi('/technology-probe',{origin});applyTechnology(origin,profile);
      render();el('triageStatus').textContent=`${origin} 기술 확인 완료 · HTTP ${profile.status}. 요청 1건.`;
    }catch(error){technologyProfiles[origin]={error:error.message,checked_at:new Date().toISOString()};render();el('triageStatus').textContent=error.message;}
    finally{busy=false;render();}
  }
  function renderTechnology(){
    const box=el('triageTechnology');box.replaceChildren(node('h2','대상 웹 기술 확인'));
    box.append(node('p','분석된 대상에 GET / 요청 1회(헤더만)로 기술을 확인합니다. 등록 자산은 분석 직후 자동 조사하고, 미등록 대상은 버튼으로 직접 확인합니다(실제 요청 1회 · 확인 후 전송). 리다이렉트·응답 본문·쿠키·인증정보는 보내지 않으며, 기술 지문이 없다고 해당 기술이 없다는 뜻은 아닙니다.'));
    const targets=new Map();   // origin → {origin, asset|null}
    for(const e of result.events){
      const origin=e.inventory?.origin||origins[TriageWorkflow.originKey(e)]||TriageWorkflow.inferredOrigin(e);
      if(!origin)continue;
      const prev=targets.get(origin);
      if(!prev||(!prev.asset&&e.inventory))targets.set(origin,{origin,asset:e.inventory||null});
    }
    if(!targets.size){box.append(node('p','조사할 접속 주소가 없습니다. 아래 "실제 접속 주소" 입력으로 대상을 지정하면 기술을 확인할 수 있습니다.'));return;}
    for(const {origin,asset} of targets.values()){
      const row=node('div','','triage-technology-row');
      const cached=technologyProfiles[origin];
      row.append(node('strong',origin),node('span',asset?`인벤토리 기술: ${asset.stack||'미기록'}${asset.stale?' (정보 오래됨)':''}`:'미등록 대상 · 수동 확인'));
      if(cached?.error)row.append(node('span',`확인 실패: ${cached.error}`));
      if(cached&&!cached.error)row.append(node('span',`응답 헤더 기술: ${cached.technologies.join(', ')||'식별되지 않음'} · HTTP ${cached.status}`));
      const button=node('button','웹 기술 확인','btn btn-secondary');button.disabled=busy;
      button.onclick=()=>probeTechnology(origin,asset,button);
      row.append(button);box.append(row);
    }
  }
  function renderOrigins(){
    el('triageOrigins').replaceChildren();
    const missing=new Map(result.events.filter(e=>e.method==='GET'&&!TriageWorkflow.inferredOrigin(e)).map(e=>[TriageWorkflow.originKey(e),e]));
    for(const [key,event] of missing){
      const title=event.host||event.destination||`대상 불명 (로그 ${event.line}번)`;
      const label=node('label',`${title} → 실제 접속 주소`);
      const input=node('input','');input.type='url';input.placeholder='https://example.com (프로토콜·포트 확인)';input.setAttribute('aria-label',`${title} 접속 주소`);
      input.onchange=()=>{origins[key]=input.value.trim();selectReady();render();};label.append(input);el('triageOrigins').append(label);
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
      button.onclick=()=>{selected.clear();for(const id of c.representative_ids)selected.add(id);el('triageScreenFilter').value='ready';render();el('triageHandoff').scrollIntoView({block:'start'});};card.append(button);
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
  function technologyStatistics(){
    const summary=TriageWorkflow.technologySummary(result.events,technologyProfiles);
    const card=node('article','','triage-stat-card triage-tech-stat');
    card.append(chartTitle('호스트 · DST 사용 기술',`대상 ${summary.targets}개 · 조사 완료 ${summary.checked}개 · 기술 식별 ${summary.identified}개 · 확인 실패 ${summary.failed}개 · 미조사 ${summary.targets-summary.checked-summary.failed}개`));
    if(summary.technologies.length){card.append(node('h4','실제 응답에서 식별된 기술별 대상 수'),countRows(summary.technologies,summary.checked));}
    const wrap=node('div','','triage-table-wrap');const table=node('table','','triage-tech-table');const head=node('tr','');
    for(const title of ['대상 호스트 / DST','등록 기술','조사 결과','확인 시각'])head.append(node('th',title));
    const thead=node('thead','');thead.append(head);table.append(thead);const tbody=node('tbody','');
    for(const r of summary.rows){
      const tr=node('tr','');const target=node('td','');target.append(node('strong',r.target),node('div',`Host: ${r.hosts.join(', ')||'미기록'}`),node('div',`DST: ${r.destinations.join(', ')||'미기록'} · 이벤트 ${r.records}건`));
      const inv=node('td',(r.inventory.join(', ')||'미등록')+(r.stale?' (갱신 필요)':''));
      const status=r.profile?(r.profile.error?`확인 실패: ${r.profile.error}`:`${r.profile.technologies?.join(', ')||'기술 식별되지 않음'} · HTTP ${r.profile.status}`):'미조사';
      tr.append(target,inv,node('td',status),node('td',r.profile?.checked_at?new Date(r.profile.checked_at).toLocaleString():'—'));tbody.append(tr);
    }
    table.append(tbody);wrap.append(table);card.append(wrap,node('p','등록 기술과 응답 헤더 관측은 별도 근거입니다. 기술 미식별은 미설치의 증거가 아니며, 현재 관측이 과거 이벤트 당시의 기술을 보증하지 않습니다. 여러 기술이 식별된 대상은 기술별 집계에 각각 포함됩니다.'));
    const jump=node('button','대상 웹 기술 조사하기','btn btn-secondary');jump.onclick=()=>{const section=el('triageTechnology');const details=section.closest('details');if(details)details.open=true;section.scrollIntoView({block:'start'});};card.append(jump);
    return card;
  }
  function statisticsPanel(){
    const s=result.statistics;const section=node('section','','triage-statistics');
    section.append(node('h2','발생 이벤트 통계'));
    if(!s){section.append(node('p','저장 당시 생성된 통계가 없습니다. 원문을 다시 분석하면 통계를 볼 수 있습니다.'));return section;}
    const grid=node('div','','triage-stat-grid');
    const names=node('article','','triage-stat-card');names.append(chartTitle('탐지명별 비율','evtname 우선 · 없으면 장비 탐지명 · 상위 10개와 기타'),donut(s.event_names,s.total));grid.append(names);
    const families=node('article','','triage-stat-card');families.append(chartTitle('이벤트 계열','정보 수집성 · 웹 · 애플리케이션 · 네트워크 · 기타'),countRows(s.families,s.total));grid.append(families);
    const targets=node('article','','triage-stat-card');targets.append(chartTitle('대상별 이벤트','HTTP Host 우선 · 없으면 DST · 상위 10개와 기타'),countRows(s.targets,s.total));grid.append(targets);
    const cve=node('article','','triage-stat-card');
    cve.append(chartTitle('CVE·제품군 공격 시도',`탐지명·요청 지문 기반 · CVE/제품 식별 ${s.cve_records||0}건 · 시도 식별이며 성공 판정 아님`));
    cve.append(node('h4','CVE별'),countRows(s.cves||[],s.cve_records||0));
    cve.append(node('h4','제품군별'));
    if((s.products||[]).length){
      for(const p of s.products){
        const detail=node('div','','triage-device-stat');detail.append(node('h5',`${p.name} · ${p.records}건 · 대상 ${p.targets}`));
        const actionItems=[['차단',p.actions.blocked||0],['허용',p.actions.allowed||0],['불명',p.actions.unknown||0]].map(([label,count])=>({label,count}));
        detail.append(countRows(actionItems,p.records));
        if(p.cves.length)detail.append(node('p','CVE: '+p.cves.join(', ')));
        cve.append(detail);
      }
    } else cve.append(node('p','탐지명·요청 지문에서 식별된 CVE/제품군이 없습니다.'));
    grid.append(cve);
    const devices=node('article','','triage-stat-card triage-devices-card');devices.append(chartTitle('장비별 처리와 응답','명시된 장비 종류별 로그 비율 · 응답 코드는 장비 기록값'));
    const deviceRow=node('div','','triage-device-row');
    for(const d of s.devices){
      const detail=node('div','','triage-device-stat');detail.append(node('h4',`${d.name} · ${d.records}건`));
      const actionItems=[['차단',d.actions.blocked||0],['허용',d.actions.allowed||0],['불명',d.actions.unknown||0]].map(([label,count])=>({label,count}));
      detail.append(node('p','장비 동작'),countRows(actionItems,d.records));
      if(d.name==='WAF'||d.name==='IDS'){
        detail.append(node('p','HTTP 응답 코드'),countRows(d.http_status,d.status_eligible));
        if(d.response_result.length)detail.append(node('p','장비 응답 판정'),countRows(d.response_result,d.response_result.reduce((sum,item)=>sum+item.count,0)));
      }
      deviceRow.append(detail);
    }
    devices.append(deviceRow);
    grid.append(devices,technologyStatistics());section.append(grid);
    const correlations=node('div','','triage-stat-correlations');correlations.append(node('h3','상관 분석 후보'));
    if(s.correlations.length)for(const c of s.correlations)correlations.append(node('p',`${c.label} · ${c.source||c.target}`));
    else correlations.append(node('p','현재 입력에서 여러 대상·출발지·공격 계열을 잇는 후보는 없습니다.'));
    section.append(correlations,node('p',s.note));
    return section;
  }
  function sectionHeading(number,title,description){const header=node('div','','triage-section-heading');const h=node('h2','');h.append(node('span',number),document.createTextNode(title));header.append(h);if(description)header.append(node('p',description));return header;}
  function renderAssessment(){
    const box=el('triageAssessment');box.replaceChildren();const o=TriageWorkflow.overview(result);
    const stats=node('section','','triage-section');stats.append(sectionHeading('01','이벤트 통계','로그 레코드 기준 · 장비 발생 횟수와 구분'));
    const metrics=node('div','','triage-metrics');
    for(const [title,value] of [['입력 로그',result.summary.records],['대상',new Set(result.events.map(e=>e.host||e.destination).filter(Boolean)).size],['차단 기록',o.blocked],['허용 · 불명',o.allowed+o.unknown]]){const m=node('div','');m.append(node('span',title),node('strong',String(value)));metrics.append(m);}stats.append(metrics);
    const grid=node('div','','triage-stat-grid');
    for(const [title,items] of [['주요 탐지',result.statistics?.event_names||[]],['대상별 이벤트',result.statistics?.targets||[]]]){const c=node('article','','triage-stat-card');c.append(node('h3',title),countRows(items.slice(0,5),result.events.length));grid.append(c);}stats.append(grid);
    const more=node('details','');more.append(node('summary','장비 · CVE · 사용 기술 상세 통계'));more.append(statisticsPanel());stats.append(more);box.append(stats);
    const scans=node('section','','triage-section');scans.append(sectionHeading('02','스캔 시도 요약','반복 탐색은 묶고, 차단 여부와 검증할 대상을 확인합니다.'));
    scans.append(node('p',o.conclusion,'triage-scan-conclusion'));
    const groups=result.attack_summary?.groups||[];
    if(groups.length){const list=node('div','','triage-scan-list');for(const g of groups.slice(0,5)){const row=node('div','','triage-scan-row');row.append(node('strong',g.host||'대상 불명'),node('span',g.title),node('small',`${g.record_count}건 · 출발지 ${g.source_count} · 경로 ${g.path_count}`),node('span',`차단 ${g.actions.blocked||0} / 허용 ${g.actions.allowed||0} / 불명 ${g.actions.unknown||0}`));list.append(row);}scans.append(list);if(groups.length>5)scans.append(node('small',`주요 5개 묶음 표시 · 전체 ${groups.length}개 묶음의 로그는 아래 목록에 포함됩니다.`));}
    const campaign=node('details','');campaign.append(node('summary','시간대별 대량 스캔 근거'),campaignPanel());scans.append(campaign);box.append(scans);
  }
  el('triageSelectReview').onclick=()=>{selectReady();el('triageScreenFilter').value='recommended';render();};
  el('triageSelectNone').onclick=()=>{selected.clear();render();};
  el('triageSendBulk').onclick=()=>{
    const transfer=updateSelection();
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
  el('triageProbeStop').onclick=()=>probeController?.abort();
  el('triageAnalyze').onclick=async()=>{
    if(busy)return; busy=true; el('triageAnalyze').disabled=true;
    el('triageExport').disabled=true;el('triageSave').disabled=true;analyzedText=null; result=null;render();
    el('triageStatus').textContent='로그 분석 중…';
    try {
      const text=el('triageInput').value;
      if(new TextEncoder().encode(text).length>2000000)throw new Error('입력은 2MB 이하로 제한됩니다.');
      const response=await fetch('/api/triage/analyze',{method:'POST',headers:{'Content-Type':'text/plain; charset=utf-8'},body:text});
      result=await _asJson(response,'로그 분석');analyzedText=text;el('triageSave').disabled=false; render(); el('triageExport').disabled=false;
      probeController=new AbortController();el('triageProbeStop').hidden=false;
      el('triageSave').disabled=true;
      const progress=await TriageWorkflow.probeTargets(result.events,
        origin=>triageApi('/technology-probe',{origin},probeController.signal),
        item=>{applyTechnology(item.origin,item.profile);render();el('triageStatus').textContent=`로그 분석 완료 · 웹 기술 조사 ${item.completed}/${item.total} · 실패 ${item.failed}`;},
        ()=>probeController.signal.aborted);
      result.technology_profiles={...technologyProfiles};
      el('triageStatus').textContent=`분석·기술 조사 ${progress.stopped?'중지':'완료'} · ${progress.completed}/${progress.total}개 처리 · 실패 ${progress.failed}개${progress.deferred?` · 자동 조사 한도 초과 ${progress.deferred}개는 개별 확인`:''}${!progress.total?' · 일치하는 등록 자산이 없어 자동 조사하지 않았습니다.':''}`;
      el('triageSave').disabled=false;
    } catch(e) {el('triageStatus').textContent=e.message;}
    finally {busy=false;probeController=null;el('triageProbeStop').hidden=true;el('triageAnalyze').disabled=false;if(result)render();}
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
      load.onclick=async()=>{if(busy)return;busy=true;try{result=await triageApi('/batches/'+b.id);analyzedText=null;el('triageSave').disabled=true;el('triageExport').disabled=false;render();el('triageStatus').textContent='저장 당시 분석 결과를 불러왔습니다. 현재 인벤토리와 다를 수 있습니다.';}catch(err){el('triageStatus').textContent=err.message;}finally{busy=false;render();}};
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

  for(const id of ['triageExcludeIps','triageExcludeScan'])el(id).onchange=()=>{selectReady();listPage=0;render();};
  el('triageCopyUrls').onclick=async()=>{const text=el('triageUrlList').value;if(!text)return;try{await navigator.clipboard.writeText(text);el('triageHandoffStatus').textContent='URL 목록을 복사했습니다. 일괄 테스트 대상 목록에 붙여넣으세요.';}catch{el('triageUrlList').focus();el('triageUrlList').select();el('triageHandoffStatus').textContent='목록을 선택했습니다. Ctrl+C로 복사하세요.'}};
  el('triageScreenFilter').onchange=()=>{listPage=0;render();};
  el('triageClear').onclick=()=>{if(busy)return;result=null;analyzedText=null;el('triageSave').disabled=true;el('triageInput').value='';el('triageFile').value='';el('triageStatus').textContent='';el('triageExport').disabled=true;render();};
  el('triageExport').onclick=()=>{
    if(!result)return;
    const url=URL.createObjectURL(new Blob([JSON.stringify(result,null,2)],{type:'application/json'}));
    const a=node('a','');a.href=url;a.download='event-analysis.json';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);
  };
})();
