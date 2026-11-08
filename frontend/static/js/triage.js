/* Session-only triage: untrusted log values are always rendered as text. */
(() => {
  const el = id => document.getElementById(id);
  // 입력 한도(바이트). 백엔드 TRIAGE_MAX_BYTES 기본값과 맞춘다. 백엔드가 최종 강제(413)하며 여기선 사전 안내용.
  const MAX_INPUT_BYTES = 20_000_000, MAX_INPUT_MB = Math.floor(MAX_INPUT_BYTES / 1_000_000);
  const SIZE_HINT = `CSV · LOG · TXT · JSON 계열 / 최대 ${MAX_INPUT_MB}MB`;
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
  function resolvedOrigins(){
    const resolved={...origins};
    for(const e of result?.events||[]){const key=TriageWorkflow.originKey(e);if(resolved[key]||(e.reasons||[]).some(r=>['HOST_CONFLICT','HOST_MISSING','PCAP_NOT_INSPECTED'].includes(r)))continue;
      const origin=eventOrigin(e);const profile=technologyProfiles[origin];if(profile&&!profile.error)resolved[key]=origin;
    }return resolved;
  }
  function currentQueue(){return TriageWorkflow.queue(result?.events||[],resolvedOrigins(),filters());}
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
      shownResult=result;listPage=0;el('triageHandoffStatus').textContent='';renderOrigins();selectReady();
      {const initial=currentQueue();el('triageScreenFilter').value=initial.ready.length?'recommended':initial.unresolved.length?'unresolved':'all';}
    }
    const q=currentQueue();const readyIds=new Set(q.ready.map(e=>e.id));
    for(const id of selected)if(!readyIds.has(id))selected.delete(id);
    renderAssessment();renderTechnology();
    el('triageIpsCount').textContent=result.events.filter(e=>TriageWorkflow.noiseKind(e)==='ips').length+'건';
    el('triageScanCount').textContent=result.events.filter(e=>TriageWorkflow.noiseKind(e)==='scan').length+'건';
    {const c=el('triageTechCount');if(c)c.textContent=result.events.filter(e=>TriageWorkflow.noiseKind(e)==='tech').length+'건';}
    for(const [title,n] of [['분석 로그',result.events.length],['제외된 요청',q.excluded.length],['테스트할 요청',q.ready.filter(e=>TriageWorkflow.recommended(e)).length],['주소·요청 정보 필요',q.unresolved.length]]){
      const item=node('div','');item.append(node('span',title),node('strong',`${n}건`));el('triageSummary').append(item);
    }
    updateSelection();
    const mode=el('triageScreenFilter').value;
    const subset=mode==='all'?result.events:mode==='recommended'?q.ready.filter(e=>TriageWorkflow.recommended(e)):(q[mode]||[]);
    const rows=TriageWorkflow.rows(subset);listPage=Math.min(listPage,Math.max(0,Math.ceil(rows.length/50)-1));
    const table=node('table','','triage-table');const head=node('thead','');const tr=node('tr','');
    for(const title of ['테스트','대상 · 요청','탐지 내용','장비 · 응답','선별 이유','로그'])tr.append(node('th',title));head.append(tr);table.append(head);
    const body=node('tbody','');
    const excludedIds=new Set(q.excluded.map(e=>e.id));
    for(const row of rows.slice(listPage*50,(listPage+1)*50)){
      const line=node('tr','');const pick=node('td','');const check=node('input','');check.type='checkbox';
      const eligible=row.items.filter(e=>readyIds.has(e.id));check.disabled=true;
      check.checked=eligible.length>0;
      check.setAttribute('aria-label',`${row.host||row.destination||'대상 불명'} ${row.path||''} 선택`);
      check.onchange=()=>{for(const e of eligible){if(check.checked)selected.add(e.id);else selected.delete(e.id);}updateSelection();};pick.append(check);
      const target=node('td','');target.append(node('strong',row.host||row.destination||'대상 불명'),node('div',row.path?`${row.method} ${row.path}`:'HTTP 요청 정보 없음','triage-path'));
      const detail=node('details','');detail.append(node('summary','원본 / 상세'));detail.ontoggle=()=>{if(detail.open&&detail.children.length===1)detail.append(node('pre',JSON.stringify(row.items,null,2)));};target.append(detail);
      const attack=node('td',row.event_name||row.signature||row.assessment?.title||row.category||'미분류');
      const outcome=node('td',`${row.device||'장비 불명'} · ${{blocked:'차단',allowed:'허용',unknown:'불명'}[row.action]||'불명'}`);outcome.append(node('div',row.status?`HTTP ${row.status}`:'응답 미기록'));
      const reason=node('td','');const excluded=excludedIds.has(row.id);
      reason.append(node('span',excluded?'테스트 제외':readyIds.has(row.id)?'테스트 가능':'정보 확인 필요',`triage-badge ${excluded?'muted':'active'}`));
      reason.append(node('div',excluded?(row.screening?.explanation||'IPS 차단 또는 단순 경로 탐색 4xx로 자동 제외'):row.queue_reason||row.screening?.explanation||row.assessment?.next_action||'요청 응답과 재현 여부를 확인하세요.'));
      const latest=row.items.find(e=>e.latest_verification)?.latest_verification;
      if(latest)reason.append(node('small',`최근 검증: ${latest.statuses.map(c=>c||'무응답').join(', ')}`));
      line.append(pick,target,attack,outcome,reason,node('td',String(row.items.length)));body.append(line);
    }
    table.append(body);const wrap=node('div','','triage-table-wrap');wrap.append(table);el('triageResults').append(wrap);
    if(!rows.length)el('triageResults').append(node('p',mode==='recommended'?'테스트할 URL이 없습니다. 제외 조건과 주소·요청 정보를 확인하세요.':'해당하는 로그가 없습니다.','triage-empty-row'));
    if(rows.length>50){const pager=node('div','','triage-actions');for(const [label,delta] of [['이전',-1],['다음',1]]){const b=node('button',label,'btn btn-secondary');b.disabled=listPage+delta<0||(listPage+delta)*50>=rows.length;b.onclick=()=>{listPage+=delta;render();};pager.append(b);}pager.append(node('span',`${listPage+1} / ${Math.ceil(rows.length/50)} 페이지 · 묶음 ${rows.length}개`));el('triageResults').append(pager);}
    for(const [key,title] of [['unsupported','HTTP 요청 없는 로그'],['errors','파싱 실패']])if(result[key]?.length){const d=node('details','');d.append(node('summary',`${title} ${result[key].length}건`));d.ontoggle=()=>{if(d.open&&d.children.length===1)d.append(node('pre',JSON.stringify(result[key],null,2)));};el('triageResults').append(d);}
  }
  function updateSelection(){
    const q=currentQueue();const transfer=TriageWorkflow.queueTransfer(q,resolvedOrigins());
    el('triageUrlList').value=transfer.urls.join('\n');
    el('triageSelectedCount').textContent=`URL ${transfer.urls.length}개`;
    el('triageQueueNote').textContent=transfer.urls.length?`테스트 가능 요청 ${transfer.links.length}건에서 같은 URL을 합쳤습니다. 주소·요청 정보가 필요한 로그 ${q.unresolved.length}건은 별도로 확인하세요.`:`테스트할 URL이 없습니다. 접속 주소 ${q.unresolved_counts.origin}건, 요청 경로 ${q.unresolved_counts.request}건, GET 이외 요청 ${q.unresolved_counts.method}건을 확인하세요.`;
    for(const id of ['triageSendBulk','triageCopyUrls'])el(id).disabled=busy||!transfer.urls.length||!!transfer.errors.length;
    return transfer;
  }
  function eventOrigin(e){return origins[TriageWorkflow.originKey(e)]||TriageWorkflow.investigationOrigin(e);}
  function applyTechnology(origin,profile){
    technologyProfiles[origin]={...profile,checked_at:new Date().toISOString()};
    result.technology_profiles={...technologyProfiles};
    if(profile.error)return;
    // 등록 자산뿐 아니라 (추론/입력)origin 이 일치하는 모든 이벤트에 관측 기술을 반영한다.
    // (이전엔 inventory.origin 만 봐서 미등록 호스트 수동 조사 결과가 반영되지 않았다.)
    const hard=['IPS_BLOCKED','SIMPLE_SCAN_4XX','ORIGIN_NOT_FOUND_SCAN','HTTP_404'];
    for(const e of result.events){
      if(eventOrigin(e)!==origin)continue;
      e.technologies=[...new Set([...(e.technologies||[]),...(profile.technologies||[])])];
      if(hard.includes(e.screening?.code)||e.reasons?.includes('MIXED_ALLOWED_BLOCKED')||e.reasons?.includes('IMPORTANT_ASSET'))continue;
      const match=TriageWorkflow.technologyMatch(e);
      const implied=TriageWorkflow.impliedTechnology(e);
      const known=(e.technologies||[]).map(t=>String(t).toLowerCase());
      if(match){
        e.screening={screened:false,code:'TECH_MATCH',explanation:`관측된 웹 기술과 요청 경로가 일치합니다: ${match}. 실제 취약 여부는 별도 확인이 필요합니다.`};
      }else if(implied){
        e.screening={screened:false,code:'TECH_UNCONFIRMED',explanation:`${implied} 대상 요청입니다. 응답 헤더만으로 해당 제품의 사용 여부를 확정할 수 없어 자산 기술 확인이 필요합니다.`};
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
    if(!asset&&typeof confirm==='function'&&!confirm(`${origin} 에 GET / 요청 1회(헤더 + 최대 128KiB 본문 로컬 분석)를 보냅니다.${isInternalHost(origin)?'\n내부망 주소로 보입니다 — 인가된 대상인지 확인하세요.':''}\n계속할까요?`))return;
    busy=true;if(button)button.disabled=true;el('triageStatus').textContent=`${origin} 기술 확인 중…`;
    try{
      const profile=await triageApi('/technology-probe',{origin});applyTechnology(origin,profile);
      render();el('triageStatus').textContent=`${origin} 기술 확인 완료 · HTTP ${profile.status}. 요청 1건.`;
    }catch(error){technologyProfiles[origin]={error:error.message,checked_at:new Date().toISOString()};render();el('triageStatus').textContent=error.message;}
    finally{busy=false;render();}
  }
  function renderTechnology(){
    const box=el('triageTechnology');box.replaceChildren(node('h2','대상 웹 기술 확인'));
    box.append(node('p','대상 홈페이지 응답으로 웹 기술을 확인합니다. 확인에 실패하면 실제 접속 주소를 입력해 다시 시도하세요. 기술이 표시되지 않아도 미사용으로 단정할 수 없습니다.'));
    const targets=new Map();   // origin → {origin, asset|null}
    for(const e of result.events){
      const origin=eventOrigin(e);
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
      if(cached&&!cached.error)row.append(node('span',`관측 기술: ${cached.technologies.join(', ')||'식별되지 않음'} · HTTP ${cached.status}`));
      if(cached&&!cached.error)row.append(node('small',`HTTP 요청 ${cached.requests||1}회 · WAF ${cached.waf||'미식별'} · 제품 버전·취약 여부는 별도 확인 필요`));
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
    panel.append(node('h2','대량 경로 탐색'));
    if(!scan){panel.append(node('p','최신 로그 분석을 실행하면 스캔 행위를 묶어 확인할 수 있습니다.'));return panel;}
    if(!scan.campaigns.length)panel.append(node('p','이 로그에서 대량 경로 탐색이 확인되지 않았습니다.'));
    for(const c of scan.campaigns){
      const card=node('article','','triage-assessment');
      card.append(node('h3',`${c.axis==='target'?'대상':'출발지'} ${c.entity} · ${c.signals.join(' / ')}`));
      card.append(node('p',`${c.window_label||'시간 불명'}${c.window_count>1?` (${c.window_count}개 15분 구간)`:''} · 로그 ${c.record_count} · 경로 ${c.path_count} · 출발지 ${c.source_count} · 자산 ${c.host_count}`));
      card.append(node('p',`차단 ${c.actions.blocked||0} / 허용 ${c.actions.allowed||0} / 불명 ${c.actions.unknown||0}`));
      card.append(node('p',c.response));
      const button=node('button',`요청 ${c.representative_ids.length}건 선택`,'btn btn-primary');button.disabled=!c.representative_ids.length;
      button.onclick=()=>{selected.clear();for(const id of c.representative_ids)selected.add(id);el('triageScreenFilter').value='recommended';render();el('triageHandoff').scrollIntoView({block:'start'});};card.append(button);
      const details=node('details','');details.append(node('summary','판단 기준과 한계'),node('p',c.ai_attribution+' · '+scan.limitations));card.append(details);panel.append(card);
    }
    if(scan.unknown_time_events)panel.append(node('p',`시각이 없어 묶지 못한 로그 ${scan.unknown_time_events}건`));
    return panel;
  }
  const chartColors=['#6366f1','#06b6d4','#f59e0b','#ef4444','#22c55e','#a855f7','#f97316','#64748b','#14b8a6','#eab308','#ec4899'];
  function chartTitle(title,description){const box=node('div','');box.append(node('h3',title),node('p',description));return box;}
  function countRows(items,total,onSelect){
    const list=node('div','','triage-stat-rows');
    for(const [index,item] of items.entries()){
      const row=node('div','','triage-stat-row'+(onSelect?' triage-stat-clickable':''));
      if(onSelect){row.setAttribute('role','button');row.tabIndex=0;row.title='클릭하면 해당 요청을 봅니다';row.onclick=()=>onSelect(item);row.onkeydown=e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();onSelect(item);}};}
      const percent=total?item.count/total*100:0;
      const label=node('span',item.label);if(!onSelect)label.title=item.label;
      const value=node('strong','');value.append(node('b',`${item.count.toLocaleString()}건`),node('small',`${percent.toFixed(1)}%`));row.append(label,value);
      const track=node('div','','triage-stat-track');const fill=node('div','','triage-stat-fill');fill.style.width=`${percent}%`;fill.style.background=({Block:'#e47777',Permit:'#24a89c',None:'#9b8ac4','HTTP 응답 미기록':'#99a3b3','처리 값 미기록':'#99a3b3'}[item.label]||'var(--accent)');track.append(fill);row.append(track);list.append(row);
    }
    if(!items.length)list.append(node('p','집계할 기록이 없습니다.'));
    return list;
  }
  function ringChart(items,total,onSelect,caption='분석 로그'){
    const wrap=node('div','','triage-ring-layout');const ring=node('div','','triage-ring');
    const svg=document.createElementNS('http://www.w3.org/2000/svg','svg');svg.setAttribute('viewBox','0 0 160 160');svg.setAttribute('aria-label',items.map(i=>`${i.label} ${i.count}건`).join(', ')||'데이터 없음');svg.setAttribute('role','img');
    function arc(color,part,offset){const c=document.createElementNS(svg.namespaceURI,'circle');for(const [key,val] of Object.entries({cx:80,cy:80,r:65,fill:'none',stroke:color,'stroke-width':17,pathLength:100,'stroke-dasharray':`${part} ${100-part}`,'stroke-dashoffset':-offset,transform:'rotate(-90 80 80)'}))c.setAttribute(key,String(val));svg.append(c);return c;}
    arc('var(--border)',100,0);let offset=0;const legend=node('div','','triage-ring-legend');
    for(const [index,item] of items.entries()){
      const part=total?item.count/total*100:0,color=item.color||chartColors[index%chartColors.length];
      if(part>0){const segment=arc(color,part,offset);const title=document.createElementNS(svg.namespaceURI,'title');title.textContent=`${item.label} ${item.count}건 · ${part.toFixed(1)}%`;segment.append(title);if(onSelect){segment.style.cursor='pointer';segment.onclick=()=>onSelect(item);}offset+=part;}
      const button=node(onSelect?'button':'div','','triage-legend-row');if(onSelect){button.type='button';button.onclick=()=>onSelect(item);}
      const dot=node('i','');dot.style.background=color;button.append(dot,node('span',item.label),node('strong',item.count.toLocaleString()),node('small',`${part.toFixed(1)}%`));legend.append(button);
    }
    const center=node('div','','triage-ring-center');center.append(node('strong',total.toLocaleString()),node('span',caption));ring.append(svg,center);wrap.append(ring,legend);return wrap;
  }
  function rankedList(items,total,onSelect){
    const list=node('div','','triage-ranked-list');for(const [index,item] of items.entries()){const button=node('button','','triage-ranked-row');button.type='button';button.onclick=()=>onSelect(item);const label=node('span',item.label,'triage-ranked-label');label.title=item.label;const value=node('span','','triage-ranked-value');value.append(node('strong',`${item.count}건`),node('small',`${total?(item.count/total*100).toFixed(1):'0.0'}%`));button.append(node('span',String(index+1).padStart(2,'0'),'triage-rank'),label,value);list.append(button);}if(!items.length)list.append(node('p','집계할 기록이 없습니다.'));return list;
  }
  function technologyStatistics(){
    const summary=TriageWorkflow.technologySummary(result.events,technologyProfiles);
    const card=node('article','','triage-stat-card triage-tech-stat');
    card.append(chartTitle('대상 웹 기술',`대상 ${summary.targets}개 · 확인 ${summary.checked}개 · 기술 식별 ${summary.identified}개 · 실패 ${summary.failed}개`));
    if(summary.technologies.length){card.append(node('h4','확인된 기술별 대상 수'),countRows(summary.technologies,summary.checked));}
    const wrap=node('div','','triage-table-wrap');const table=node('table','','triage-tech-table');const head=node('tr','');
    for(const title of ['대상','등록 기술','확인된 기술','확인 시각'])head.append(node('th',title));
    const thead=node('thead','');thead.append(head);table.append(thead);const tbody=node('tbody','');
    for(const r of summary.rows){
      const tr=node('tr','');const target=node('td','');target.append(node('strong',r.target),node('div',`Host: ${r.hosts.join(', ')||'미기록'}`),node('div',`DST: ${r.destinations.join(', ')||'미기록'} · 이벤트 ${r.records}건`));
      const inv=node('td',(r.inventory.join(', ')||'미등록')+(r.stale?' (갱신 필요)':''));
      const status=r.profile?(r.profile.error?`확인 실패: ${r.profile.error}`:`${r.profile.technologies?.join(', ')||'기술 식별되지 않음'} · HTTP ${r.profile.status}`):'미조사';
      tr.append(target,inv,node('td',status),node('td',r.profile?.checked_at?new Date(r.profile.checked_at).toLocaleString():'—'));tbody.append(tr);
    }
    table.append(tbody);wrap.append(table);card.append(wrap,node('p','기술 미식별은 미사용을 뜻하지 않습니다. 현재 확인된 기술은 로그 발생 당시와 다를 수 있습니다.'));
    const jump=node('button','웹 기술 다시 확인','btn btn-secondary');jump.onclick=()=>{const section=el('triageTechnology');const details=section.closest('details');if(details)details.open=true;section.scrollIntoView({block:'start'});};card.append(jump);
    return card;
  }
  function statisticsPanel(){
    const s=result.statistics;const section=node('section','','triage-statistics');

    if(!s){section.append(node('p','저장 당시 생성된 통계가 없습니다. 원문을 다시 분석하면 통계를 볼 수 있습니다.'));return section;}
    const grid=node('div','','triage-stat-grid');
    const inspector=node('dialog','','triage-stat-inspector triage-detail-dialog');
    inspector.setAttribute('aria-label','이벤트 상세 검토');
    inspector.addEventListener('click',event=>{if(event.target!==inspector)return;const bounds=inspector.getBoundingClientRect();if(event.clientX<bounds.left||event.clientX>bounds.right||event.clientY<bounds.top||event.clientY>bounds.bottom)inspector.close();});
    const detectionName=e=>{const name=(e.event_name||'').trim();const m=name.match(/^multiple\s+signatures\s+from\s+(\S+)/i);return m?`다수 시그니처(장비 집계) · 출발지 ${m[1]}`:name||'탐지명 없음';};
    function inspect(title,events){
      inspector.replaceChildren();inspector.scrollTop=0;
      const heading=node('div','','triage-inspector-heading');heading.append(node('h3',`${title} · ${events.length}건`));const close=node('button','닫기 ×','btn btn-secondary');close.onclick=()=>inspector.close();heading.append(close);inspector.append(heading);
      const counts=new Map();for(const e of events){const name=detectionName(e);counts.set(name,(counts.get(name)||0)+1);}
      const metrics=node('div','','triage-detail-metrics');
      for(const [label,value] of [['탐지 종류',counts.size],['차단',events.filter(e=>e.action==='blocked').length],['허용',events.filter(e=>e.action==='allowed').length],['처리 불명',events.filter(e=>e.action==='unknown').length]]){const item=node('div','');item.append(node('span',label),node('strong',String(value)));metrics.append(item);}inspector.append(metrics);
      const filter=node('label','탐지명 ','triage-detail-filter');const select=node('select','');select.setAttribute('aria-label','상세 탐지명 필터');const all=node('option',`전체 탐지명 (${counts.size}종)`);all.value='';select.append(all);
      for(const [name,count] of [...counts].sort((a,b)=>b[1]-a[1])){const option=node('option',`${name} (${count}건)`);option.value=name;select.append(option);}
      select.onchange=()=>showLogs(select.value||title,select.value?events.filter(e=>detectionName(e)===select.value):events);filter.append(select);inspector.append(filter);
      const tech=node('details','','triage-asset-details');tech.append(node('summary','대상 웹 기술'));
      const targets=new Map();for(const e of events){const key=eventOrigin(e)||e.host||e.destination||'대상 불명';if(!targets.has(key))targets.set(key,{event:e,products:new Set()});for(const product of e.products||[])targets.get(key).products.add(product);}
      for(const [target,item] of targets){const profile=technologyProfiles[eventOrigin(item.event)];const status=!profile?'미조사':profile.error?'조사 실패':profile.technologies?.length?'관측: '+profile.technologies.join(', '):'조사 완료 · 기술 미식별';const row=node('div','','triage-asset-line');row.append(node('strong',target),node('span','공격 대상 제품: '+([...item.products].join(', ')||'미식별')),node('span','자산 조사: '+status));tech.append(row);}
      const investigate=node('button','웹 기술 확인','btn btn-secondary');investigate.onclick=()=>{inspector.close();el('triageTechnologyDetails').open=true;el('triageTechnologyDetails').scrollIntoView({block:'start'});};tech.append(investigate);inspector.append(tech);
      showLogs(title,events);
      if(!inspector.open)inspector.showModal();
    }
    function showLogs(title,events){
      inspector.querySelector('.triage-inspector-logs')?.remove();
      const box=node('div','','triage-inspector-logs');
      const grouped=new Map();for(const e of events){const key=JSON.stringify([e.host||e.destination,e.method,e.path,detectionName(e),e.action_raw,e.status]);if(!grouped.has(key))grouped.set(key,{event:e,count:0,items:[]});grouped.get(key).count++;grouped.get(key).items.push(e);}
      const entries=[...grouped.values()];let page=0;
      const multiTarget=new Set(events.map(e=>e.host||e.destination||'대상 불명')).size>1;
      const toolbar=node('div','','triage-request-toolbar');
      toolbar.append(node('h4',`요청 ${entries.length}개`),node('span',`로그 ${events.length}건`));
      const search=node('input','');search.type='search';search.placeholder='경로·탐지명 검색';search.setAttribute('aria-label','요청 경로 또는 탐지명 검색');toolbar.append(search);
      const wrap=node('div','','triage-requests-wrap'),table=node('table','','triage-requests-table');
      table.setAttribute('aria-label',`${title} 요청 목록`);
      const head=node('thead',''),header=node('tr','');
      let sortKey=null,sortDirection=1;
      const sortHeaders=[],collator=new Intl.Collator('ko',{numeric:true,sensitivity:'base'});
      const sortValues={path:entry=>entry.event.path||null,name:entry=>detectionName(entry.event),
        action:entry=>({blocked:'차단',allowed:'허용',unknown:'불명'}[entry.event.action]||'불명'),
        status:entry=>entry.event.status??null,count:entry=>entry.count};
      for(const [label,key] of [['요청 경로','path'],['탐지명','name'],['처리','action'],['HTTP','status'],['건수','count'],['상세',null]]){
        const th=node('th','');th.scope='col';
        if(key){
          const button=node('button','','triage-column-sort'),arrow=node('span','↕');button.type='button';arrow.setAttribute('aria-hidden','true');button.append(document.createTextNode(label),arrow);
          button.onclick=()=>{sortDirection=sortKey===key?-sortDirection:1;sortKey=key;page=0;draw();};
          th.append(button);sortHeaders.push({th,button,arrow,key,label});
        }else th.textContent=label;
        header.append(th);
      }head.append(header);
      const body=node('tbody','');table.append(head,body);wrap.append(table);
      const pager=node('div','','triage-actions triage-request-pager');
      function draw(){body.replaceChildren();pager.replaceChildren();
        const query=search.value.trim().toLowerCase();
        const filtered=entries.filter(({event:e})=>!query||[e.path,detectionName(e),e.host,e.destination].some(v=>String(v||'').toLowerCase().includes(query)));
        if(sortKey)filtered.sort((a,b)=>{
          const left=sortValues[sortKey](a),right=sortValues[sortKey](b);
          // Keep missing values at the bottom in either direction.
          if(left===null||right===null)return left===right?0:left===null?1:-1;
          return sortDirection*(typeof left==='number'&&typeof right==='number'?left-right:collator.compare(String(left),String(right)));
        });
        for(const {th,button,arrow,key,label} of sortHeaders){
          const active=sortKey===key;
          th.setAttribute('aria-sort',active?(sortDirection===1?'ascending':'descending'):'none');
          arrow.textContent=active?(sortDirection===1?'↑':'↓'):'↕';
          button.setAttribute('aria-label',`${label} ${active&&sortDirection===1?'내림차순':'오름차순'} 정렬`);
        }
        for(const {event:e,count,items} of filtered.slice(page*15,(page+1)*15)){
          const row=node('tr',''),path=node('td','','triage-request-path');
          path.append(node('span',e.method||'—','triage-method'),node('code',e.path||'경로 없음'));
          if(multiTarget)path.append(node('small',e.host||e.destination||'대상 불명'));
          const action=node('td',''),label={blocked:'차단',allowed:'허용',unknown:'불명'}[e.action]||'불명';
          const badge=node('span',label,`triage-action-badge ${['blocked','allowed'].includes(e.action)?e.action:'unknown'}`);badge.title=e.action_raw||'장비 처리 값 없음';action.append(badge);
          const status=node('td',e.status?String(e.status):'—','triage-http-status');
          const expandCell=node('td',''),expand=node('button','보기','triage-request-expand');expand.type='button';expand.setAttribute('aria-expanded','false');expand.setAttribute('aria-label',`${e.path||'요청'} 상세 보기`);expandCell.append(expand);
          row.append(path,node('td',detectionName(e),'triage-request-name'),action,status,node('td',String(count),'triage-request-count'),expandCell);body.append(row);
          const detailRow=node('tr','','triage-request-expanded');detailRow.hidden=true;const detail=node('td','');detail.colSpan=6;detailRow.append(detail);body.append(detailRow);
          expand.onclick=()=>{
            const open=detailRow.hidden;detailRow.hidden=!open;expand.textContent=open?'접기':'보기';expand.setAttribute('aria-expanded',String(open));
            if(!open||detail.children.length)return;
            detail.append(node('code',`${e.method||'—'} ${e.host||e.destination||''}${e.path||''}`,'triage-full-request'));
            const evidence=[...new Set(items.flatMap(item=>[...(item.cve||[]),...(item.products||[])]))];if(evidence.length)detail.append(node('p',evidence.join(' · ')));
            const select=node('select','');select.setAttribute('aria-label','원본 로그 선택');
            for(const [index,item] of items.entries()){const option=node('option',`${item.line}행 · ${item.timestamp||'시각 없음'} · ${item.source||'출발지 없음'}`);option.value=String(index);select.append(option);}
            const raw=node('details','','triage-request-raw');raw.append(node('summary','원본 로그'));
            const pre=node('pre','');raw.append(pre);const update=()=>{pre.textContent=JSON.stringify(items[Number(select.value)||0],null,2);};select.onchange=update;raw.ontoggle=()=>{if(raw.open)update();};detail.append(select,raw);
          };
        }
        if(!filtered.length){const row=node('tr',''),cell=node('td','검색 결과가 없습니다.');cell.colSpan=6;row.append(cell);body.append(row);}
        pager.append(node('span',`${filtered.length}개 요청${filtered.length?` · ${page*15+1}–${Math.min((page+1)*15,filtered.length)} 표시`:''}`));
        if(filtered.length>15)for(const [text,delta] of [['이전',-1],['다음',1]]){const button=node('button',text,'btn btn-secondary');button.disabled=page+delta<0||(page+delta)*15>=filtered.length;button.onclick=()=>{page+=delta;draw();};pager.append(button);}
      }
      search.oninput=()=>{page=0;draw();};
      box.append(toolbar,wrap,pager);draw();inspector.insertBefore(box,inspector.querySelector('.triage-asset-details'));
    }
    function interactiveRows(items,onSelect){const rows=countRows(items,s.total);[...rows.children].forEach((row,i)=>{row.tabIndex=0;row.setAttribute('role','button');row.title=({'정보 수집성':'파일·경로 탐색 등 정보 수집 요청','웹 공격':'SQL 삽입·XSS·경로 탐색 등 일반 웹 공격','애플리케이션 공격':'제품·CVE 취약점 또는 코드 실행·인증 우회 공격','네트워크 공격':'포트 탐색·네트워크 공격','기타/미분류':'현재 규칙으로 계열을 결정하지 못한 로그'}[items[i].label]||items[i].label)+' · 클릭하여 상세 보기';row.classList.add('triage-stat-clickable');row.onclick=()=>onSelect(items[i]);row.onkeydown=e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();row.click();}};});return rows;}
    const counts=new Map();for(const e of result.events){const name=detectionName(e);counts.set(name,(counts.get(name)||0)+1);}const allNames=[...counts].map(([label,count])=>({label,count})).sort((a,b)=>b.count-a.count||a.label.localeCompare(b.label));
    const names=node('article','','triage-stat-card triage-names-card');names.append(chartTitle('많이 탐지된 이벤트','상위 5개'),rankedList(allNames.slice(0,5),s.total,item=>inspect(item.label,result.events.filter(e=>detectionName(e)===item.label))));
    if(allNames.length>5){const rest=allNames.slice(5);const labels=new Set(rest.map(x=>x.label));const more=node('button',`그 외 탐지명 ${rest.length}종 · ${rest.reduce((n,x)=>n+x.count,0)}건 보기`,'triage-stat-more');more.onclick=()=>inspect('그 외 탐지명',result.events.filter(e=>labels.has(detectionName(e))));names.append(more);}grid.append(names);
    const families=node('article','','triage-stat-card triage-family-card');families.append(chartTitle('이벤트 유형','유형을 선택하면 관련 로그를 볼 수 있습니다.'),ringChart(s.families,s.total,item=>inspect(item.label,result.events.filter(e=>e.family===item.label))));grid.prepend(families);grid.append(inspector);
    const supporting=node('div','','triage-stat-grid');
    const targetKey=e=>e.host||e.destination||'대상 불명';
    const targetsCard=node('article','','triage-stat-card triage-target-card');targetsCard.append(chartTitle('대상별 이벤트','대상을 선택하면 관련 로그를 볼 수 있습니다.'));
    const targetMap=new Map();for(const e of result.events){const key=targetKey(e);if(!targetMap.has(key))targetMap.set(key,[]);targetMap.get(key).push(e);}
    const targetLegend=node('div','','triage-mini-legend');for(const [label,color] of [['차단','#4e7cbd'],['허용','#dc8451'],['불명','#a5afbd']]){const item=node('span',label);item.style.setProperty('--dot',color);targetLegend.append(item);}targetsCard.append(targetLegend);
    const targetList=node('div','','triage-target-list');const table=node('table','','triage-target-table');const thead=node('thead','');const header=node('tr','');for(const label of ['대상','로그','처리 분포','탐지'])header.append(node('th',label));thead.append(header);table.append(thead);const tbody=node('tbody','');
    for(const [target,events] of [...targetMap].sort((a,b)=>b[1].length-a[1].length)){
      const row=node('tr','');const first=node('td','');const button=node('button',target,'triage-target-link');button.onclick=()=>inspect(target,events);first.append(button);
      const distribution=node('td','');const bar=node('div','','triage-stacked-bar');const counts=['blocked','allowed','unknown'].map(action=>events.filter(e=>e.action===action).length);bar.setAttribute('role','img');bar.setAttribute('aria-label',`차단 ${counts[0]} · 허용 ${counts[1]} · 불명 ${counts[2]}`);bar.title=bar.getAttribute('aria-label');counts.forEach((count,index)=>{if(!count)return;const part=node('span','');part.style.width=`${count/events.length*100}%`;part.style.background=['#4e7cbd','#dc8451','#a5afbd'][index];bar.append(part);});distribution.append(bar,node('small',counts.join(' / ')));
      row.append(first,node('td',String(events.length)),distribution,node('td',`${new Set(events.map(detectionName)).size}종`));tbody.append(row);
    }table.append(tbody);targetList.append(table);targetsCard.append(targetList);grid.append(targetsCard);
    const cve=node('article','','triage-stat-card triage-product-card');cve.append(chartTitle('공격 대상 제품 유형','요청에 나타난 제품명 기준'));
    const productTypes={
      '네트워크 · 보안 장비':['citrix','fortios','pan-os','ivanti','f5-bigip','cisco-asa','cisco-ios-xe','checkpoint','sonicwall','d-link'],
      '장비 · 카메라':['hikvision','hpe-ilo','linear-emerge','magicinfo'],
      '웹 프레임워크':['struts','spring','laravel','react','telerik'],
      '웹 · 애플리케이션 서버':['apache-httpd','nginx','tomcat','weblogic','jboss','coldfusion','wso2'],
      '업무 서비스 · CMS':['exchange','confluence','wordpress','drupal','phpmyadmin','jenkins','papercut','goanywhere','crushftp','centrestack','mylittleadmin','whatsup-gold','solarwinds-whd','sysaid','sharepoint','zimbra','dotcms','vbulletin','subsonic','screenconnect','forticlient-ems','simplehelp','teamcity','aspera-faspex'],
      '라이브러리 · 시스템 구성요소':['log4j','bash']
    };
    const productType=product=>Object.keys(productTypes).find(type=>productTypes[type].includes(product))||'제품 유형 확인 필요';
    const productGroups=new Map();
    for(const e of result.events){const products=e.products?.length?e.products:(e.cve?.length?['제품 미식별']:[]);for(const product of new Set(products)){if(!productGroups.has(product))productGroups.set(product,[]);productGroups.get(product).push(e);}}
    const typeGroups=new Map();for(const [product,events] of productGroups){const type=productType(product);if(!typeGroups.has(type))typeGroups.set(type,[]);typeGroups.get(type).push({product,events});}
    function openProduct(type,product,events){
      inspect(`${type} / ${product}`,events);
      const chips=node('div','','triage-cve-chips');
      for(const id of [...new Set(events.flatMap(e=>e.cve||[]))]){const related=events.filter(e=>(e.cve||[]).includes(id));const chip=node('button',`${id} · ${related.length}건`,'triage-cve-chip');chip.onclick=()=>{showLogs(`${product} / ${id}`,related);for(const item of chips.children)item.setAttribute('aria-pressed',String(item===chip));};chips.append(chip);}
      if(!chips.children.length)chips.append(node('small','CVE 번호 미식별 · 제품 대상 탐색'));
      inspector.insertBefore(chips,inspector.children[2]||null);
    }
    function openType(type,groups){
      const events=[...new Set(groups.flatMap(g=>g.events))];inspect(type,events);
      const products=node('div','','triage-product-popup');products.append(node('h4','제품별 스캔 · 클릭하여 CVE 확인'));
      const items=groups.map(g=>({label:g.product,count:g.events.length})).sort((a,b)=>b.count-a.count);
      products.append(interactiveRows(items,item=>{const group=groups.find(g=>g.product===item.label);openProduct(type,group.product,group.events);}));
      inspector.insertBefore(products,inspector.children[2]||null);
    }
    const typeItems=[...typeGroups].map(([label,groups])=>({label,count:new Set(groups.flatMap(g=>g.events)).size})).sort((a,b)=>b.count-a.count);
    const tiles=node('div','','triage-product-tiles');for(const [index,item] of typeItems.entries()){const button=node('button','','triage-product-tile');button.style.setProperty('--tile-color',chartColors[index%chartColors.length]);button.append(node('span',item.label),node('strong',`${item.count}건`),node('small',`${typeGroups.get(item.label).length}개 제품군  →`));button.onclick=()=>openType(item.label,typeGroups.get(item.label));tiles.append(button);}cve.append(tiles);
    cve.append(node('p','한 로그에 여러 제품이 있으면 중복 집계합니다.'));
    if(!productGroups.size)cve.append(node('p','제품 또는 CVE가 식별된 기록이 없습니다.'));grid.append(cve,inspector);
    const devices=node('article','','triage-stat-card triage-devices-card');devices.append(chartTitle('장비별 차단·허용과 HTTP 응답','로그에 기록된 값 기준'));
    const deviceRow=node('div','','triage-device-row');
    for(const d of s.devices){
      const detail=node('div','','triage-device-stat');detail.append(node('h4',`${d.name} · ${d.records}건`));
      // 다른 통계 요소처럼 각 수치를 클릭하면 해당 요청을 인스펙터로 연다. 라벨→이벤트 매핑은
      // 통계 집계와 동일한 규칙(원 처리 값·상태 코드·응답 판정)을 사용한다.
      const deviceEvents=result.events.filter(e=>(e.device||'미확인')===d.name);
      const rawLabel=e=>{const r=String(e.action_raw||'').trim();return ({block:'Block',permit:'Permit',none:'None'}[r.toLowerCase()]||r)||'처리 값 미기록';};
      const statusLabel=e=>e.status!=null?String(e.status):'HTTP 응답 미기록';
      const byLabel=(rows,fn,item)=>{const shown=new Set(rows.filter(x=>x.label!=='기타').map(x=>x.label));return item.label==='기타'?deviceEvents.filter(e=>!shown.has(fn(e))):deviceEvents.filter(e=>fn(e)===item.label);};
      const actionItems=[['차단',d.actions.blocked||0],['허용',d.actions.allowed||0],['불명',d.actions.unknown||0]].map(([label,count])=>({label,count}));
      const actMap={'차단':'blocked','허용':'allowed','불명':'unknown'};
      if(d.name!=='IDS'||d.action_values?.some(item=>item.label!=='처리 값 미기록')){
        const rows=d.action_values||actionItems,usingRaw=!!d.action_values;
        detail.append(node('p','장비 처리 값'),countRows(rows,d.records,item=>inspect(`${d.name} · ${item.label}`,usingRaw?byLabel(rows,rawLabel,item):deviceEvents.filter(e=>(e.action||'unknown')===actMap[item.label]))));
      }
      if(d.name==='WAF')detail.append(node('p','None은 로그의 원래 처리 값이며 허용으로 단정하지 않습니다.'));
      if(d.name==='WAF'||d.name==='IDS'){
        detail.append(node('p','HTTP 응답 코드'),countRows(d.http_status,d.status_eligible,item=>inspect(`${d.name} · HTTP ${item.label}`,byLabel(d.http_status,statusLabel,item))));
        if(d.response_result.length){const shownRes=new Set(d.response_result.filter(x=>x.label!=='기타').map(x=>x.label));detail.append(node('p','장비 응답 판정'),countRows(d.response_result,d.response_result.reduce((sum,item)=>sum+item.count,0),item=>inspect(`${d.name} · ${item.label}`,deviceEvents.filter(e=>e.response_result&&(item.label==='기타'?!shownRes.has(String(e.response_result)):String(e.response_result)===item.label)))));}
      }
      deviceRow.append(detail);
    }
    devices.append(deviceRow);
    supporting.append(devices,technologyStatistics());section.append(grid);
    const extra=node('details','','triage-supporting');extra.append(node('summary','장비·웹 기술 상세'),supporting);section.append(extra);
    const correlations=node('div','','triage-stat-correlations');correlations.append(node('h3','함께 나타난 패턴'));
    if(s.correlations.length)for(const c of s.correlations)correlations.append(node('p',`${c.label} · ${c.source||c.target}`));
    else correlations.append(node('p','여러 대상·출발지·공격 유형을 잇는 패턴이 없습니다.'));
    extra.append(correlations,node('p',s.note));
    return section;
  }
  function sectionHeading(number,title,description){const header=node('div','','triage-section-heading');const h=node('h2','');h.append(node('span',number),document.createTextNode(title));header.append(h);if(description)header.append(node('p',description));return header;}
  const RULE_LABELS={scan_response:'탐색 중 응답 차이',mixed_action:'차단·허용 혼재',scan_to_attack:'탐색→공격 전환',attack_errors:'공격 요청 5XX',sensitive_probe:'민감 경로 탐색',distributed_scan:'분산 경로 탐색',multi_target_scan:'다중 대상 탐색'};
  function anomaliesPanel(){
    const panel=node('section','','triage-section triage-anomalies');
    const analysis=result.anomaly_analysis;
    panel.append(sectionHeading('분석','이상 징후','관련 로그를 묶어 확인할 부분을 찾았습니다.'));
    if(!analysis){panel.append(node('p','이 기록에는 이상 징후 결과가 없습니다. 원본 로그를 다시 분석하세요.'));return panel;}
    const findings=analysis.findings||[], coverage=analysis.coverage;
    const events=new Map(result.events.map(e=>[e.id,e]));
    const anomDetection=e=>{const name=(e.event_name||'').trim();const m=name.match(/^multiple\s+signatures\s+from\s+(\S+)/i);return m?`다수 시그니처(장비 집계) · 출발지 ${m[1]}`:name||'탐지명 없음';};
    const actsOf=f=>{const a={blocked:0,allowed:0,unknown:0};for(const id of f.event_ids){const e=events.get(id);if(e)a[e.action]=(a[e.action]||0)+1;}return a;};
    // 클릭 시 요약을 띄우는 공용 팝업 — 통계 인스펙터(.triage-detail-dialog)와 같은 셸 재사용.
    const inspector=node('dialog','','triage-anomaly-inspector triage-detail-dialog');inspector.setAttribute('aria-label','이상 징후 상세');
    inspector.addEventListener('click',event=>{if(event.target!==inspector)return;const b=inspector.getBoundingClientRect();if(event.clientX<b.left||event.clientX>b.right||event.clientY<b.top||event.clientY>b.bottom)inspector.close();});
    function findingLogs(title,ids){
      const box=node('div','','triage-inspector-logs');box.append(node('h4','근거 로그'),node('p',title,'triage-active-filter'));
      const list=[];for(const id of ids){const e=events.get(id);if(e)list.push(e);}
      const grouped=new Map();for(const e of list){const key=JSON.stringify([e.host||e.destination,e.method,e.path,anomDetection(e),e.action_raw,e.status]);if(!grouped.has(key))grouped.set(key,{event:e,count:0});grouped.get(key).count++;}
      const entries=[...grouped.values()];let page=0;const cards=node('div','','triage-request-cards'),pager=node('div','','triage-actions');
      function draw(){cards.replaceChildren();pager.replaceChildren();
        for(const {event:e,count} of entries.slice(page*15,(page+1)*15)){
          const card=node('details','','triage-request-card'),summary=node('summary','','triage-request-summary'),top=node('div','','triage-request-heading');
          top.append(node('strong',e.host||e.destination||'대상 불명'),node('span',`${count}건 · ${e.action_raw||'처리 미기록'} · ${e.status?'HTTP '+e.status:'HTTP 미기록'}`,'triage-response-label'));
          summary.append(top,node('div',anomDetection(e),'triage-request-detection'),node('div',`${e.method||'메서드 불명'} ${e.path||'경로 미기록'}`,'triage-request-preview'));
          card.append(summary,node('code',`${e.method||'메서드 불명'} ${e.path||'경로 미기록'} · ${e.timestamp||'시각 미기록'} · 출발지 ${e.source||'불명'} · ${e.device||'장비 불명'} · 원본 ${e.line}행`));
          const evidence=[...(e.cve||[]),...(e.products||[])];if(evidence.length)card.append(node('small',evidence.join(' · ')));cards.append(card);
        }
        if(entries.length>15){for(const [text,delta] of [['이전',-1],['다음',1]]){const b=node('button',text,'btn btn-secondary');b.disabled=page+delta<0||(page+delta)*15>=entries.length;b.onclick=()=>{page+=delta;draw();};pager.append(b);}pager.append(node('span',`${page+1} / ${Math.ceil(entries.length/15)} 페이지`));}
      }
      box.append(node('p',`로그 ${list.length}건 · 중복을 합친 요청 ${entries.length}개`),cards,pager);draw();return box;
    }
    function openFinding(f){
      inspector.replaceChildren();inspector.scrollTop=0;
      const heading=node('div','','triage-inspector-heading'),titleWrap=node('div','');
      titleWrap.append(node('span',f.priority==='high'?'우선 확인':'확인 필요',`triage-badge ${f.priority==='high'?'active':'muted'}`),node('h3',f.title));
      const close=node('button','닫기 ×','btn btn-secondary');close.onclick=()=>inspector.close();heading.append(titleWrap,close);inspector.append(heading);
      const acts=actsOf(f),metrics=node('div','','triage-detail-metrics');
      for(const [label,value] of [['관련 로그',f.event_ids.length],['차단',acts.blocked||0],['허용',acts.allowed||0],['테스트 후보',f.candidate_ids.length]]){const item=node('div','');item.append(node('span',label),node('strong',String(value)));metrics.append(item);}inspector.append(metrics);
      const q=TriageWorkflow.findingQueue(result.events,f,resolvedOrigins(),filters()),transfer=TriageWorkflow.queueTransfer(q,resolvedOrigins());
      const summary=node('div','','triage-finding-summary');
      for(const [label,text] of [['관측 내용',f.evidence],['가능한 영향',f.impact],['확인할 사항',f.next_action],['테스트 대상',`제외 ${q.excluded.length}건 · 주소·요청 정보 필요 ${q.unresolved.length}건 · 보낼 URL ${transfer.urls.length}개`],['대상 · 시각',`${f.targets.join(' · ')} · ${f.start} ~ ${f.end}`],['판단 범위',`${f.context} · ${f.outcome}`]]){const row=node('div','');row.append(node('span',label),node('p',text));summary.append(row);}inspector.append(summary);
      const send=node('button','이 요청으로 일괄 테스트 준비','btn btn-primary');send.disabled=busy||!transfer.urls.length||!!transfer.errors.length;
      send.onclick=()=>sendToBulk(TriageWorkflow.queueTransfer(TriageWorkflow.findingQueue(result.events,f,resolvedOrigins(),filters()),resolvedOrigins()));inspector.append(send);
      inspector.append(findingLogs(f.title,f.event_ids));
      if(!inspector.open)inspector.showModal();
    }
    function openGroup(title,group){
      inspector.replaceChildren();inspector.scrollTop=0;
      const heading=node('div','','triage-inspector-heading');heading.append(node('h3',`${title} · 이상 징후 ${group.length}개`));const close=node('button','닫기 ×','btn btn-secondary');close.onclick=()=>inspector.close();heading.append(close);inspector.append(heading);
      inspector.append(rankedList(group.map(f=>({label:f.title,count:f.event_ids.length,finding:f})),group.reduce((n,f)=>n+f.event_ids.length,0),item=>openFinding(item.finding)));
      if(!inspector.open)inspector.showModal();
    }
    const policy=()=>{const d=node('details','');d.append(node('summary','분석 범위와 판정 기준'),node('p','동일 15분 구간에서 404 경로 3개 이상과 200·206 응답의 혼재, 탐색 이후 공격 요청, 동일 경로의 차단·허용 혼재, 공격 요청 5XX 3건 이상, 민감 경로 탐색 3건 이상, 출발지 3개·경로 5개 이상의 집중 또는 대상 3개 이상의 탐색을 확인합니다. IPS 차단과 단순 스캔 4XX도 분석 근거에 포함하며, 테스트 전달에는 화면의 제외 필터를 적용합니다.'));return d;};
    panel.append(node('p',`이상 징후 ${findings.length}개 · 우선 확인 ${findings.filter(f=>f.priority==='high').length}개`));
    if(!findings.length){panel.append(node('p','이 로그에서 규칙에 해당하는 이상 징후가 발견되지 않았습니다. 안전 판정은 아닙니다.'),inspector,policy());return panel;}
    // 시각화: 규칙 유형 도넛 + 가장 많이 지목된 대상 Top5 (신호 2개 이상일 때)
    if(findings.length>1){
      const grid=node('div','','triage-stat-grid');
      const ruleGroups=new Map();for(const f of findings){if(!ruleGroups.has(f.rule))ruleGroups.set(f.rule,[]);ruleGroups.get(f.rule).push(f);}
      const ruleItems=[...ruleGroups].map(([rule,group])=>({label:RULE_LABELS[rule]||rule,count:group.length,group})).sort((a,b)=>b.count-a.count);
      const ruleCard=node('article','','triage-stat-card');ruleCard.append(chartTitle('이상 징후 유형','유형을 선택하면 관련 항목을 볼 수 있습니다.'));
      ruleCard.append(ruleGroups.size>1?ringChart(ruleItems,findings.length,item=>openGroup(item.label,item.group),'이상 징후'):countRows(ruleItems,findings.length));grid.append(ruleCard);
      const targetGroups=new Map();for(const f of findings)for(const t of f.targets){if(!targetGroups.has(t))targetGroups.set(t,[]);targetGroups.get(t).push(f);}
      const targetItems=[...targetGroups].map(([t,group])=>({label:t,count:group.length,group})).sort((a,b)=>b.count-a.count).slice(0,5);
      const targetCard=node('article','','triage-stat-card');targetCard.append(chartTitle('이상 징후가 많은 대상','상위 5개 · 대상을 선택하면 관련 항목을 볼 수 있습니다.'),rankedList(targetItems,findings.length,item=>openGroup(item.label,item.group)));grid.append(targetCard);
      panel.append(grid);
    }
    const details=node('details','','triage-anomaly-details');
    details.append(node('summary',`이상 징후 목록 보기 (${findings.length}개)`));
    if(coverage.missing_time||coverage.missing_target)details.append(node('p',`분석에 포함하지 못한 로그: 시각 없음 ${coverage.missing_time}건 · 대상 없음 ${coverage.missing_target}건`));
    // 신호 리스트 — 백엔드 정렬(우선순위 우선) 보존, 각 행 클릭 시 요약 팝업.
    const max=Math.max(1,...findings.map(f=>f.event_ids.length));let visible=0;
    const signals=node('div','','triage-anomaly-signals'),more=node('button','더 보기','btn btn-secondary');
    const appendPage=()=>{
      for(const f of findings.slice(visible,visible+10)){
        const row=node('button','',`triage-signal-row triage-stat-clickable ${f.priority}`);row.type='button';
        const head=node('div','','triage-signal-head');head.append(node('span',f.priority==='high'?'우선 확인':'확인 필요',`triage-badge ${f.priority==='high'?'active':'muted'}`),node('strong',f.title));
        const meta=node('div',`${f.targets.join(' · ')} · ${f.start} ~ ${f.end} · 로그 ${f.event_ids.length}건 · 테스트 후보 ${f.candidate_ids.length}건`,'triage-signal-meta');
        const acts=actsOf(f),total=f.event_ids.length||1,bar=node('div','','triage-stacked-bar');
        bar.setAttribute('role','img');bar.setAttribute('aria-label',`차단 ${acts.blocked||0} · 허용 ${acts.allowed||0} · 불명 ${acts.unknown||0}`);bar.title=bar.getAttribute('aria-label');
        for(const [k,c] of [['blocked','#4e7cbd'],['allowed','#dc8451'],['unknown','#a5afbd']]){const n=acts[k]||0;if(!n)continue;const part=node('span','');part.style.width=`${n/total*100}%`;part.style.background=c;bar.append(part);}
        const scale=node('div','','triage-stat-track'),fill=node('div','','triage-stat-fill');fill.style.width=`${f.event_ids.length/max*100}%`;fill.style.background=f.priority==='high'?'#c07935':'var(--accent)';scale.append(fill);
        row.append(head,meta,bar,scale);row.onclick=()=>openFinding(f);signals.append(row);
      }
      visible+=10;more.hidden=visible>=findings.length;
    };more.onclick=appendPage;details.append(signals,more,policy());appendPage();
    panel.append(details,inspector);return panel;
  }
  function renderAssessment(){
    const box=el('triageAssessment');box.replaceChildren();const events=result.events;const o=TriageWorkflow.overview(result);const q=currentQueue();
    const scans=node('section','','triage-section triage-overview');scans.append(sectionHeading('01','분석 요약','현재 입력 로그 기준'));
    const targetCounts=new Map(),productCounts=new Map();const sources=new Set();const cves=new Set();
    for(const e of events){const target=e.host||e.destination||'대상 불명';targetCounts.set(target,(targetCounts.get(target)||0)+1);if(e.source)sources.add(e.source);for(const p of new Set(e.products||[]))productCounts.set(p,(productCounts.get(p)||0)+1);for(const id of e.cve||[])cves.add(id);}
    const metrics=node('div','','triage-metrics');
    for(const [label,value] of [['분석 로그',events.length+'건'],['대상 / 출발지',targetCounts.size+' / '+sources.size],['테스트할 URL',q.unique_urls.length+'개'],['정보 확인 필요',q.unresolved.length+'건']]){const item=node('div','');item.append(node('span',label),node('strong',String(value)));metrics.append(item);}scans.append(metrics);
    const productAttempts=events.filter(e=>e.products?.length||e.cve?.length).length;
    const targets=new Map();for(const e of events){const origin=eventOrigin(e);const key=origin||e.host||e.destination||'대상 불명';targets.set(key,origin?technologyProfiles[origin]:null);}
    const profiles=[...targets.values()];const checked=profiles.filter(p=>p&&!p.error).length,failed=profiles.filter(p=>p?.error).length,identified=profiles.filter(p=>p&&!p.error&&p.technologies?.length).length;
    const campaigns=result.scan_analysis?.campaigns||[];
    const overview=node('div','','triage-summary-body');
    const headline=node('div','','triage-summary-headline');headline.append(node('span','이번 로그의 핵심','triage-kicker'),node('h3',productAttempts?`제품·CVE 관련 로그 ${productAttempts}건`:'제품·CVE 관련 로그 없음'),node('p',`제품 ${productCounts.size}종 · CVE ${cves.size}종 · 대량 탐색 ${campaigns.length}건`));
    const focal=node('div','','triage-focus-target');const first=[...targetCounts].sort((a,b)=>b[1]-a[1])[0];focal.append(node('span','가장 많이 탐지된 대상'),node('strong',first?first[0]:'대상 없음'),node('small',first?`${first[1]}건 · 전체의 ${(first[1]/events.length*100).toFixed(1)}%`:''));headline.append(focal);overview.append(headline);
    const pipeline=node('div','','triage-summary-pipeline');pipeline.append(node('h3','테스트 요청 분류'));
    for(const [label,value,color,description] of [
      ['제외된 요청',q.excluded.length,'neutral','IPS 차단 또는 단순 경로 탐색 4xx'],
      ['테스트 가능',q.ready.length,'ready','접속 주소와 GET 경로 확인'],
      ['정보 확인 필요',q.unresolved.length,'attention','접속 주소 또는 요청 내용 확인']]){
      const row=node('div','',`triage-pipeline-row ${color}`);const name=node('span','');name.append(node('strong',label),node('small',description));row.append(name,node('b',`${value}건`));pipeline.append(row);
    }
    if(q.unresolved.length){
      const details=[];for(const [label,count] of [['접속 주소·포트 미확인',q.unresolved_counts.origin],['HTTP 요청 경로 없음',q.unresolved_counts.request],['GET 이외 요청',q.unresolved_counts.method],['주소·경로 형식 확인',q.unresolved_counts.other]])if(count)details.push(`${label} ${count}건`);
      pipeline.append(node('p',details.join(' · '),'triage-pipeline-next'));
      if(q.unresolved_counts.origin&&events.some(e=>/\.test(?::\d+)?$/i.test(e.host||e.destination||'')))
        pipeline.append(node('small','이 입력에는 .test 예시 주소가 있습니다. 실제 서비스의 접속 주소를 입력해야 검증 URL을 만들 수 있습니다.'));
    }
    overview.append(pipeline);
    const tech=node('div','','triage-summary-tech');tech.append(node('h3','자산 기술 조사'));const ratio=targets.size?checked/targets.size*100:0;tech.append(node('strong',`${checked} / ${targets.size}`),node('span','대상 응답 확인'));
    const progress=node('div','','triage-tech-progress');const fill=node('span','');fill.style.width=ratio+'%';progress.append(fill);tech.append(progress,node('p',`기술 식별 ${identified} · 미식별 ${checked-identified}`),node('small',`실패 ${failed} · 미완료 ${targets.size-checked-failed}`));overview.append(tech);scans.append(overview);
    const actions=node('div','','triage-actions');
    for(const [label,id] of [['일괄 테스트 URL 보기','triageHandoff'],['정보가 필요한 로그 보기','triageFilterSection'],['웹 기술 조사 보기','triageTechnologyDetails']]){const button=node('button',label,'btn btn-secondary');button.onclick=()=>{if(id==='triageFilterSection'){el('triageScreenFilter').value='unresolved';render();}if(id==='triageTechnologyDetails')el(id).open=true;el(id).scrollIntoView({block:'start'});};actions.append(button);}scans.append(actions);
    const omitted=result.summary.excluded_detections||0;const errors=result.errors?.length||0;const unsupported=result.unsupported?.length||0;
    if(omitted||errors||unsupported)scans.append(node('small',`입력 ${result.summary.records}건 중 UDS 패턴 제외 ${omitted}건 · 파싱 실패 ${errors}건 · 지원하지 않는 로그 ${unsupported}건`));
    const campaign=node('details','');campaign.append(node('summary','대량 경로 탐색 보기'),campaignPanel());scans.append(campaign);box.append(scans);
    const stats=node('section','','triage-section');stats.append(sectionHeading('02','이벤트 통계',''),statisticsPanel());box.append(stats);
    box.append(anomaliesPanel());
  }
  el('triageSelectReview').onclick=()=>{selectReady();el('triageScreenFilter').value='recommended';render();};
  el('triageSelectNone').onclick=()=>{selected.clear();render();};
  function sendToBulk(transfer){
    if(transfer.errors.length){el('triageHandoffStatus').textContent=transfer.errors.join(' / ');return;}
    if(!transfer.urls.length)return;
    if(!state.payloads){el('triageHandoffStatus').textContent='일괄 테스트 구성을 불러오는 중입니다. 잠시 후 다시 시도하세요.';return;}
    switchView('bulk');switchModalTab('multi');switchMultiPayloadMode('custom');
    el('multiUrls').value=transfer.urls.join('\n');el('multiMethod').value='GET';el('multiCustomPayloads').value='';el('multiTargetParam').value='';el('multiInjectIn').value='params';el('multiConcurrency').value='1';
    window.triageBulkContext={events:transfer.links,urls:transfer.urls,created:new Date().toISOString()};
    let banner=el('triageBulkBanner');if(!banner){banner=node('section','','triage-assessment');banner.id='triageBulkBanner';el('mtab-multi').prepend(banner);}
    banner.replaceChildren(node('h3',`이벤트 분석에서 보낸 URL ${transfer.urls.length}개`),node('p','요청 헤더와 테스트 설정을 확인한 뒤 시작하세요.'));
    const back=node('button','이벤트 분석으로 돌아가기','btn btn-secondary');back.onclick=()=>switchView('triage');banner.append(back);
    banner.scrollIntoView({block:'start'});
  }
  el('triageSendBulk').onclick=()=>sendToBulk(updateSelection());

  async function loadLogFiles(files) {
    if(busy){el('triageStatus').textContent='현재 작업이 끝난 뒤 파일을 넣어주세요.';return;}
    if(!files?.length)return;
    if(files.length!==1){el('triageStatus').textContent='로그 파일은 한 번에 1개씩 넣어주세요.';return;}
    const file=files[0];
    if(file.size>MAX_INPUT_BYTES){el('triageStatus').textContent=`파일이 너무 큽니다. ${MAX_INPUT_MB}MB 이하 파일을 넣어주세요.`;return;}
    if(!/\.(csv|log|txt|json|jsonl|ndjson)$/i.test(file.name)){el('triageStatus').textContent='CSV, LOG, TXT, JSON, JSONL, NDJSON 파일을 넣어주세요.';return;}
    busy=true;el('triageAnalyze').disabled=true;el('triageFile').disabled=true;
    try {
      const text=await file.text();
      if(!text.trim())throw new Error('빈 파일입니다. 로그가 포함된 파일을 넣어주세요.');
      el('triageInput').value=text;el('triageFileHint').textContent=file.name+' · '+Math.max(1,Math.ceil(file.size/1024))+' KB';
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
      if(new TextEncoder().encode(text).length>MAX_INPUT_BYTES)throw new Error(`입력은 ${MAX_INPUT_MB}MB 이하로 제한됩니다.`);
      const response=await fetch('/api/triage/analyze',{method:'POST',headers:{'Content-Type':'text/plain; charset=utf-8'},body:text});
      result=await _asJson(response,'로그 분석');analyzedText=text;el('triageSave').disabled=false; render(); el('triageExport').disabled=false;
      probeController=new AbortController();el('triageProbeStop').hidden=false;
      el('triageSave').disabled=true;
      const progress=await TriageWorkflow.probeTargets(result.events,
        origin=>triageApi('/technology-probe',{origin},probeController.signal),
        item=>{applyTechnology(item.origin,item.profile);render();el('triageStatus').textContent=`로그 분석 완료 · 웹 기술 조사 ${item.completed}/${item.total} · 실패 ${item.failed}`;},
        ()=>probeController.signal.aborted,eventOrigin);
      result.technology_profiles={...technologyProfiles};
      el('triageStatus').textContent=`로그 분석 완료 · 웹 기술 확인 ${progress.completed}/${progress.total}개 · 실패 ${progress.failed}개${progress.stopped?' · 확인 중지':''}${progress.deferred?` · ${progress.deferred}개는 개별 확인 필요`:''}${!progress.total?' · 확인할 대상 주소 없음':''}`;
      el('triageSave').disabled=false;
    } catch(e) {el('triageStatus').textContent=e.message;}
    finally {busy=false;probeController=null;el('triageProbeStop').hidden=true;el('triageAnalyze').disabled=false;if(result)render();}
  };

  async function textPost(path,text) {
    if(new TextEncoder().encode(text).length>MAX_INPUT_BYTES)throw new Error(`입력은 ${MAX_INPUT_MB}MB 이하로 제한됩니다.`);
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
  el('triageCopyUrls').onclick=async()=>{const text=el('triageUrlList').value;if(!text)return;try{await navigator.clipboard.writeText(text);el('triageHandoffStatus').textContent='URL을 복사했습니다.';}catch{el('triageUrlList').focus();el('triageUrlList').select();el('triageHandoffStatus').textContent='URL을 선택했습니다. Ctrl+C로 복사하세요.'}};
  el('triageScreenFilter').onchange=()=>{listPage=0;render();};
  el('triageClear').onclick=()=>{if(busy)return;result=null;analyzedText=null;el('triageSave').disabled=true;el('triageInput').value='';el('triageFileHint').textContent=SIZE_HINT;el('triageFile').value='';el('triageStatus').textContent='';el('triageExport').disabled=true;render();};
  el('triageExport').onclick=()=>{
    if(!result)return;
    const url=URL.createObjectURL(new Blob([JSON.stringify(result,null,2)],{type:'application/json'}));
    const a=node('a','');a.href=url;a.download='event-analysis.json';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);
  };
})();
