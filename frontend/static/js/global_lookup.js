/* Server-paged global findings and traffic. Evidence bodies load only on disclosure. */
const globalLookupState={findings:{page:0,seq:0,assetId:''},traffic:{page:0,seq:0,assetId:''}};
const runTrafficState={runId:null,page:0,seq:0};
const trafficCompare={items:[],notice:''};
const trafficSourceLabels={browser:'브라우저',agent:'자율 검증',manual:'수동 요청',
  bulk:'일괄 테스트',raw:'원문 패킷',multi:'다중 대상'};

function trafficCompareKey(item) {return `${item.run_id||''}:${item.id}`;}
function clearTrafficComparison() {
  trafficCompare.items=[];trafficCompare.notice='';renderTrafficComparison();refreshTrafficCompareButtons();
}
function refreshTrafficCompareButtons() {
  for(const row of agentEl('globalTrafficRows').children) {
    for(const button of row.children[1]?.children||[]) {
      if(button.dataset?.compareKey)button.textContent=trafficCompare.items.some(
        item=>trafficCompareKey(item)===button.dataset.compareKey)?'비교 해제':'비교에 담기';
    }
  }
}
function renderTrafficComparison() {
  const panel=agentEl('globalTrafficCompare');panel.replaceChildren();
  panel.hidden=trafficCompare.items.length===0;
  if(panel.hidden)return;
  const head=uiNode('div','lookup-compare-head');
  head.append(uiNode('strong','',`트래픽 메타데이터 비교 · ${trafficCompare.items.length}/2건`));
  const clear=uiNode('button','aw-link','선택 지우기');clear.type='button';
  clear.onclick=clearTrafficComparison;
  head.append(clear);panel.append(head);
  if(trafficCompare.notice)panel.append(uiNode('p','aw-muted',trafficCompare.notice));
  if(trafficCompare.items.length<2) {
    panel.append(uiNode('p','aw-muted','비교할 기록 한 건을 더 선택하세요.'));return;
  }
  const [left,right]=trafficCompare.items;
  const fields=[['출처','source'],['메서드','method'],['도메인','origin'],
    ['경로','path'],['HTTP 상태','status'],['기록 시각','created']];
  const table=uiNode('table','');
  const header=uiNode('tr','');
  for(const label of ['항목','첫 기록','둘째 기록','비교'])header.append(uiNode('th','',label));
  table.append(header);
  for(const [label,key] of fields) {
    const first=key==='source'?(trafficSourceLabels[left.source]||left.source):
      key==='created'?new Date(left.created*1000).toLocaleString('ko-KR'):
      key==='status'?(left.status??'미관측'):left[key];
    const second=key==='source'?(trafficSourceLabels[right.source]||right.source):
      key==='created'?new Date(right.created*1000).toLocaleString('ko-KR'):
      key==='status'?(right.status??'미관측'):right[key];
    const row=uiNode('tr','');
    row.append(uiNode('th','',label),uiNode('td','',String(first)),uiNode('td','',String(second)));
    const difference=first!==second;
    const result=uiNode('td','',difference?'다름':'같음');result.dataset.different=String(difference);
    row.append(result);table.append(row);
  }
  panel.append(uiNode('p','lookup-scroll-hint','표를 가로로 스크롤해 두 기록과 비교 결과를 확인하세요.'));
  const scroller=uiNode('div','lookup-compare-table');scroller.append(table);panel.append(scroller);
}
function toggleTrafficComparison(item) {
  const key=trafficCompareKey(item);
  const index=trafficCompare.items.findIndex(entry=>trafficCompareKey(entry)===key);
  if(index>=0)trafficCompare.items.splice(index,1);
  else if(trafficCompare.items.length===2) {
    trafficCompare.notice='두 건까지 선택할 수 있습니다. 한 건을 해제한 뒤 선택하세요.';
    renderTrafficComparison();return;
  }
  else trafficCompare.items.push({id:item.id,run_id:item.run_id||'',created:item.created,
    source:item.source,method:item.method,origin:item.origin,path:item.path,status:item.status});
  trafficCompare.notice='';
  renderTrafficComparison();refreshTrafficCompareButtons();
}

function setGlobalLookupAssetFilter(kind,assetId) {
  if(!Object.hasOwn(globalLookupState,kind))return;
  const state=globalLookupState[kind];
  const next=/^[a-f0-9]{64}$/i.test(assetId||'')?assetId.toLowerCase():'';
  if(state.assetId!==next){state.assetId=next;state.page=0;if(kind==='traffic')clearTrafficComparison();}
}
function globalLookupRoute(kind) {
  const id=globalLookupState[kind]?.assetId;
  const base='#'+kind+(id?'/'+id:'');
  if(kind==='findings') {
    const query=new URLSearchParams();
    const verdict=agentEl('globalFindingVerdict').value;
    const status=agentEl('globalFindingStatus').value;
    if(['confirmed','suspicious','inconclusive'].includes(verdict))query.set('verdict',verdict);
    if(['open','triaged','resolved','false_positive','ignored'].includes(status))query.set('status',status);
    if(agentEl('globalFindingGroup').checked)query.set('group','1');
    if(agentEl('globalFindingArchived').checked)query.set('archived','1');
    return base+(query.size?'?'+query:'');
  }
  const query=new URLSearchParams();
  const source=agentEl('globalTrafficSource').value;
  const method=agentEl('globalTrafficMethod').value;
  const status=agentEl('globalTrafficStatus').value.trim();
  const from=agentEl('globalTrafficFrom').value;
  const through=agentEl('globalTrafficThrough').value;
  if(['agent','browser','manual','bulk','raw','multi'].includes(source))query.set('source',source);
  if(['GET','POST','PUT','PATCH','DELETE','HEAD','OPTIONS'].includes(method))query.set('method',method);
  if(/^[1-5][0-9]{2}$/.test(status)&&Number(status)<=599)query.set('status',status);
  if(/^\d{4}-\d{2}-\d{2}$/.test(from))query.set('from',from);
  if(/^\d{4}-\d{2}-\d{2}$/.test(through))query.set('through',through);
  if(agentEl('globalTrafficArchived').checked)query.set('archived','1');
  return base+(query.size?'?'+query:'');
}
function restoreTrafficFilters(rawQuery) {
  clearTrafficComparison();
  const query=new URLSearchParams(rawQuery||'');
  const allowed={Source:['','agent','browser','manual','bulk','raw','multi'],
    Method:['','GET','POST','PUT','PATCH','DELETE','HEAD','OPTIONS']};
  for(const [name,key] of [['Source','source'],['Method','method']]) {
    const value=query.get(key)||'';
    agentEl('globalTraffic'+name).value=allowed[name].includes(value)?value:'';
  }
  const status=query.get('status')||'';
  agentEl('globalTrafficStatus').value=/^[1-5][0-9]{2}$/.test(status)&&Number(status)<=599?status:'';
  for(const [name,key] of [['From','from'],['Through','through']]) {
    const value=query.get(key)||'';
    agentEl('globalTraffic'+name).value=/^\d{4}-\d{2}-\d{2}$/.test(value)?value:'';
  }
  agentEl('globalTrafficArchived').checked=query.get('archived')==='1';
  globalLookupState.traffic.page=0;
}
function restoreFindingFilters(rawQuery) {
  const query=new URLSearchParams(rawQuery||'');
  const verdict=query.get('verdict')||'',status=query.get('status')||'';
  agentEl('globalFindingVerdict').value=['confirmed','suspicious','inconclusive'].includes(verdict)?verdict:'';
  agentEl('globalFindingStatus').value=['open','triaged','resolved','false_positive','ignored'].includes(status)?status:'';
  agentEl('globalFindingGroup').checked=query.get('group')==='1';
  agentEl('globalFindingArchived').checked=query.get('archived')==='1';
  globalLookupState.findings.page=0;
}

function initGlobalLookup(kind) {
  const prefix=kind==='findings'?'globalFinding':'globalTraffic';
  const state=globalLookupState[kind];
  if(state.initialized)return;
  state.initialized=true;
  agentEl(prefix+'ClearAsset').onclick=()=>{setGlobalLookupAssetFilter(kind,'');switchView(kind);};
  let debounce;
  agentEl(prefix+'Search').oninput=()=>{
    if(kind==='traffic')clearTrafficComparison();
    clearTimeout(debounce);debounce=setTimeout(()=>{state.page=0;loadGlobalLookup(kind);},250);
  };
  const filters=kind==='findings'?['Verdict','Status','Group','Archived']:['Source','Method','Status','From','Through','Archived'];
  for(const name of filters)agentEl(prefix+name).onchange=()=>{
    state.page=0;
    if(kind==='traffic')clearTrafficComparison();
    if(typeof history!=='undefined'&&typeof location!=='undefined') {
      const route=globalLookupRoute(kind);
      if(location.hash!==route)history.pushState(null,'',route);
    }
    loadGlobalLookup(kind);
  };
  agentEl(prefix+'Prev').onclick=()=>{if(state.page>0){state.page--;loadGlobalLookup(kind);}};
  agentEl(prefix+'Next').onclick=()=>{state.page++;loadGlobalLookup(kind);};
}

async function openGlobalLookup(kind) {
  initGlobalLookup(kind);
  if(kind==='traffic')clearTrafficComparison();
  await loadGlobalLookup(kind);
}

function globalLookupRunButton(runId, label, mode) {
  const button=uiNode('button','aw-link',label);button.type='button';
  button.onclick=()=>{switchView('agent');selectRun(runId);setDetailMode(mode);};
  return button;
}

function globalLookupAssetButton(assetId) {
  if(!/^[a-f0-9]{64}$/i.test(assetId||''))return null;
  const button=uiNode('button','aw-link','자산 열기');button.type='button';
  button.onclick=()=>{setAssetFocus(assetId);switchView('assets');};
  return button;
}
function globalTrafficFindingButton(assetId) {
  if(!/^[a-f0-9]{64}$/i.test(assetId||''))return null;
  const button=uiNode('button','aw-link','같은 자산의 발견');button.type='button';
  button.onclick=()=>{
    agentEl('globalFindingSearch').value='';
    agentEl('globalFindingVerdict').value='';
    agentEl('globalFindingStatus').value='';
    agentEl('globalFindingGroup').checked=false;
    agentEl('globalFindingArchived').checked=agentEl('globalTrafficArchived').checked;
    setGlobalLookupAssetFilter('findings',assetId);
    switchView('findings');
  };
  return button;
}
function globalFindingTrafficButton(assetId) {
  if(!/^[a-f0-9]{64}$/i.test(assetId||''))return null;
  const button=uiNode('button','aw-link','같은 자산의 트래픽');button.type='button';
  button.onclick=()=>{
    agentEl('globalTrafficSearch').value='';
    for(const name of ['Source','Method','Status','From','Through'])agentEl('globalTraffic'+name).value='';
    agentEl('globalTrafficArchived').checked=agentEl('globalFindingArchived').checked;
    setGlobalLookupAssetFilter('traffic',assetId);
    switchView('traffic');
  };
  return button;
}

function globalLookupRow(kind,item) {
  const row=uiNode('article','lookup-row');
  const top=uiNode('div','lookup-row-top');
  top.append(uiNode('strong','',`${item.method} ${item.origin}${item.path}`));
  const badge=kind==='findings'
    ?`${{confirmed:'확증',suspicious:'의심',inconclusive:'미확정'}[item.verdict]||item.verdict} · ${item.category}`
    :`${trafficSourceLabels[item.source]||item.source} · HTTP ${item.status??'미관측'}`;
  top.append(uiNode('span','aw-muted',badge));row.append(top);
  const actions=uiNode('div','lookup-actions');
  actions.append(uiNode('time','aw-muted',new Date(item.created*1000).toLocaleString('ko-KR')));
  const assetButton=globalLookupAssetButton(item.asset_id);
  if(assetButton)actions.append(assetButton);
  if(kind==='traffic') {
    const findingButton=globalTrafficFindingButton(item.asset_id);
    if(findingButton)actions.append(findingButton);
    const compare=uiNode('button','aw-link',trafficCompare.items.some(
      entry=>trafficCompareKey(entry)===trafficCompareKey(item))?'비교 해제':'비교에 담기');
    compare.type='button';compare.dataset.compareKey=trafficCompareKey(item);
    compare.onclick=()=>toggleTrafficComparison(item);actions.append(compare);
  } else {
    const trafficButton=globalFindingTrafficButton(item.asset_id);
    if(trafficButton)actions.append(trafficButton);
  }
  if(item.run_id)actions.append(globalLookupRunButton(item.run_id,'작업 열기',kind==='findings'?'findings':'history'));
  if(kind==='traffic'&&item.run_id) {
    const detail=uiNode('details','lookup-evidence');
    detail.append(uiNode('summary','','요청·응답 보기'));
    detail.ontoggle=async()=>{
      if(!detail.open||detail.dataset.loaded)return;
      detail.dataset.loaded='loading';
      const body=uiNode('pre','lookup-body','불러오는 중…');detail.append(body);
      try {
        const event=await agentApi(`/history/runs/${encodeURIComponent(item.run_id)}/events/${encodeURIComponent(item.id)}`);
        body.textContent=JSON.stringify(event.data,null,2);
        detail.dataset.loaded='done';
      } catch(error) {body.textContent=error.message;detail.dataset.loaded='';}
    };
    actions.append(detail);
  } else if(kind==='findings') {
    actions.append(uiNode('span','aw-muted',`증거 ${item.evidence_count}개 · ${item.status}`));
  }
  row.append(actions);return row;
}

function globalFindingGroupRow(item,filters,pageSeq) {
  const row=uiNode('article','lookup-row');
  const top=uiNode('div','lookup-row-top');
  top.append(uiNode('strong','',`${item.method} ${item.origin}${item.path} · ${item.category}`),
    uiNode('span','aw-muted',`행위자 ${item.actor_id||'기본'} · 작업 ${item.run_count}개 · 확증 ${item.confirmed_count} · 의심 ${item.suspicious_count} · 미확정 ${item.inconclusive_count}`));
  row.append(top);
  const assetButton=globalLookupAssetButton(item.asset_id);
  if(assetButton)top.append(assetButton);
  const trafficButton=globalFindingTrafficButton(item.asset_id);
  if(trafficButton)top.append(trafficButton);
  const detail=uiNode('details','lookup-evidence');
  detail.append(uiNode('summary','','작업별 판정 보기'));
  const body=uiNode('div','lookup-rows'),footer=uiNode('div','lookup-actions');
  detail.append(body,footer);
  let offset=0,loading=false;
  async function nextPage() {
    if(loading)return;loading=true;
    const query=new URLSearchParams({asset_id:item.asset_id,category:item.category,
      actor_id:item.actor_id,input_shape_id:item.input_shape_id,
      verdict:filters.verdict,status:filters.status,
      archived:filters.archived,offset:String(offset),limit:'50'});
    footer.replaceChildren(uiNode('span','aw-muted','불러오는 중…'));
    try {
      const result=await agentApi(`/history/findings/groups/members?${query}`);
      if(pageSeq!==globalLookupState.findings.seq)return;
      for(const finding of result.items)body.append(globalLookupRow('findings',finding));
      offset+=result.items.length;
      footer.replaceChildren();
      if(result.has_more){const more=uiNode('button','aw-link','더 보기');more.type='button';more.onclick=nextPage;footer.append(more);}
    } catch(error) {if(pageSeq===globalLookupState.findings.seq)footer.replaceChildren(uiNode('span','aw-muted',error.message));}
    finally {loading=false;}
  }
  detail.ontoggle=()=>{if(detail.open&&offset===0&&!loading)return nextPage();};
  row.append(detail);return row;
}

async function loadGlobalLookup(kind) {
  const prefix=kind==='findings'?'globalFinding':'globalTraffic';
  const state=globalLookupState[kind],seq=++state.seq;
  const count=agentEl(prefix+'Count'),container=agentEl(prefix+'Rows');
  const assetFilter=agentEl(prefix+'AssetFilter');
  assetFilter.hidden=!state.assetId;
  agentEl(prefix+'AssetLabel').textContent=state.assetId?`선택 자산 ${state.assetId.slice(0,12)}…`:'';
  count.textContent='불러오는 중…';
  const query=new URLSearchParams({offset:String(state.page*50),limit:'50',
    search:agentEl(prefix+'Search').value,archived:agentEl(prefix+'Archived').checked?'true':'false'});
  if(state.assetId)query.set('asset_id',state.assetId);
  if(kind==='findings') {
    query.set('verdict',agentEl(prefix+'Verdict').value);
    query.set('status',agentEl(prefix+'Status').value);
  } else {
    query.set('source',agentEl(prefix+'Source').value);
    query.set('method',agentEl(prefix+'Method').value);
    const status=agentEl(prefix+'Status').value.trim();
    if(status) {
      if(!/^[1-5][0-9]{2}$/.test(status)||Number(status)>599) {
        container.replaceChildren();count.textContent='HTTP 상태 코드는 100~599 사이여야 합니다.';
        agentEl(prefix+'Prev').disabled=true;agentEl(prefix+'Next').disabled=true;return;
      }
      query.set('status_code',status);
    }
    const from=agentEl(prefix+'From').value,through=agentEl(prefix+'Through').value;
    const dayStart=value=>{
      const [year,month,day]=value.split('-').map(Number);
      const date=new Date(year,month-1,day);
      return date.getFullYear()===year&&date.getMonth()===month-1&&date.getDate()===day
        ?date:null;
    };
    const start=from?dayStart(from):null,end=through?dayStart(through):null;
    if((from&&!start)||(through&&!end)||(start&&end&&end<start)) {
      container.replaceChildren();count.textContent='날짜 범위를 확인해 주세요.';
      agentEl(prefix+'Prev').disabled=true;agentEl(prefix+'Next').disabled=true;return;
    }
    if(start)query.set('since',String(start.getTime()/1000));
    if(end){end.setDate(end.getDate()+1);query.set('before',String(end.getTime()/1000));}
  }
  const grouped=kind==='findings'&&agentEl('globalFindingGroup').checked;
  try {
    const result=await agentApi(`/history/${kind==='findings'?(grouped?'findings/groups':'findings'):'traffic'}?${query}`);
    if(seq!==state.seq)return;
    container.replaceChildren();
    const filters={verdict:query.get('verdict')||'',status:query.get('status')||'',archived:query.get('archived')||'false'};
    for(const item of result.items)container.append(grouped?globalFindingGroupRow(item,filters,seq):globalLookupRow(kind,item));
    if(!result.items.length)container.append(uiNode('p','sm-empty',grouped?'묶을 수 있는 발견이 없습니다. 주소 구조가 없는 발견은 개별 보기에서 확인하세요.':'조건에 맞는 기록이 없습니다.'));
    count.textContent=`전체 ${result.total}개${grouped?' 묶음':''} · ${state.page+1}페이지`;
    agentEl(prefix+'Prev').disabled=state.page===0;
    agentEl(prefix+'Next').disabled=!result.has_more;
  } catch(error) {if(seq===state.seq)count.textContent=error.message;}
}

function renderAgentExplore(run) {
  const box=agentEl('agentExploreForms');box.replaceChildren();
  const forms=run.recon?.form_candidates||[];
  if(!forms.length){box.append(uiNode('p','sm-empty','등록된 POST 폼이 없습니다.'));return;}
  const status={pending:'검사 대기',untested:'미검사',testing:'검사 중',interrupted:'중단',
    skipped_budget:'예산 부족',confirmed:'확증',suspicious:'의심',inconclusive:'미확정'};
  for(const form of forms) {
    const endpoint=run.data?.endpoints?.[form.endpoint_id]||{};
    const row=uiNode('article','lookup-row');
    row.append(uiNode('strong','',`${endpoint.method||'POST'} ${endpoint.url||form.endpoint_id}`),
      uiNode('p','aw-muted',`${form.source==='rendered_dom'?'렌더링된 화면':form.source==='html'?'HTML':'등록된 요청'} · ${status[form.status]||form.status} · ${form.login?'로그인 후보':'입력 폼'}`));
    const list=uiNode('ul','lookup-fields');
    const schema=form.field_schema?.length?form.field_schema:form.fields.map(name=>({name,type:'유형 미기록'}));
    for(const field of schema)list.append(uiNode('li','',`${field.name} · ${field.type}${field.required?' · 필수':''}`));
    row.append(list);box.append(row);
  }
}

async function loadRunTraffic(runId,archived=false) {
  if(runTrafficState.runId!==runId){runTrafficState.runId=runId;runTrafficState.page=0;}
  const seq=++runTrafficState.seq;
  const count=agentEl('agentTrafficCount'),box=agentEl('agentTrafficRows');
  count.textContent='불러오는 중…';
  agentEl('agentTrafficPrev').onclick=()=>{if(runTrafficState.page>0){runTrafficState.page--;loadRunTraffic(runId,archived);}};
  agentEl('agentTrafficNext').onclick=()=>{runTrafficState.page++;loadRunTraffic(runId,archived);};
  try {
    const query=new URLSearchParams({run_id:runId,offset:String(runTrafficState.page*50),limit:'50',archived:archived?'true':'false'});
    const result=await agentApi('/history/traffic?'+query);
    if(seq!==runTrafficState.seq||runTrafficState.runId!==runId)return;
    box.replaceChildren();
    for(const item of result.items)box.append(globalLookupRow('traffic',item));
    if(!result.items.length)box.append(uiNode('p','sm-empty','이 작업의 트래픽이 없습니다.'));
    count.textContent=`요청 ${result.total}개 · ${runTrafficState.page+1}페이지`;
    agentEl('agentTrafficPrev').disabled=runTrafficState.page===0;
    agentEl('agentTrafficNext').disabled=!result.has_more;
  } catch(error) {if(seq===runTrafficState.seq)count.textContent=error.message;}
}

const opsState={page:0,seq:0,initialized:false};
async function openOps() {
  if(!opsState.initialized) {
    opsState.initialized=true;
    agentEl('opsRefresh').onclick=()=>loadOps();
    agentEl('opsPrev').onclick=()=>{if(opsState.page>0){opsState.page--;loadOps();}};
    agentEl('opsNext').onclick=()=>{opsState.page++;loadOps();};
    agentEl('opsEgressAudit').onclick=()=>openEgressAudit();
  }
  await loadOps();
}
async function loadOps() {
  const seq=++opsState.seq;
  const readiness=agentEl('opsReadiness');readiness.textContent='준비 상태 확인 중…';
  agentEl('opsCount').textContent='작업 진단 불러오는 중…';
  const results=await Promise.allSettled([
    agentApi('/browser/readiness'),
    fetch('/api/ai-status').then(response=>_asJson(response,'AI 상태')),
    fetch('/api/egress/policy').then(response=>_asJson(response,'반출 정책')),
    agentApi(`/history/diagnostics?offset=${opsState.page*20}&limit=20`),
  ]);
  if(seq!==opsState.seq)return;
  const values=results.map(result=>result.status==='fulfilled'?result.value:null);
  const [browser,ai,policy,diagnostics]=values;
  readiness.replaceChildren();
  for(const [label,value] of [
    ['브라우저',browser?(browser.ready?`${browser.engine} ${browser.version} · 사용 가능`:`사용 불가 · ${browser.code}`):'조회 실패'],
    ['AI 모델',ai?(ai.enabled?'설정됨':'사용 불가'):'조회 실패'],
    ['반출 정책',policy?(policy.mode||'설정 확인 필요'):'조회 실패'],
  ])readiness.append(uiNode('p','',`${label}: ${value}`));
  const box=agentEl('opsRows');box.replaceChildren();
  if(!diagnostics){agentEl('opsCount').textContent='작업 진단 조회 실패';return;}
  agentEl('opsCount').textContent=`작업 ${diagnostics.total}개 · ${opsState.page+1}페이지`;
  const browserStates={started:'시작됨 · 결과 미확인',completed:'완료',unknown:'결과 기록 없음',
    skipped_budget:'예산 부족으로 건너뜀',unavailable:'사용 불가',
    playwright_unavailable:'Playwright 미설치',browser_missing:'브라우저 실행 파일 없음',
    browser_launch_failed:'브라우저 실행 실패',browser_timeout:'탐색 시간 초과',
    websocket_guard_unavailable:'웹소켓 차단 기능 없음'};
  for(const item of diagnostics.items) {
    const row=uiNode('article','lookup-row');
    const procedure=item.procedure_sha256?.slice(0,12)||'기록 없음';
    const prompt=item.prompt_sha256?.slice(0,12)||'기록 없음';
    const tokens=item.token_count==null?'미제공':String(item.token_count);
    row.append(uiNode('strong','',`${item.name||item.id.slice(0,8)} · ${item.state}`),
      uiNode('p','aw-muted',`정책 v${item.policy_version} · 절차 ${procedure} · 프롬프트 ${prompt} · 모델 ${item.model||'미사용'} · AI 호출 ${item.ai_calls}회 · 모델 대기 ${(item.planner_elapsed_ms/1000).toFixed(1)}초 · 거절 ${item.planner_failures}회 · 토큰 ${tokens} · 브라우저 ${browserStates[item.browser_status]||item.browser_status||'미실행'} · 요청 오류 ${item.request_errors??0}회`),
      uiNode('p','aw-muted',item.reason||'기록된 중단 사유 없음'),
      globalLookupRunButton(item.id,'작업 열기','timeline'));
    box.append(row);
  }
  if(!diagnostics.items.length)box.append(uiNode('p','sm-empty','기록된 작업이 없습니다.'));
  agentEl('opsPrev').disabled=opsState.page===0;
  agentEl('opsNext').disabled=!diagnostics.has_more;
}
