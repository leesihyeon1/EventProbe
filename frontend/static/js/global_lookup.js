/* Server-paged global findings and traffic. Evidence bodies load only on disclosure. */
const globalLookupState={findings:{page:0,seq:0},traffic:{page:0,seq:0}};
const runTrafficState={runId:null,page:0,seq:0};

function initGlobalLookup(kind) {
  const prefix=kind==='findings'?'globalFinding':'globalTraffic';
  const state=globalLookupState[kind];
  if(state.initialized)return;
  state.initialized=true;
  let debounce;
  agentEl(prefix+'Search').oninput=()=>{
    clearTimeout(debounce);debounce=setTimeout(()=>{state.page=0;loadGlobalLookup(kind);},250);
  };
  const filters=kind==='findings'?['Verdict','Status','Archived']:['Source','Archived'];
  for(const name of filters)agentEl(prefix+name).onchange=()=>{state.page=0;loadGlobalLookup(kind);};
  agentEl(prefix+'Prev').onclick=()=>{if(state.page>0){state.page--;loadGlobalLookup(kind);}};
  agentEl(prefix+'Next').onclick=()=>{state.page++;loadGlobalLookup(kind);};
}

async function openGlobalLookup(kind) {
  initGlobalLookup(kind);
  await loadGlobalLookup(kind);
}

function globalLookupRunButton(runId, label, mode) {
  const button=uiNode('button','aw-link',label);button.type='button';
  button.onclick=()=>{switchView('agent');selectRun(runId);setDetailMode(mode);};
  return button;
}

function globalLookupRow(kind,item) {
  const row=uiNode('article','lookup-row');
  const top=uiNode('div','lookup-row-top');
  top.append(uiNode('strong','',`${item.method} ${item.origin}${item.path}`));
  const badge=kind==='findings'
    ?`${{confirmed:'확증',suspicious:'의심',inconclusive:'미확정'}[item.verdict]||item.verdict} · ${item.category}`
    :`${item.source==='browser'?'브라우저':'자율 검증'} · HTTP ${item.status??'미관측'}`;
  top.append(uiNode('span','aw-muted',badge));row.append(top);
  const actions=uiNode('div','lookup-actions');
  actions.append(uiNode('time','aw-muted',new Date(item.created*1000).toLocaleString('ko-KR')));
  actions.append(globalLookupRunButton(item.run_id,'작업 열기',kind==='findings'?'findings':'history'));
  if(kind==='traffic') {
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
  } else {
    actions.append(uiNode('span','aw-muted',`증거 ${item.evidence_count}개 · ${item.status}`));
  }
  row.append(actions);return row;
}

async function loadGlobalLookup(kind) {
  const prefix=kind==='findings'?'globalFinding':'globalTraffic';
  const state=globalLookupState[kind],seq=++state.seq;
  const count=agentEl(prefix+'Count'),container=agentEl(prefix+'Rows');
  count.textContent='불러오는 중…';
  const query=new URLSearchParams({offset:String(state.page*50),limit:'50',
    search:agentEl(prefix+'Search').value,archived:agentEl(prefix+'Archived').checked?'true':'false'});
  if(kind==='findings') {
    query.set('verdict',agentEl(prefix+'Verdict').value);
    query.set('status',agentEl(prefix+'Status').value);
  } else query.set('source',agentEl(prefix+'Source').value);
  try {
    const result=await agentApi(`/history/${kind==='findings'?'findings':'traffic'}?${query}`);
    if(seq!==state.seq)return;
    container.replaceChildren();
    for(const item of result.items)container.append(globalLookupRow(kind,item));
    if(!result.items.length)container.append(uiNode('p','sm-empty','조건에 맞는 기록이 없습니다.'));
    count.textContent=`전체 ${result.total}개 · ${state.page+1}페이지`;
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
  for(const item of diagnostics.items) {
    const row=uiNode('article','lookup-row');
    row.append(uiNode('strong','',`${item.name||item.id.slice(0,8)} · ${item.state}`),
      uiNode('p','aw-muted',`정책 v${item.policy_version} · 모델 ${item.model||'미사용'} · AI 호출 ${item.ai_calls}회 · 모델 대기 ${(item.planner_elapsed_ms/1000).toFixed(1)}초 · 거절 ${item.planner_failures}회 · 토큰 미제공 · 브라우저 ${item.browser_status||'미실행'}`),
      uiNode('p','aw-muted',item.reason||'기록된 중단 사유 없음'),
      globalLookupRunButton(item.id,'작업 열기','timeline'));
    box.append(row);
  }
  if(!diagnostics.items.length)box.append(uiNode('p','sm-empty','기록된 작업이 없습니다.'));
  agentEl('opsPrev').disabled=opsState.page===0;
  agentEl('opsNext').disabled=!diagnostics.has_more;
}
