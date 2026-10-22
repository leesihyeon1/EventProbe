/* Workspace presentation. Server/AI/target operations remain in existing controllers. */
let workspaceRuns = [], workspacePage = 0;
const workspaceSelectedIds = new Set();
const workspacePageSize = 10;
const WORKSPACE_TITLES = {agent:'자율 검증', assets:'Asset', findings:'발견', traffic:'트래픽', settings:'설정 · 감사', bulk:'일괄 테스트', request:'요청 / 분석', results:'일괄 테스트 결과', report:'검증 리포트'};
function uiNode(tag, cls, text) {
  const el = document.createElement(tag); if (cls) el.className = cls;
  if (text !== undefined) el.textContent = text; return el;
}
function uiCommand(icon, label, action, cls='icon-button') {
  const b = uiNode('button', cls); b.type='button'; b.append(epIcon(icon));
  b.title=label; b.setAttribute('aria-label',label); b.onclick=action; return b;
}
function syncWorkspace(view) {
  agentEl('workspaceTitle').textContent = WORKSPACE_TITLES[view];
  document.querySelectorAll('.workspace-links button[data-view]').forEach(b => {
    b.title=WORKSPACE_TITLES[b.dataset.view];
    if (b.dataset.view===view) b.setAttribute('aria-current','page'); else b.removeAttribute('aria-current');
  });
  document.body.classList.remove('mobile-nav-open'); updateNavToggle();
  const hash = view==='agent' && agentRunId ? agentDetailRoute(agentRunId) :
    (['findings','traffic'].includes(view)&&typeof globalLookupRoute==='function'?globalLookupRoute(view):
    view==='assets'&&typeof assetRoute==='function'?assetRoute():'#'+view);
  if (location.hash!==hash) history.pushState(null,'',hash);
  if (view!=='agent') clearTimeout(agentTimer);
}
function agentDetailRoute(id) {
  return '#agent/'+id+(agentDetailMode==='findings'?'':'/'+agentDetailMode);
}
function updateNavToggle() {
  const expanded=matchMedia('(max-width:800px)').matches ? document.body.classList.contains('mobile-nav-open') : !document.body.classList.contains('nav-collapsed');
  const b=agentEl('navToggle'); b.setAttribute('aria-expanded',String(expanded));
  b.title=expanded?'주 메뉴 접기':'주 메뉴 펼치기'; b.setAttribute('aria-label',b.title);
}
function applyWorkspaceTheme(theme) {
  document.documentElement.dataset.theme=theme;
  const b=agentEl('themeToggle'); b.replaceChildren(epIcon(theme==='dark'?'Sun':'Moon'));
  b.title=theme==='dark'?'밝은 테마':'어두운 테마'; b.setAttribute('aria-label',b.title);
}
function showAgentList() {
  agentRunId=null; clearTimeout(agentTimer);
  agentEl('agentListView').hidden=false; agentEl('agentDetailView').hidden=true;
  if(location.hash!=='#agent')history.pushState(null,'','#agent'); loadAgentList();
}
function showAgentDetail() {
  _awRun=null;
  resetSiteMap();
  resetFindings();
  resetCoverage();
  agentEl('agentListView').hidden=true; agentEl('agentDetailView').hidden=false;
  agentEl('agentRunTitle').textContent='작업 불러오는 중';
  agentEl('agentConclusion').hidden=true;
  agentEl('agentStatus').textContent=''; agentEl('agentSummary').replaceChildren(); agentEl('agentResults').replaceChildren();
  agentEl('agentRunBadge').textContent='조회 중'; agentEl('agentRunBadge').dataset.state='';
  ['agentStop','agentHoldPlan','agentApproveStep','agentDenyStep','agentSkipPlan','agentRevokePlan','agentResume','agentExport','agentArchiveDownload'].forEach(id=>{ const el=agentEl(id); if(el) el.disabled=true; });
}
function openAgentNew() {
  agentEl('agentSourceRequest').checked=true;
  agentEl('agentSourceDomain').checked=false;
  agentEl('agentTargetScope').value='request_only';
  const req=_currentRequestForm();
  agentEl('agentRequestMethod').textContent=req.method;
  agentEl('agentRequestUrl').textContent=req.url || '대상 요청 없음';
  // Local preview only. Rendering never invokes an AI provider.
  agentEl('agentRequestPreview').textContent=JSON.stringify({params:req.params,headers:getHeadersObj(),body:req.body||''},null,2);
  agentEl('agentFormError').hidden=true; syncAgentSource(); agentEl('agentNew').showModal();
}
function syncAgentSource() {
  const domain=agentEl('agentSourceDomain').checked;
  agentEl('agentDomainFields').hidden=!domain;
  agentEl('agentDomainUrl').disabled=!domain;
  agentEl('agentDomainUrl').required=domain;
  agentEl('agentPacketFields').hidden=domain;
  agentEl('agentPolicyDetails').hidden=domain;
  agentEl('agentPolicyDetails').querySelectorAll('input,textarea,button').forEach(el=>el.disabled=domain);
  agentEl('agentTargetScope').value=domain?'same_origin':'request_only';
  agentEl('agentTargetScope').disabled=domain;
  resetPlanPreview();
}
let agentDetailMode='findings', _awRun=null;
const DETAIL_VIEWS={overview:['agentOverviewPanel','awTabOverview'],findings:['agentFindings','awTabFindings'],sitemap:['agentSiteMap','awTabSiteMap'],explore:['agentExplore','awTabExplore'],traffic:['agentTraffic','awTabTraffic'],coverage:['agentCoverage','awTabCoverage'],graph:['agentGraph','awTabGraph'],timeline:['agentEvents','awTabTimeline'],history:['agentHistory','awTabHistory']};
const MAIN_DETAIL_TABS={overview:'awTabOverview',recon:'awTabRecon',findings:'awTabFindings',traffic:'awTabTraffic',coverage:'awTabCoverage',record:'awTabRecord'};
let lastReconMode='explore',lastRecordMode='timeline';
function mainDetailMode(mode) {
  return ['explore','sitemap'].includes(mode)?'recon':
    ['timeline','graph','history'].includes(mode)?'record':mode;
}
function syncDetailMode() {
  if(['explore','sitemap'].includes(agentDetailMode))lastReconMode=agentDetailMode;
  if(['timeline','graph','history'].includes(agentDetailMode))lastRecordMode=agentDetailMode;
  for(const [mode,[panel,tab]] of Object.entries(DETAIL_VIEWS)) {
    const selected=agentDetailMode===mode;
    agentEl(panel).hidden=!selected;
    agentEl(tab).setAttribute('aria-selected',String(selected));
    agentEl(tab).tabIndex=selected?0:-1;
  }
  const main=mainDetailMode(agentDetailMode);
  for(const [mode,tab] of Object.entries(MAIN_DETAIL_TABS)) {
    const selected=mode===main;
    agentEl(tab).setAttribute('aria-selected',String(selected));
    agentEl(tab).tabIndex=selected?0:-1;
  }
  agentEl('agentReconControls').hidden=main!=='recon';
  agentEl('agentRecordControls').hidden=main!=='record';
  agentEl('awTabRecon').setAttribute('aria-controls',agentDetailMode==='sitemap'?'agentSiteMap':'agentExplore');
  agentEl('awTabRecord').setAttribute('aria-controls',agentDetailMode==='graph'?'agentGraph':agentDetailMode==='history'?'agentHistory':'agentEvents');
  if(_awRun && agentDetailMode==='graph') renderAgentGraph(_awRun);
  if(_awRun && agentDetailMode==='sitemap') renderAgentSiteMap(_awRun);
  if(_awRun && agentDetailMode==='explore') renderAgentExplore(_awRun);
  if(_awRun && agentDetailMode==='traffic') loadRunTraffic(_awRun.id,_awRun.data?.archived);
  if(_awRun && agentDetailMode==='findings') renderAgentFindings(_awRun);
  if(_awRun && agentDetailMode==='coverage') renderAgentCoverage(_awRun);
  if(_awRun && agentDetailMode==='history') loadHistoryPage();
  const timelineMore=agentEl('timelineMore');
  if(timelineMore) timelineMore.hidden=agentDetailMode!=='timeline' ||
    !(typeof timelineState!=='undefined' && timelineState.hasMore);
  if(_awRun?.view==='timeline' && agentDetailMode==='timeline') loadTimelinePage();
  if(_awRun) renderAgentConclusion(_awRun.conclusion);
}
function setDetailMode(mode) {
  const previous=agentDetailMode;
  agentDetailMode = Object.hasOwn(DETAIL_VIEWS,mode) ? mode : 'findings';
  if(agentRunId && previous!==agentDetailMode && typeof location!=='undefined' && typeof history!=='undefined') {
    const hash=agentDetailRoute(agentRunId);
    if(location.hash!==hash)history.pushState(null,'',hash);
  }
  try { localStorage.setItem('ep-detail-view', agentDetailMode); } catch(e) {}
  const mapModes=['graph','sitemap','explore','traffic','coverage'];
  const desired=mapModes.includes(agentDetailMode)?'map':agentDetailMode;
  const refresh=agentDetailMode!=='history' &&
    ((agentDetailMode==='overview' && _awRun && _awRun.view!=='overview') ||
     (_awRun?.compact && _awRun.view!==desired) ||
     (previous==='history' && !_awRun));
  if(refresh) _awRun=null;
  syncDetailMode();
  if(refresh && agentRunId) pollAgent();
}
function saveAgentFilters() {
  try { localStorage.setItem('ep-agent-filters',JSON.stringify({
    state:agentEl('agentFilter').value||'',category:agentEl('agentCategory').value||'',archived:_showArchived
  })); } catch(e) {}
}
function restoreAgentFilters() {
  try {
    const saved=JSON.parse(localStorage.getItem('ep-agent-filters')||'{}');
    if(['','running','paused','interrupted','completed','limited'].includes(saved.state)) agentEl('agentFilter').value=saved.state;
    if(typeof saved.category==='string'&&saved.category.length<=40) agentEl('agentCategory').value=saved.category;
    _showArchived=saved.archived===true;
    agentEl('agentArchivedToggle').setAttribute('aria-pressed',String(_showArchived));
  } catch(e) {}
}
function initAgentWorkspace() {
  restoreAgentFilters();
  agentEl('agentNewButton').onclick=openAgentNew;
  ['agentSourceRequest','agentSourceDomain'].forEach(id=>agentEl(id).onchange=syncAgentSource);
  agentEl('agentDomainUrl').oninput=resetPlanPreview;
  agentEl('agentTargetScope').onchange=resetPlanPreview;
  ['agentNewClose','agentNewCancel'].forEach(id=>agentEl(id).onclick=()=>agentEl('agentNew').close());
  agentEl('agentEditRequest').onclick=()=>{agentEl('agentNew').close();switchView('request');agentEl('urlInput').focus();};
  agentEl('agentBack').onclick=showAgentList;
  agentEl('agentSearch').oninput=()=>{workspacePage=0;loadAgentList();};
  agentEl('agentFilter').onchange=()=>{workspacePage=0;saveAgentFilters();loadAgentList();};
  agentEl('agentCategory').oninput=()=>{workspacePage=0;saveAgentFilters();loadAgentList();};
  agentEl('agentToolsMenu').ontoggle=()=>{
    if(agentEl('agentToolsMenu').open) document.querySelectorAll('.aw-row-menu[open]').forEach(menu=>menu.open=false);
  };
  agentEl('agentPrev').onclick=()=>{workspacePage--;loadAgentList();};
  agentEl('agentNext').onclick=()=>{workspacePage++;loadAgentList();};
  const wireTabs=(modes,tabId,select)=>modes.forEach((mode,index)=>{
    const tab=agentEl(tabId(mode));tab.onclick=()=>select(mode);
    tab.onkeydown=e=>{
      const next=e.key==='ArrowRight'?(index+1)%modes.length:e.key==='ArrowLeft'?(index+modes.length-1)%modes.length:e.key==='Home'?0:e.key==='End'?modes.length-1:null;
      if(next===null)return;
      e.preventDefault();select(modes[next]);agentEl(tabId(modes[next])).focus();
    };
  });
  wireTabs(Object.keys(MAIN_DETAIL_TABS),mode=>MAIN_DETAIL_TABS[mode],mode=>
    setDetailMode(mode==='recon'?lastReconMode:mode==='record'?lastRecordMode:mode));
  wireTabs(['explore','sitemap'],mode=>DETAIL_VIEWS[mode][1],setDetailMode);
  wireTabs(['timeline','graph','history'],mode=>DETAIL_VIEWS[mode][1],setDetailMode);
  initSiteMap();
  initFindings();
  initHistory();
  agentEl('awGraphZoomIn').onclick=()=>_zoomGraph(1.2);
  agentEl('awGraphZoomOut').onclick=()=>_zoomGraph(0.83);
  agentEl('awGraphFit').onclick=()=>_fitGraph();
  try { const saved=localStorage.getItem('ep-detail-view');if(Object.hasOwn(DETAIL_VIEWS,saved)) agentDetailMode=saved; } catch(e) {}
  syncDetailMode();
}
function filteredAgentRuns(runs, search, stateFilter, categoryFilter='') {
  const q=search.trim().toLowerCase();
  return runs.filter(r=>(!stateFilter||r.state===stateFilter) &&
    (!categoryFilter||r.category===categoryFilter) && (!q||`${r.name||''} ${r.goal} ${r.id}`.toLowerCase().includes(q)));
}
function emptyAgentRow(message, icon='FileSearch') {
  const row=uiNode('tr'),cell=uiNode('td','aw-empty'); cell.colSpan=6;
  cell.append(epIcon(icon),uiNode('p','',message));row.append(cell);return row;
}
function renderAgentListError(message) {
  agentEl('agentList').replaceChildren(emptyAgentRow(message,'CircleAlert'));
  agentEl('agentCount').textContent='조회 실패';
}
function renderAgentList(result) {
  workspaceSelectedIds.clear();
  const server=result && !Array.isArray(result);
  if(result) workspaceRuns=server?result.runs:result;
  const counts=server?result.state_counts||{}:Object.fromEntries(['running','paused','interrupted','completed','limited'].map(state=>[state,workspaceRuns.filter(r=>r.state===state).length]));
  const scopeTotal=server?result.scope_total:workspaceRuns.length;
  const metrics=agentEl('agentMetrics');metrics.replaceChildren();
  const stats=[['전체 작업',scopeTotal,'Layers',''],['실행 중',counts.running||0,'Activity','running'],['일시정지 / 중단',(counts.paused||0)+(counts.interrupted||0),'Pause','paused'],['종료',(counts.completed||0)+(counts.limited||0),'CircleCheck','']];
  for (const [label,count,icon,tone] of stats) {const d=uiNode('div','aw-metric');d.dataset.tone=tone;const l=uiNode('span');l.append(epIcon(icon),document.createTextNode(label));d.append(l,uiNode('strong','',String(count)));metrics.append(d);}
  const filtered=server?workspaceRuns:filteredAgentRuns(workspaceRuns,agentEl('agentSearch').value,agentEl('agentFilter').value,agentEl('agentCategory').value);
  const total=server?result.total:filtered.length;
  const pages=Math.max(1,Math.ceil(total/workspacePageSize));workspacePage=Math.max(0,Math.min(workspacePage,pages-1));
  const list=agentEl('agentList');list.replaceChildren();
  const archiveBulk=agentEl('agentBatchArchive'),stopBulk=agentEl('agentBatchStop');
  archiveBulk.textContent=_showArchived?'선택 복원':'선택 보관';
  archiveBulk.disabled=true;stopBulk.disabled=true;
  const start=workspacePage*workspacePageSize;
  for (const run of (server?filtered:filtered.slice(start,start+workspacePageSize))) {
    const row=uiNode('tr');row.dataset.run=run.id;
    const selection=uiNode('td','aw-select-cell'),task=uiNode('td'),title=uiNode('button','aw-task-title',run.name||run.goal||'목표 없음');title.type='button';title.title=run.goal;title.onclick=()=>selectRun(run.id);
    const check=uiNode('input');check.type='checkbox';check.setAttribute('aria-label',`작업 ${run.id.slice(0,8)} 선택`);
    check.onchange=()=>{if(check.checked)workspaceSelectedIds.add(run.id);else workspaceSelectedIds.delete(run.id);
      archiveBulk.disabled=!workspaceSelectedIds.size;
      stopBulk.disabled=_showArchived||!workspaceRuns.some(item=>workspaceSelectedIds.has(item.id)&&item.state==='running');};
    selection.append(check);task.append(title);
    if(run.category) task.append(uiNode('span','aw-plan-chip',run.category));
    const status=uiNode('td'),badge=uiNode('span','aw-badge',AGENT_STATE_LABELS[run.state]||run.state);badge.dataset.state=run.state;status.append(badge);
    const created=uiNode('td'),date=new Date(run.created*1000),time=uiNode('time','',date.toLocaleString('ko-KR',{month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit',hour12:false}));time.dateTime=date.toISOString();created.append(time);
    const id=uiNode('td');id.append(uiNode('code','',run.id.slice(0,8)));id.title=run.id;
    const actions=uiNode('td'),buttons=uiNode('div','aw-row-actions');
    const archive=uiNode('button','aw-link',_showArchived?'복원':'보관');archive.type='button';
    archive.onclick=()=>_showArchived?unarchiveRun(run.id):archiveRun(run.id);
    const menu=uiNode('details','aw-row-menu'),summary=uiNode('summary');
    summary.setAttribute('aria-label','작업 관리');summary.title='작업 관리';summary.append(epIcon('Settings2'));
    const options=uiNode('div','aw-row-menu-items');
    const edit=uiCommand('Pencil','이름·분류 수정',()=>editRunMetadata(run),'aw-link');
    edit.append(document.createTextNode('이름·분류 수정'));
    const remove=uiCommand('Trash2','작업 및 증거 삭제',()=>deleteRun(run.id),'aw-link danger');
    remove.append(document.createTextNode('작업 및 증거 삭제'));
    options.append(edit,archive,remove);
    menu.ontoggle=()=>{if(menu.open) {agentEl('agentToolsMenu').open=false;
      document.querySelectorAll('.aw-row-menu[open]').forEach(other=>{if(other!==menu) other.open=false;});}};
    menu.append(summary,options);
    buttons.append(uiCommand('ArrowRight','작업 열기',()=>selectRun(run.id)),menu);actions.append(buttons);
    row.append(selection,task,status,created,id,actions);list.append(row);
  }
  if (!filtered.length) list.append(emptyAgentRow(scopeTotal?'검색 결과가 없습니다.':'아직 검증 작업이 없습니다.'));
  agentEl('agentCount').textContent=`${total}개`;
  agentEl('agentPageInfo').textContent=total?`${start+1}–${Math.min(start+workspacePageSize,total)} / ${total}개`:'0개';
  agentEl('agentPrev').disabled=workspacePage===0;agentEl('agentNext').disabled=workspacePage>=pages-1;
}
function evidenceSection(title, data) {
  const s=uiNode('section');s.append(uiNode('h4','',title),uiNode('pre','',typeof data==='string'?data:JSON.stringify(data,null,2)));return s;
}
function renderWorkspaceEvent(event) {
  const d=event.data||{},card=uiNode('details','aw-event');card.dataset.event=event.id;
  const types={action:['실행 계획','Crosshair'],request_started:['HTTP 요청','Send'],observation:['응답 관측','Activity'],verification:['검증 판정','CircleCheck'],plan:['조건부 계획','ListChecks'],plan_approval:['계획 승인','CircleCheck'],plan_rejected:['계획 거부','CircleAlert'],plan_revoke:['계획 철회','CircleAlert'],plan_hold:['계획 보류','Pause'],plan_branch:['로컬 분기','ArrowRight'],plan_skip:['단계 건너뜀','ArrowRight'],plan_resume_blocked:['재개 보류','CircleAlert'],plan_result:['계획 결과','FileChartColumn'],error:['오류','CircleAlert']};
  types.planner_retry=['재계획','RefreshCw'];types.conclusion=['결론','FileChartColumn'];
  types.plan_step_approval_requested=['단계 검토 대기','Pause'];
  types.plan_step_approval=['단계 승인 기록','CircleCheck'];
  types.plan_step_denied=['단계 거절 기록','CircleAlert'];
  types.discovery=['경로 발견','FileSearch'];types.discovery_limit=['경로 수집 한도','CircleAlert'];
  types.browser_recon=['브라우저 탐색','Monitor'];types.planner_recovery=['검사 절차 선택','Crosshair'];
  const [label,icon]=types[event.kind]||[event.kind,'CircleDashed'];
  const summary=uiNode('summary'),heading=uiNode('span','aw-event-title');
  const retryLabels={category_out_of_scope:'요청한 검사 유형 이탈',duplicate_action:'이전 행동 반복',missing_evidence_basis:'관측 근거 누락',invalid_evidence_basis:'현재 작업에 없는 증거 참조',invalid_action_schema:'행동 형식 오류',provider_temporary:'AI 연결 일시 오류',insufficient_request_budget:'검사 요청 예산 부족'};
  const browserLabels={started:'브라우저 탐색 시작 · 결과 미확인',completed:'브라우저 탐색 완료',skipped_budget:'요청 또는 시간 예산 부족으로 건너뜀',unavailable:'브라우저 사용 불가',playwright_unavailable:'Playwright 미설치',browser_missing:'브라우저 실행 파일 없음',browser_launch_failed:'브라우저 실행 실패',browser_timeout:'탐색 시간 초과',websocket_guard_unavailable:'웹소켓 차단 기능 없음'};
  const text=event.kind==='action'?`${d.kind} · ${d.hypothesis}`:event.kind==='observation'?`${d.request?.method||''} ${d.request?.url||''} · HTTP ${d.response?.status}`:event.kind==='verification'?`${d.status} · 증거 ${(d.evidence_ids||[]).length}개`:event.kind==='planner_retry'?`${retryLabels[d.code]||d.code} · ${d.attempt}/${d.max_attempts}`:event.kind==='browser_recon'?`${browserLabels[d.code]||browserLabels[d.status]||'탐색 완료'}${d.code&&browserLabels[d.code]&&d.status==='unavailable'?' · 브라우저 설치 상태 확인':''}`:event.kind==='planner_recovery'?(d.code==='observed_login_form'?'발견한 로그인 폼 검사 선택':d.code==='suspicious_probe'?'의심 결과 재검증 선택':'기존 검사 재검증 선택'):d.text||d.reason||d.message||d.outcome||d.action_id||label;
  heading.append(uiNode('span','aw-event-kind',label),document.createTextNode(text));summary.append(epIcon(icon),heading);card.append(summary);
  const body=uiNode('div','aw-event-body');
  if (event.kind==='observation') {
    const grid=uiNode('div','aw-evidence-grid');grid.append(evidenceSection('요청',d.request),evidenceSection(`응답 · ${d.response?.time_ms||0} ms`,d.response?.body||''));body.append(grid);
  } else if (event.kind==='verification') {
    const list=uiNode('ul');for(const item of [...(d.confirmed||[]),...(d.limitations||[])]) list.append(uiNode('li','',typeof item==='string'?item:item.scope||item.kind||JSON.stringify(item)));body.append(list);
  } else if(event.kind==='action') {body.append(uiNode('p','',d.expected||d.hypothesis));}
  const raw=uiNode('details','aw-raw');raw.append(uiNode('summary','','원본 이벤트'),uiNode('pre','',JSON.stringify(d,null,2)));body.append(raw);card.append(body);return card;
}
function renderAgentConclusion(conclusion) {
  const panel=agentEl('agentConclusion');
  panel.hidden=!conclusion;
  const results=agentEl('agentResults');results.replaceChildren();
  if(!conclusion) return;
  for(const [key,label,icon] of [['confirmed','확증','CircleCheck'],['suspicious','의심','CircleAlert'],['inconclusive','미확정','CircleDashed']]) {
    const item=uiNode('span');item.dataset.verdict=key;
    item.append(epIcon(icon),document.createTextNode(`${label} ${conclusion.counts?.[key]||0}`));
    results.append(item);
  }
  const signature=JSON.stringify(conclusion);
  if(panel.dataset.signature===signature) return;
  panel.dataset.signature=signature;
  panel.dataset.verdict=conclusion.verdict;
  const title=conclusion.completion==='running'?'현재 관측 결과':conclusion.completion==='partial'?'부분 결론 · 미완료':'검증 결론';
  const heading=uiNode('div','aw-conclusion-heading');
  heading.append(epIcon(conclusion.verdict==='confirmed'?'CircleAlert':'FileSearch'),uiNode('h3','',title));
  panel.replaceChildren(heading,uiNode('p','',conclusion.text));
  const counts=conclusion.counts||{};
  panel.append(uiNode('p','aw-muted',`확증 ${counts.confirmed||0} · 의심 ${counts.suspicious||0} · 미확정 ${counts.inconclusive||0} · 관측 ${conclusion.observation_count||0}건`));
  if(conclusion.goals?.length) {
    const goals=uiNode('ul','aw-conclusion-goals');
    for(const goal of conclusion.goals) {
      const label=`${goal.status==='met'?'충족':goal.status==='pending'?'진행 중':'미충족'} · ${goal.title} (${goal.category})`;
      const row=uiNode('li','',label);
      if(goal.reason) row.append(uiNode('span','aw-muted',` · ${goal.reason}`));
      goals.append(row);
    }
    panel.append(goals);
  }
  if(conclusion.verifications?.length) {
    const evidence=uiNode('ul','aw-conclusion-verifications');
    const statuses={confirmed:'확증',suspicious:'의심',inconclusive:'미확정'};
    for(const result of conclusion.verifications) {
      const row=uiNode('li'),label=`${result.category} · ${statuses[result.status]||result.status} · 증거 ${result.evidence_ids.length}개`;
      row.append(uiNode('span','',label),uiCommand('FileSearch','검증 근거 보기',()=>{
        if(_awRun?.compact) {openHistoryEvidence(result.id);return;}
        setDetailMode('timeline');
        const event=[...agentEl('agentEvents').children].find(e=>e.dataset.event===result.id);
        if(event){event.open=true;event.scrollIntoView({block:'center'});event.querySelector('summary').focus();}
      }));evidence.append(row);
    }
    panel.append(evidence);
  }
  if(conclusion.stop_reason) panel.append(uiNode('p','aw-conclusion-reason',conclusion.stop_reason));
  const next=uiNode('ul');for(const item of conclusion.next_steps||[]) next.append(uiNode('li','',item));
  panel.append(next,uiNode('p','aw-muted',conclusion.scope_note));
}
function renderAgentRunHeader(run) {
  const data=run.data,spec=data.spec;
  agentEl('agentRunTitle').textContent=data.name||spec.goal;
  const badge=agentEl('agentRunBadge');badge.textContent=AGENT_STATE_LABELS[run.state]||run.state;badge.dataset.state=run.state;
  const revoked=spec.approved_plan_revoked_at!=null;
  const nextStep=!revoked && data.spec?.mode==='plan' && data.plan_checkpoint?.phase!=='done' && data.plan_checkpoint?.current
    ? ` · 계획 단계 ${data.plan_checkpoint.current}` : '';
  agentEl('agentStatus').textContent=(data.category?`${data.category} · `:'')+
    (data.name?`${spec.goal} · `:'')+(data.retest_of?'발견 재검증 실행 · ':'')+
    (data.reason||'실행 기록 수집 중')+nextStep;
  agentEl('agentStop').disabled=run.state!=='running';
  const reviewPhase=data.plan_checkpoint?.phase;
  agentEl('agentResume').disabled=revoked||['approval_required','denied'].includes(reviewPhase)||!['paused','interrupted'].includes(run.state);
  agentEl('agentExport').disabled=false;
  agentEl('agentApproveStep').disabled=agentEl('agentDenyStep').disabled=reviewPhase!=='approval_required'||run.state!=='paused';
  const hold=agentEl('agentHoldPlan');
  if(hold) hold.disabled=!(spec.mode==='plan' && !revoked && run.state==='running' && (run.has_plan_event||run.events?.some(e=>e.kind==='plan')));
  const archive=agentEl('agentArchiveDownload'); if(archive) archive.disabled=run.state==='running';
  const skip=agentEl('agentSkipPlan');
  if(skip) skip.disabled=!(run.data?.spec?.mode==='plan' && !revoked && reviewPhase!=='denied' && ['paused','interrupted'].includes(run.state)
    && (run.has_plan_event||run.events?.some(e=>e.kind==='plan')) && run.data?.plan_checkpoint?.phase!=='done');
  const revoke=agentEl('agentRevokePlan');
  if(revoke) revoke.disabled=!((spec.approved_plan||data.has_approved_plan) && !revoked && ['running','paused','interrupted'].includes(run.state));
  const stats=agentEl('agentSummary');stats.replaceChildren();
  for(const [label,value] of [['단계',`${data.steps} / ${spec.max_steps}`],['HTTP 요청',`${data.requests} / ${spec.max_requests}`],['AI 호출',`${data.ai_calls} / ${spec.max_ai_calls}`],['경과 시간',`${Math.round(data.elapsed)}초`],['발견 경로',data.endpoints_count??Object.keys(data.endpoints||{}).length]]) {const s=uiNode('div','aw-run-stat');s.append(uiNode('span','',label),uiNode('strong','',String(value)));stats.append(s);}
  if(run.tool_summary) for(const [label,value] of [['응답 관측',run.tool_summary.http_observed],['요청 오류',run.tool_summary.http_error],['결과 미확인',run.tool_summary.http_unresolved]]) {
    const s=uiNode('div','aw-run-stat');s.append(uiNode('span','',label),uiNode('strong','',String(value)));stats.append(s);
  }
  const latestPlanner=[...(data.planner_attempts||[])].reverse().find(item=>item.model);
  for(const [label,value] of [['절차 SHA-256',data.procedure_sha256?.agent?.slice(0,12)],
    ['AI 모델',latestPlanner?.model],['프롬프트 SHA-256',latestPlanner?.prompt_sha256?.slice(0,12)]]) {
    if(!value) continue;
    const s=uiNode('div','aw-run-stat');s.append(uiNode('span','',label),uiNode('strong','',String(value)));stats.append(s);
  }
  if(run.event_count!==undefined) agentEl('agentEventCount').textContent=`${run.event_count}개 이벤트`;
}
function renderAgentWorkspace(run) {
  renderAgentConclusion(run.conclusion);
  renderAgentRunHeader(run);
  if(!run.conclusion) {
    const results=agentEl('agentResults');
    for(const [key,label,icon] of [['confirmed','확증','CircleCheck'],['suspicious','의심','CircleAlert'],['inconclusive','미확정','CircleDashed']]) {
      const n=run.events.filter(e=>e.kind==='verification'&&e.data.status===key).length;
      const item=uiNode('span');item.dataset.verdict=key;
      item.append(epIcon(icon),document.createTextNode(`${label} ${n}`));results.append(item);
    }
  }
  const container=agentEl('agentEvents');if(container.dataset.run!==run.id){container.replaceChildren();container.dataset.run=run.id;}
  const existing=new Set([...container.children].map(el=>el.dataset.event));
  for(const event of run.events) if(!existing.has(event.id)) container.append(renderWorkspaceEvent(event));
  agentEl('agentEventCount').textContent=`${run.events.length}개 이벤트`;
  _awRun=run;
  syncDetailMode();
}
function restoreWorkspaceRoute() {
  const [route,rawQuery='']=location.hash.split('?',2);
  const match=route.match(/^#(agent|request|results|report|assets|findings|traffic|settings|bulk)(?:\/([a-zA-Z0-9_-]+))?(?:\/([a-z]+))?$/);
  if(match?.[1]==='assets'&&typeof restoreAssetFilters==='function')restoreAssetFilters(rawQuery);
  if(match?.[1]==='traffic'&&typeof restoreTrafficFilters==='function')restoreTrafficFilters(rawQuery);
  if(match?.[1]==='findings'&&typeof restoreFindingFilters==='function')restoreFindingFilters(rawQuery);
  if(match?.[1]==='assets'&&typeof setAssetFocus==='function')setAssetFocus(match[2]||'');
  if(['findings','traffic'].includes(match?.[1])&&typeof setGlobalLookupAssetFilter==='function')
    setGlobalLookupAssetFilter(match[1],match[2]||'');
  if(match?.[1]==='agent') {
    const incoming=match[2]||null;
    agentDetailMode=Object.hasOwn(DETAIL_VIEWS,match[3])?match[3]:'findings';
    if(incoming!==agentRunId){agentRunId=incoming;if(agentRunId)showAgentDetail();}
    if(!agentRunId){agentEl('agentListView').hidden=false;agentEl('agentDetailView').hidden=true;}
    syncDetailMode();
  }
  switchView(match?.[1]||'request');
}
window.addEventListener('DOMContentLoaded',()=>{
  hydrateIcons();
  let theme='light';try{theme=localStorage.getItem('ep-theme')||'light';}catch(e){}
  applyWorkspaceTheme(theme==='dark'?'dark':'light');
  agentEl('themeToggle').onclick=()=>{const t=document.documentElement.dataset.theme==='dark'?'light':'dark';applyWorkspaceTheme(t);try{localStorage.setItem('ep-theme',t);}catch(e){}};
  agentEl('navToggle').onclick=()=>{document.body.classList.toggle(matchMedia('(max-width:800px)').matches?'mobile-nav-open':'nav-collapsed');updateNavToggle();};
  document.addEventListener('keydown',e=>{if(e.key==='Escape'){document.body.classList.remove('mobile-nav-open');updateNavToggle();}});
  matchMedia('(max-width:800px)').addEventListener('change',()=>{document.body.classList.remove('nav-collapsed','mobile-nav-open');updateNavToggle();});
  restoreWorkspaceRoute();
});
window.addEventListener('hashchange',restoreWorkspaceRoute);
