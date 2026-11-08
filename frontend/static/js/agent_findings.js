/* Findings view. Renders server-derived findings (run.findings); triage goes through
   the local PATCH endpoint. No target or AI I/O; all text via textContent. */
const FD_STATUS={open:'미처리',triaged:'분류됨',resolved:'해결',false_positive:'오탐',ignored:'무시'};
const FD_SEVERITY={info:'정보',low:'낮음',medium:'보통',high:'높음',critical:'심각'};
const FD_VERDICT={confirmed:'확증',suspicious:'의심',inconclusive:'미확정'};
const FD_VULN=new Set(['sqli','xss','ssti','lfi','ssrf','cmdi','redirect','nosql']);
let findingsState={runId:null,model:[],signature:'',selected:null};
function resetFindings() {
  findingsState={runId:null,model:[],signature:'',selected:null};
  agentEl('fdContent').replaceChildren();agentEl('fdDetail').replaceChildren();agentEl('fdCount').textContent='';
  delete agentEl('fdDetail').dataset.signature;
  agentEl('fdSearch').value='';agentEl('fdStatus').value='';agentEl('fdSeverity').value='';
}
function initFindings() {
  mountSavedLibraryButton(agentEl('fdReport')?.parentElement,'fdSavedLibrary');
  agentEl('fdSearch').oninput=drawFindings;
  agentEl('fdStatus').onchange=drawFindings;agentEl('fdSeverity').onchange=drawFindings;
  agentEl('fdReport').onclick=()=>{if(findingsState.runId) window.open('/api/agent/runs/'+encodeURIComponent(findingsState.runId)+'/report','_blank','noopener');};
}
function filterFindings(rows,search,status,severity) {
  const q=search.trim().toLowerCase();
  return rows.filter(f=>(!status||f.status===status) && (!severity||f.severity===severity) &&
    (!q||`${f.category} ${f.method} ${f.path} ${f.actor_id} ${(f.query_keys||[]).join(' ')}`.toLowerCase().includes(q)));
}
function renderAgentFindings(run) {
  if(findingsState.runId!==run.id){resetFindings();findingsState.runId=run.id;}
  const model=run.findings || [], signature=JSON.stringify(model);
  if(signature===findingsState.signature) return;
  findingsState.signature=signature;findingsState.model=model;
  drawFindings();
}
function fdBadge(value,label,prefix){const b=uiNode('span',prefix+'-badge',label);b.dataset[prefix==='sev'?'sev':'state']=value;return b;}
function findingLabel(f){return `${f.method} ${f.path}`;}
function selectFinding(id) {
  findingsState.selected=id;
  for(const b of agentEl('fdContent').querySelectorAll('button[data-key]')) b.setAttribute('aria-pressed',String(b.dataset.key===id));
  renderFindingDetail(findingsState.model.find(f=>f.id===id));
}
function findingRowButton(f) {
  const b=uiNode('button','fd-row');b.type='button';b.dataset.key=f.id;
  b.setAttribute('aria-pressed',String(findingsState.selected===f.id));
  b.append(fdBadge(f.severity,FD_SEVERITY[f.severity]||f.severity,'sev'),
    uiNode('span','fd-category',f.category),
    uiNode('span','sm-path',findingLabel(f)),
    uiNode('span','fd-verdict',FD_VERDICT[f.verdict]||f.verdict));
  b.append(uiNode('span','fd-status',FD_STATUS[f.status]||f.status));
  if(f.incomplete_evidence) b.append(uiNode('span','sm-flag','증거 일부 누락'));
  b.onclick=()=>selectFinding(f.id);return b;
}
function drawFindings() {
  const model=findingsState.model;
  const rows=filterFindings(model,agentEl('fdSearch').value,agentEl('fdStatus').value,agentEl('fdSeverity').value);
  agentEl('fdCount').textContent=`발견 ${model.length}개 · 표시 ${rows.length}개`;
  agentEl('fdReport').disabled=!findingsState.runId;
  if(!rows.some(f=>f.id===findingsState.selected)) findingsState.selected=rows[0]?.id || null;
  const content=agentEl('fdContent'), scroll=content.scrollTop;
  const focused=document.activeElement, focusKey=content.contains(focused)?focused.dataset.key:null;
  content.replaceChildren();
  if(!rows.length) content.append(uiNode('p','sm-empty',model.length?'조건에 맞는 발견이 없습니다.':'연결된 증거로 확인된 발견이 없습니다.'));
  else for(const f of rows) content.append(findingRowButton(f));
  content.scrollTop=scroll;
  if(focusKey) [...content.querySelectorAll('[data-key]')].find(el=>el.dataset.key===focusKey)?.focus({preventScroll:true});
  renderFindingDetail(rows.find(f=>f.id===findingsState.selected));
}
async function retestFinding(f) {
  // 실제 대상에 요청을 보내는 외부 동작이므로 먼저 확인한다(리뷰 P2).
  if(typeof confirm==='function' && !confirm('이 발견을 새 실행으로 재검증합니다. 대상에 실제 요청을 보냅니다. 계속할까요?')) return;
  try {
    const headers=(typeof getHeadersObj==='function')?getHeadersObj():{};
    const run=await agentApi(`/runs/${encodeURIComponent(findingsState.runId)}/findings/${encodeURIComponent(f.id)}/retest`,{request_headers:headers});
    if(typeof selectRun==='function' && run && run.id) selectRun(run.id);   // 새 재검증 실행으로 이동
  } catch(e) { /* _asJson surfaces the error to the user */ }
}
async function patchFinding(id,patch) {
  try {
    const updated=await agentApi(`/runs/${encodeURIComponent(findingsState.runId)}/findings/${encodeURIComponent(id)}`,patch,'PATCH');
    _awRun={...updated,view:'findings'};findingsState.signature='';renderAgentFindings(updated);selectFinding(id);
  } catch(e) { /* _asJson surfaces the error to the user */ }
}
function fdSelect(label,current,options,onchange) {
  const wrap=uiNode('label','fd-field');wrap.append(uiNode('span','',label));
  const sel=uiNode('select');
  for(const [value,text] of options){const o=uiNode('option','',text);o.value=value;if(value===current)o.selected=true;sel.append(o);}
  sel.onchange=()=>onchange(sel.value);wrap.append(sel);return wrap;
}
function renderFindingDetail(f) {
  const panel=agentEl('fdDetail'),signature=JSON.stringify(f || null);
  if(panel.dataset.signature===signature) return;
  panel.dataset.signature=signature;
  const focused=panel.contains(document.activeElement)?document.activeElement.dataset.event:null;
  panel.replaceChildren();
  if(!f){panel.append(uiNode('p','sm-empty','선택된 발견 없음'));return;}
  panel.append(uiNode('h4','',f.category),uiNode('p','sm-origin',`${f.method} ${f.path}`),
    fdBadge(f.verdict,FD_VERDICT[f.verdict]||f.verdict,'state'));
  const facts=uiNode('dl','sm-facts');
  for(const [label,value] of [['행위자',f.actor_id||'-'],['쿼리 키',(f.query_keys||[]).join(', ')||'없음'],
    ['증거',`${(f.evidence_ids||[]).length}개${f.incomplete_evidence?' · 일부 누락':''}`],['기본 심각도',FD_SEVERITY[f.default_severity]||f.default_severity]])
    facts.append(uiNode('dt','',label),uiNode('dd','',value));
  panel.append(facts);
  const controls=uiNode('div','fd-controls');
  controls.append(
    fdSelect('상태',f.status,Object.entries(FD_STATUS),v=>patchFinding(f.id,{status:v})),
    fdSelect('심각도',f.severity,Object.entries(FD_SEVERITY),v=>patchFinding(f.id,{severity:v})));
  panel.append(controls);
  const exports=uiNode('div','fd-evidence-exports');
  const base=`/api/agent/runs/${encodeURIComponent(findingsState.runId)}/findings/${encodeURIComponent(f.id)}/evidence.zip`;
  for(const [label,url] of [['증거 ZIP (요약)',base],['내부 원본 ZIP',base+'?raw=true']]) {
    const link=uiNode('a','aw-link');
    link.append(epIcon('Download'),document.createTextNode(label));
    link.setAttribute('href',url);link.setAttribute('download','finding-evidence.zip');
    link.title=label==='내부 원본 ZIP'?'요청·응답 원문이 포함됩니다.':'URL 값·헤더 값·본문을 제외합니다.';
    if(label==='내부 원본 ZIP') link.onclick=event=>{
      if(typeof confirm==='function' && !confirm('이 ZIP에는 내부 URL, 요청·응답 원문과 헤더가 포함됩니다. 로컬로 다운로드할까요?')) event.preventDefault();
    };
    exports.append(link);
  }
  const preserve=savedPreserveButton(findingsState.runId,f.id);exports.append(preserve);
  panel.append(exports);
  if(FD_VULN.has(f.category)) {
    const retest=uiNode('button','aw-link fd-retest','새 실행으로 재검증');retest.type='button';
    retest.onclick=()=>retestFinding(f);
    panel.append(retest);
  }
  const comparison=uiNode('div','fd-retest-history');
  const compareButton=uiNode('button','aw-link','재검증 이력 보기');compareButton.type='button';
  compareButton.onclick=async()=>{
    const runId=findingsState.runId,findingId=f.id;
    compareButton.disabled=true;comparison.replaceChildren(uiNode('p','aw-muted','이력 불러오는 중…'));
    try {
      const result=await agentApi(`/history/runs/${encodeURIComponent(runId)}/findings/${encodeURIComponent(findingId)}/retests`);
      if(findingsState.runId!==runId||findingsState.selected!==findingId)return;
      comparison.replaceChildren();
      if(!result.items?.length)comparison.append(uiNode('p','aw-muted','연결된 재검증 실행이 없습니다.'));
      for(const item of result.items||[]) {
        const row=uiNode('div','fd-retest-row');
        const verdict=item.finding?(FD_VERDICT[item.finding.verdict]||item.finding.verdict):'판정 기록 없음';
        const shape=item.same_request_shape===true?'요청 구조 일치':item.same_request_shape===false?'요청 구조 변경':'요청 구조 미확인';
        row.append(uiNode('p','aw-muted',`${new Date(item.created*1000).toLocaleString('ko-KR')} · ${item.state} · ${shape}`),
          uiNode('p','',`${FD_VERDICT[result.original?.verdict]||result.original?.verdict||'원본 판정 없음'} → ${verdict}${item.finding?.incomplete_evidence?' · 증거 일부 누락':''}`));
        if(item.same_request_shape===false&&item.request_shape)row.append(
          uiNode('p','aw-muted',`${result.original?.method||''} ${result.original?.origin||''}${result.original?.path||''} → ${item.request_shape.method} ${item.request_shape.origin}${item.request_shape.path}`));
        const open=uiNode('button','aw-link','재검증 실행 열기');open.type='button';
        open.onclick=()=>selectRun(item.run_id);row.append(open);comparison.append(row);
      }
    } catch(error) {
      if(findingsState.runId===runId&&findingsState.selected===findingId)
        comparison.replaceChildren(uiNode('p','aw-muted',error.message||'이력 조회 실패'));
    } finally {compareButton.disabled=false;}
  };
  panel.append(compareButton,comparison);
  const noteWrap=uiNode('div','fd-note');
  const area=uiNode('textarea');area.value=f.note||'';area.placeholder='메모 (로컬 저장)';area.setAttribute('aria-label','발견 메모');
  const save=uiNode('button','aw-link','메모 저장');save.type='button';save.onclick=()=>patchFinding(f.id,{note:area.value});
  noteWrap.append(area,save);panel.append(uiNode('h5','','분류'),noteWrap);
  if(f.evidence_ids?.length) {
    panel.append(uiNode('h5','','관련 증거'));const list=uiNode('div','sm-evidence');
    f.evidence_ids.forEach((id,i)=>{const b=uiCommand('FileSearch',`응답 관측 ${i+1}`,()=>showFindingEvidence(id),'aw-link');b.dataset.event=id;b.append(document.createTextNode(`응답 관측 ${i+1}`));list.append(b);});
    panel.append(list);
    if(focused) [...list.children].find(b=>b.dataset.event===focused)?.focus({preventScroll:true});
  }
  if(f.history?.length) {
    panel.append(uiNode('h5','','변경 이력'));const log=uiNode('ul','fd-history');
    for(const h of f.history){const parts=[];if(h.status)parts.push('상태 '+(FD_STATUS[h.status]||h.status));if(h.severity)parts.push('심각도 '+(FD_SEVERITY[h.severity]||h.severity));if('note' in h)parts.push('메모 변경');
      log.append(uiNode('li','',`${new Date(h.created*1000).toLocaleString('ko-KR')} · ${parts.join(', ')}`));}
    panel.append(log);
  }
}
async function showFindingEvidence(id) {
  const runId=agentRunId;
  const compact=_awRun?.compact;
  setDetailMode(compact?'history':'timeline');
  const container=agentEl(compact?'ahEvents':'agentEvents');
  let event=[...container.children].find(el=>el.dataset.event===id);
  if(!event && compact) {
    try {
      const full=await agentApi(`/history/runs/${encodeURIComponent(runId)}/events/${encodeURIComponent(id)}`);
      if(runId!==agentRunId || historyState.runId!==runId) return;
      event=[...container.children].find(el=>el.dataset.event===id);
      if(!event) {event=renderWorkspaceEvent(full);container.append(event);historyState.seen.add(id);}
    } catch(error) {agentEl('ahCount').textContent=error.message;return;}
  }
  if(event){event.open=true;event.scrollIntoView({block:'center'});event.querySelector('summary')?.focus();}
}


/* Independent evidence library: every body is a local, explicit disclosure. */
let savedLibraryState={page:0,query:'',request:0,detailRequest:0,selected:null,version:null};
function mountSavedLibraryButton(parent,id) {
  if(!parent||document.getElementById?.(id))return;
  const button=uiNode('button','aw-link','보존한 발견');button.id=id;button.type='button';
  button.onclick=()=>openSavedLibrary();parent.append(button);
}
function savedPreserveButton(runId,findingId) {
  const button=uiNode('button','aw-link','증거 별도 보존');button.type='button';
  button.onclick=()=>preserveSourceFinding(runId,findingId,button);return button;
}
async function preserveSourceFinding(runId,findingId,button) {
  if(typeof confirm==='function'&&!confirm('선택한 발견의 URL·요청·응답 값을 별도로 보존합니다. 실행 기록을 삭제해도 남으며 보존 목록에서 따로 삭제합니다. 계속할까요?'))return;
  button.disabled=true;
  try {
    const base=`/runs/${encodeURIComponent(runId)}/findings/${encodeURIComponent(findingId)}`;
    const previous=await agentApi(base+'/preserved');
    const body=previous.saved?{expected_revision:previous.saved.revision}:{};
    const result=await agentApi(base+'/preserve',body);
    button.textContent=result.unchanged?'이미 보존됨':'보존 완료';
    if(button.isConnected!==false)await openSavedLibrary(result.id);
  } catch(error){button.textContent=error.message||'보존 실패';}
  finally{button.disabled=false;}
}
function ensureSavedLibrary() {
  let dialog=document.getElementById('savedFindingDialog');if(dialog)return dialog;
  dialog=uiNode('dialog','aw-dialog');dialog.id='savedFindingDialog';dialog.setAttribute('aria-label','별도 보존한 발견');
  const head=uiNode('div','aw-dialog-head'),title=uiNode('h2','','보존한 발견');
  const close=uiNode('button','aw-link','닫기');close.type='button';close.onclick=()=>{savedLibraryState.request++;savedLibraryState.detailRequest++;dialog.close();};head.append(title,close);
  const form=uiNode('div','aw-form');
  form.append(uiNode('p','aw-muted','실행 기록과 별개로 보존한 시점의 증거입니다. 조회·가져오기는 대상 요청이나 AI 호출을 만들지 않습니다.'));
  const search=uiNode('input');search.id='savedFindingSearch';search.type='search';search.maxLength=200;search.placeholder='보존 발견 검색';search.setAttribute('aria-label','보존 발견 검색');
  const find=uiNode('button','aw-link','검색');find.type='button';find.onclick=()=>{savedLibraryState.page=0;savedLibraryState.query=search.value;loadSavedLibrary();};
  const file=uiNode('input');file.type='file';file.accept='.zip';file.setAttribute('aria-label','보존 패키지 가져오기');
  const status=uiNode('p','aw-muted');status.id='savedFindingStatus';status.setAttribute('role','status');
  file.onchange=async()=>{const selected=file.files?.[0];if(!selected)return;
    try{const result=await uploadSavedFindingPackage(selected);await loadSavedLibrary();await showSavedFinding(result.id);}
    catch(error){status.textContent=error.message;}finally{file.value='';}};
  const list=uiNode('div');list.id='savedFindingList';
  const prev=uiNode('button','aw-link','이전');prev.type='button';prev.id='savedFindingPrev';prev.onclick=()=>{if(savedLibraryState.page>0){savedLibraryState.page--;loadSavedLibrary();}};
  const next=uiNode('button','aw-link','다음');next.type='button';next.id='savedFindingNext';next.onclick=()=>{savedLibraryState.page++;loadSavedLibrary();};
  const detail=uiNode('section');detail.id='savedFindingDetail';detail.setAttribute('aria-label','보존 발견 상세');
  form.append(search,find,file,status,list,prev,next,detail);dialog.append(head,form);document.body.append(dialog);return dialog;
}
async function openSavedLibrary(savedId) {
  const dialog=ensureSavedLibrary();if(!dialog.open)dialog.showModal();
  await loadSavedLibrary();if(savedId)await showSavedFinding(savedId);
}
async function loadSavedLibrary() {
  const state=savedLibraryState,request=++state.request;
  const list=document.getElementById('savedFindingList'),status=document.getElementById('savedFindingStatus');if(!list)return;
  try {
    const page=await agentApi(`/saved-findings?offset=${state.page*25}&limit=25&search=${encodeURIComponent(state.query)}`);
    if(request!==state.request)return;
    if(!page.items.length&&page.total>0&&state.page>0){state.page=Math.floor((page.total-1)/25);return loadSavedLibrary();}
    list.replaceChildren();status.textContent=`별도 보존 ${page.total}개`;
    for(const item of page.items) {
      const row=uiNode('button','fd-row');row.type='button';
      row.append(fdBadge(item.severity,FD_SEVERITY[item.severity]||item.severity,'sev'),
        uiNode('span','fd-category',item.category),uiNode('span','sm-path',`${item.method} ${item.origin}${item.path}`),
        uiNode('span','fd-verdict',FD_VERDICT[item.verdict]||item.verdict),uiNode('span','fd-status',FD_STATUS[item.status]||item.status));
      row.onclick=()=>showSavedFinding(item.id);list.append(row);
    }
    if(!page.items.length)list.append(uiNode('p','aw-muted','보존한 발견이 없습니다. 작업의 발견 상세에서 증거를 별도 보존할 수 있습니다.'));
    document.getElementById('savedFindingPrev').disabled=state.page===0;
    document.getElementById('savedFindingNext').disabled=!page.has_more;
  } catch(error){if(request===state.request)status.textContent=error.message;}
}
function savedDownload(label,url,raw=false) {
  const link=uiNode('a','aw-link',label);link.setAttribute('href',url);link.setAttribute('download','');
  if(raw)link.onclick=event=>{if(typeof confirm==='function'&&!confirm('내부 URL·요청·응답 값이 포함된 보존 자료를 로컬로 내려받을까요?'))event.preventDefault();};
  return link;
}
async function showSavedFinding(savedId,version=null) {
  const state=savedLibraryState,request=++state.detailRequest;
  state.selected=savedId;state.version=version;
  const detail=document.getElementById('savedFindingDetail');if(!detail)return;
  detail.replaceChildren(uiNode('p','aw-muted','보존 기록을 불러오는 중…'));
  try {
    const query=version?'?version='+version:'';
    const record=await agentApi('/saved-findings/'+encodeURIComponent(savedId)+query);
    if(request!==state.detailRequest)return;
    state.version=record.version;detail.replaceChildren();
    const f=record.finding,base='/saved-findings/'+encodeURIComponent(savedId),downloadBase='/api/agent'+base;
    detail.append(uiNode('h3','',`${f.category} · ${f.method} ${f.origin}${f.path}`),
      uiNode('p','aw-muted',`보존 버전 ${record.version} / ${record.current_version} · ${FD_VERDICT[f.verdict]||f.verdict} · 원본 실행 ${record.source_run_id}`));
    const versions=uiNode('select');versions.setAttribute('aria-label','증거 버전');
    for(const value of record.versions){const option=uiNode('option','',`보존 버전 ${value.version}`);option.value=value.version;option.selected=value.version===record.version;versions.append(option);}
    versions.onchange=()=>showSavedFinding(savedId,Number(versions.value));detail.append(versions);
    const report=uiNode('a','aw-link','보존 보고서');report.setAttribute('href',downloadBase+'/report?version='+record.version);report.setAttribute('target','_blank');report.setAttribute('rel','noopener');
    detail.append(report,savedDownload('증거 ZIP (요약)',downloadBase+'/evidence.zip?version='+record.version),
      savedDownload('보존 관측 ZIP',downloadBase+'/evidence.zip?raw=true&version='+record.version,true),
      savedDownload('전체 버전 복원 패키지',downloadBase+'/archive.zip',true));
    const patch=async data=>{try{await agentApi(base,{expected_revision:record.revision,...data},'PATCH');await showSavedFinding(savedId,record.version);loadSavedLibrary();}
      catch(error){if(state.selected===savedId)document.getElementById('savedFindingStatus').textContent=error.message;}};
    detail.append(fdSelect('분류 상태 (보존 발견 전체)',f.status,Object.entries(FD_STATUS),status=>patch({status})),
      fdSelect('심각도',f.severity,Object.entries(FD_SEVERITY),severity=>patch({severity})));
    const note=uiNode('textarea');note.value=f.note||'';note.maxLength=2000;note.setAttribute('aria-label','보존 발견 메모');
    const save=uiNode('button','aw-link','메모 저장');save.type='button';save.onclick=()=>patch({note:note.value});detail.append(note,save);
    for(const item of record.evidence.filter(e=>e.kind==='observation')) {
      const body=uiNode('details'),heading=uiNode('summary','',`보존한 관측 열기 · ${item.event_id.slice(0,8)}`);body.append(heading);
      body.ontoggle=async()=>{if(!body.open||body.dataset.loaded)return;body.dataset.loaded='loading';
        try{const event=await agentApi(base+'/evidence/'+encodeURIComponent(item.id)+'?version='+record.version);
          if(state.selected!==savedId||state.version!==record.version||request!==state.detailRequest)return;
          body.append(uiNode('pre','',JSON.stringify(event.data,null,2)));body.dataset.loaded='yes';}
        catch(error){body.dataset.loaded='';body.append(uiNode('p','aw-muted',error.message));}};
      detail.append(body);
    }
    const remove=uiNode('button','aw-link danger','보존 발견과 증거 삭제');remove.type='button';
    remove.onclick=async()=>{if(typeof confirm==='function'&&!confirm('별도 보존한 이 발견의 모든 증거 버전을 영구 삭제할까요? 원본 실행과 다른 보존 발견은 삭제하지 않습니다.'))return;
      try{await agentApi(base+'?expected_revision='+record.revision,undefined,'DELETE');state.detailRequest++;state.selected=null;detail.replaceChildren();await loadSavedLibrary();}
      catch(error){document.getElementById('savedFindingStatus').textContent=error.message;}};detail.append(remove);
    if(FD_VULN.has(f.category)||f.category==='auth') {
      const bodyInput=uiNode('textarea');bodyInput.setAttribute('aria-label','재검증 본문 다시 입력');bodyInput.placeholder='원본 본문을 자동 복사하지 않습니다. 필요한 경우 다시 입력하세요.';bodyInput.maxLength=100000;
      if(record.source.body_reentry_required)detail.append(bodyInput);
      const write=!['GET','HEAD'].includes(f.method);
      const retest=uiNode('button','aw-link',write?'쓰기 요청을 허용하고 새 실행으로 재검증':'새 세션으로 재검증');retest.type='button';
      retest.onclick=async()=>{if(record.source.body_reentry_required&&!bodyInput.value){document.getElementById('savedFindingStatus').textContent='재검증할 요청 본문을 다시 입력하세요.';return;}
        if(typeof confirm==='function'&&!confirm(`${f.method} ${f.origin}${f.path}에 실제 요청을 보냅니다. 과거 인증 헤더는 재사용하지 않습니다. 새 실행으로 재검증할까요?`))return;
        const input={version:record.version,allow_write_methods:write};if(record.source.body_reentry_required)input.request_body=bodyInput.value;
        try{const run=await agentApi(base+'/retest',input);document.getElementById('savedFindingDialog').close();if(typeof switchView==='function')switchView('agent');if(typeof selectRun==='function')selectRun(run.id);}
        catch(error){document.getElementById('savedFindingStatus').textContent=error.message;}};detail.append(retest);
    }
    const history=uiNode('button','aw-link','재검증 이력 보기'),historyRows=uiNode('div');history.type='button';
    history.onclick=async()=>{try{const page=await agentApi(base+'/retests');if(request!==state.detailRequest)return;historyRows.replaceChildren();
      for(const item of page.items){const row=uiNode('p','',item.evidence_available?`새 실행 ${item.run_id.slice(0,8)} · ${item.verdict?FD_VERDICT[item.verdict]||item.verdict:'판정 미기록'}`:'재검증 실행 기록 없음 · 현재 판정 미확인');historyRows.append(row);}}
      catch(error){historyRows.replaceChildren(uiNode('p','aw-muted',error.message));}};detail.append(history,historyRows);
  } catch(error){if(request===state.detailRequest)detail.replaceChildren(uiNode('p','aw-muted',error.message));}
}
