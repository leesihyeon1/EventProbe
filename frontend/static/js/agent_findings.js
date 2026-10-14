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
    _awRun=updated;findingsState.signature='';renderAgentFindings(updated);selectFinding(id);
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
  panel.append(exports);
  if(FD_VULN.has(f.category)) {
    const retest=uiNode('button','aw-link fd-retest','새 실행으로 재검증');retest.type='button';
    retest.onclick=()=>retestFinding(f);
    panel.append(retest);
  }
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
function showFindingEvidence(id) {
  setDetailMode('timeline');
  const event=[...agentEl('agentEvents').children].find(el=>el.dataset.event===id);
  if(event){event.open=true;event.scrollIntoView({block:'center'});event.querySelector('summary')?.focus();}
}
