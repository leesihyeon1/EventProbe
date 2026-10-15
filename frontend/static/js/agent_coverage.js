/* Passive, local coverage projection: endpoint × 검사 종류 (actor breakdown in detail).
   Reads only the persisted run snapshot. No target or AI I/O. Text via textContent. */
const COV_CHECK_ORDER=['sqli','xss','ssti','lfi','ssrf','cmdi','redirect','nosql','access','probe','observe'];
const COV_CHECK_LABEL={sqli:'SQLi',xss:'XSS',ssti:'SSTI',lfi:'LFI',ssrf:'SSRF',cmdi:'CMDi',redirect:'리다이렉트',nosql:'NoSQL',access:'접근제어',probe:'기타 탐지',observe:'관측'};
const COV_STATES={confirmed:'확증',suspicious:'의심',inconclusive:'미확정',observed:'관측',requested:'요청',planned:'계획',none:'미검사'};
const COV_PROGRESS={none:0,planned:1,requested:2,observed:3};
const COV_VERDICT={inconclusive:1,suspicious:2,confirmed:3};
function coverageAddress(request) {
  try {
    const url=new URL(request.url);
    if(!['http:','https:'].includes(url.protocol) || url.username || url.password) return {origin:'',path:request.url||''};
    return {origin:url.origin, path:url.pathname||'/'};
  } catch(_) { return {origin:'', path:(request && request.url)||''}; }
}
function coverageCheck(action) {
  const kind=action.kind;
  if(kind==='access') return 'access';
  if(kind==='observe') return 'observe';
  if(kind==='probe' || kind==='confirm') return action.category || 'probe';
  return null; // finish / wait_oob are not endpoint checks
}
function _covProgress(target,state){ if(COV_PROGRESS[state]>COV_PROGRESS[target.state]) target.state=state; }
function _covVerdict(target,status){ if((COV_VERDICT[status]||0)>(COV_VERDICT[target.verdict]||0)) target.verdict=status; }
function covDisplay(cell){ return cell.verdict || cell.state; }
function buildCoverageModel(run) {
  const data=run.data || {}, endpoints=data.endpoints || {}, spec=data.spec || {};
  const seed=coverageAddress(endpoints.seed || spec.request || {});
  const events=[...new Map((run.events || []).map(e=>[e.id,e])).values()];
  const observations=new Set(events.filter(e=>e.kind==='observation').map(e=>e.id));
  const actions=new Map();
  for(const e of events) if(e.kind==='action' && e.step_id) actions.set(e.step_id, e.data || {});
  const rows=Object.entries(endpoints).map(([id,req])=>{
    const a=coverageAddress(req || {});
    return {id, method:(req.method || 'GET').toUpperCase(), path:a.path, origin:a.origin,
      seed:id==='seed', outside:!!seed.origin && !!a.origin && a.origin!==seed.origin};
  });
  const cells=Object.create(null), checks=new Set();
  const cellFor=(endpointId,check)=>{
    checks.add(check);
    const row=cells[endpointId] || (cells[endpointId]=Object.create(null));
    return row[check] || (row[check]={state:'none', verdict:null, stepIds:[], requests:0, observations:0,
      verifications:[], evidenceIds:[], actors:Object.create(null)});
  };
  const actorFor=(cell,actor)=>cell.actors[actor || 'unknown'] || (cell.actors[actor || 'unknown']={state:'none', verdict:null, status:null, requests:0, observations:0});
  const stepCell=step=>{
    const action=actions.get(step); if(!action) return null;
    const check=coverageCheck(action); if(!check) return null;
    return {cell:cellFor(action.endpoint_id || 'seed', check), action};
  };
  for(const [step,action] of actions) {
    const check=coverageCheck(action); if(!check) continue;
    const cell=cellFor(action.endpoint_id || 'seed', check);
    if(!cell.stepIds.includes(step)) cell.stepIds.push(step);
    _covProgress(cell,'planned'); _covProgress(actorFor(cell,action.actor_id),'planned');
  }
  const obsActor=new Map();
  for(const e of events) {
    const d=e.data || {};
    if(e.kind==='request_started') {
      const sc=stepCell(e.step_id); if(!sc) continue;
      sc.cell.requests++; _covProgress(sc.cell,'requested');
      const a=actorFor(sc.cell, d.actor_id || sc.action.actor_id); a.requests++; _covProgress(a,'requested');
    }
    if(e.kind==='observation') {
      const sc=stepCell(e.step_id); if(!sc) continue;
      const actor=d.actor_id || sc.action.actor_id;
      sc.cell.observations++; _covProgress(sc.cell,'observed');
      const a=actorFor(sc.cell,actor); a.observations++; a.status=d.response?.status ?? a.status; _covProgress(a,'observed');
      obsActor.set(e.id,{actor}); if(d.id) obsActor.set(d.id,{actor});
    }
  }
  for(const e of events) {
    if(e.kind!=='verification') continue;
    const d=e.data || {}, sc=stepCell(e.step_id); if(!sc) continue;
    const refs=[...new Set(d.evidence_ids || [])], valid=refs.filter(id=>observations.has(id));
    const status=refs.length && refs.length===valid.length && ['confirmed','suspicious','inconclusive'].includes(d.status) ? d.status : 'inconclusive';
    sc.cell.verifications.push({id:e.id, status, incomplete:valid.length!==refs.length});
    for(const id of valid) if(!sc.cell.evidenceIds.includes(id)) sc.cell.evidenceIds.push(id);
    _covVerdict(sc.cell,status);
    // Access checks cite the owner baseline too; only the tested actor gets the verdict.
    const action=sc.action, actors=new Set(valid.map(id=>obsActor.get(id)?.actor));
    for(const id of valid) {
      const info=obsActor.get(id); if(!info) continue;
      if(action.actor_id ? info.actor!==action.actor_id : actors.size!==1) continue;
      _covVerdict(actorFor(sc.cell,info.actor), status);
    }
  }
  const checkList=COV_CHECK_ORDER.filter(c=>checks.has(c));
  const summary=Object.create(null);
  for(const row of rows) for(const check of checkList) {
    const cell=cells[row.id]?.[check]; const state=cell?covDisplay(cell):'none';
    summary[state]=(summary[state] || 0)+1;
  }
  const conclusion=run.conclusion || {};
  return {rows:rows.sort((a,b)=>(a.outside-b.outside)||(b.seed-a.seed)||a.path.localeCompare(b.path)),
    checks:checkList, cells,
    summary, budget:run.state==='limited',
    unfinished:(conclusion.unfinished_steps || []).length,
    partial:conclusion.completion==='partial'};
}
let coverageState={runId:null,model:null,signature:'',selected:null};
function resetCoverage() {
  coverageState={runId:null,model:null,signature:'',selected:null};
  agentEl('cvGrid').replaceChildren();agentEl('cvDetail').replaceChildren();agentEl('cvSummary').textContent='';
  delete agentEl('cvDetail').dataset.signature;
}
function renderAgentCoverage(run) {
  if(coverageState.runId!==run.id){resetCoverage();coverageState.runId=run.id;}
  const model=buildCoverageModel(run), signature=JSON.stringify(model);
  if(signature===coverageState.signature) return;
  coverageState.signature=signature;coverageState.model=model;drawCoverage();
}
function covCell(state){const b=uiNode('span','cv-cell',COV_STATES[state]||state);b.dataset.state=state;return b;}
function selectCoverage(key) {
  coverageState.selected=key;
  for(const b of agentEl('cvGrid').querySelectorAll('button[data-key]')) b.setAttribute('aria-pressed',String(b.dataset.key===key));
  const [endpointId,check]=key.split('\u0000');
  renderCoverageDetail(endpointId,check);
}
function drawCoverage() {
  const model=coverageState.model; if(!model) return;
  const counted=Object.entries(model.summary).filter(([s])=>s!=='none').map(([s,n])=>`${COV_STATES[s]} ${n}`).join(' · ');
  agentEl('cvSummary').textContent=`엔드포인트 ${model.rows.length} × 검사 ${model.checks.length}` +
    (counted?` · ${counted}`:'') + (model.budget?' · 예산 소진(미실행=미검사)':'') + (model.unfinished?` · 미판정 ${model.unfinished}`:'');
  if(coverageState.selected){const [eid,chk]=coverageState.selected.split('\u0000');
    if(!model.rows.some(r=>r.id===eid) || !model.checks.includes(chk)) coverageState.selected=null;}
  const grid=agentEl('cvGrid'), scroll=grid.scrollTop;
  const focused=document.activeElement, focusKey=grid.contains(focused)?focused.dataset.key:null;
  grid.replaceChildren();
  if(!model.checks.length){grid.append(uiNode('p','sm-empty','기록된 검사가 없습니다.'));renderCoverageDetail();return;}
  const table=uiNode('table','cv-table'), head=uiNode('tr');
  head.append(uiNode('th','cv-corner','엔드포인트'));
  for(const check of model.checks){const th=uiNode('th','',COV_CHECK_LABEL[check]||check);th.scope='col';head.append(th);}
  const thead=uiNode('thead');thead.append(head);const tbody=uiNode('tbody');
  for(const row of model.rows) {
    const tr=uiNode('tr'); if(row.outside) tr.dataset.outside='true';
    const label=uiNode('th','cv-row-label');label.scope='row';
    label.append(uiNode('span','sm-method',row.method),uiNode('span','cv-path',row.path||'/'));
    if(row.outside) label.append(uiNode('span','sm-flag','범위 밖'));
    tr.append(label);
    for(const check of model.checks) {
      const td=uiNode('td');const cell=model.cells[row.id]?.[check];
      const state=cell?covDisplay(cell):'none';const key=row.id+'\u0000'+check;
      const b=uiNode('button','cv-btn');b.type='button';b.dataset.key=key;
      b.setAttribute('aria-pressed',String(coverageState.selected===key));
      b.setAttribute('aria-label',`${row.path||'/'} · ${COV_CHECK_LABEL[check]||check} · ${COV_STATES[state]}`);
      b.append(covCell(state));b.onclick=()=>selectCoverage(key);
      if(cell?.verifications.some(v=>v.incomplete)) b.append(uiNode('span','cv-mark','!'));
      td.append(b);tr.append(td);
    }
    tbody.append(tr);
  }
  table.replaceChildren(thead,tbody);grid.append(table);grid.scrollTop=scroll;
  if(focusKey) [...grid.querySelectorAll('[data-key]')].find(el=>el.dataset.key===focusKey)?.focus({preventScroll:true});
  const sel=coverageState.selected?coverageState.selected.split('\u0000'):null;
  renderCoverageDetail(sel?.[0],sel?.[1]);
}
function showCoverageEvidence(id) {
  if(_awRun?.compact) return openHistoryEvidence(id);
  setDetailMode('timeline');
  const event=[...agentEl('agentEvents').children].find(el=>el.dataset.event===id);
  if(event){event.open=true;event.scrollIntoView({block:'center'});event.querySelector('summary')?.focus();}
}
function renderCoverageDetail(endpointId,check) {
  const panel=agentEl('cvDetail');
  const model=coverageState.model, row=model?.rows.find(r=>r.id===endpointId);
  const cell=endpointId&&check?model?.cells[endpointId]?.[check]:null;
  const signature=JSON.stringify([endpointId,check,cell||null]);
  if(panel.dataset.signature===signature) return;
  panel.dataset.signature=signature;
  const focused=panel.contains(document.activeElement)?document.activeElement.dataset.event:null;
  panel.replaceChildren();
  if(!row || !check){panel.append(uiNode('p','sm-empty','셀을 선택하세요'));return;}
  const state=cell?covDisplay(cell):'none';
  panel.append(uiNode('h4','',`${COV_CHECK_LABEL[check]||check}`),uiNode('p','sm-origin',`${row.method} ${row.path||'/'}`),covCell(state));
  const facts=uiNode('dl','sm-facts');
  for(const [label,value] of [['상태',COV_STATES[state]],['요청 / 관측',`${cell?.requests||0} / ${cell?.observations||0}`],['판정 수',String(cell?.verifications.length||0)]])
    facts.append(uiNode('dt','',label),uiNode('dd','',value));
  panel.append(facts);
  if(cell && Object.keys(cell.actors).length) {
    panel.append(uiNode('h5','','행위자별'));
    for(const [id,a] of Object.entries(cell.actors)) {
      const line=uiNode('div','sm-actor');
      line.append(uiNode('strong','',id),uiNode('span','',COV_STATES[a.verdict||a.state]),uiNode('span','',a.status!==null?`HTTP ${a.status}`:'응답 없음'));
      panel.append(line);
    }
  }
  if(cell?.evidenceIds.length) {
    panel.append(uiNode('h5','','관련 증거'));const list=uiNode('div','sm-evidence');
    cell.evidenceIds.forEach((id,i)=>{const b=uiCommand('FileSearch',`응답 관측 ${i+1}`,()=>showCoverageEvidence(id),'aw-link');b.dataset.event=id;b.append(document.createTextNode(`응답 관측 ${i+1}`));list.append(b);});
    panel.append(list);
    if(focused) [...list.children].find(b=>b.dataset.event===focused)?.focus({preventScroll:true});
  } else if(state==='none') panel.append(uiNode('p','aw-muted','이 엔드포인트에서 해당 검사를 실행하지 않았습니다.'));
}
