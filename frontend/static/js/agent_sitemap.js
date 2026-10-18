/* Passive, local projection of persisted request evidence. No target or AI I/O. */
function siteMapAddress(request) {
  try {
    const url = new URL(request.url);
    if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password) return null;
    const query = [...new Set([...url.searchParams.keys(), ...Object.keys(request.params || {})])].sort();
    const method = (request.method || 'GET').toUpperCase();
    return {key:JSON.stringify([url.origin, method, url.pathname, query]), origin:url.origin,
      method, path:url.pathname, query};
  } catch (_) { return null; }
}
function buildSiteMapModel(run) {
  const data=run.data || {}, spec=data.spec || {}, endpoints=data.endpoints || {};
  const seed=siteMapAddress(endpoints.seed || spec.request || {});
  const rows=new Map(), requests=new Map(), observations=new Map(), actions=new Map();
  const events=[...new Map((run.events || []).map(e=>[e.id,e])).values()];
  const ensure=request=>{
    const a=siteMapAddress(request || {}); if(!a) return null;
    if(!rows.has(a.key)) rows.set(a.key,{...a, fields:[],seed:false, registered:false, scopeKnown:!!seed, outside:!!seed && a.origin!==seed.origin,
      sources:[], requests:[], observations:[], errors:[], verifications:[], actors:Object.create(null), failed:false, truncated:false,browser:false});
    const row=rows.get(a.key);
    row.fields=[...new Set([...row.fields,...(request.body_fields||[])])].sort();
    return row;
  };
  for(const [id,request] of Object.entries(endpoints)) {
    const row=ensure(request); if(row){row.registered=true;row.seed ||= id==='seed';}
  }
  if(!endpoints.seed && seed){const row=ensure(spec.request);row.seed=true;row.registered=true;}
  for(const e of events) if(e.kind==='action' && e.step_id) actions.set(e.step_id,e.data || {});
  // Payload variants belong to the tested endpoint, not new discovered assets.
  const rowFor=e=>{
    const d=e.data || {}, action=actions.get(e.step_id), actual=d.request;
    if(action && ['probe','confirm'].includes(action.kind)) {
      const base=endpoints[action.endpoint_id || 'seed'];
      const a=siteMapAddress(actual || {}), b=siteMapAddress(base || {});
      if(a && b && a.origin===b.origin) return ensure(base);
    }
    return ensure(actual);
  };
  const actorFor=(row,id)=>row.actors[id || 'unknown'] ||= {requests:0,observations:0,status:null,verdicts:[],failed:false};
  for(const e of events) {
    const d=e.data || {};
    if(e.kind==='request_started') {
      const row=rowFor(e); if(!row) continue;
      row.requests.push(e.id);requests.set(e.id,{row,actor:d.actor_id});actorFor(row,d.actor_id).requests++;
    }
    if(e.kind==='observation') {
      const row=rowFor(e) || requests.get(d.request_id)?.row; if(!row) continue;
      const actor=d.actor_id || requests.get(d.request_id)?.actor;
      row.observations.push(e.id);row.truncated ||= !!d.response?.truncated;
      row.lastObserved=e.created;
      const state=actorFor(row,actor);state.observations++;state.status=d.response?.status ?? null;
      observations.set(e.id,{row,actor});
      if(d.id) observations.set(d.id,{row,actor,eventId:e.id});
    }
    if(e.kind==='request_error') {
      const request=requests.get(d.request_id);
      if(request){request.row.failed=true;request.row.errors.push(e.id);actorFor(request.row,request.actor).failed=true;}
    }
  }
  for(const e of events) {
    const d=e.data || {};
    if(e.kind==='discovery') {
      const row=ensure(endpoints[d.endpoint_id]);
      const source=observations.get(d.source_observation_id);
      if(row && source) row.sources.push({eventId:source.eventId || d.source_observation_id,path:source.row.path});
    }
    if(e.kind==='browser_discovery') {
      const row=ensure(endpoints[d.endpoint_id]);
      if(row) row.browser=true;
    }
    if(e.kind==='verification') {
      const refs=[...new Set(d.evidence_ids || [])], valid=refs.map(id=>observations.get(id)).filter(Boolean);
      const status=refs.length && refs.length===valid.length && ['confirmed','suspicious','inconclusive'].includes(d.status) ? d.status : 'inconclusive';
      for(const row of new Set(valid.map(o=>o.row))) row.verifications.push({id:e.id,status,category:d.category || '',incomplete:valid.length!==refs.length});
      const action=actions.get(e.step_id), actors=new Set(valid.map(o=>o.actor));
      for(const o of valid) {
        // Access checks also cite the owner's baseline; that is not the tested actor.
        if(action?.actor_id ? o.actor!==action.actor_id : actors.size!==1) continue;
        const actor=actorFor(o.row,o.actor);
        if(!actor.verdicts.includes(status)) actor.verdicts.push(status);
      }
    }
  }
  for(const candidate of run.recon?.form_candidates || []) {
    const address=siteMapAddress(endpoints[candidate.endpoint_id] || {});
    const row=address && rows.get(address.key);
    if(row) (row.formCandidates ||= []).push(candidate);
  }
  const result=[...rows.values()].sort((a,b)=>a.origin.localeCompare(b.origin)||a.path.localeCompare(b.path)||a.method.localeCompare(b.method)||a.key.localeCompare(b.key));
  for(const row of result) {
    row.state=['confirmed','suspicious','inconclusive'].find(s=>row.verifications.some(v=>v.status===s)) ||
      (row.observations.length?'observed':row.requests.length?'requested':row.browser?'discovered':row.seed?'registered':'discovered');
  }
  return {rows:result, limited:events.some(e=>e.kind==='discovery_limit')};
}
const SM_STATES={registered:'등록',discovered:'발견 · 미요청',requested:'요청 · 응답 없음',observed:'관측 · 미판정',confirmed:'확증',suspicious:'의심',inconclusive:'미확정'};
let siteMapState={runId:null,model:null,signature:'',selected:null,view:'tree',open:new Map()};
function filterSiteMapRows(rows,search,method,state) {
  const q=search.trim().toLowerCase();
  return rows.filter(r=>(!method||r.method===method) && (!q||`${r.origin} ${r.path} ${r.query.join(' ')}`.toLowerCase().includes(q)) &&
    (!state || (state==='failed'?r.failed:state==='outside'?r.outside:state==='judged'?r.verifications.length>0:r.state===state)));
}
function resetSiteMap() {
  siteMapState={runId:null,model:null,signature:'',selected:null,view:siteMapState.view,open:new Map()};
  agentEl('smContent').replaceChildren();agentEl('smDetail').replaceChildren();agentEl('smCount').textContent='';agentEl('smStack').textContent='';
  delete agentEl('smDetail').dataset.signature;
  agentEl('smSearch').value='';agentEl('smMethod').value='';agentEl('smState').value='';
}
function initSiteMap() {
  agentEl('smSearch').oninput=drawSiteMap;
  agentEl('smMethod').onchange=drawSiteMap;agentEl('smState').onchange=drawSiteMap;
  for(const mode of ['tree','list']) agentEl(mode==='tree'?'smTree':'smList').onclick=()=>{siteMapState.view=mode;drawSiteMap();};
}
function renderAgentSiteMap(run) {
  if(siteMapState.runId!==run.id){resetSiteMap();siteMapState.runId=run.id;}
  const model=buildSiteMapModel(run), signature=JSON.stringify([model,run.recon || null]);
  if(signature===siteMapState.signature) return;
  siteMapState.signature=signature;siteMapState.model=model;
  const recon=run.recon || {};
  const labels=[`관측 ${recon.observed_endpoint_count ?? 0}/${recon.endpoint_count ?? model.rows.length}`];
  if(recon.technologies?.length) labels.push(`기술 ${recon.technologies.join(', ')}`);
  if(recon.server_headers?.length) labels.push(`서버 ${recon.server_headers.slice(0,3).join(', ')}`);
  agentEl('smStack').textContent=run.recon?labels.join(' · '):'';
  const method=agentEl('smMethod'), selected=method.value;
  method.replaceChildren(uiNode('option','','모든 메서드'));method.firstChild.value='';
  for(const name of [...new Set(model.rows.map(r=>r.method))].sort()){const option=uiNode('option','',name);option.value=name;method.append(option);}
  method.value=[...method.options].some(o=>o.value===selected)?selected:'';
  drawSiteMap();
}
function siteMapBadge(row) {
  const b=uiNode('span','sm-badge',SM_STATES[row.state]);b.dataset.state=row.state;return b;
}
function siteMapLabel(row) {return row.path+(row.query.length?` ? ${row.query.join(', ')}`:'');}
function selectSiteMapRow(key) {
  siteMapState.selected=key;
  for(const b of agentEl('smContent').querySelectorAll('button[data-key]')) b.setAttribute('aria-pressed',String(b.dataset.key===key));
  renderSiteMapDetail(siteMapState.model.rows.find(r=>r.key===key));
}
function siteMapRowButton(row) {
  const b=uiNode('button','sm-endpoint');b.type='button';b.dataset.key=row.key;
  b.setAttribute('aria-pressed',String(siteMapState.selected===row.key));
  b.append(uiNode('span','sm-method',row.method),uiNode('span','sm-path',siteMapLabel(row)),siteMapBadge(row));
  if(row.failed || row.outside){const flag=uiNode('span','sm-flag',row.outside?'범위 밖':'요청 오류');b.append(flag);}
  b.onclick=()=>selectSiteMapRow(row.key);return b;
}
function drawSiteMap() {
  const model=siteMapState.model; if(!model) return;
  const search=agentEl('smSearch').value, rows=filterSiteMapRows(model.rows,search,agentEl('smMethod').value,agentEl('smState').value);
  const filtering=!!(search.trim() || agentEl('smMethod').value || agentEl('smState').value);
  agentEl('smCount').textContent=`기록된 경로 ${model.rows.length}개 · 표시 ${rows.length}개${model.limited?' · 경로 수집 한도 도달':''}`;
  agentEl('smTree').setAttribute('aria-pressed',String(siteMapState.view==='tree'));
  agentEl('smList').setAttribute('aria-pressed',String(siteMapState.view==='list'));
  if(!rows.some(r=>r.key===siteMapState.selected)) siteMapState.selected=rows[0]?.key || null;
  const content=agentEl('smContent'), scroll=content.scrollTop;
  // Keep keyboard focus across polling without resetting the search field or tree state.
  const focused=document.activeElement, focusKey=content.contains(focused)?focused.dataset.key || focused.dataset.folder:null;
  content.replaceChildren();
  if(!rows.length) content.append(uiNode('p','sm-empty',model.rows.length?'조건에 맞는 경로가 없습니다.':'기록된 경로가 없습니다.'));
  else if(siteMapState.view==='list') {
    for(const row of rows) {const item=uiNode('div','sm-list-row');item.append(uiNode('span','sm-origin',row.origin),siteMapRowButton(row));content.append(item);}
  } else {
    const roots=new Map();
    for(const row of rows) {
      if(!roots.has(row.origin)) roots.set(row.origin,{label:row.origin,children:new Map(),rows:[],key:row.origin});
      let node=roots.get(row.origin);
      for(const [index,part] of row.path.split('/').slice(1).entries()) {
        if(!part && index===row.path.split('/').length-2) continue;
        const key=node.key+'/'+part;
        if(!node.children.has(part)) node.children.set(part,{label:part+'/',key,children:new Map(),rows:[]});
        node=node.children.get(part);
      }
      node.rows.push(row);
    }
    const renderBranch=(node,depth)=>{
      const details=uiNode('details','sm-branch'), summary=uiNode('summary','',node.label);summary.dataset.folder=node.key;
      details.open=filtering?true:siteMapState.open.get(node.key) ?? depth<2;
      details.ontoggle=()=>{if(details.isConnected && !filtering) siteMapState.open.set(node.key,details.open);};
      details.append(summary);
      const body=uiNode('div','sm-children');
      for(const row of node.rows) body.append(siteMapRowButton(row));
      for(const child of node.children.values()) body.append(renderBranch(child,depth+1));
      details.append(body);return details;
    };
    for(const root of roots.values()) content.append(renderBranch(root,0));
  }
  content.scrollTop=scroll;
  if(focusKey) [...content.querySelectorAll('[data-key], [data-folder]')].find(el=>(el.dataset.key||el.dataset.folder)===focusKey)?.focus({preventScroll:true});
  renderSiteMapDetail(rows.find(r=>r.key===siteMapState.selected));
}
function showSiteMapEvidence(id) {
  if(_awRun?.compact) return openHistoryEvidence(id);
  setDetailMode('timeline');
  const event=[...agentEl('agentEvents').children].find(el=>el.dataset.event===id);
  if(event){event.open=true;event.scrollIntoView({block:'center'});event.querySelector('summary')?.focus();}
}
function renderSiteMapDetail(row) {
  const panel=agentEl('smDetail'),signature=JSON.stringify(row || null);
  if(panel.dataset.signature===signature) return;
  panel.dataset.signature=signature;
  const focused=panel.contains(document.activeElement)?document.activeElement.dataset.event:null;
  panel.replaceChildren();
  if(!row){panel.append(uiNode('p','sm-empty','선택된 경로 없음'));return;}
  panel.append(uiNode('h4','',row.method+' '+row.path),uiNode('p','sm-origin',row.origin),siteMapBadge(row));
  const facts=uiNode('dl','sm-facts');
  for(const [label,value] of [['쿼리 키',row.query.join(', ')||'없음'],['본문 필드',row.fields.join(', ')||'없음'],['출처',row.seed?'시작 요청':row.browser?'브라우저 통신에서 발견':row.sources.length?'응답에서 발견':row.registered?'출처 미기록':'요청 기록'],['요청 / 응답',`${row.requests.length} / ${row.observations.length}`],['범위',!row.scopeKnown?'시작 요청 미기록':row.outside?'시작 요청과 다른 출처':'시작 요청과 동일 출처']]) facts.append(uiNode('dt','',label),uiNode('dd','',value));
  if(row.lastObserved) facts.append(uiNode('dt','','최근 관측'),uiNode('dd','',new Date(row.lastObserved*1000).toLocaleString('ko-KR')));
  panel.append(facts);
  if(row.formCandidates?.length) {
    const labels={pending:'검사 대기',testing:'검사 중',interrupted:'검사 중단',skipped_budget:'예산 부족으로 미검사',untested:'미검사',confirmed:'확증',suspicious:'의심',inconclusive:'미확정'};
    panel.append(uiNode('h5','','폼 검사 상태'));
    for(const candidate of row.formCandidates) panel.append(uiNode('p','sm-actor',
      `${candidate.login?'로그인 폼':'POST 폼'} · ${labels[candidate.status]||candidate.status} · ${candidate.source==='rendered_dom'?'브라우저 DOM':candidate.source==='html'?'HTML 응답':'등록된 요청'}`));
  }
  if(row.truncated) panel.append(uiNode('p','sm-flag','일부 응답이 잘림'));
  if(row.failed) panel.append(uiNode('p','sm-flag','요청 오류 기록 있음'));
  if(Object.keys(row.actors).length) {
    panel.append(uiNode('h5','','행위자별 관측'));
    for(const [id,a] of Object.entries(row.actors)) {
      const line=uiNode('div','sm-actor');line.append(uiNode('strong','',id),uiNode('span','',a.status!==null?`HTTP ${a.status}`:'응답 없음'),uiNode('span','',a.verdicts.map(s=>SM_STATES[s]).join(' · ')||'미판정'));
      if(a.failed) line.append(uiNode('span','sm-flag','요청 오류'));panel.append(line);
    }
  }
  const links=[...row.sources.map(s=>[s.eventId,`발견 근거 · ${s.path}`]),...row.verifications.map(v=>[v.id,`${SM_STATES[v.status]} · ${v.category||'검증'}${v.incomplete?' · 증거 일부 누락':''}`]),...row.errors.map((id,i)=>[id,`요청 오류 ${i+1}`]),...row.observations.map((id,i)=>[id,`응답 관측 ${i+1}`]),...row.requests.filter(id=>!row.observations.length).map((id,i)=>[id,`요청 ${i+1}`])];
  if(links.length) {
    panel.append(uiNode('h5','','관련 증거'));const list=uiNode('div','sm-evidence');
    for(const [id,label] of links){const b=uiCommand('FileSearch',label,()=>showSiteMapEvidence(id),'aw-link');b.dataset.event=id;b.append(document.createTextNode(label));list.append(b);}panel.append(list);
    if(focused) [...list.children].find(b=>b.dataset.event===focused)?.focus({preventScroll:true});
  }
}
