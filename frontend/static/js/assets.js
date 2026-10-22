/* Read-only projection of persisted maps. All requests stay on the local API. */
const assets={page:0,itemPage:0,sequence:0,run:null,model:null,selected:null,initialized:false,global:false,total:0,focusId:''};
function setAssetFocus(id) {
  const next=/^[a-f0-9]{64}$/i.test(id||'')?id.toLowerCase():'';
  if(assets.focusId!==next){assets.focusId=next;assets.itemPage=0;assets.selected=next||null;}
  if(next&&assets.initialized){agentEl('assetRun').value='';agentEl('assetSearch').value='';}
}
function assetRoute() {
  const base='#assets'+(assets.focusId?'/'+assets.focusId:'');
  if(typeof agentEl!=='function')return base;
  const query=new URLSearchParams();
  for(const [name,key] of [['From','from'],['Through','through']]) {
    const value=agentEl('asset'+name).value;
    if(/^\d{4}-\d{2}-\d{2}$/.test(value))query.set(key,value);
  }
  if(agentEl('assetArchived').checked)query.set('archived','1');
  return base+(query.size?'?'+query:'');
}
function restoreAssetFilters(rawQuery) {
  const query=new URLSearchParams(rawQuery||'');
  for(const [name,key] of [['From','from'],['Through','through']]) {
    const value=query.get(key)||'';
    agentEl('asset'+name).value=/^\d{4}-\d{2}-\d{2}$/.test(value)?value:'';
  }
  agentEl('assetArchived').checked=query.get('archived')==='1';
  assets.itemPage=0;
}
function assetDayStart(value) {
  const [year,month,day]=value.split('-').map(Number);
  const date=new Date(year,month-1,day);
  return date.getFullYear()===year&&date.getMonth()===month-1&&date.getDate()===day
    ?date:null;
}
async function openAssets() {
  if(!assets.initialized) {
    assets.initialized=true;
    let debounce;
    agentEl('assetRunSearch').oninput=()=>{clearTimeout(debounce);debounce=setTimeout(()=>{assets.page=0;loadAssetRuns();},250);};
    agentEl('assetArchived').onchange=()=>{assets.page=0;assets.itemPage=0;syncWorkspace('assets');loadAssetRuns();};
    for(const name of ['From','Through'])agentEl('asset'+name).onchange=()=>{
      assets.itemPage=0;syncWorkspace('assets');if(assets.global)loadAssetMap();
    };
    agentEl('assetPrev').onclick=()=>{assets.page--;loadAssetRuns();};
    agentEl('assetNext').onclick=()=>{assets.page++;loadAssetRuns();};
    agentEl('assetRefresh').onclick=loadAssetRuns;
    agentEl('assetRun').onchange=()=>{setAssetFocus('');syncWorkspace('assets');loadAssetMap();};
    agentEl('assetSearch').oninput=()=>{if(assets.focusId){setAssetFocus('');syncWorkspace('assets');}if(assets.global){clearTimeout(assets.searchTimer);assets.searchTimer=setTimeout(()=>{assets.itemPage=0;loadAssetMap();},250);}else drawAssets();};
    agentEl('assetClearFocus').onclick=()=>{setAssetFocus('');syncWorkspace('assets');loadAssetMap();};
    agentEl('assetState').onchange=drawAssets;
    agentEl('assetItemPrev').onclick=()=>{assets.itemPage--;loadAssetMap();};
    agentEl('assetItemNext').onclick=()=>{assets.itemPage++;loadAssetMap();};
    agentEl('assetOpen').onclick=()=>{const row=assets.model?.rows.find(r=>r.key===assets.selected);const id=assets.run?.id||row?.runs?.[0]?.id;if(id){switchView('agent');selectRun(id);}};
  }
  await loadAssetRuns();
}
function clearAssets(message) {
  assets.run=null;assets.model=null;assets.selected=null;
  agentEl('assetOpen').disabled=true;
  agentEl('assetGraph').replaceChildren(uiNode('p','sm-empty',message));
  agentEl('assetDetail').replaceChildren();agentEl('assetStack').textContent='';agentEl('assetCount').textContent='';
}
async function loadAssetRuns() {
  const token=++assets.sequence, select=agentEl('assetRun'), previous=select.value;
  clearAssets('작업 불러오는 중…');
  try {
    const query=new URLSearchParams({offset:assets.page*20,limit:20,search:agentEl('assetRunSearch').value,archived:agentEl('assetArchived').checked?'true':'false'});
    const result=await agentApi('/history/runs?'+query);
    if(token!==assets.sequence)return;
    select.replaceChildren();
    const all=uiNode('option','','전체 작업');all.value='';select.append(all);
    for(const run of result.runs) {const option=uiNode('option','',`${run.name||run.goal||'검증 작업'} · ${run.id.slice(0,8)}`);option.value=run.id;select.append(option);}
    select.disabled=false;
    agentEl('assetPrev').disabled=assets.page===0;
    agentEl('assetNext').disabled=(assets.page+1)*20>=result.total;
    if(result.runs.some(r=>r.id===previous))select.value=previous;
    await loadAssetMap();
  } catch(error) {if(token===assets.sequence)clearAssets('작업 조회 실패: '+error.message);}
}
async function loadAssetMap() {
  const id=agentEl('assetRun').value, token=++assets.sequence;
  clearAssets('자산 불러오는 중…');
  assets.global=!id;
  agentEl('assetFocus').hidden=!assets.focusId;
  agentEl('assetFocusLabel').textContent=assets.focusId?`선택 자산 ${assets.focusId.slice(0,12)}…`:'';
  agentEl('assetState').disabled=!id;
  agentEl('assetFrom').disabled=!!id;
  agentEl('assetThrough').disabled=!!id;
  agentEl('assetState').title=id?'관측 상태':'상태는 작업별 사이트맵에서 확인';
  if(!id)agentEl('assetState').value='';
  try {
    if(!id) {
      const query=new URLSearchParams({offset:assets.itemPage*50,limit:50,search:agentEl('assetSearch').value,archived:agentEl('assetArchived').checked?'true':'false'});
      if(assets.focusId)query.set('asset_id',assets.focusId);
      const from=agentEl('assetFrom').value,through=agentEl('assetThrough').value;
      const start=from?assetDayStart(from):null,end=through?assetDayStart(through):null;
      if((from&&!start)||(through&&!end)||(start&&end&&end<start)) {
        clearAssets('요청 관측 날짜 범위를 확인해 주세요.');return;
      }
      if(start)query.set('since',String(start.getTime()/1000));
      if(end){end.setDate(end.getDate()+1);query.set('before',String(end.getTime()/1000));}
      const result=await agentApi('/history/assets?'+query);
      if(token!==assets.sequence)return;
      assets.total=result.total;
      assets.model={rows:result.assets.map(a=>({...a,key:a.id,seed:false,browser:false,
        state:'registered',requests:[],observations:[],sources:[],actors:{},failed:false,outside:false})),limited:false};
      agentEl('assetStack').textContent='작업과 수동 요청에서 수집한 경로 · 작업을 선택하면 관측 및 판정 상태 표시';
      drawAssets();return;
    }
    const run=await agentApi('/history/runs/'+encodeURIComponent(id)+'/map');
    if(token!==assets.sequence)return;
    assets.run=run;assets.model=buildSiteMapModel(run);
    agentEl('assetOpen').disabled=false;
    const recon=run.recon||{};
    agentEl('assetStack').textContent=[...(recon.technologies||[]),...(recon.server_headers||[])].join(' · ');
    drawAssets();
  } catch(error) {if(token===assets.sequence)clearAssets('사이트맵 조회 실패: '+error.message);}
}
function drawAssets() {
  if(!assets.model)return;
  const rows=filterSiteMapRows(assets.model.rows,assets.global?'':agentEl('assetSearch').value,'',agentEl('assetState').value);
  agentEl('assetCount').textContent=assets.global?`경로 ${assets.total}개 · ${assets.itemPage+1}페이지`:`경로 ${rows.length} / ${assets.model.rows.length}개${assets.model.limited?' · 수집 한도 도달':''}`;
  agentEl('assetItemPrev').disabled=!assets.global||assets.itemPage===0;
  agentEl('assetItemNext').disabled=!assets.global||(assets.itemPage+1)*50>=assets.total;
  const graph=agentEl('assetGraph');graph.replaceChildren();
  if(!rows.length){graph.append(uiNode('p','sm-empty','표시할 경로가 없습니다.'));agentEl('assetDetail').replaceChildren();return;}
  if(!rows.some(r=>r.key===assets.selected))assets.selected=rows[0].key;
  const roots=new Map();
  for(const row of rows) {
    if(!roots.has(row.origin))roots.set(row.origin,{label:row.origin,children:new Map(),rows:[]});
    let branch=roots.get(row.origin);
    for(const part of row.path.split('/').filter(Boolean)) {
      if(!branch.children.has(part))branch.children.set(part,{label:part,children:new Map(),rows:[]});
      branch=branch.children.get(part);
    }
    branch.rows.push(row);
  }
  const render=node=>{
    const branch=uiNode('div','asset-branch'), label=uiNode('div','asset-folder',node.label);
    branch.append(label);
    const children=uiNode('div','asset-children');
    for(const row of node.rows) {
      const button=uiNode('button','asset-node');button.type='button';button.dataset.key=row.key;
      button.setAttribute('aria-pressed',String(row.key===assets.selected));button.title=row.method+' '+siteMapLabel(row);
      button.append(uiNode('span','sm-method',row.method),uiNode('span','sm-path',siteMapLabel(row)),siteMapBadge(row));
      button.onclick=()=>{assets.selected=row.key;graph.querySelectorAll('[data-key]').forEach(b=>b.setAttribute('aria-pressed',String(b.dataset.key===row.key)));showAssetDetail(row);};
      children.append(button);
    }
    for(const child of node.children.values())children.append(render(child));
    branch.append(children);return branch;
  };
  for(const root of roots.values())graph.append(render(root));
  showAssetDetail(rows.find(r=>r.key===assets.selected));
}
function showAssetDetail(row) {
  const panel=agentEl('assetDetail');panel.replaceChildren();
  if(!row){agentEl('assetOpen').disabled=true;return;}
  panel.append(uiNode('h4','',row.method+' '+row.path),uiNode('p','sm-origin',row.origin),siteMapBadge(row));
  if(assets.global) {
    const facts=uiNode('dl','sm-facts');
    for(const [key,value] of [['작업',`${row.run_count}개`],['수동 요청',`${row.manual_count||0}개`],['쿼리 키',row.query_known===false?'과거 기록에서 확인 불가':row.query.join(', ')||'없음'],['본문 필드',row.fields.join(', ')||'없음'],['최초 연결',new Date(row.first_seen*1000).toLocaleString('ko-KR')],['최근 연결 갱신',new Date(row.last_seen*1000).toLocaleString('ko-KR')]])facts.append(uiNode('dt','',key),uiNode('dd','',value));
    panel.append(facts,uiNode('h5','','관련 작업'));
    const links=uiNode('div','lookup-actions');
    for(const [kind,label] of [['traffic','관련 트래픽'],['findings','관련 발견']]) {
      const button=uiNode('button','aw-link',label);button.type='button';
      button.onclick=()=>{setGlobalLookupAssetFilter(kind,row.id);switchView(kind);};
      links.append(button);
    }
    panel.append(links);
    for(const run of row.runs){const button=uiCommand('ArrowRight',run.name||run.id.slice(0,8),()=>{switchView('agent');selectRun(run.id);},'aw-link');button.append(document.createTextNode(run.name||run.id.slice(0,8)));panel.append(button);}
    agentEl('assetOpen').disabled=!row.runs.length;return;
  }
  agentEl('assetOpen').disabled=false;
  const facts=uiNode('dl','sm-facts');
  for(const [key,value] of [['파라미터',row.query.join(', ')||'없음'],['본문 필드',row.fields.join(', ')||'없음'],['요청 / 응답',`${row.requests.length} / ${row.observations.length}`],['발견 출처',row.seed?'시작 요청':row.browser?'브라우저 통신':row.sources.map(s=>s.path).join(', ')||'출처 미기록'],['HTTP 상태',[...new Set(Object.values(row.actors).map(a=>a.status).filter(s=>s!==null))].join(', ')||'미관측']])facts.append(uiNode('dt','',key),uiNode('dd','',value));
  panel.append(facts);
  if(row.formCandidates?.length) {
    const labels={pending:'검사 대기',testing:'검사 중',interrupted:'검사 중단',skipped_budget:'예산 부족으로 미검사',untested:'미검사',confirmed:'확증',suspicious:'의심',inconclusive:'미확정'};
    for(const candidate of row.formCandidates)panel.append(uiNode('p','sm-actor',`${candidate.login?'로그인 폼':'POST 폼'} · ${labels[candidate.status]||candidate.status}`));
  }
  if(row.failed)panel.append(uiNode('p','sm-flag','요청 오류 기록 있음'));
  if(row.outside)panel.append(uiNode('p','sm-flag','시작 요청과 다른 출처'));
}
