const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const vm=require('node:vm');
const source=fs.readFileSync(path.join(__dirname,'../static/js/agent.js'),'utf8');

class Element {
  constructor(tag='div'){this.tagName=tag;this.children=[];this.dataset={};this.attributes={};this.value='';this.textContent='';this.hidden=false;}
  append(...n){this.children.push(...n);} replaceChildren(...n){this.children=[...n];}
  setAttribute(k,v){this.attributes[k]=v;} showModal(){this.open=true;} close(){this.open=false;}
}
const desc=n=>n.children.flatMap(c=>[c,...desc(c)]);
const all=n=>[n,...desc(n)];
const INCIDENTS=[
  {id:'i1',created:20,title:'SQLi 경보',category:'sqli',source:'soar',asset_id:'app-7',traffic_id:'flow-42',external_id:'EVT-9'},
  {id:'i2',created:10,title:'XSS 경보',category:'xss',source:'siem',asset_id:'web-1',traffic_id:'',external_id:''}];

function setup(){
  const nodes=new Map(); const get=id=>{if(!nodes.has(id))nodes.set(id,new Element());return nodes.get(id);};
  const calls=[];
  const ctx=vm.createContext({
    document:{getElementById:get,createElement:t=>new Element(t),createTextNode:t=>{const e=new Element('#text');e.textContent=t;return e;},querySelector:()=>null,querySelectorAll:()=>[]},
    window:{}, console, Date,
    uiNode:(tag,cls,text)=>{const e=new Element(tag);if(cls)e.className=cls;if(text!==undefined)e.textContent=text;return e;},
    uiCommand:()=>new Element('button'),
    epIcon:()=>new Element('icon'),
  });
  vm.runInContext(source,ctx);
  ctx.agentApi=async(p,data)=>{calls.push({p,data});return {incidents:INCIDENTS};};  // override clobbered declaration
  return {ctx,get,calls};
}

test('renders incidents with category/source chips and correlation meta, text-only',()=>{
  const {ctx,get}=setup();
  ctx.renderIncidents(INCIDENTS);
  const box=get('incidentsList');
  const strongs=all(box).filter(n=>n.tagName==='strong').map(n=>n.textContent);
  assert(strongs.includes('SQLi 경보') && strongs.includes('XSS 경보'));
  const chips=all(box).filter(n=>n.className==='aw-plan-chip').map(n=>n.textContent);
  assert(chips.includes('sqli') && chips.includes('soar'));
  assert(all(box).some(n=>n.textContent && n.textContent.includes('자산 app-7')));
  assert(all(box).every(n=>n.innerHTML===undefined));   // DOM-only, no markup injection
});

test('empty incident list shows a clear message',()=>{
  const {ctx,get}=setup();
  ctx.renderIncidents([]);
  assert(all(get('incidentsList')).some(n=>n.textContent && n.textContent.includes('수집된 사건이 없습니다')));
});

test('openIncidents fetches the list and opens the dialog',async()=>{
  const {ctx,get,calls}=setup();
  await ctx.openIncidents();
  assert(calls.some(c=>c.p==='/incidents?limit=25'));
  assert.equal(get('incidentsDialog').open,true);
  assert.equal(get('incidentTrace').hidden,true);
});

test('incident pages append without repeating earlier rows',async()=>{
  const {ctx,get,calls}=setup();
  ctx.agentApi=async p=>{
    calls.push({p});
    return !p.includes('before_created=')?
      {incidents:[INCIDENTS[0]],has_more:true,next_cursor:{created:20,id:'i1'}}:
      {incidents:[INCIDENTS[1]],has_more:false,next_cursor:{created:10,id:'i2'}};
  };
  await ctx.loadIncidents();
  assert.equal(get('incidentsMore').hidden,false);
  await get('incidentsMore').onclick();
  assert.deepEqual(calls.map(c=>c.p),['/incidents?limit=25',
    '/incidents?limit=25&before_created=20&before_id=i1']);
  assert.equal(all(get('incidentsList')).filter(n=>n.tagName==='strong').length,2);
  assert.equal(get('incidentsMore').hidden,true);
});

test('submitIncident posts the contract with the chosen location/param',async()=>{
  const {ctx,get,calls}=setup();
  get('incTitle').value='수동 사건';
  get('incCategory').value='sqli';
  get('incUrl').value='https://app.test/api/items?q=1';
  get('incLocation').value='param';
  get('incAssetId').value='app-7';
  await ctx.submitIncident({preventDefault(){}});
  const post=calls.find(c=>c.p==='/incidents' && c.data);
  assert(post, 'POST /incidents 호출이 있어야 한다');
  assert.equal(post.data.title,'수동 사건');
  assert.equal(post.data.category,'sqli');
  assert.equal(post.data.asset_id,'app-7');
  assert.equal(post.data.request.url,'https://app.test/api/items?q=1');
});

test('submitIncident requires a title before posting',async()=>{
  const {ctx,get,calls}=setup();
  get('incTitle').value='';
  await ctx.submitIncident({preventDefault(){}});
  assert(!calls.some(c=>c.p==='/incidents' && c.data));   // no POST without a title
  assert(get('incidentFormError').textContent.includes('제목'));
});

test('access incident verify renders the owner/non-owner session form',()=>{
  const {ctx,get}=setup();
  ctx.verifyIncident('i1','access');
  const box=get('incidentTrace');
  assert.equal(box.hidden,false);
  assert(all(box).some(n=>n.textContent && n.textContent.includes('소유자/비소유자')));
  assert.equal(all(box).filter(n=>n.tagName==='input').length,4);   // owner/intruder cookie + pointer + value
  assert(all(box).some(n=>n.tagName==='button'));
});

test('submitAccessVerify posts the access policy and two sessions',async()=>{
  const {ctx,calls}=setup();
  ctx.confirm=()=>true; ctx.getHeadersObj=()=>({}); ctx.loadAgentList=async()=>{}; ctx.selectRun=()=>{};
  await ctx.submitAccessVerify('i1','own=1','intr=2','/id','7');
  const post=calls.find(c=>c.p==='/incidents/i1/verify' && c.data);
  assert(post,'verify POST 가 있어야 한다');
  assert.equal(post.data.access.identity_pointer,'/id');
  assert.equal(post.data.access.identity_value,'7');
  assert.equal(post.data.actor_headers.owner.Cookie,'own=1');
  assert.equal(post.data.actor_headers.intruder.Cookie,'intr=2');
  assert.equal(post.data.access.owner_actor,'owner');
  assert.equal(post.data.access.intruder_actor,'intruder');
});

test('submitAccessVerify requires an identity pointer and value',async()=>{
  const {ctx,get,calls}=setup();
  ctx.confirm=()=>true; ctx.getHeadersObj=()=>({}); ctx.loadAgentList=async()=>{}; ctx.selectRun=()=>{};
  await ctx.submitAccessVerify('i1','','','id','');   // pointer not '/' and no value
  assert(!calls.some(c=>c.p==='/incidents/i1/verify' && c.data));
  assert(get('incidentFormError').textContent.includes('식별 포인터'));
});

test('renderIncidentTrace shows status label, correlation and linked runs',()=>{
  const {ctx,get}=setup();
  ctx.renderIncidentTrace({status:'not_reproduced',category:'sqli',asset_id:'app-7',traffic_id:'flow-42',
    reason:'이번 재검증에서 재현되지 않았습니다(대상 전체의 안전/해결을 의미하지 않습니다).',
    runs:[{run_id:'r1',state:'completed',verdict:'inconclusive',evidence_ids:['o1']}],
    note:'사건 보고 자체는 증거가 아닙니다.'});
  const box=get('incidentTrace');
  const texts=all(box).map(n=>n.textContent);
  assert(texts.includes('재현 안 됨'));                     // status label, not raw code
  assert(texts.some(t=>t && t.includes('자산 app-7')));
  assert(texts.some(t=>t && t.includes('안전/해결을 의미하지 않')));
  assert(texts.some(t=>t && t.includes('inconclusive')));
});

test('incident trace links matching asset findings to their run',()=>{
  const {ctx,get}=setup();
  const opened=[]; ctx.selectRun=id=>opened.push(id); ctx.setDetailMode=mode=>opened.push(mode);
  get('incidentsDialog').open=true;
  ctx.renderIncidentTrace({status:'suspicious',category:'sqli',asset_id:'app-7',runs:[],
    finding_groups:[{asset_id:'app-7',method:'GET',origin:'https://app.test',path:'/items',
      findings:[{run_id:'r2',finding_id:'f2',verdict:'suspicious',evidence_ids:['o2']}]}]});
  const box=get('incidentTrace');
  assert(all(box).some(n=>n.textContent && n.textContent.includes('자산별 연결 발견')));
  assert(all(box).some(n=>n.textContent && n.textContent.includes('GET https://app.test /items')));
  const open=all(box).find(n=>n.tagName==='button' && n.textContent==='발견 열기');
  open.onclick();
  assert.deepEqual(opened,['r2','findings']);
  assert.equal(get('incidentsDialog').open,false);
  assert(all(box).every(n=>n.innerHTML===undefined));
});

test('incident deletion audit is local read-only and renders no event body',async()=>{
  const {ctx,get,calls}=setup();
  ctx.agentApi=async p=>{calls.push({p});return {deletions:[{
    incident_id:'i1',source:'siem',category:'sqli',deleted:1000}]};};
  await ctx.openIncidentDeletions();
  const box=get('incidentsAudit');
  assert.equal(box.hidden,false);
  assert(calls.some(c=>c.p==='/incidents/deletions'));
  assert(all(box).some(n=>n.textContent && n.textContent.includes('사건 i1')));
  assert(all(box).every(n=>n.innerHTML===undefined));
});

test('asset trace keeps each incident status and opens linked findings',async()=>{
  const {ctx,get,calls}=setup();
  const opened=[]; ctx.selectRun=id=>opened.push(id); ctx.setDetailMode=mode=>opened.push(mode);
  ctx.agentApi=async p=>{calls.push({p});return {asset_id:'app-7',incidents:[
    {incident_id:'old',category:'sqli',status:'reproduced'},
    {incident_id:'new',category:'sqli',status:'not_reproduced'}],finding_groups:[{
      category:'sqli',method:'GET',origin:'https://app.test',path:'/items',
      incident_ids:['old','new'],findings:[{incident_id:'new',run_id:'r2',finding_id:'f2',verdict:'inconclusive'}]
    }],note:'과거 발견은 현재 확증이 아닙니다.'};};
  await ctx.showAssetTrace('app-7');
  const box=get('incidentTrace');
  assert(calls.some(c=>c.p==='/incidents/asset-trace?asset_id=app-7'));
  const texts=all(box).map(n=>n.textContent);
  assert(texts.some(t=>t && t.includes('재현')));
  assert(texts.some(t=>t && t.includes('재현 안 됨')));
  assert(texts.some(t=>t && t.includes('사건 2건')));
  const open=all(box).find(n=>n.tagName==='button' && n.textContent==='발견 열기');
  open.onclick();
  assert.deepEqual(opened,['r2','findings']);
  assert(all(box).every(n=>n.innerHTML===undefined));
});
