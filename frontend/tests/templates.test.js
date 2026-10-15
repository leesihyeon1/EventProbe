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

function setup() {
  const nodes=new Map(); const get=id=>{if(!nodes.has(id))nodes.set(id,new Element());return nodes.get(id);};
  const calls=[]; const promptQueue=[];
  const ctx=vm.createContext({
    document:{getElementById:get,createElement:t=>new Element(t),createTextNode:t=>{const e=new Element('#text');e.textContent=t;return e;},querySelector:()=>null,querySelectorAll:()=>[]},
    window:{}, console,
    uiNode:(tag,cls,text)=>{const e=new Element(tag);if(cls)e.className=cls;if(text!==undefined)e.textContent=text;return e;},
    uiCommand:(icon,label,act)=>{const b=new Element('button');b.title=label;b.onclick=act;return b;},
    epIcon:()=>new Element('icon'),
    getHeadersObj:()=>({Cookie:'s=1'}), selectRun:(id)=>{ctx._selected=id;}, loadAgentList:async()=>{},
    confirm:()=>ctx._confirm!==false, prompt:()=>promptQueue.shift(),
    _selected:null, _confirm:true, _updated:null, _templates:[],
  });
  vm.runInContext(source,ctx);
  ctx.agentApi=async(p,data,method)=>{
    calls.push({path:p,data,method});
    if (p.startsWith('/templates?') && !method && data===undefined) return {templates:ctx._templates};
    return ctx._updated || {};
  };
  ctx._collectSpec=()=>({goal:'g', request:{url:'https://app.test/'}});
  // agent.js declares selectRun/loadAgentList itself; override after load so the test observes them.
  ctx.selectRun=(id)=>{ctx._selected=id;};
  ctx.loadAgentList=async()=>{};
  return {ctx,get,calls,promptQueue};
}

test('save template collects the spec and posts it with a name and category',async()=>{
  const {ctx,calls,promptQueue}=setup();
  promptQueue.push('내 템플릿','auth');
  await ctx.saveTemplate();
  const c=calls.find(x=>x.path==='/templates' && x.data);
  assert(c && c.data.name==='내 템플릿' && c.data.category==='auth');
  assert.equal(c.data.spec.goal,'g');
});

test('cancelling the name prompt saves nothing',async()=>{
  const {ctx,calls,promptQueue}=setup();
  promptQueue.push(null);                  // 취소
  await ctx.saveTemplate();
  assert(!calls.some(x=>x.path==='/templates' && x.data));
});

test('renders templates and running one confirms, posts, and navigates',async()=>{
  const {ctx,get,calls}=setup();
  ctx.renderTemplates([{id:'t1',name:'로그인 점검',category:'auth',goal:'목표 문구'}]);
  const nodes=all(get('templatesList'));
  assert(nodes.some(n=>n.textContent==='로그인 점검') && nodes.some(n=>n.textContent==='목표 문구'));
  const runBtn=nodes.find(n=>n.tagName==='button' && n.textContent==='실행');
  assert(runBtn,'run button present');
  ctx._updated={id:'new-run'};
  await runBtn.onclick();
  const c=calls.find(x=>x.path==='/templates/t1/run');
  assert(c && c.data.request_headers.Cookie==='s=1');   // 현재 세션 헤더 재주입
  assert.equal(ctx._selected,'new-run');                // 새 실행으로 이동
});

test('empty template list shows guidance',()=>{
  const {ctx,get}=setup();
  ctx.renderTemplates([]);
  assert(all(get('templatesList')).some(n=>/템플릿이 없습니다/.test(n.textContent||'')));
});

test('delete template sends DELETE then refreshes',async()=>{
  const {ctx,calls}=setup();
  await ctx.deleteTemplate('t1');
  assert(calls.some(x=>x.path==='/templates/t1' && x.method==='DELETE'));
  assert(calls.some(x=>x.path.startsWith('/templates?') && !x.method));   // 목록 재조회
});

test('template search sends encoded filters and disables stale pinned plans',async()=>{
  const {ctx,get,calls}=setup();
  get('templatesSearch').value='로그인 검사';
  get('templatesCategory').value='access';
  ctx.agentApi=async(p)=>{calls.push({path:p});return {policy_version:2,templates:[
    {id:'old',name:'로그인 검사',category:'access',goal:'g',pinned_plan:true,policy_version:1}
  ]};};
  await ctx.loadTemplates();
  assert.equal(calls[0].path,'/templates?search='+encodeURIComponent('로그인 검사')+'&category=access&offset=0&limit=25');
  const nodes=all(get('templatesList'));
  assert(nodes.some(n=>n.textContent==='정책 갱신 필요'));
  assert.equal(nodes.find(n=>n.tagName==='button' && n.textContent==='실행').disabled,true);
});

test('template pages append and keep the current search scope',async()=>{
  const {ctx,get,calls}=setup();
  get('templatesSearch').value='login';
  ctx.agentApi=async p=>{calls.push({path:p});return p.includes('offset=0')?
    {templates:[{id:'t1',name:'first'}],has_more:true}:
    {templates:[{id:'t2',name:'second'}],has_more:false};};
  await ctx.loadTemplates();
  assert.equal(get('templatesMore').hidden,false);
  await get('templatesMore').onclick();
  assert.deepEqual(calls.map(x=>x.path),[
    '/templates?search=login&offset=0&limit=25',
    '/templates?search=login&offset=1&limit=25']);
  assert.equal(all(get('templatesList')).filter(n=>n.tagName==='strong').length,2);
  assert.equal(get('templatesMore').hidden,true);
});

test('bulk category updates only selected templates and reports each failure',async()=>{
  const {ctx,get,calls,promptQueue}=setup();
  ctx._templates=[{id:'t1',name:'first'},{id:'t2',name:'second'}];
  ctx.agentApi=async(p,data,method)=>{
    calls.push({path:p,data,method});
    return p==='/templates/batch/category'?
      {succeeded:1,failed:1,results:[{id:'t1',ok:true},{id:'t2',ok:false,error:'권한 없음'}]}:
      {templates:ctx._templates};
  };
  ctx.renderTemplates(ctx._templates);
  const checks=all(get('templatesList')).filter(n=>n.tagName==='input');
  checks.forEach(check=>{check.checked=true;check.onchange();});
  assert.equal(get('templatesBulkCategory').disabled,false);
  promptQueue.push('access');
  await ctx.batchTemplateCategory();
  const call=calls.find(c=>c.path==='/templates/batch/category');
  assert.equal(call.data.category,'access');
  assert.deepEqual(Array.from(call.data.ids),['t1','t2']);
  assert(get('templatesBulkResult').textContent.includes('1건 실패'));
  assert(all(get('templatesBulkResult')).some(n=>n.textContent.includes('t2: 권한 없음')));
});

test('template revision saves current form and displays version history as text',async()=>{
  const {ctx,get,calls,promptQueue}=setup();
  promptQueue.push('새 이름','access');
  await ctx.reviseTemplate({id:'t1',name:'old',category:'auth'});
  const saved=calls.find(call=>call.path==='/templates/t1' && call.method==='PATCH');
  assert(saved && saved.data.name==='새 이름' && saved.data.spec.goal==='g');
  ctx.agentApi=async(path,data,method)=>{calls.push({path,data,method});
    return path.endsWith('/revisions')?{revisions:[
      {version:2,created:1700000001,name:'new',category:'access'},
      {version:1,created:1700000000,name:'<script>x</script>',category:'access'}]}:{templates:[]};};
  await ctx.showTemplateRevisions({id:'t1',name:'새 이름'});
  assert(all(get('templatesRevisions')).some(node=>(node.textContent||'').includes('<script>x</script>')));
  assert(all(get('templatesRevisions')).every(node=>node.innerHTML===undefined));
  const restore=all(get('templatesRevisions')).find(node=>node.textContent==='이 버전 복원');
  await restore.onclick();
  assert(calls.some(call=>call.path==='/templates/t1/revisions/1/restore'));
});
