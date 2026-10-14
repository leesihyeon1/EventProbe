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
    if (p==='/templates' && !method && data===undefined) return {templates:ctx._templates};
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
  assert(calls.some(x=>x.path==='/templates' && !x.method));   // 목록 재조회
});
