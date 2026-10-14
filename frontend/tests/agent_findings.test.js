const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const vm=require('node:vm');
const source=fs.readFileSync(path.join(__dirname,'../static/js/agent_findings.js'),'utf8');

class Element {
  constructor(tag='div'){this.tagName=tag;this.children=[];this.dataset={};this.attributes={};this.value='';this.textContent='';}
  append(...nodes){this.children.push(...nodes);}
  replaceChildren(...nodes){this.children=[...nodes];}
  setAttribute(k,v){this.attributes[k]=v;}
  getAttribute(k){return this.attributes[k];}
  focus(){this.focused=true;}
  scrollIntoView(){this.scrolled=true;}
  contains(node){return descendants(this).includes(node);}
  querySelector(sel){return this.querySelectorAll(sel)[0];}
  querySelectorAll(sel){return descendants(this).filter(n=>matches(n,sel));}
}
class ElementText{constructor(text){this.textContent=text;this.children=[];}}
const descendants=n=>n.children.flatMap(c=>[c,...descendants(c)]);
const allNodes=n=>[n,...descendants(n)];
function matches(n,sel){
  return sel.split(',').some(part=>{
    const m=part.trim().match(/^([a-zA-Z]*)(?:\[data-([a-zA-Z]+)\])?$/);
    if(!m) return false;
    if(m[1] && n.tagName!==m[1]) return false;
    if(m[2] && !(m[2] in n.dataset)) return false;
    return true;
  });
}
function setup() {
  const nodes=new Map();
  const get=id=>{if(!nodes.has(id))nodes.set(id,new Element());return nodes.get(id);};
  const calls=[], opens=[];
  const context=vm.createContext({
    document:{createElement:t=>new Element(t),createTextNode:t=>new ElementText(t),activeElement:new Element()},
    window:{open:(...a)=>opens.push(a)},
    agentEl:get, epIcon:name=>new Element('icon-'+name),
    uiNode:(tag,cls,text)=>{const el=new Element(tag);if(cls)el.className=cls;if(text!==undefined)el.textContent=text;return el;},
    uiCommand:(icon,label,action,cls='icon-button')=>{const b=new Element('button');b.append(new Element('icon-'+icon));b.title=label;b.onclick=action;return b;},
    setDetailMode:()=>{},
    agentApi:async(path,data,method)=>{calls.push({path,data,method});return context._updated;},
    getHeadersObj:()=>({Cookie:'s=1'}), selectRun:(id)=>{context._selected=id;}, confirm:()=>context._confirm!==false,
    _awRun:null, _updated:null, _selected:null, _confirm:true, console, Date, Set, Map,
  });
  vm.runInContext(source,context);
  return {context,get,calls,opens};
}

const finding=(over={})=>({id:'f1',category:'xss',verdict:'confirmed',severity:'high',status:'open',
  method:'GET',path:'/items',actor_id:'owner',query_keys:['id'],evidence_ids:['o1'],
  incomplete_evidence:false,default_severity:'high',note:'',history:[],...over});
const run=(findings=[finding()])=>({id:'run1',findings});

test('filters compose across status, severity and text without needing values',()=>{
  const {context}=setup();
  const rows=[finding({id:'a',status:'open',severity:'high',category:'xss',path:'/login'}),
    finding({id:'b',status:'resolved',severity:'low',category:'idor',path:'/orders'})];
  assert.equal(context.filterFindings(rows,'','open','').length,1);
  assert.equal(context.filterFindings(rows,'idor','','').length,1);
  assert.equal(context.filterFindings(rows,'login','','low').length,0);
  assert.equal(context.filterFindings(rows,'','','high').length,1);
});

test('renders findings rows, counts, and a default selection with triage controls',()=>{
  const {context,get}=setup();
  context.renderAgentFindings(run([finding({id:'a'}),finding({id:'b',severity:'low',category:'idor'})]));
  assert.equal(get('fdContent').children.length,2);
  assert.match(get('fdCount').textContent,/발견 2개 · 표시 2개/);
  // Detail panel for the default-selected finding has status + severity selects.
  const selects=allNodes(get('fdDetail')).filter(n=>n.tagName==='select');
  assert.equal(selects.length,2);
});

test('identical poll keeps selection; switching run clears state',()=>{
  const {context,get}=setup();
  context.renderAgentFindings(run([finding({id:'a'}),finding({id:'b'})]));
  vm.runInContext('findingsState.selected="b"',context);
  context.renderAgentFindings(run([finding({id:'a'}),finding({id:'b'})])); // identical signature
  assert.equal(vm.runInContext('findingsState.selected',context),'b'); // selection preserved
  context.resetFindings();
  assert.equal(get('fdContent').children.length,0);
  assert.equal(vm.runInContext('findingsState.runId',context),null);
});

test('triage PATCHes the local endpoint and adopts the returned snapshot',async()=>{
  const {context,calls}=setup();
  context.renderAgentFindings(run([finding({id:'f1',status:'open'})]));
  context._updated=run([finding({id:'f1',status:'resolved',history:[{created:1700000000,status:'resolved'}]})]);
  await context.patchFinding('f1',{status:'resolved'});
  assert.equal(calls.length,1);
  assert.equal(calls[0].method,'PATCH');
  assert.equal(calls[0].path,'/runs/run1/findings/f1');
  assert.deepEqual({...calls[0].data},{status:'resolved'});
  assert.equal(context._awRun.findings[0].status,'resolved'); // server truth adopted
});

test('vuln findings offer retest; it confirms, posts to the retest endpoint, and navigates',async()=>{
  const {context,get,calls}=setup();
  context.renderAgentFindings(run([finding({id:'f1',category:'sqli'})]));
  const retestBtn=allNodes(get('fdDetail')).find(n=>n.tagName==='button'&&n.textContent==='새 실행으로 재검증');
  assert(retestBtn,'retest button present for a vuln finding');
  context._updated={id:'retest-run'};
  await retestBtn.onclick();
  const call=calls.find(c=>c.path==='/runs/run1/findings/f1/retest');
  assert(call && call.data.request_headers.Cookie==='s=1');   // reuses current session headers
  assert.equal(context._selected,'retest-run');               // navigates to the new run
});

test('a non-vuln finding offers no retest, and declining the confirm sends nothing',async()=>{
  const {context,get,calls}=setup();
  context.renderAgentFindings(run([finding({id:'f1',category:'access',verdict:'confirmed'})]));
  assert(!allNodes(get('fdDetail')).some(n=>n.textContent==='새 실행으로 재검증')); // access is not retestable here
  context._confirm=false;
  await context.retestFinding({id:'f1',category:'sqli'});
  assert(!calls.some(c=>c.path==='/runs/run1/findings/f1/retest'));  // declined → no request
});

test('report button opens the local report endpoint for the current run only',()=>{
  const {context,get,opens}=setup();
  context.initFindings();
  context.renderAgentFindings(run());
  get('fdReport').onclick();
  assert.equal(opens.length,1);
  assert.equal(opens[0][0],'/api/agent/runs/run1/report');
  assert.equal(opens[0][1],'_blank');
});

test('renderer has no network, no HTML injection, and only opens the local report',()=>{
  assert(!/\bfetch\s*\(/.test(source));                       // mutations go through agentApi
  assert(!/innerHTML|outerHTML|insertAdjacentHTML|location\s*=|\.href\s*=/.test(source));
  assert.equal((source.match(/window\.open\(/g)||[]).length,1); // exactly one navigation
  assert(/window\.open\([^;]*\/report/.test(source));           // and it is the local report
});
