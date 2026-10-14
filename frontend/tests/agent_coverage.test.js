const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const vm=require('node:vm');
const source=fs.readFileSync(path.join(__dirname,'../static/js/agent_coverage.js'),'utf8');

// Pure-model context.
const mctx=vm.createContext({URL,console});vm.runInContext(source,mctx);
const req=(url='https://app.test/',method='GET')=>({url,method});
const ev=(id,kind,data={},step_id='')=>({id,kind,data,step_id,created:1700000000});
const action=(step,kind,over={})=>ev('a'+step,'action',{kind,endpoint_id:'seed',actor_id:'owner',category:'',...over},step);
const run=(events=[],endpoints={seed:req()},extra={})=>({id:'run1',state:'completed',data:{endpoints,spec:{request:endpoints.seed}},events,conclusion:{},...extra});
const build=(...a)=>mctx.buildCoverageModel(run(...a));
const cellOf=(m,ep,chk)=>m.cells[ep]?.[chk];

test('cell advances observe→verdict and columns follow the known order',()=>{
  const m=build([
    action('s0','observe'), ev('r0','request_started',{actor_id:'owner'},'s0'), ev('o0','observation',{id:'o0',actor_id:'owner',response:{status:200}},'s0'),
    action('s1','probe',{category:'xss'}), ev('r1','request_started',{actor_id:'owner'},'s1'), ev('o1','observation',{id:'o1',actor_id:'owner',response:{status:200}},'s1'),
    ev('v1','verification',{status:'confirmed',evidence_ids:['o1']},'s1'),
  ]);
  assert.deepEqual([...m.checks],['xss','observe']);         // catalog order, not insertion order
  assert.equal(mctx.covDisplay(cellOf(m,'seed','observe')),'observed');
  assert.equal(mctx.covDisplay(cellOf(m,'seed','xss')),'confirmed');
  assert.equal(cellOf(m,'seed','xss').evidenceIds.length,1);
});

test('a verdict without fully linked evidence degrades to inconclusive and is marked',()=>{
  const m=build([action('s1','probe',{category:'sqli'}), ev('o1','observation',{id:'o1',actor_id:'owner',response:{status:200}},'s1'),
    ev('v1','verification',{status:'confirmed',evidence_ids:['o1','ghost']},'s1')]);
  const cell=cellOf(m,'seed','sqli');
  assert.equal(mctx.covDisplay(cell),'inconclusive');
  assert.equal(cell.verifications[0].incomplete,true);
});

test('access verdict attaches to the tested actor only, not the owner baseline',()=>{
  const m=build([action('s1','access',{actor_id:'reader',object_id:'obj'}),
    ev('ow','observation',{id:'ow',actor_id:'owner',response:{status:200}},'s1'),
    ev('rd','observation',{id:'rd',actor_id:'reader',response:{status:200}},'s1'),
    ev('v1','verification',{status:'confirmed',evidence_ids:['ow','rd']},'s1')]);
  const cell=cellOf(m,'seed','access');
  assert.equal(cell.actors.reader.verdict,'confirmed');
  assert.equal(cell.actors.owner.verdict,null);             // owner baseline keeps no verdict
  assert.equal(cell.actors.owner.state,'observed');
});

test('planned-only actions, out-of-scope rows and budget flags are distinct',()=>{
  const m=build([action('s1','probe',{category:'xss'})],                        // action, no request
    {seed:req(),ext:req('https://other.test/x')},
    {state:'limited',conclusion:{unfinished_steps:['s1'],completion:'partial'}});
  assert.equal(mctx.covDisplay(cellOf(m,'seed','xss')),'planned');
  assert.equal(m.rows.find(r=>r.id==='ext').outside,true);
  assert.equal(m.rows.find(r=>r.seed).outside,false);
  assert.equal(m.budget,true);
  assert.equal(m.unfinished,1);
  assert(m.summary.none>0);                                  // in-scope endpoint has unchecked cells
});

test('coverageCheck ignores finish/wait_oob and maps kinds to columns',()=>{
  assert.equal(mctx.coverageCheck({kind:'finish'}),null);
  assert.equal(mctx.coverageCheck({kind:'wait_oob'}),null);
  assert.equal(mctx.coverageCheck({kind:'access'}),'access');
  assert.equal(mctx.coverageCheck({kind:'probe',category:''}),'probe');
});

// DOM render context.
class Element {
  constructor(tag='div'){this.tagName=tag;this.children=[];this.dataset={};this.attributes={};this.value='';this.textContent='';}
  append(...n){this.children.push(...n);} replaceChildren(...n){this.children=[...n];}
  appendChild(n){this.children.push(n);return n;}
  setAttribute(k,v){this.attributes[k]=v;} getAttribute(k){return this.attributes[k];}
  focus(){this.focused=true;} scrollIntoView(){this.scrolled=true;}
  contains(node){return desc(this).includes(node);}
  querySelector(s){return this.querySelectorAll(s)[0];}
  querySelectorAll(s){return desc(this).filter(n=>match(n,s));}
}
class ElementText{constructor(t){this.textContent=t;this.children=[];}}
const desc=n=>n.children.flatMap(c=>[c,...desc(c)]);
const all=n=>[n,...desc(n)];
const match=(n,sel)=>sel.split(',').some(p=>{const m=p.trim().match(/^([a-zA-Z]*)(?:\[data-([a-zA-Z]+)\])?$/);return m&&(!m[1]||n.tagName===m[1])&&(!m[2]||(m[2] in n.dataset));});
function setup(){
  const nodes=new Map(); const get=id=>{if(!nodes.has(id))nodes.set(id,new Element());return nodes.get(id);};
  const ctx=vm.createContext({
    document:{createElement:t=>new Element(t),createTextNode:t=>new ElementText(t),activeElement:new Element()},
    agentEl:get, epIcon:n=>new Element('icon-'+n),
    uiNode:(tag,cls,text)=>{const e=new Element(tag);if(cls)e.className=cls;if(text!==undefined)e.textContent=text;return e;},
    uiCommand:(icon,label,act)=>{const b=new Element('button');b.title=label;b.onclick=act;return b;},
    setDetailMode:()=>{}, URL, console, Set, Map,
  });
  vm.runInContext(source,ctx);
  return {ctx,get};
}

test('render builds a header per check plus corner, a row per endpoint, and selectable cells',()=>{
  const {ctx,get}=setup();
  ctx.renderAgentCoverage(run([
    action('s1','probe',{category:'xss'}), ev('o1','observation',{id:'o1',actor_id:'owner',response:{status:200}},'s1'),
    ev('v1','verification',{status:'confirmed',evidence_ids:['o1']},'s1'),
  ]));
  const headers=all(get('cvGrid')).filter(n=>n.tagName==='th');
  assert(headers.some(h=>h.textContent==='XSS'));           // check column present
  const cells=all(get('cvGrid')).filter(n=>n.tagName==='button'&&'key' in n.dataset);
  assert(cells.length>=1);
  ctx.selectCoverage('seed\u0000xss');
  assert(all(get('cvDetail')).some(n=>n.textContent==='확증')); // detail shows the verdict
  assert.match(get('cvSummary').textContent,/엔드포인트 1 × 검사 1/);
});

test('renderer has no network, no HTML injection, and no target navigation',()=>{
  assert(!/\b(fetch|XMLHttpRequest|WebSocket|EventSource)\s*\(/.test(source));
  assert(!/innerHTML|outerHTML|insertAdjacentHTML|location\s*=|window\.open|\.href\s*=/.test(source));
});
