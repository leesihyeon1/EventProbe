const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

class Element {
  constructor(tag='div') { this.tagName=tag;this.children=[];this.dataset={};this.attributes={};this.value='';this.textContent=''; }
  append(...nodes) {this.children.push(...nodes);}
  replaceChildren(...nodes) {this.children=[...nodes];}
  setAttribute(k,v) {this.attributes[k]=v;}
  scrollIntoView() {this.scrolled=true;}
  focus() {this.focused=true;}
  querySelector(selector) {return this.children.find(n=>n.tagName===selector);}
}
function setup() {
  const nodes=new Map();
  const get=id=>{if(!nodes.has(id))nodes.set(id,new Element());return nodes.get(id);};
  const context=vm.createContext({
    document:{createElement:tag=>new Element(tag),createTextNode:text=>new ElementText(text)},
    window:{addEventListener(){}},agentEl:get,epIcon:name=>new Element('icon-'+name),
    AGENT_STATE_LABELS:{running:'running',completed:'completed',paused:'paused',limited:'limited'},
    selectRun(){},deleteRun(){},console,Date,Set,Map,
  });
  vm.runInContext(fs.readFileSync(path.join(__dirname,'../static/js/workspace.js'),'utf8'),context);
  return {context,get};
}
class ElementText {constructor(text){this.textContent=text;this.children=[];}}
const allNodes = n => [n,...n.children.flatMap(allNodes)];

test('search matches goal or ID, independently combined with status',()=>{
  const {context}=setup();
  const runs=[{id:'abc123',goal:'Login check',state:'running'},{id:'def456',goal:'Profile',state:'completed'}];
  assert.equal(context.filteredAgentRuns(runs,' LOGIN ','running').length,1);
  assert.equal(context.filteredAgentRuns(runs,'ABC123','').length,1);
  assert.equal(context.filteredAgentRuns(runs,'Login','completed').length,0);
});
test('pagination clamps after filtering and renders a proper table empty state',()=>{
  const {context,get}=setup();
  const runs=Array.from({length:23},(_,i)=>({id:'id'+i,goal:'Goal '+i,state:'completed',created:1700000000}));
  context.renderAgentList(runs);
  assert.equal(get('agentList').children.length,10);
  vm.runInContext('workspacePage=2;renderAgentList()',context);
  assert.equal(get('agentList').children.length,3);
  get('agentSearch').value='absent';context.renderAgentList();
  assert.equal(get('agentList').children[0].children[0].colSpan,5);
  assert.equal(get('agentNext').disabled,true);
});
test('response evidence stays text and has separate request/response panes',()=>{
  const {context}=setup();
  const raw='<script>throw new Error("never execute")</script>';
  const event=context.renderWorkspaceEvent({id:'obs1',kind:'observation',data:{request:{method:'GET',url:'https://synthetic.invalid'},response:{status:200,body:raw,time_ms:5}}});
  const descendants=allNodes(event);
  assert(descendants.some(n=>n.tagName==='pre'&&n.textContent===raw));
  assert.equal(descendants.filter(n=>n.tagName==='section').length,2);
  assert(descendants.every(n=>n.innerHTML===undefined));
});
test('detail polling preserves expanded events without duplicates',()=>{
  const {context,get}=setup();
  const run={id:'run',state:'paused',data:{spec:{goal:'test',max_steps:8,max_requests:24,max_ai_calls:8},steps:1,requests:1,ai_calls:0,elapsed:1,endpoints:{seed:{}}},events:[{id:'a',kind:'action',data:{kind:'observe',hypothesis:'test'}}]};
  context.renderAgentWorkspace(run);
  get('agentEvents').children[0].open=true;
  context.renderAgentWorkspace(run);
  assert.equal(get('agentEvents').children.length,1);
  assert.equal(get('agentEvents').children[0].open,true);
  assert.equal(get('agentResume').disabled,false);
  assert.equal(get('agentStop').disabled,true);
});

test('partial conclusion is visible, text-only, and stable between identical polls',()=>{
  const {context,get}=setup();
  const conclusion={completion:'partial',verdict:'inconclusive',text:'<script>synthetic</script>',
    counts:{confirmed:0,suspicious:0,inconclusive:1},observation_count:3,
    stop_reason:'budget',next_steps:['review evidence'],scope_note:'not a safety claim'};
  context.renderAgentConclusion(conclusion);
  const panel=get('agentConclusion'),first=panel.children[0];
  assert.equal(panel.hidden,false);
  assert(allNodes(panel).some(n=>n.textContent==='부분 결론 · 미완료'));
  assert(allNodes(panel).some(n=>n.textContent===conclusion.text));
  assert(allNodes(panel).every(n=>n.innerHTML===undefined));
  context.renderAgentConclusion(conclusion);
  assert.equal(panel.children[0],first);
  context.renderAgentConclusion(null);
  assert.equal(panel.hidden,true);
});

test('conclusion evidence button opens the linked verification event',()=>{
  const {context,get}=setup();
  const event=context.renderWorkspaceEvent({id:'verification-1',kind:'verification',data:{status:'inconclusive'}});
  get('agentEvents').append(event);
  context.renderAgentConclusion({completion:'partial',verdict:'inconclusive',text:'synthetic',
    counts:{},verifications:[{id:'verification-1',category:'sqli',status:'inconclusive',evidence_ids:['observation-1']}],
    next_steps:[],scope_note:'scope'});
  const button=allNodes(get('agentConclusion')).find(n=>n.tagName==='button');
  button.onclick();
  assert.equal(event.open,true);
  assert.equal(event.scrolled,true);
  assert.equal(event.querySelector('summary').focused,true);
  assert.equal(get('agentEvents').hidden,false);
});
