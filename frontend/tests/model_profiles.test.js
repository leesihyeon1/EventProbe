const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const vm=require('node:vm');
const source=fs.readFileSync(path.join(__dirname,'../static/js/agent.js'),'utf8');

class Element {
  constructor(tag='div'){this.tagName=tag;this.children=[];this.value='';this.dataset={};this.textContent='';}
  append(...nodes){this.children.push(...nodes);}
  replaceChildren(...nodes){this.children=[...nodes];}
  setAttribute(){}
}
function setup(){
  const nodes=new Map(['agentModelOrder','agentPlanSteps','agentPlanMode','agentPlanPreviewWrap'].map(id=>[id,new Element()]));
  const context=vm.createContext({window:{},document:{getElementById:id=>nodes.get(id)||null,createElement:tag=>new Element(tag)},console,URL});
  vm.runInContext(source,context);
  return {context,nodes};
}
test('model ordering copies selections and rejects duplicate or oversized chains',()=>{
  const {context}=setup();const ids=['first','backup'];context.setAgentModelChain(ids);ids.push('outside');
  assert.deepEqual(Array.from(vm.runInContext('_agentModelChain',context)),['first','backup']);
  assert.throws(()=>context.setAgentModelChain(['a','a']));
  assert.throws(()=>context.setAgentModelChain(Array.from({length:9},(_,i)=>String(i))));
});
test('changing model order clears the old approved preview',()=>{
  const {context}=setup();vm.runInContext('_approvedPlan={entry:"old"}',context);
  context.setAgentModelChain(['backup']);assert.equal(vm.runInContext('_approvedPlan',context),null);
});
test('model names render as text and move/remove controls preserve ordering',()=>{
  const {context,nodes}=setup();
  vm.runInContext('_agentModelProfiles=[{id:"a",name:"<script>unsafe</script>"},{id:"b",name:"backup"}]',context);
  context.setAgentModelChain(['a','b']);const list=nodes.get('agentModelOrder');
  assert.match(list.children[0].children[0].textContent,/<script>unsafe<\/script>/);
  assert.equal(list.children[0].innerHTML,undefined);
  list.children[0].children[1].children[1].onclick();
  assert.deepEqual(Array.from(vm.runInContext('_agentModelChain',context)),['b','a']);
  list.children[0].children[1].children[2].onclick();
  assert.deepEqual(Array.from(vm.runInContext('_agentModelChain',context)),['a']);
});
test('model metadata editor has no plaintext key input or remote request endpoint',()=>{
  const modelCode=source.slice(source.indexOf('/* Task model profiles'));
  assert(!/innerHTML|localStorage|sessionStorage/.test(modelCode));
  assert(!/input\.type\s*=\s*['"]password/.test(modelCode));
  assert.match(modelCode,/key_env/);
  assert(!/fetch\(/.test(modelCode));
});

test('call history stays local, renders text, and ignores a previous task response',async()=>{
  const {context,nodes}=setup();
  const panel=new Element();panel.dataset.run='first';nodes.set('agentModelHistory',panel);
  const rows=new Element();nodes.set('agentModelHistoryRows',rows);
  let resolveOld;
  const calls=[];
  context.agentApi=url=>{calls.push(url);return url.includes('first')?new Promise(resolve=>{resolveOld=resolve;}):Promise.resolve({items:[
    {model:'<script>model</script>',status:'completed',error_code:'',actual_tokens:null,latency_ms:10}]});};
  const old=context.loadModelCallHistory('first');
  panel.dataset.run='second';await context.loadModelCallHistory('second');
  resolveOld({items:[{model:'OLD_PRIVATE_MODEL',status:'error'}]});await old;
  assert(calls.every(url=>url.startsWith('/runs/')));
  assert.equal(rows.children.length,1);
  assert.match(rows.children[0].textContent,/<script>model<\/script>/);
  assert.match(rows.children[0].textContent,/토큰 미제공/);
  assert(!rows.children[0].textContent.includes('OLD_PRIVATE_MODEL'));
  assert.equal(rows.children[0].innerHTML,undefined);
});


test('default task requests stay compatible until the backend is restarted',()=>{
  const {context}=setup();
  assert.equal(Object.hasOwn(context.modelChainSpecFields(),'model_profile_ids'),false);
  context.setAgentModelChain(['chosen']);
  const body=context.modelChainSpecFields();
  assert.deepEqual(Array.from(body.model_profile_ids),['chosen']);
  body.model_profile_ids.push('mutated');
  assert.deepEqual(Array.from(context.modelChainSpecFields().model_profile_ids),['chosen']);
});
