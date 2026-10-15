const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const vm=require('node:vm');
const source=fs.readFileSync(path.join(__dirname,'../static/js/agent.js'),'utf8');

class Element {
  constructor(tag='div'){this.tagName=tag;this.children=[];this.dataset={};this.attributes={};this.value='';this.textContent='';this.hidden=false;this.checked=false;this.disabled=false;}
  append(...n){this.children.push(...n);} replaceChildren(...n){this.children=[...n];}
  setAttribute(k,v){this.attributes[k]=v;} getAttribute(k){return this.attributes[k];}
  showModal(){this.open=true;} close(){this.open=false;} focus(){} reportValidity(){return true;} checkValidity(){return true;}
  querySelectorAll(sel){return desc(this).filter(n=>sel.split(',').some(s=>n.tagName===s.trim()));}
  querySelector(sel){return this.querySelectorAll(sel)[0];}
}
const desc=n=>n.children.flatMap(c=>[c,...desc(c)]);
const all=n=>[n,...desc(n)];
const PLAN={entry:'p1',steps:[
  {action_id:'p1',action:{kind:'probe',category:'sqli',hypothesis:'반사 확인'},branches:[{predicate:{kind:'verdict_in',verdicts:['suspicious']},next:'p2'}],default_next:''},
  {action_id:'p2',action:{kind:'confirm',category:'sqli',hypothesis:'차등 확증'},branches:[],default_next:''}]};

function setup() {
  const nodes=new Map(); const get=id=>{if(!nodes.has(id))nodes.set(id,new Element());return nodes.get(id);};
  const calls=[];
  const ctx=vm.createContext({
    document:{getElementById:get,createElement:t=>new Element(t),createTextNode:t=>{const e=new Element('#text');e.textContent=t;return e;},querySelector:()=>null,querySelectorAll:()=>[]},
    window:{}, console,
    _currentRequestForm:()=>({method:'GET',url:'https://app.test/?id=1',params:{},body:''}),
    getHeadersObj:()=>({}), getUseDefaults:()=>false, getDefaultHeaderProfile:()=>({}),
    loadAgentList:async()=>{}, selectRun:()=>{}, switchView:()=>{}, epIcon:()=>new Element('icon'),
  });
  vm.runInContext(source,ctx);
  // agent.js declares its own agentApi (fetch-based); override it after load with a recording stub.
  ctx.agentApi=async(p,data)=>{calls.push({path:p,data});return p==='/plan'?{plan:PLAN,fingerprint:'abc1234567'}:{id:'run1'};};
  return {ctx,get,calls};
}

test('preview pins the generated plan and renders it text-only with the fingerprint',async()=>{
  const {ctx,get}=setup();
  get('agentPlanMode').checked=true; ctx.syncPlanPreview();
  await ctx.previewPlan();
  const box=get('agentPlanSteps');
  assert(all(box).some(n=>typeof n.textContent==='string' && n.textContent.includes('abc1234567'))); // fingerprint shown
  assert.equal(all(box).filter(n=>n.tagName==='li').length,2);          // one row per step
  assert(all(box).every(n=>n.innerHTML===undefined));                    // no markup injection
});

test('startAgent pins the approved plan only in plan mode',async()=>{
  const {ctx,get,calls}=setup();
  get('agentPlanMode').checked=true; ctx.syncPlanPreview();
  await ctx.previewPlan();
  await ctx.startAgent();
  const body=calls.find(c=>c.path==='/runs').data;
  assert.equal(body.mode,'plan');
  assert.deepEqual(body.approved_plan,PLAN);                              // exact approved plan pinned
  assert(body.approved_plan_expires_at>Date.now()/1000);
});

test('preview policy revision is pinned into the approved run',async()=>{
  const {ctx,get,calls}=setup();
  ctx.agentApi=async(p,data)=>{calls.push({path:p,data});return p==='/plan'
    ?{plan:PLAN,fingerprint:'abc1234567',policy_version:2}:{id:'run1'};};
  get('agentPlanMode').checked=true; ctx.syncPlanPreview();
  await ctx.previewPlan(); await ctx.startAgent();
  assert.equal(calls.find(c=>c.path==='/runs').data.policy_version,2);
});

test('an expired preview cannot start a pinned run',async()=>{
  const {ctx,get,calls}=setup();
  get('agentPlanMode').checked=true; ctx.syncPlanPreview();
  await ctx.previewPlan();
  vm.runInContext('_approvedPlanExpiresAt=1',ctx);
  await ctx.startAgent();
  assert(!calls.some(c=>c.path==='/runs'));
  assert.match(get('agentFormError').textContent,/만료/);
});

test('turning plan mode off clears the pin and hides the preview',async()=>{
  const {ctx,get,calls}=setup();
  get('agentPlanMode').checked=true; ctx.syncPlanPreview();
  await ctx.previewPlan();
  get('agentPlanMode').checked=false; ctx.syncPlanPreview();
  assert.equal(get('agentPlanPreviewWrap').hidden,true);
  assert.equal(get('agentPlanSteps').children.length,0);
  await ctx.startAgent();
  const body=calls.find(c=>c.path==='/runs').data;
  assert.equal(body.mode,'iterative');
  assert(!('approved_plan' in body));                                     // no stale pin
});

test('local scope restrictions are included in the run spec',()=>{
  const {ctx,get}=setup();
  get('agentAllowedPaths').value='/api\n/api/v2';
  get('agentDeniedPaths').value='/api/admin';
  get('agentAllowedMethods').value='GET, head';
  get('agentAllowedCategories').value='SQLI, xss';
  const spec=ctx._collectSpec();
  assert.deepEqual(Array.from(spec.allowed_path_prefixes),['/api','/api/v2']);
  assert.deepEqual(Array.from(spec.denied_path_prefixes),['/api/admin']);
  assert.deepEqual(Array.from(spec.allowed_methods),['GET','HEAD']);
  assert.deepEqual(Array.from(spec.allowed_categories),['sqli','xss']);
  assert.equal(spec.policy_version,1);
});

test('multiple evidence goals are collected with independent completion rules',()=>{
  const {ctx}=setup();
  const rows=[
    {'goal-id':'sql','goal-title':'SQL 검증','goal-category':'sqli','goal-completion':'confirmed','goal-actor':'current','goal-endpoint':'seed'},
    {'goal-id':'xss','goal-title':'XSS 검증','goal-category':'xss','goal-completion':'tested','goal-actor':'','goal-endpoint':''},
  ].map(values=>({querySelector:selector=>({value:values[selector.slice(1)]})}));
  ctx.document.querySelectorAll=selector=>selector==='#agentGoalsForm .goal-row'?rows:[];
  const goals=ctx._collectSpec().goals;
  assert.equal(goals.length,2);
  assert.equal(goals[0].completion,'confirmed');
  assert.equal(goals[1].category,'xss');
});

test('predicate text maps the enumerated branch kinds',()=>{
  const {ctx}=setup();
  assert.equal(ctx._predicateText({kind:'always'}),'항상');
  assert.equal(ctx._predicateText({kind:'verdict_in',verdicts:['confirmed','suspicious']}),'판정 ∈ confirmed/suspicious');
  assert.equal(ctx._predicateText({kind:'status_in',statuses:[200,500]}),'상태 ∈ 200/500');
  assert.equal(ctx._predicateText({kind:'signal_present',signal:'DB'}),'신호 DB');
});

test('a failed preview clears the pin so no plan is silently executed',async()=>{
  const {ctx,get,calls}=setup();
  get('agentPlanMode').checked=true; ctx.syncPlanPreview();
  ctx.agentApi=async(p,data)=>{calls.push({path:p,data}); if(p==='/plan')throw new Error('허용되지 않은 계획'); return {id:'run1'};};
  await ctx.previewPlan();
  assert.equal(get('agentFormError').hidden,false);
  await ctx.startAgent();
  const body=calls.find(c=>c.path==='/runs').data;
  assert(!('approved_plan' in body));                                     // nothing pinned after a failed preview
});
