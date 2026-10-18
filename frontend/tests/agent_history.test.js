const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const vm=require('node:vm');
const source=fs.readFileSync(path.join(__dirname,'../static/js/agent_history.js'),'utf8');

class Element {
  constructor(tag='div') {this.tagName=tag;this.children=[];this.dataset={};this.textContent='';}
  append(...nodes){this.children.push(...nodes);}
  replaceChildren(...nodes){this.children=[...nodes];}
  replaceWith(node){this.replacement=node;}
  scrollIntoView(){this.scrolled=true;}
  querySelector(){return null;}
}

function setup() {
  const nodes=new Map(),calls=[];
  const get=id=>{if(!nodes.has(id))nodes.set(id,new Element());return nodes.get(id);};
  const context=vm.createContext({
    agentRunId:'run1',agentDetailMode:'history',agentEl:get,Date,Set,
    uiNode:(tag,cls,text)=>{const node=new Element(tag);node.className=cls;node.textContent=text||'';return node;},
    epIcon:name=>new Element('icon-'+name),
    agentApi:async url=>{calls.push(url);return context.answer(url);},
    renderWorkspaceEvent:event=>{const row=new Element('details');row.dataset.event=event.id;row.textContent=event.data.body;return row;},
    setDetailMode:mode=>{context.agentDetailMode=mode;},
  });
  vm.runInContext(source,context);
  return {context,get,calls};
}

test('cursor pages append once and fetch body only when opened',async()=>{
  const {context,get,calls}=setup();
  const event={id:'event1',kind:'observation',created:1700000000,cursor:7};
  context.answer=url=>url.endsWith('/event1')?{...event,data:{body:'PRIVATE_RESPONSE'}}:
    {events:[event],cursor:7,has_more:false};
  context.initHistory();
  await context.loadHistoryPage();
  assert.equal(get('ahEvents').children.length,1);
  assert.equal(get('ahCount').textContent,'1개 이벤트');
  assert.equal(calls.length,1);
  assert(!JSON.stringify(get('ahEvents').children).includes('PRIVATE_RESPONSE'));
  await context.loadHistoryPage();
  assert.equal(get('ahEvents').children.length,1);
  assert(calls[1].includes('after=7'));
  const row=get('ahEvents').children[0];row.open=true;
  await row.ontoggle();
  assert.equal(calls.length,3);
  assert.equal(row.replacement.textContent,'PRIVATE_RESPONSE');
});

test('switching runs resets the cursor and ignores the old page',async()=>{
  const {context,get,calls}=setup();
  context.answer=()=>({events:[],cursor:4,has_more:false});
  await context.loadHistoryPage();
  context.agentRunId='run2';
  await context.loadHistoryPage();
  assert(calls[1].includes('/runs/run2/events?after=0'));
  assert.equal(get('ahEvents').children.length,0);
});

test('linked map evidence opens one local event without a full run snapshot',async()=>{
  const {context,get,calls}=setup();
  context.agentDetailMode='sitemap';
  context.answer=()=>({id:'event1',kind:'observation',data:{body:'PRIVATE_RESPONSE'}});
  await context.openHistoryEvidence('event1');
  assert.deepEqual(calls,['/history/runs/run1/events/event1']);
  assert.equal(context.agentDetailMode,'history');
  assert.equal(get('ahEvents').children[0].open,true);
});

test('timeline pages metadata and opens only selected raw event',async()=>{
  const {context,get,calls}=setup();
  context.agentDetailMode='timeline';
  const event={id:'event1',kind:'observation',created:1700000000,cursor:7};
  context.answer=url=>url.endsWith('/event1')?{...event,data:{body:'PRIVATE_RESPONSE'}}:
    {events:[event],cursor:7,has_more:false};
  context.initHistory();
  await context.loadTimelinePage();
  assert.equal(get('agentEvents').children.length,1);
  assert.equal(get('agentEvents').children[0].children[0].textContent,'작업 전체 기록');
  assert.equal(get('agentEventCount').textContent,'1개 이벤트 표시');
  assert(!JSON.stringify(get('agentEvents').children).includes('PRIVATE_RESPONSE'));
  const row=get('agentEvents').children[0]._rows.children[0];row.open=true;
  await row.ontoggle();
  assert.equal(row.replacement.textContent,'PRIVATE_RESPONSE');
  assert.equal(calls.length,2);
});
