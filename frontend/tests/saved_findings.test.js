const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const vm=require('node:vm');
const source=fs.readFileSync(path.join(__dirname,'../static/js/agent_findings.js'),'utf8');

function setup(){
  const nodes=new Map();
  class Element {
    constructor(tag='div'){this.tagName=tag;this.children=[];this.dataset={};this.attributes={};this.textContent='';this.value='';this.isConnected=true;}
    set id(value){this._id=value;nodes.set(value,this);}get id(){return this._id;}
    append(...children){for(const c of children){c.parentElement=this;this.children.push(c);}}
    replaceChildren(...children){this.children=[];this.append(...children);}
    setAttribute(key,value){this.attributes[key]=value;}
    showModal(){this.open=true;}close(){this.open=false;}
  }
  const document={getElementById:id=>nodes.get(id)||null,createElement:tag=>new Element(tag),body:new Element('body')};
  const calls=[],selected=[];
  const context=vm.createContext({document,console,confirm:()=>true,
    uiNode:(tag,cls,text)=>{const e=new Element(tag);e.className=cls;e.textContent=text||'';return e;},
    agentApi:async(url,body,method)=>{calls.push({url,body,method});return context.answer(url,body,method);},
    selectRun:id=>selected.push(id),switchView(){},getHeadersObj(){throw new Error('Never reuse current credentials');},
  });
  vm.runInContext(source,context);
  context.answer=url=>url.includes('/evidence/')?{data:{response:{body:'PRIVATE_SNAPSHOT_BODY'}}}:
    url==='/saved-findings/saved1/retest'?{id:'fresh'}:url.includes('/preserved')?{saved:null}:
    url.includes('/preserve')?{id:'saved1',unchanged:false}:url.startsWith('/saved-findings?')?
    {items:[],total:0,has_more:false}:record(url.includes('second')?'second':'saved1');
  return {context,nodes,calls,selected};
}
function record(id){return {id,revision:1,current_version:1,version:1,source_run_id:'old-run',
  finding:{id,category:'sqli',method:'GET',origin:'https://example.test',path:'/<script>text</script>',
    verdict:'confirmed',status:'open',severity:'high',note:''},
  versions:[{version:1}],source:{body_reentry_required:false},
  evidence:[{id:'snapshot1',event_id:'original-event',kind:'observation'}]};}
const all=node=>[node,...node.children.flatMap(all)];

test('preservation sends local mutations and opens the independent identity',async()=>{
  const {context,nodes,calls}=setup();
  const button=context.savedPreserveButton('source-run','legacy-id');
  await button.onclick();
  const capture=calls.find(c=>c.url.endsWith('/preserve'));
  assert.equal(capture.url,'/runs/source-run/findings/legacy-id/preserve');
  assert.equal(Object.keys(capture.body).length,0);
  assert(calls.some(c=>c.url==='/saved-findings/saved1'));
  assert(nodes.get('savedFindingDialog').open);
});

test('saved body is fetched only on disclosure and rendered as text',async()=>{
  const {context,nodes,calls}=setup();
  await context.openSavedLibrary('saved1');
  const detail=nodes.get('savedFindingDetail');
  assert(!calls.some(c=>c.url.includes('/evidence/')));
  assert(all(detail).some(n=>n.textContent.includes('<script>text</script>')));
  const evidence=all(detail).find(n=>n.tagName==='details');evidence.open=true;await evidence.ontoggle();
  assert(calls.some(c=>c.url==='/saved-findings/saved1/evidence/snapshot1?version=1'));
  assert(all(detail).some(n=>n.tagName==='pre'&&n.textContent.includes('PRIVATE_SNAPSHOT_BODY')));
  assert(all(detail).every(n=>n.innerHTML===undefined));
});

test('late evidence from another selection is ignored',async()=>{
  const {context,nodes}=setup();await context.openSavedLibrary('saved1');
  let resolveOld;const previous=context.answer;
  context.answer=url=>url.includes('/evidence/')?new Promise(resolve=>{resolveOld=resolve;}):previous(url);
  const body=all(nodes.get('savedFindingDetail')).find(n=>n.tagName==='details');body.open=true;
  const pending=body.ontoggle();await context.showSavedFinding('second');
  resolveOld({data:{response:{body:'OLD_PRIVATE_BODY'}}});await pending;
  assert.equal(body.children.length,1);
  assert(!all(nodes.get('savedFindingDetail')).some(n=>n.textContent.includes('OLD_PRIVATE_BODY')));
});

test('retest starts a fresh run without copying current editor headers',async()=>{
  const {context,nodes,calls,selected}=setup();await context.openSavedLibrary('saved1');
  const button=all(nodes.get('savedFindingDetail')).find(n=>n.tagName==='button'&&n.textContent==='새 세션으로 재검증');
  await button.onclick();const request=calls.find(c=>c.url.endsWith('/retest'));
  assert.equal(request.body.version,1);
  assert.equal(request.body.allow_write_methods,false);
  assert.equal(Object.hasOwn(request.body,'request_headers'),false);
  assert.deepEqual(selected,['fresh']);
});

test('independent deletion uses revision and never deletes the source run',async()=>{
  const {context,nodes,calls}=setup();await context.openSavedLibrary('saved1');
  const button=all(nodes.get('savedFindingDetail')).find(n=>n.tagName==='button'&&n.textContent==='보존 발견과 증거 삭제');
  await button.onclick();const removal=calls.find(c=>c.method==='DELETE');
  assert.equal(removal.url,'/saved-findings/saved1?expected_revision=1');
  assert(!calls.some(c=>c.method==='DELETE'&&c.url.startsWith('/runs/')));
});
