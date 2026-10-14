const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const vm=require('node:vm');
const source=fs.readFileSync(path.join(__dirname,'../static/js/agent.js'),'utf8');

class Element {
  constructor(tag='div'){this.tagName=tag;this.children=[];this.dataset={};this.attributes={};this.value='';this.textContent='';}
  append(...n){this.children.push(...n);} replaceChildren(...n){this.children=[...n];}
  setAttribute(k,v){this.attributes[k]=v;} showModal(){this.open=true;} close(){this.open=false;}
}
const desc=n=>n.children.flatMap(c=>[c,...desc(c)]);
const all=n=>[n,...desc(n)];
const RECORDS=[
  {run_id:'r2',deleted:1760000600,reason:'retention',state:'completed',events:5,goal:'오래된 작업'},
  {run_id:'r1',deleted:1760000000,reason:'manual',state:'paused',events:3,goal:'민감 작업'}];

function setup(result){
  const nodes=new Map(); const get=id=>{if(!nodes.has(id))nodes.set(id,new Element());return nodes.get(id);};
  const calls=[];
  const ctx=vm.createContext({
    document:{getElementById:get,createElement:t=>new Element(t),createTextNode:t=>{const e=new Element('#text');e.textContent=t;return e;},querySelector:()=>null,querySelectorAll:()=>[]},
    window:{}, console, Date,
    uiNode:(tag,cls,text)=>{const e=new Element(tag);if(cls)e.className=cls;if(text!==undefined)e.textContent=text;return e;},
    epIcon:()=>new Element('icon'),
  });
  vm.runInContext(source,ctx);
  ctx.agentApi=async(p)=>{calls.push(p);return {deletions:result||RECORDS};};   // override clobbered declaration
  return {ctx,get,calls};
}

test('renders deletion records with reason labels, text-only',()=>{
  const {ctx,get}=setup();
  ctx.renderDeletions(RECORDS);
  const cells=all(get('deletionsRecords')).filter(n=>n.tagName==='td').map(n=>n.textContent);
  assert(cells.includes('수동 삭제') && cells.includes('보존 정리'));
  assert(cells.includes('민감 작업') && cells.includes('5'));
  assert.equal(all(get('deletionsRecords')).filter(n=>n.tagName==='tr').length,3); // header + 2
  assert(all(get('deletionsRecords')).every(n=>n.innerHTML===undefined));
});

test('retention rows are flagged distinctly',()=>{
  const {ctx,get}=setup();
  ctx.renderDeletions(RECORDS);
  const retention=all(get('deletionsRecords')).filter(n=>n.tagName==='tr' && n.dataset.reason==='retention');
  assert.equal(retention.length,1);
});

test('empty deletion log shows a clear message',()=>{
  const {ctx,get}=setup();
  ctx.renderDeletions([]);
  assert(all(get('deletionsRecords')).some(n=>n.textContent==='삭제 기록이 없습니다.'));
});

test('openDeletions fetches the audit and opens the dialog',async()=>{
  const {ctx,get,calls}=setup();
  await ctx.openDeletions();
  assert(calls.includes('/deletions'));
  assert.equal(get('deletionsDialog').open,true);
  assert(all(get('deletionsRecords')).some(n=>n.tagName==='table'));
});
