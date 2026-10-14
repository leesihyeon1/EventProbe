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
const SAMPLE={summary:{mode:'strict',count:3,external:2,blocked:1,channels:{chat:2,embeddings:1},findings:{email:1,canary:1}},
  records:[
    {ts:'2026-10-15T01:00:00',channel:'chat',model:'m1',dest_host:'nvidia.api',trusted_dest:false,chars:42,findings:[{kind:'email',severity:'block',sample:'a***@b'}],blocked:true},
    {ts:'2026-10-15T01:01:00',channel:'embeddings',model:'m1',dest_host:'localhost',trusted_dest:true,chars:10,findings:[],blocked:false}]};

function setup(result){
  const nodes=new Map(); const get=id=>{if(!nodes.has(id))nodes.set(id,new Element());return nodes.get(id);};
  const fetchCalls=[];
  const ctx=vm.createContext({
    document:{getElementById:get,createElement:t=>new Element(t),createTextNode:t=>{const e=new Element('#text');e.textContent=t;return e;},querySelector:()=>null,querySelectorAll:()=>[]},
    window:{}, console,
    uiNode:(tag,cls,text)=>{const e=new Element(tag);if(cls)e.className=cls;if(text!==undefined)e.textContent=text;return e;},
    epIcon:()=>new Element('icon'),
    fetch:async(u)=>{fetchCalls.push(u);return {};},
    _asJson:async()=>result,
  });
  vm.runInContext(source,ctx);
  return {ctx,get,fetchCalls};
}

test('renders summary chips and newest-first records, text-only, without raw samples',()=>{
  const {ctx,get}=setup();
  ctx.renderEgressAudit(SAMPLE);
  const chipText=all(get('egressAuditSummary')).map(n=>n.textContent).join(' ');
  assert(chipText.includes('strict') && chipText.includes('발견 email'));
  const rows=all(get('egressAuditRecords')).filter(n=>n.tagName==='tr');
  assert.equal(rows.length,3);                                  // header + 2 records
  const firstData=all(get('egressAuditRecords')).filter(n=>n.tagName==='td').map(n=>n.textContent);
  assert(firstData.includes('2026-10-15T01:01:00'));            // newest-first ordering (later ts shown first)
  assert(all(get('egressAuditRecords')).every(n=>n.innerHTML===undefined));
  assert(!JSON.stringify(all(get('egressAuditRecords')).map(n=>n.textContent)).includes('a***@b')); // redacted sample not rendered
});

test('blocked rows are flagged and external/blocked chips alert',()=>{
  const {ctx,get:g}=setup();
  ctx.renderEgressAudit(SAMPLE);
  const blocked=all(g('egressAuditRecords')).filter(n=>n.tagName==='tr' && n.dataset.blocked==='true');
  assert.equal(blocked.length,1);
  const alerts=all(g('egressAuditSummary')).filter(n=>n.dataset && n.dataset.alert);
  assert(alerts.some(c=>c.dataset.alert==='block') && alerts.some(c=>c.dataset.alert==='ext'));
});

test('empty audit shows a clear message',()=>{
  const {ctx,get}=setup();
  ctx.renderEgressAudit({summary:{mode:'permissive',count:0},records:[]});
  assert(all(get('egressAuditRecords')).some(n=>n.textContent==='기록된 외부 전송이 없습니다.'));
});

test('model usage section renders latency and tokens when present',()=>{
  const {ctx,get}=setup();
  ctx.renderEgressAudit({summary:SAMPLE.summary, records:SAMPLE.records,
    usage:[{channel:'chat',model:'m9',calls:3,errors:1,avg_latency_ms:210,max_latency_ms:400,tokens:120}]});
  const cells=all(get('egressAuditRecords')).filter(n=>n.tagName==='td').map(n=>n.textContent);
  assert(cells.includes('m9') && cells.includes('210ms') && cells.includes('120'));
  assert(all(get('egressAuditRecords')).some(n=>n.textContent==='모델 사용'));
});

test('openEgressAudit fetches the audit endpoint and opens the dialog',async()=>{
  const {ctx,get,fetchCalls}=setup(SAMPLE);
  await ctx.openEgressAudit();
  assert(fetchCalls.some(u=>String(u).includes('/api/egress/audit')));
  assert.equal(get('egressAuditDialog').open,true);
  assert(all(get('egressAuditRecords')).some(n=>n.tagName==='table'));
});
