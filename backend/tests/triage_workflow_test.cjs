const assert=require('node:assert/strict');
const {overview,targets}=require('../../frontend/static/js/triage_workflow.js');
const events=[{id:'a',line:1,host:'source.test',path:'/.env',method:'GET',action:'blocked',priority:'low'},{id:'b',line:2,host:'source.test',path:'/.env',method:'GET',action:'blocked',priority:'low'}];
assert.match(overview({events}).conclusion,/모든 이벤트/);
let r=targets(events,new Set(['a','b']),{'source.test':'https://approved.test'});
assert.equal(r.urls.length,1);assert.equal(r.links.length,2);assert.equal(r.errors.length,0);
assert.equal(targets(events,new Set(['a']),{}).errors.length,1);
for(const path of ['//evil.test/x','/\\evil.test','/x#frag','/bad path'])assert.equal(targets([{...events[0],path}],new Set(['a']),{'source.test':'https://approved.test'}).errors.length,1);
assert.equal(targets([{...events[0],method:'POST'}],new Set(['a']),{'source.test':'https://approved.test'}).errors.length,1);
assert.equal(targets(events,new Set(['a']),{'source.test':'https://user:secret@approved.test'}).errors.length,1);
console.log('triage workflow: overview, selection, deduplication, origin and method checks passed');

const workflow=require('../../frontend/static/js/triage_workflow.js');
const inferred={...events[0],fields:{dport:'443'},reasons:[]};
assert.equal(workflow.inferredOrigin(inferred),'https://source.test');
assert.equal(workflow.targets([inferred],new Set(['a']),{}).urls[0],'https://source.test/.env');
assert.equal(workflow.inferredOrigin({...inferred,reasons:['HOST_CONFLICT']}),'');
assert.equal(workflow.inferredOrigin({...inferred,fields:{}}),'');
assert.equal(workflow.rows(events).length,1);
assert.equal(workflow.rows(events)[0].items.length,2);
assert.equal(workflow.rows([{...events[0],path:'/x?id=1'},{...events[1],path:'/x?id=2'}]).length,2);
assert.equal(workflow.rows([{...events[0],priority:'low'},{...events[1],priority:'review'}])[0].priority,'review');
console.log('analysis table: grouping, priority ordering and automatic URL recovery passed');

const assessed=[
  {...events[0],priority:'review',assessment:{rank:2,importance:'medium'}},
  {...events[1],priority:'low',assessment:{rank:1,importance:'high'}}
];
assert.equal(workflow.rows(assessed)[0].id,'b');
assert.equal(workflow.rows([{...assessed[0],priority:'low'},assessed[1]]).length,2);
assert.equal(workflow.rows([...assessed,{...events[0],id:'legacy'}])[2].id,'legacy');
console.log('attack importance: blocked high-impact attacks remain visible; legacy rows supported');

{
  const events=[
    {host:'web.test',destination:'192.0.2.10',inventory:{origin:'https://web.test',stack:'nginx',stale:false}},
    {host:'web.test',destination:'192.0.2.11',inventory:{origin:'https://web.test',stack:'nginx',stale:false}},
    {host:'other.test',destination:'192.0.2.12'},
    {host:'failed.test',inventory:{origin:'https://failed.test',stack:'IIS',stale:true}}
  ];
  let summary=workflow.technologySummary(events,{'https://web.test':{technologies:['nginx','nginx','PHP'],status:200,checked_at:'2026-11-01T00:00:00Z'},'https://failed.test':{error:'timeout'}});
  assert.equal(summary.targets,3);assert.equal(summary.checked,1);assert.equal(summary.identified,1);assert.equal(summary.failed,1);
  assert.equal(summary.rows[0].records,2);assert.equal(summary.rows[0].destinations.length,2);
  assert.equal(summary.technologies.find(t=>t.label==='nginx').count,1);
  assert.equal(summary.technologies.some(t=>t.label==='IIS'),false);
  assert.equal(workflow.technologySummary(events,{}).checked,0);
  summary=workflow.technologySummary(events,{'https://web.test':{technologies:[],status:403}});
  assert.equal(summary.checked,1);assert.equal(summary.identified,0);
  assert.equal(summary.rows[2].stale,true);
  console.log('technology statistics: distinct targets, DST association, source separation, failures and unidentified profiles passed');
}

(async()=>{
  const events=Array.from({length:23},(_,i)=>({inventory:{origin:`https://target${i}.test`}}));
  events.push(events[0]);let active=0,maxActive=0,calls=0;const updates=[];
  const result=await workflow.probeTargets(events,async origin=>{active++;maxActive=Math.max(maxActive,active);calls++;await new Promise(resolve=>setTimeout(resolve,1));active--;if(origin.endsWith('1.test'))throw new Error('test failure');return {technologies:['nginx'],status:200};},p=>updates.push(p));
  assert.equal(calls,23);assert.equal(maxActive,2);assert.equal(result.deferred,0);assert.equal(result.failed,3);assert.equal(updates.length,23);
  let stopped=true;
  const cancelled=await workflow.probeTargets(events,async()=>{throw Error('must not run');},()=>{},()=>stopped);
  assert.equal(cancelled.completed,0);assert.equal(cancelled.stopped,true);
  const queried=[];const all=await workflow.probeTargets([{host:'unregistered.test'},{destination:'192.0.2.10'}],async origin=>{queried.push(origin);return {technologies:[]};});
  assert.equal(all.total,2);assert.deepEqual(queried,['https://unregistered.test','https://192.0.2.10']);
  console.log('automatic technology probes: deduplication, concurrency, cap, failure isolation, stop and registration checks passed');
})().catch(error=>{console.error(error);process.exitCode=1;});

{
 const base={host:'a.test',path:'/check',method:'GET',fields:{dport:'443'},action:'blocked',priority:'low'};
 const events=[{...base,id:'ips',device:'IPS',action_raw:'Block'},{...base,id:'404',status:404,screening:{code:'HTTP_404'}},{...base,id:'waf',device:'WAF'},{...base,id:'duplicate',device:'IDS',action:'unknown'},{...base,id:'missing',host:'b.test',fields:{}}];
 const q=workflow.queue(events);
 const transfer=workflow.queueTransfer(q);
 assert.equal(q.excluded.length,2);assert.equal(q.unresolved.length,1);
 assert.deepEqual(transfer.urls,['https://a.test/check']);
 assert.deepEqual(transfer.links.map(e=>e.event_id),['waf','duplicate']);
 assert.equal(workflow.queueTransfer(workflow.queue(events,{}, {ips:false,scan:false})).links.length,4);
 console.log('noise filtering -> automatic URL handoff: all remaining requests, deduplication and missing origins passed');
}

{
 const events=[{id:'dst',line:1,destination:'192.0.2.10',method:'GET',path:'/check',fields:{dest_port:'80'}},
 {id:'asset',line:2,host:'app.test',method:'GET',path:'/login',inventory:{origin:'https://app.test:8443'}}];
 assert.deepEqual(workflow.queueTransfer(workflow.queue(events)).urls,['http://192.0.2.10/check','https://app.test:8443/login']);
 const observed={id:'probe',host:'observed.test',method:'GET',path:'/api'};
 assert.deepEqual(workflow.queueTransfer(workflow.queue([observed],{'observed.test':'https://observed.test'}),{'observed.test':'https://observed.test'}).urls,['https://observed.test/api']);
 console.log('verification origins: DST port, inventory and observed origin handoff passed');
}
