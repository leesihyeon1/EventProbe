const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const vm=require('node:vm');
const source=fs.readFileSync(path.join(__dirname,'../static/js/agent_sitemap.js'),'utf8');
const ctx=vm.createContext({URL,console});vm.runInContext(source,ctx);
const req=(url='https://example.test/',method='GET',params={})=>({url,method,params});
const ev=(id,kind,data={},step_id='s1')=>({id,kind,data,step_id,created:1700000000});
const obs=(id,request=req(),actor_id='reader',status=200)=>ev(id,'observation',{id,request,actor_id,response:{status,body:'PRIVATE_RESPONSE',headers:{'X-Secret':'PRIVATE_HEADER'}}});
const run=(events=[],endpoints={seed:req()})=>({id:'run1',data:{endpoints,spec:{request:endpoints.seed}},events});
const build=(...args)=>ctx.buildSiteMapModel(run(...args));
const plain=x=>JSON.parse(JSON.stringify(x));

test('groups values, retains method, origin, trailing slash and query keys',()=>{
  const rows=build([], {seed:req('https://example.test/users?id=secret1'),same:req('https://example.test/users?id=secret2#frag'),
    params:req('https://example.test/users','GET',{id:'secret3'}),post:req('https://example.test/users?id=secret4','POST'),
    slash:req('https://example.test/users/?id=secret5'),port:req('https://example.test:8443/users?id=secret6'),
    keys:req('https://example.test/users?a=x')}).rows;
  assert.equal(rows.length,5);
  assert(!JSON.stringify(rows).includes('secret'));
  assert.equal(rows.filter(r=>r.outside).length,1);
});
test('rejects non-HTTP URLs, credentials and invalid URLs',()=>{
  for(const url of ['javascript:alert(1)','file:///test','https://user:pass@example.test','not a URL']) assert.equal(ctx.siteMapAddress(req(url)),null);
});
test('probe payload paths group under original endpoint, but outside origins remain visible',()=>{
  const m=build([ev('a','action',{kind:'probe',endpoint_id:'seed'}),obs('o',req('https://example.test/injected/path?payload=bad')),
    obs('outside',req('https://outside.test/escape'))]);
  assert.equal(m.rows.length,2);
  assert.equal(m.rows.find(r=>r.seed).observations.length,1);
  assert(m.rows.find(r=>r.outside).path==='/escape');
});
test('discovery links only real source evidence; old records do not invent provenance',()=>{
  const m=build([obs('o'),ev('d','discovery',{endpoint_id:'next',source_observation_id:'o'}),ev('d2','discovery',{endpoint_id:'old',source_observation_id:'missing'})],
    {seed:req(),next:req('https://example.test/next'),old:req('https://example.test/old')});
  assert.equal(m.rows.find(r=>r.path==='/next').sources[0].eventId,'o');
  assert.equal(m.rows.find(r=>r.path==='/next').state,'discovered');
  assert.equal(m.rows.find(r=>r.path==='/old').sources.length,0);
  assert.equal(m.rows.find(r=>r.seed).state,'observed');
});
test('HTTP success is not confirmation, missing proof downgrades a verdict',()=>{
  assert.equal(build([obs('o')]).rows[0].state,'observed');
  const m=build([obs('o'),ev('v','verification',{status:'confirmed',evidence_ids:['o','missing']})]);
  assert.equal(m.rows[0].state,'inconclusive');
  assert.equal(m.rows[0].verifications[0].incomplete,true);
  assert.equal(build([ev('v','verification',{status:'confirmed',evidence_ids:[]})]).rows[0].state,'registered');
});
test('access object URL and actor verdict are not assigned to seed or owner',()=>{
  const object=req('https://example.test/orders/42');
  const m=build([ev('a','action',{kind:'access',actor_id:'reader',object_id:'o'}),obs('owner',object,'owner'),obs('reader',object),
    ev('v','verification',{status:'confirmed',evidence_ids:['owner','reader']})]);
  const row=m.rows.find(r=>r.path==='/orders/42');
  assert.equal(m.rows.find(r=>r.seed).state,'registered');
  assert.equal(row.state,'confirmed');
  assert.deepEqual(plain(row.actors.owner.verdicts),[]);
  assert.deepEqual(plain(row.actors.reader.verdicts),['confirmed']);
});
test('actor HTTP statuses, request errors and truncated evidence remain distinct',()=>{
  const o=obs('o',req(),'owner',403);o.data.response.truncated=true;
  const m=build([ev('r','request_started',{request:req(),actor_id:'reader'}),o,obs('reader',req()),
    ev('err','request_error',{request_id:'r'}),ev('orphan','request_error',{request_id:'missing'})]);
  assert.equal(m.rows[0].actors.owner.status,403);
  assert.equal(m.rows[0].actors.reader.status,200);
  assert.equal(m.rows[0].actors.reader.failed,true);
  assert.equal(m.rows[0].actors.owner.failed,false);
  assert(m.rows[0].truncated);
});
test('duplicate polling events do not inflate counts and prototype-like actor IDs are safe',()=>{
  const o=obs('o',req(),'__proto__');const m=build([o,o]);
  assert.equal(m.rows[0].observations.length,1);
  assert.equal(m.rows[0].actors.__proto__.observations,1);
});
test('search, method and state filters compose without matching query values',()=>{
  const rows=build([obs('o')],{seed:req(),next:req('https://example.test/api/items?q=PRIVATE_QUERY','POST')}).rows;
  assert.equal(ctx.filterSiteMapRows(rows,'items','POST','discovered').length,1);
  assert.equal(ctx.filterSiteMapRows(rows,'PRIVATE_QUERY','','').length,0);
  assert.equal(ctx.filterSiteMapRows(rows,'items','GET','').length,0);
});
test('model excludes body/header values and records collection limits without fake coverage',()=>{
  const m=build([obs('o'),ev('limit','discovery_limit',{limit:40,skipped:3})]);
  assert.equal(m.limited,true);
  assert(!JSON.stringify(m).includes('PRIVATE_'));
  assert(!('coverage' in m));
});
test('renderer has no network, HTML interpretation, or target navigation',()=>{
  assert(!/\b(fetch|XMLHttpRequest|WebSocket|EventSource)\s*\(/.test(source));
  assert(!/innerHTML|outerHTML|insertAdjacentHTML|location\s*=|window\.open|\.href\s*=/.test(source));
});
