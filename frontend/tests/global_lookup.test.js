const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const vm=require('node:vm');

class Element {
  constructor(tag='div'){this.tagName=tag;this.children=[];this.value='';this.checked=false;this.textContent='';this.dataset={};}
  append(...children){this.children.push(...children);}
  replaceChildren(...children){this.children=[...children];}
}
const nodes=new Map();
const get=id=>{if(!nodes.has(id))nodes.set(id,new Element());return nodes.get(id);};
const calls=[];
const context=vm.createContext({
  agentEl:get,uiNode:(tag,cls,text)=>{const node=new Element(tag);node.className=cls;node.textContent=text||'';return node;},
  agentApi:async url=>{
    calls.push(url);
    if(url.includes('/events/'))return {data:{request:{body:'PRIVATE_BODY'}}};
    if(url.includes('/diagnostics'))return {items:[{id:'run1',name:'local',state:'paused',
      policy_version:1,model:'',ai_calls:0,planner_elapsed_ms:0,planner_failures:0,
      procedure_sha256:'a'.repeat(64),prompt_sha256:'b'.repeat(64),token_count:null,
      browser_status:'unknown',request_errors:2,reason:''}],total:1,has_more:false};
    return {items:[{id:'ob1',run_id:'run1',created:1,method:'POST',origin:'https://example.test',
      path:'/login',source:'agent',status:302}],total:1,has_more:false};
  },
  URLSearchParams,Date,setTimeout,clearTimeout,Promise,fetch:async()=>({ok:true,json:async()=>({})}),
  _asJson:async response=>response.json(),openEgressAudit(){},switchView(){},selectRun(){},setDetailMode(){},
});
vm.runInContext(fs.readFileSync(path.join(__dirname,'../static/js/global_lookup.js'),'utf8'),context);

test('traffic list pages metadata and opens raw evidence only on disclosure',async()=>{
  await context.openGlobalLookup('traffic');
  assert.equal(calls.length,1);
  assert.match(calls[0],/history\/traffic/);
  const row=get('globalTrafficRows').children[0];
  assert.equal(row.children[0].children[0].textContent,'POST https://example.test/login');
  const details=row.children[1].children.find(child=>child.tagName==='details');
  details.open=true;
  await details.ontoggle();
  assert.equal(calls.length,2);
  assert.match(calls[1],/history\/runs\/run1\/events\/ob1/);
  assert.match(details.children[1].textContent,/PRIVATE_BODY/);
});

test('selected asset filters both global lists and can be cleared',async()=>{
  const id='a'.repeat(64);
  context.setGlobalLookupAssetFilter('traffic',id);
  assert.equal(context.globalLookupRoute('traffic'),'#traffic/'+id);
  await context.openGlobalLookup('traffic');
  assert.equal(new URLSearchParams(calls.at(-1).split('?')[1]).get('asset_id'),id);
  assert.equal(get('globalTrafficAssetFilter').hidden,false);
  get('globalTrafficClearAsset').onclick();
  assert.equal(context.globalLookupRoute('traffic'),'#traffic');
  context.setGlobalLookupAssetFilter('findings',id);
  await context.openGlobalLookup('findings');
  assert.equal(new URLSearchParams(calls.at(-1).split('?')[1]).get('asset_id'),id);
  context.setGlobalLookupAssetFilter('findings','invalid');
  assert.equal(context.globalLookupRoute('findings'),'#findings');
});

test('traffic filters send status and inclusive local date range',async()=>{
  get('globalTrafficMethod').value='POST';
  get('globalTrafficStatus').value='302';
  get('globalTrafficFrom').value='2026-10-21';
  get('globalTrafficThrough').value='2026-10-22';
  await context.loadGlobalLookup('traffic');
  const query=new URLSearchParams(calls.at(-1).split('?')[1]);
  assert.equal(query.get('method'),'POST');
  assert.equal(query.get('status_code'),'302');
  assert.equal(Number(query.get('since')),new Date(2026,9,21).getTime()/1000);
  assert.equal(Number(query.get('before')),new Date(2026,9,23).getTime()/1000);
  const count=calls.length;
  get('globalTrafficFrom').value='2026-10-24';
  await context.loadGlobalLookup('traffic');
  assert.equal(calls.length,count);
  assert.match(get('globalTrafficCount').textContent,/날짜 범위/);
  get('globalTrafficFrom').value='';get('globalTrafficThrough').value='';
  get('globalTrafficStatus').value='';get('globalTrafficMethod').value='';
});

test('traffic filter link restores safe fields and omits free text',async()=>{
  const location={hash:'#traffic'};
  context.location=location;
  context.history={pushState(_state,_title,hash){location.hash=hash;}};
  get('globalTrafficSearch').value='private search text';
  get('globalTrafficSource').value='manual';
  get('globalTrafficMethod').value='POST';
  get('globalTrafficStatus').value='302';
  get('globalTrafficFrom').value='2026-10-21';
  get('globalTrafficThrough').value='2026-10-22';
  get('globalTrafficArchived').checked=true;
  get('globalTrafficMethod').onchange();
  assert.match(location.hash,/^#traffic\?/);
  assert(!location.hash.includes('private'));
  const saved=location.hash;
  for(const name of ['Source','Method','Status','From','Through'])get('globalTraffic'+name).value='';
  get('globalTrafficArchived').checked=false;
  context.restoreTrafficFilters(saved.split('?')[1]);
  assert.equal(context.globalLookupRoute('traffic'),saved);
  context.restoreTrafficFilters('source=unknown&method=TRACE&status=999&from=oops&archived=2');
  assert.equal(context.globalLookupRoute('traffic'),'#traffic');
  get('globalTrafficSearch').value='';
  context.location=undefined;context.history=undefined;
});

test('finding verdict, status and grouping restore from a direct link',async()=>{
  const location={hash:'#findings'};
  context.location=location;
  context.history={pushState(_state,_title,hash){location.hash=hash;}};
  context.initGlobalLookup('findings');
  get('globalFindingSearch').value='private search text';
  get('globalFindingVerdict').value='suspicious';
  get('globalFindingStatus').value='triaged';
  get('globalFindingGroup').checked=true;
  get('globalFindingArchived').checked=true;
  get('globalFindingVerdict').onchange();
  const saved=location.hash;
  assert.equal(saved,'#findings?verdict=suspicious&status=triaged&group=1&archived=1');
  assert(!saved.includes('private'));
  get('globalFindingVerdict').value='';get('globalFindingStatus').value='';
  get('globalFindingGroup').checked=false;get('globalFindingArchived').checked=false;
  context.restoreFindingFilters(saved.split('?')[1]);
  assert.equal(context.globalLookupRoute('findings'),saved);
  context.restoreFindingFilters('verdict=unknown&status=bad&group=2&archived=2');
  assert.equal(context.globalLookupRoute('findings'),'#findings');
  get('globalFindingSearch').value='';
  context.location=undefined;context.history=undefined;
  await Promise.resolve();
});

test('manual traffic has no run navigation or evidence fetch',()=>{
  const before=calls.length;
  const row=context.globalLookupRow('traffic',{id:'manual1',run_id:'',created:1,
    method:'GET',origin:'https://example.test',path:'/page',source:'manual',status:null});
  assert.match(row.children[0].children[1].textContent,/수동 요청 · HTTP 미관측/);
  assert.equal(row.children[1].children.some(child=>child.tagName==='details'),false);
  assert.equal(row.children[1].children.some(child=>/undefined/.test(child.textContent)),false);
  assert.equal(calls.length,before);
});

test('traffic comparison uses only two metadata projections and clears on filter change',()=>{
  const before=calls.length;
  const items=[
    {id:'one',run_id:'run1',created:1,source:'agent',method:'GET',
      origin:'https://example.test',path:'/one',status:200,body:'PRIVATE_BODY'},
    {id:'two',run_id:'',created:2,source:'manual',method:'POST',
      origin:'https://example.test',path:'/two',status:302,headers:'PRIVATE_HEADER'},
    {id:'three',run_id:'',created:3,source:'manual',method:'GET',
      origin:'https://example.test',path:'/three',status:null},
  ];
  const rows=items.map(item=>context.globalLookupRow('traffic',item));
  get('globalTrafficRows').replaceChildren(...rows);
  const compare=row=>row.children[1].children.find(child=>child.dataset.compareKey);
  compare(rows[0]).onclick();
  assert.equal(get('globalTrafficCompare').hidden,false);
  compare(rows[1]).onclick();
  const panel=get('globalTrafficCompare');
  assert.match(JSON.stringify(panel),/다름/);
  assert(!JSON.stringify(panel).includes('PRIVATE_BODY'));
  assert(!JSON.stringify(panel).includes('PRIVATE_HEADER'));
  assert.equal(calls.length,before);
  compare(rows[2]).onclick();
  assert.match(JSON.stringify(panel),/두 건까지 선택/);
  assert.equal(vm.runInContext('trafficCompare.items.length',context),2);
  compare(rows[0]).onclick();
  assert.equal(vm.runInContext('trafficCompare.items.length',context),1);
  get('globalTrafficSource').onchange();
  assert.equal(panel.hidden,true);
  assert.equal(vm.runInContext('trafficCompare.items.length',context),0);
});

test('traffic and grouped findings can open their exact asset',()=>{
  const id='a'.repeat(64),navigation=[];
  context.setAssetFocus=value=>navigation.push(['asset',value]);
  context.switchView=value=>navigation.push(['view',value]);
  const row=context.globalLookupRow('traffic',{id:'manual1',run_id:'',asset_id:id,created:1,
    method:'GET',origin:'https://example.test',path:'/page',source:'manual',status:200});
  row.children[1].children.find(child=>child.textContent==='자산 열기').onclick();
  const group=context.globalFindingGroupRow({asset_id:id,category:'sqli',actor_id:'current',
    method:'GET',origin:'https://example.test',path:'/page',run_count:1,
    confirmed_count:1,suspicious_count:0,inconclusive_count:0},
    {verdict:'',status:'',archived:'false'},0);
  group.children[0].children.find(child=>child.textContent==='자산 열기').onclick();
  assert.deepEqual(navigation,[['asset',id],['view','assets'],['asset',id],['view','assets']]);
});

test('traffic opens same-asset findings without fetching evidence',()=>{
  const id='b'.repeat(64),before=calls.length,views=[];
  context.switchView=view=>views.push(view);
  get('globalTrafficArchived').checked=true;
  get('globalFindingSearch').value='old search';
  get('globalFindingVerdict').value='confirmed';
  get('globalFindingStatus').value='open';
  get('globalFindingGroup').checked=true;
  const row=context.globalLookupRow('traffic',{id:'manual1',run_id:'',asset_id:id,
    created:1,method:'GET',origin:'https://example.test',path:'/page',source:'manual',status:200});
  row.children[1].children.find(child=>child.textContent==='같은 자산의 발견').onclick();
  assert.deepEqual(views,['findings']);
  assert.equal(context.globalLookupRoute('findings'),'#findings/'+id+'?archived=1');
  assert.equal(get('globalFindingSearch').value,'');
  assert.equal(get('globalFindingVerdict').value,'');
  assert.equal(get('globalFindingGroup').checked,false);
  assert.equal(calls.length,before);
  context.restoreFindingFilters('');
  assert.equal(context.globalLookupRoute('findings'),'#findings/'+id);
  context.setGlobalLookupAssetFilter('findings','');
  get('globalTrafficArchived').checked=false;
  const noAsset=context.globalLookupRow('traffic',{id:'manual2',run_id:'',asset_id:'',
    created:1,method:'GET',origin:'https://example.test',path:'/other',source:'manual',status:200});
  assert.equal(noAsset.children[1].children.some(child=>child.textContent==='같은 자산의 발견'),false);
});

test('findings and groups return to same-asset traffic',()=>{
  const id='c'.repeat(64),before=calls.length,views=[];
  context.switchView=view=>views.push(view);
  get('globalFindingArchived').checked=true;
  get('globalTrafficSearch').value='old search';
  get('globalTrafficSource').value='manual';
  get('globalTrafficMethod').value='POST';
  get('globalTrafficStatus').value='302';
  get('globalTrafficFrom').value='2026-10-21';
  const finding=context.globalLookupRow('findings',{id:'f1',run_id:'run1',asset_id:id,
    created:1,method:'GET',origin:'https://example.test',path:'/page',
    verdict:'confirmed',category:'access',evidence_count:1,status:'open'});
  finding.children[1].children.find(child=>child.textContent==='같은 자산의 트래픽').onclick();
  assert.equal(context.globalLookupRoute('traffic'),'#traffic/'+id+'?archived=1');
  assert.equal(get('globalTrafficSearch').value,'');
  assert.equal(get('globalTrafficSource').value,'');
  assert.equal(get('globalTrafficFrom').value,'');
  const group=context.globalFindingGroupRow({asset_id:id,category:'access',actor_id:'current',
    method:'GET',origin:'https://example.test',path:'/page',run_count:1,
    confirmed_count:1,suspicious_count:0,inconclusive_count:0},
    {verdict:'',status:'',archived:'true'},0);
  group.children[0].children.find(child=>child.textContent==='같은 자산의 트래픽').onclick();
  assert.deepEqual(views,['traffic','traffic']);
  assert.equal(calls.length,before);
  context.setGlobalLookupAssetFilter('traffic','');
  get('globalFindingArchived').checked=false;
  get('globalTrafficArchived').checked=false;
});

test('raw and multi-target traffic use passive source labels',()=>{
  for(const [source,label] of [['raw','원문 패킷'],['multi','다중 대상']]) {
    const row=context.globalLookupRow('traffic',{id:'x',run_id:'',created:1,
      method:'GET',origin:'https://example.test',path:'/page',source,status:200});
    assert.match(row.children[0].children[1].textContent,new RegExp(label));
    assert.equal(row.children[1].children.some(child=>child.tagName==='details'),false);
  }
});

test('grouped findings keep per-run verdicts and fetch members on disclosure',async()=>{
  get('globalFindingGroup').checked=true;
  const urls=[];
  const previousApi=context.agentApi;
  context.agentApi=async url=>{
    urls.push(url);
    if(url.includes('/groups/members'))return {items:[{id:'f1',run_id:'run1',created:1,
      method:'GET',origin:'https://example.test',path:'/item',category:'sqli',
      verdict:'confirmed',status:'open',evidence_count:1}],total:1,has_more:false};
    return {items:[{asset_id:'a'.repeat(64),input_shape_id:'b'.repeat(64),category:'sqli',actor_id:'current',method:'GET',
      origin:'https://example.test',path:'/item',run_count:2,finding_count:2,
      confirmed_count:1,suspicious_count:1,inconclusive_count:0}],total:1,has_more:false};
  };
  await context.openGlobalLookup('findings');
  assert.match(urls[0],/history\/findings\/groups\?/);
  assert.equal(urls.length,1);
  const group=get('globalFindingRows').children[0];
  assert.match(group.children[0].children[1].textContent,/확증 1 · 의심 1/);
  const detail=group.children[1];detail.open=true;await detail.ontoggle();
  assert.match(urls[1],/history\/findings\/groups\/members\?/);
  assert.equal(detail.children[1].children.length,1);
  assert.match(detail.children[1].children[0].children[0].children[1].textContent,/확증/);
  get('globalFindingGroup').checked=false;
  context.agentApi=previousApi;
});

test('form view shows types and states without displaying saved values',()=>{
  context.renderAgentExplore({recon:{form_candidates:[{endpoint_id:'login',login:true,
    source:'html',status:'untested',fields:['user','password'],field_schema:[
      {name:'user',type:'text',required:true},{name:'password',type:'password',required:true}]}]},
    data:{endpoints:{login:{method:'POST',url:'https://example.test/login'}}}});
  const row=get('agentExploreForms').children[0];
  assert.match(row.children[1].textContent,/미검사/);
  assert.match(row.children[2].children[1].textContent,/password · password · 필수/);
  assert(!JSON.stringify(row).includes('PRIVATE_BODY'));
});

test('operations view distinguishes missing browser result and request errors',async()=>{
  await context.loadOps();
  const row=get('opsRows').children[0];
  assert.match(row.children[1].textContent,/브라우저 결과 기록 없음/);
  assert.match(row.children[1].textContent,/요청 오류 2회/);
  assert.match(row.children[1].textContent,/절차 a{12} · 프롬프트 b{12}/);
  assert.match(row.children[1].textContent,/토큰 미제공/);
  assert(!JSON.stringify(row).includes('PRIVATE_BODY'));
});
