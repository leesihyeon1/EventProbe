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
  querySelectorAll() {return this.children;}
}
function setup() {
  const nodes=new Map();
  const get=id=>{if(!nodes.has(id))nodes.set(id,new Element());return nodes.get(id);};
  const context=vm.createContext({
    document:{createElement:tag=>new Element(tag),createTextNode:text=>new ElementText(text)},
    window:{addEventListener(){}},agentEl:get,epIcon:name=>new Element('icon-'+name),
    AGENT_STATE_LABELS:{running:'running',completed:'completed',paused:'paused',limited:'limited'},
    selectRun(){},deleteRun(){},archiveRun(){},unarchiveRun(){},pollAgent(){},resetPlanPreview(){},agentRunId:null,_showArchived:false,console,Date,Set,Map,
  });
  vm.runInContext(fs.readFileSync(path.join(__dirname,'../static/js/workspace.js'),'utf8'),context);
  return {context,get};
}
class ElementText {constructor(text){this.textContent=text;this.children=[];}}
const allNodes = n => [n,...n.children.flatMap(allNodes)];

test('workspace opens requests by default and preserves direct run links',()=>{
  const {context,get}=setup();
  const views=[];context.switchView=view=>views.push(view);
  context.location={hash:''};context.restoreWorkspaceRoute();
  assert.equal(views[0],'request');
  context.location.hash='#agent/run123';
  context.resetSiteMap=()=>{};context.resetFindings=()=>{};context.resetCoverage=()=>{};
  context.restoreWorkspaceRoute();
  assert.equal(views[1],'agent');
  assert.equal(get('agentDetailView').hidden,false);
});

test('bulk test has a restorable workspace route',()=>{
  const {context}=setup();
  let opened;
  context.switchView=view=>{opened=view;};
  context.location={hash:'#bulk'};
  context.restoreWorkspaceRoute();
  assert.equal(opened,'bulk');
});

test('asset scoped lookup link restores its filter from the route',()=>{
  const {context}=setup();
  const id='a'.repeat(64);
  let restored;
  context.setGlobalLookupAssetFilter=(kind,assetId)=>{restored=[kind,assetId];};
  context.switchView=()=>{};
  context.location={hash:'#findings/'+id};
  context.restoreWorkspaceRoute();
  assert.deepEqual(restored,['findings',id]);
  context.location.hash='#findings';
  context.restoreWorkspaceRoute();
  assert.deepEqual(restored,['findings','']);
});

test('traffic route passes its filter query to the lookup view',()=>{
  const {context}=setup();
  let restored;
  context.restoreTrafficFilters=query=>{restored=query;};
  context.setGlobalLookupAssetFilter=()=>{};
  context.switchView=()=>{};
  context.location={hash:'#traffic?method=POST&status=302'};
  context.restoreWorkspaceRoute();
  assert.equal(restored,'method=POST&status=302');
});

test('finding route passes archived scope for restoration',()=>{
  const {context}=setup();
  let restored;
  context.restoreFindingFilters=query=>{restored=query;};
  context.setGlobalLookupAssetFilter=()=>{};
  context.switchView=()=>{};
  context.location={hash:'#findings/'+'a'.repeat(64)+'?archived=1'};
  context.restoreWorkspaceRoute();
  assert.equal(restored,'archived=1');
});

test('asset detail link restores the focused asset from the route',()=>{
  const {context}=setup();
  const id='b'.repeat(64);
  let restored;
  context.setAssetFocus=value=>{restored=value;};
  context.switchView=()=>{};
  context.location={hash:'#assets/'+id};
  context.restoreWorkspaceRoute();
  assert.equal(restored,id);
  context.location.hash='#assets';
  context.restoreWorkspaceRoute();
  assert.equal(restored,'');
});

test('asset route forwards date filters for restoration',()=>{
  const {context}=setup();
  let restored;
  context.restoreAssetFilters=query=>{restored=query;};
  context.setAssetFocus=()=>{};
  context.switchView=()=>{};
  context.location={hash:'#assets?from=2026-10-21&through=2026-10-22'};
  context.restoreWorkspaceRoute();
  assert.equal(restored,'from=2026-10-21&through=2026-10-22');
});

test('detail tab is encoded in a direct link and restored',()=>{
  const {context}=setup();
  const location={hash:'#agent/run123'};
  context.location=location;
  context.history={pushState(_a,_b,hash){location.hash=hash;},replaceState(_a,_b,hash){location.hash=hash;}};
  context.resetSiteMap=()=>{};context.resetFindings=()=>{};context.resetCoverage=()=>{};
  context.switchView=()=>{};
  context.restoreWorkspaceRoute();
  context.setDetailMode('explore');
  assert.equal(location.hash,'#agent/run123/explore');
  context.setDetailMode('overview');
  assert.equal(location.hash,'#agent/run123/overview');
  context.setDetailMode('findings');
  location.hash='#agent/run123/overview';
  context.restoreWorkspaceRoute();
  assert.equal(vm.runInContext('agentDetailMode',context),'overview');
});

test('source switch isolates domain fields and clears old plan approval',()=>{
  const {context,get}=setup();
  let resets=0;context.resetPlanPreview=()=>resets++;
  const credential=new Element('textarea');get('agentPolicyDetails').append(credential);
  get('agentSourceDomain').checked=true;context.syncAgentSource();
  assert.equal(get('agentPacketFields').hidden,true);
  assert.equal(get('agentDomainUrl').required,true);
  assert.equal(get('agentTargetScope').value,'same_origin');
  assert.equal(credential.disabled,true);
  get('agentSourceDomain').checked=false;context.syncAgentSource();
  assert.equal(get('agentDomainUrl').disabled,true);
  assert.equal(get('agentTargetScope').value,'request_only');
  assert.equal(credential.disabled,false);
  assert.equal(resets,2);
});

test('search matches goal or ID, independently combined with status',()=>{
  const {context}=setup();
  const runs=[{id:'abc123',goal:'Login check',state:'running'},{id:'def456',goal:'Profile',state:'completed'}];
  assert.equal(context.filteredAgentRuns(runs,' LOGIN ','running').length,1);
  assert.equal(context.filteredAgentRuns(runs,'ABC123','').length,1);
  assert.equal(context.filteredAgentRuns(runs,'Login','completed').length,0);
  assert.equal(context.filteredAgentRuns([{...runs[0],name:'Reviewed',category:'access'}],
    'Reviewed','running','access').length,1);
  assert.equal(context.filteredAgentRuns([{...runs[0],category:'access'}],
    '','running','xss').length,0);
});
test('pagination clamps after filtering and renders a proper table empty state',()=>{
  const {context,get}=setup();
  const runs=Array.from({length:23},(_,i)=>({id:'id'+i,goal:'Goal '+i,state:'completed',created:1700000000}));
  context.renderAgentList(runs);
  assert.equal(get('agentList').children.length,10);
  const cells=get('agentList').children[0].children;
  assert.equal(cells.length,6);
  assert.equal(cells[0].children[0].tagName,'input');
  assert.equal(cells[1].children[0].tagName,'button');
  vm.runInContext('workspacePage=2;renderAgentList()',context);
  assert.equal(get('agentList').children.length,3);
  get('agentSearch').value='absent';context.renderAgentList();
  assert.equal(get('agentList').children[0].children[0].colSpan,6);
  assert.equal(get('agentNext').disabled,true);
});
test('server page reports the real total and state counts beyond the visible rows',()=>{
  const {context,get}=setup();
  vm.runInContext('workspacePage=2',context);
  const runs=Array.from({length:10},(_,i)=>({id:'id'+i,goal:'Goal '+i,state:'completed',created:1700000000}));
  context.renderAgentList({runs,total:64,scope_total:70,state_counts:{completed:60,running:10},offset:20,limit:10});
  assert.equal(get('agentList').children.length,10);
  assert.equal(get('agentCount').textContent,'64개');
  assert.equal(get('agentPageInfo').textContent,'21–30 / 64개');
  assert.equal(get('agentMetrics').children[0].children[1].textContent,'70');
  assert.equal(get('agentNext').disabled,false);
});

test('bulk controls follow selected visible rows and running state',()=>{
  const {context,get}=setup();
  const runs=[{id:'one',goal:'One',state:'completed',created:1700000000},
    {id:'two',goal:'Two',state:'running',created:1700000001}];
  context.renderAgentList({runs,total:2,scope_total:2,state_counts:{completed:1,running:1}});
  const first=get('agentList').children[0].children[0].children[0];
  first.checked=true;first.onchange();
  assert.equal(get('agentBatchArchive').disabled,false);
  assert.equal(get('agentBatchStop').disabled,true);
  const second=get('agentList').children[1].children[0].children[0];
  second.checked=true;second.onchange();
  assert.equal(get('agentBatchStop').disabled,false);
  context.renderAgentList({runs,total:2,scope_total:2,state_counts:{completed:1,running:1}});
  assert.equal(get('agentBatchArchive').disabled,true);
});

test('leaving compact history requests map detail for graph tabs',()=>{
  const {context}=setup();
  let refreshed=0;context.pollAgent=()=>{refreshed++;};
  vm.runInContext("agentRunId='run';agentDetailMode='history';_awRun={id:'run',compact:true,events:[]};setDetailMode('graph')",context);
  assert.equal(refreshed,1);
  assert.equal(vm.runInContext('_awRun',context),null);
});

test('opening overview refreshes a map projection before showing its summary',()=>{
  const {context}=setup();
  let polls=0;context.pollAgent=()=>polls++;
  vm.runInContext("agentRunId='run';_awRun={id:'run',view:'map',compact:false};setDetailMode('overview')",context);
  assert.equal(vm.runInContext('_awRun',context),null);
  assert.equal(polls,1);
});

test('switching compact map tabs reuses metadata but timeline refreshes',()=>{
  const {context}=setup();
  let refreshed=0;context.pollAgent=()=>{refreshed++;};
  context.renderAgentSiteMap=()=>{};
  vm.runInContext("agentRunId='run';agentDetailMode='graph';_awRun={id:'run',compact:true,view:'map',events:[]};setDetailMode('sitemap')",context);
  assert.equal(refreshed,0);
  vm.runInContext("setDetailMode('timeline')",context);
  assert.equal(refreshed,1);
  assert.equal(vm.runInContext('_awRun',context),null);
});

test('state, category and archive filters restore without saving search text',()=>{
  const {context,get}=setup();
  const values=new Map();
  context.localStorage={getItem:key=>values.get(key),setItem:(key,value)=>values.set(key,value)};
  get('agentFilter').value='paused';get('agentCategory').value='access';get('agentSearch').value='sensitive query';
  vm.runInContext('_showArchived=true;saveAgentFilters()',context);
  assert(!values.get('ep-agent-filters').includes('sensitive query'));
  get('agentFilter').value='';get('agentCategory').value='';
  vm.runInContext('_showArchived=false;restoreAgentFilters()',context);
  assert.equal(get('agentFilter').value,'paused');
  assert.equal(get('agentCategory').value,'access');
  assert.equal(get('agentArchivedToggle').attributes['aria-pressed'],'true');
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

test('goal completion and missing reason render as text',()=>{
  const {context,get}=setup();
  context.renderAgentConclusion({completion:'partial',verdict:'inconclusive',text:'부분 결론',
    counts:{},observation_count:0,verifications:[],next_steps:[],scope_note:'범위 제한',
    goals:[{id:'g1',title:'<script>not markup</script>',category:'xss',status:'unmet',
            reason:'연결 증거 없음',evidence_ids:[]}]});
  const nodes=allNodes(get('agentConclusion'));
  assert(nodes.some(n=>n.textContent.includes('미충족 · <script>not markup</script>')));
  assert(nodes.every(n=>n.innerHTML===undefined));
});
test('detail polling preserves expanded events without duplicates',()=>{
  const {context,get}=setup();
  vm.runInContext("agentDetailMode='timeline'",context);
  const run={id:'run',state:'paused',data:{spec:{goal:'test',max_steps:8,max_requests:24,max_ai_calls:8},steps:1,requests:1,ai_calls:0,elapsed:1,endpoints:{seed:{}}},events:[{id:'a',kind:'action',data:{kind:'observe',hypothesis:'test'}}]};
  context.renderAgentWorkspace(run);
  get('agentEvents').children[0].open=true;
  context.renderAgentWorkspace(run);
  assert.equal(get('agentEvents').children.length,1);
  assert.equal(get('agentEvents').children[0].open,true);
  assert.equal(get('agentResume').disabled,false);
  assert.equal(get('agentStop').disabled,true);
});

test('revoked approval disables resume and intervention controls',()=>{
  const {context,get}=setup();
  const run={id:'run',state:'paused',data:{spec:{goal:'test',mode:'plan',approved_plan:{entry:'s',steps:[]},
    max_steps:8,max_requests:24,max_ai_calls:0},plan_checkpoint:{current:'s',phase:'ready'},
    steps:0,requests:0,ai_calls:0,elapsed:0,endpoints:{seed:{}}},events:[{kind:'plan'}]};
  context.renderAgentRunHeader(run);
  assert.equal(get('agentRevokePlan').disabled,false);
  assert.equal(get('agentResume').disabled,false);
  run.data.spec.approved_plan_revoked_at=100;
  context.renderAgentRunHeader(run);
  assert.equal(get('agentRevokePlan').disabled,true);
  assert.equal(get('agentResume').disabled,true);
  assert.equal(get('agentSkipPlan').disabled,true);
});

test('active plan exposes hold control only after its plan is recorded',()=>{
  const {context,get}=setup();
  const run={id:'run',state:'running',data:{spec:{goal:'test',mode:'plan',max_steps:8,max_requests:24,max_ai_calls:0},
    steps:0,requests:0,ai_calls:0,elapsed:0,endpoints:{seed:{}}},events:[]};
  context.renderAgentRunHeader(run);
  assert.equal(get('agentHoldPlan').disabled,true);
  run.events=[{kind:'plan'}];
  context.renderAgentRunHeader(run);
  assert.equal(get('agentHoldPlan').disabled,false);
  run.data.spec.approved_plan_revoked_at=100;
  context.renderAgentRunHeader(run);
  assert.equal(get('agentHoldPlan').disabled,true);
});

test('review gate disables resume and exposes approve or deny until decided',()=>{
  const {context,get}=setup();
  const run={id:'r',state:'paused',data:{spec:{goal:'g',mode:'plan',max_steps:2,max_requests:2,max_ai_calls:0},
    plan_checkpoint:{current:'second',phase:'approval_required'},steps:1,requests:1,ai_calls:0,elapsed:1,endpoints:{}}};
  context.renderAgentRunHeader(run);
  assert.equal(get('agentResume').disabled,true);
  assert.equal(get('agentApproveStep').disabled,false);
  assert.equal(get('agentDenyStep').disabled,false);
  run.data.plan_checkpoint.phase='approved';
  context.renderAgentRunHeader(run);
  assert.equal(get('agentResume').disabled,false);
  assert.equal(get('agentApproveStep').disabled,true);
  run.data.plan_checkpoint.phase='denied';
  context.renderAgentRunHeader(run);
  assert.equal(get('agentResume').disabled,true);
  assert.equal(get('agentSkipPlan').disabled,true);
});

test('run header shows recorded model, procedure hash and tool outcomes as text',()=>{
  const {context,get}=setup();
  context.renderAgentRunHeader({id:'r',state:'completed',data:{spec:{goal:'g',max_steps:1,max_requests:2,max_ai_calls:1},
    steps:1,requests:1,ai_calls:1,elapsed:1,endpoints:{},procedure_sha256:{agent:'a'.repeat(64)},
    planner_attempts:[{model:'synthetic-model',prompt_sha256:'b'.repeat(64)}]},
    tool_summary:{http_observed:1,http_error:0,http_unresolved:0},events:[]});
  const text=allNodes(get('agentSummary')).map(item=>item.textContent).join(' ');
  assert.match(text,/synthetic-model/);
  assert.match(text,/aaaaaaaaaaaa/);
  assert.match(text,/bbbbbbbbbbbb/);
  assert.match(text,/응답 관측/);
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
  assert(allNodes(get('agentResults')).some(n=>n.textContent==='미확정 1'));
  context.renderAgentConclusion(conclusion);
  assert.equal(panel.children[0],first);
  context.renderAgentConclusion(null);
  assert.equal(panel.hidden,true);
  assert.equal(get('agentResults').children.length,0);
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

test('detail tabs have one selected panel and support arrow navigation',()=>{
  const {context,get}=setup();
  let initialized=0;context.initSiteMap=()=>initialized++;context.initFindings=()=>{};context.initHistory=()=>{};context.loadHistoryPage=()=>{};context.resetCoverage=()=>{};
  context.initAgentWorkspace();
  assert.equal(initialized,1);
  context.setDetailMode('sitemap');
  assert.equal(get('agentSiteMap').hidden,false);
  assert.equal(get('agentEvents').hidden,true);
  assert.equal(get('agentGraph').hidden,true);
  assert.equal(get('awTabSiteMap').tabIndex,0);
  assert.equal(get('awTabTimeline').tabIndex,-1);
  context.setDetailMode('history');
  assert.equal(get('agentHistory').hidden,false);
  assert.equal(get('agentRecordControls').hidden,false);
  assert.equal(get('agentOverviewPanel').hidden,true);
  context.setDetailMode('sitemap');
  let prevented=false;
  get('awTabSiteMap').onkeydown({key:'ArrowLeft',preventDefault(){prevented=true;}});
  assert(prevented);
  assert.equal(get('agentExplore').hidden,false);
  assert.equal(get('agentSiteMap').hidden,true);
  assert.equal(get('awTabExplore').focused,true);
  get('awTabRecon').onkeydown({key:'ArrowLeft',preventDefault(){prevented=true;}});
  assert.equal(get('agentOverviewPanel').hidden,false);
  assert.equal(get('agentReconControls').hidden,true);
  assert.equal(get('awTabOverview').focused,true);
});

test('sitemap receives only the existing run snapshot, and switching tasks clears it',()=>{
  const {context,get}=setup();
  let snapshot=null,resets=0;
  context.renderAgentSiteMap=run=>snapshot=run;context.resetSiteMap=()=>resets++;context.resetFindings=()=>{};context.resetCoverage=()=>{};
  const run={id:'synthetic',state:'completed',data:{spec:{goal:'synthetic'},endpoints:{},steps:0,requests:0,ai_calls:0,elapsed:0},events:[]};
  context.setDetailMode('sitemap');context.renderAgentWorkspace(run);
  assert.equal(snapshot,run);
  context.showAgentDetail();
  assert.equal(resets,1);
  assert.equal(vm.runInContext('_awRun',context),null);
  assert.equal(get('agentRunTitle').textContent,'작업 불러오는 중');
});
