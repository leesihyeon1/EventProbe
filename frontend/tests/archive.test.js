const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const vm=require('node:vm');
const source=fs.readFileSync(path.join(__dirname,'../static/js/agent.js'),'utf8');

function setup() {
  const nodes=new Map(); const get=id=>{if(!nodes.has(id))nodes.set(id,{textContent:'',dataset:{},setAttribute(){}});return nodes.get(id);};
  const calls=[];
  const ctx=vm.createContext({
    document:{getElementById:get,createElement:()=>({}),createTextNode:()=>({}),querySelector:()=>null,querySelectorAll:()=>[]},
    window:{}, console,clearTimeout:()=>{},setTimeout:()=>1,
    renderAgentList:()=>{}, renderAgentListError:(m)=>{ctx._err=m;},
    workspacePage:0,workspacePageSize:10,
  });
  vm.runInContext(source,ctx);
  ctx.agentApi=async(p,data,method)=>{calls.push({path:p,data,method});return {runs:[]};};
  return {ctx,calls};
}

test('loadAgentList searches the full server history in the selected archive scope',async()=>{
  const {ctx,calls}=setup();
  await ctx.loadAgentList();
  assert(calls.some(c=>c.path.startsWith('/history/runs?archived=0&offset=0&limit=10')));
  ctx.document.getElementById('agentCategory').value='access';
  calls.length=0;await ctx.loadAgentList();
  assert(calls[0].path.includes('&category=access'));
  vm.runInContext('_showArchived=true',ctx);
  calls.length=0;
  await ctx.loadAgentList();
  assert(calls.some(c=>c.path.startsWith('/history/runs?archived=1&offset=0&limit=10')));
});

test('archiveRun posts to archive then refreshes the list',async()=>{
  const {ctx,calls}=setup();
  await ctx.archiveRun('r1');
  assert(calls.some(c=>c.path==='/runs/r1/archive'));
  assert(calls.some(c=>c.path.startsWith('/history/runs?'))); // 목록 갱신
});

test('unarchiveRun posts to unarchive then refreshes the list',async()=>{
  const {ctx,calls}=setup();
  await ctx.unarchiveRun('r1');
  assert(calls.some(c=>c.path==='/runs/r1/unarchive'));
  assert(calls.some(c=>c.path.startsWith('/history/runs?')));
});

test('history polling stays compact on first load and after completion',async()=>{
  const {ctx,calls}=setup();
  vm.runInContext('agentRunId="r1"',ctx);
  ctx.agentDetailMode='history';ctx._awRun=null;
  ctx._agentViewActive=()=>true;
  ctx.renderAgentRunHeader=()=>{};ctx.loadHistoryPage=async()=>{};ctx.loadAgentList=()=>{};
  ctx.renderAgentWorkspace=()=>{};
  let pages=0;ctx.loadHistoryPage=async()=>{pages++;};
  ctx.agentApi=async path=>{
    calls.push({path});
    return path.endsWith('/status')?{state:ctx._state||'running',has_pending_oob:false,event_count:0}:
      {id:'r1',events:[]};
  };
  await ctx.pollAgent();
  assert.deepEqual(calls.map(c=>c.path),['/history/runs/r1/status']);
  assert.equal(pages,1);
  ctx.historyState={runId:'r1',hasMore:true};
  ctx._state='completed';
  await ctx.pollAgent();
  assert.deepEqual(calls.map(c=>c.path),['/history/runs/r1/status','/history/runs/r1/status']);
  assert.equal(pages,1); // Polling never walks through the backlog without a click.
  assert.equal(ctx._awRun.compact,true);
});

test('findings first load and unchanged poll never fetch full event bodies',async()=>{
  const {ctx,calls}=setup();
  vm.runInContext('agentRunId="r1"',ctx);
  ctx.agentDetailMode='findings';ctx._awRun=null;ctx._agentViewActive=()=>true;
  ctx.renderAgentRunHeader=()=>{};ctx.renderAgentConclusion=()=>{};
  ctx.renderAgentFindings=()=>{};ctx.loadAgentList=()=>{};
  ctx.agentApi=async path=>{
    calls.push({path});
    return path.endsWith('/status')?
      {id:'r1',state:'running',updated:123,event_count:2000,has_pending_oob:false}:
      {id:'r1',state:'running',updated:123,event_count:2000,has_pending_oob:false,findings:[]};
  };
  await ctx.pollAgent();await ctx.pollAgent();
  assert.deepEqual(calls.map(c=>c.path),['/history/runs/r1/findings','/history/runs/r1/status']);
  assert.equal(ctx._awRun.compact,true);
});

test('late findings response cannot replace a newly selected detail tab',async()=>{
  const {ctx}=setup();
  vm.runInContext('agentRunId="r1"',ctx);
  ctx.agentDetailMode='findings';ctx._awRun=null;ctx._agentViewActive=()=>true;
  let finish;
  ctx.agentApi=()=>new Promise(resolve=>{finish=resolve;});
  const pending=ctx.pollAgent();
  ctx.agentDetailMode='graph';
  finish({id:'r1',state:'completed',updated:1,event_count:1,findings:[]});
  await pending;
  assert.equal(ctx._awRun,null);
});

test('map tabs fetch compact metadata and skip unchanged raw snapshots',async()=>{
  const {ctx,calls}=setup();
  vm.runInContext('agentRunId="r1"',ctx);
  ctx.agentDetailMode='graph';ctx._awRun=null;ctx._agentViewActive=()=>true;
  ctx.renderAgentRunHeader=()=>{};ctx.renderAgentConclusion=()=>{};
  ctx.syncDetailMode=()=>{};ctx.loadAgentList=()=>{};
  ctx.agentApi=async path=>{
    calls.push({path});
    return path.endsWith('/status')?
      {id:'r1',state:'running',updated:123,event_count:2000,has_pending_oob:false}:
      {id:'r1',state:'running',updated:123,event_count:2000,has_pending_oob:false,
        compact:true,view:'map',events:[]};
  };
  await ctx.pollAgent();await ctx.pollAgent();
  assert.deepEqual(calls.map(c=>c.path),['/history/runs/r1/map','/history/runs/r1/status']);
  assert.equal(ctx._awRun.view,'map');
});

test('timeline first load and unchanged poll never fetch full event bodies',async()=>{
  const {ctx,calls}=setup();
  vm.runInContext('agentRunId="r1"',ctx);
  ctx.agentDetailMode='timeline';ctx._awRun=null;ctx._agentViewActive=()=>true;
  ctx.renderAgentRunHeader=()=>{};ctx.renderAgentConclusion=()=>{};
  let pages=0;ctx.loadTimelinePage=async()=>{pages++;};
  ctx.loadAgentList=()=>{};
  const view={id:'r1',state:'running',updated:123,event_count:1,compact:true,view:'timeline'};
  ctx.agentApi=async path=>{
    calls.push({path});
    return path.endsWith('/status')?{state:'running',updated:123,event_count:1,has_pending_oob:false}:view;
  };
  await ctx.pollAgent();
  ctx.timelineState={runId:'r1',hasMore:true};
  await ctx.pollAgent();
  assert.deepEqual(calls.map(c=>c.path),['/history/runs/r1/conclusion','/history/runs/r1/status']);
  assert.equal(pages,1);
  assert.equal(ctx._awRun.view,'timeline');
});

test('overview loads the compact conclusion without opening event pages',async()=>{
  const {ctx,calls}=setup();
  vm.runInContext('agentRunId="r1"',ctx);
  ctx.agentDetailMode='overview';ctx._awRun=null;ctx._agentViewActive=()=>true;
  ctx.renderAgentRunHeader=()=>{};ctx.renderAgentConclusion=()=>{};
  ctx.loadTimelinePage=()=>{throw new Error('overview must not load event pages');};
  ctx.loadAgentList=()=>{};
  ctx.agentApi=async path=>{
    calls.push({path});
    return {id:'r1',state:'running',updated:123,event_count:2000,has_pending_oob:false};
  };
  await ctx.pollAgent();await ctx.pollAgent();
  assert.deepEqual(calls.map(c=>c.path),['/history/runs/r1/conclusion','/history/runs/r1/status']);
  assert.equal(ctx._awRun.view,'overview');
});

test('new evidence refreshes conclusion and cursor timeline without a full snapshot',async()=>{
  const {ctx,calls}=setup();
  vm.runInContext('agentRunId="r1"',ctx);
  ctx.agentDetailMode='timeline';ctx._awRun=null;ctx._agentViewActive=()=>true;
  ctx.renderAgentRunHeader=()=>{};ctx.renderAgentConclusion=()=>{};
  let pages=0;ctx.loadTimelinePage=async()=>{pages++;};
  ctx.loadAgentList=()=>{};
  let count=1;
  ctx.agentApi=async path=>{
    calls.push({path});
    if(path.endsWith('/status')) return {state:'running',updated:123,event_count:2,has_pending_oob:false};
    return {id:'r1',state:'running',updated:123,event_count:count++,compact:true,view:'timeline'};
  };
  await ctx.pollAgent();
  await ctx.pollAgent();
  assert.deepEqual(calls.map(c=>c.path),['/history/runs/r1/conclusion',
    '/history/runs/r1/status','/history/runs/r1/conclusion']);
  assert.equal(ctx._awRun.event_count,2);
  assert.equal(pages,2);
});

test('portable archive download requires explicit raw-evidence confirmation',()=>{
  const {ctx}=setup();
  vm.runInContext('agentRunId="r1"',ctx);
  const links=[];
  ctx.document.createElement=()=>{const link={click(){links.push(link.href);}};return link;};
  ctx.confirm=()=>false;
  ctx.downloadRunArchive();
  assert.equal(links.length,0);
  ctx.confirm=()=>true;
  ctx.downloadRunArchive();
  assert.deepEqual(links,['/api/agent/runs/r1/archive.zip']);
});

test('portable archive import sends local zip and opens archived run',async()=>{
  const {ctx,calls}=setup();
  const input=ctx.document.getElementById('agentArchiveFile');
  input.files=[{size:3,arrayBuffer:async()=>new Uint8Array([1,2,3]).buffer}];
  ctx.fetch=async(url,options)=>{calls.push({url,options});return {};};
  ctx._asJson=async()=>({id:'restored'});
  ctx.selectRun=id=>calls.push({selected:id});
  await ctx.importRunArchive();
  assert(calls.some(c=>c.url==='/api/agent/archives/import' && c.options.method==='POST'));
  assert(calls.some(c=>c.path && c.path.includes('archived=1')));
  assert(calls.some(c=>c.selected==='restored'));
  assert.equal(input.value,'');
});

test('bulk archive sends only selected IDs and renders each result',async()=>{
  const {ctx,calls}=setup();
  ctx.workspaceSelectedIds=new Set(['mine','other']);
  ctx.confirm=()=>true;
  const details=ctx.document.getElementById('agentBatchResults');
  details.children=[];details.replaceChildren=function(){this.children=[];};
  details.append=function(item){this.children.push(item);};
  ctx.uiNode=(_tag,_class,text)=>({textContent:text});
  ctx.loadAgentList=async()=>{};
  ctx.agentApi=async(path,data)=>{
    calls.push({path,data});
    return {succeeded:1,failed:1,results:[{id:'mine',ok:true},{id:'other',ok:false,error:'권한 없음'}]};
  };
  await ctx.bulkRunAction('archive');
  assert.equal(calls[0].path,'/runs/batch');
  assert.equal(calls[0].data.action,'archive');
  assert.deepEqual(Array.from(calls[0].data.ids),['mine','other']);
  assert.equal(details.children.length,2);
  assert.match(ctx.document.getElementById('agentBatchStatus').textContent,/성공 1개, 실패 1개/);
});

test('metadata edit saves inactive run label and category without starting work',async()=>{
  const {ctx,calls}=setup();
  const answers=['Reviewed','access'];ctx.prompt=()=>answers.shift();
  ctx.loadAgentList=async()=>{};
  await ctx.editRunMetadata({id:'r1',state:'completed',name:'',category:''});
  assert.equal(calls.length,1);
  assert.equal(calls[0].path,'/runs/r1/metadata');
  assert.equal(calls[0].method,'PATCH');
  assert.equal(calls[0].data.name,'Reviewed');
  assert.equal(calls[0].data.category,'access');
});
