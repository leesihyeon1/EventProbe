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

test('history polling uses compact status until the run finishes',async()=>{
  const {ctx,calls}=setup();
  vm.runInContext('agentRunId="r1"',ctx);
  ctx.agentDetailMode='history';ctx._awRun={id:'r1',events:[]};
  ctx._agentViewActive=()=>true;
  ctx.renderAgentRunHeader=()=>{};ctx.loadHistoryPage=async()=>{};ctx.loadAgentList=()=>{};
  ctx.renderAgentWorkspace=()=>{};
  ctx.agentApi=async path=>{
    calls.push({path});
    return path.endsWith('/status')?{state:ctx._state||'running',has_pending_oob:false,event_count:0}:
      {id:'r1',events:[]};
  };
  await ctx.pollAgent();
  assert.deepEqual(calls.map(c=>c.path),['/history/runs/r1/status']);
  ctx._state='completed';
  await ctx.pollAgent();
  assert.deepEqual(calls.map(c=>c.path).slice(1),['/history/runs/r1/status','/runs/r1']);
});
