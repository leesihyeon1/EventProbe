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
    window:{}, console,
    renderAgentList:()=>{}, renderAgentListError:(m)=>{ctx._err=m;},
  });
  vm.runInContext(source,ctx);
  ctx.agentApi=async(p,data,method)=>{calls.push({path:p,data,method});return {runs:[]};};
  return {ctx,calls};
}

test('loadAgentList requests the archive list only when toggled',async()=>{
  const {ctx,calls}=setup();
  await ctx.loadAgentList();
  assert(calls.some(c=>c.path==='/runs') && !calls.some(c=>c.path==='/runs?archived=1'));
  vm.runInContext('_showArchived=true',ctx);
  calls.length=0;
  await ctx.loadAgentList();
  assert(calls.some(c=>c.path==='/runs?archived=1'));
});

test('archiveRun posts to archive then refreshes the list',async()=>{
  const {ctx,calls}=setup();
  await ctx.archiveRun('r1');
  assert(calls.some(c=>c.path==='/runs/r1/archive'));
  assert(calls.some(c=>c.path==='/runs'));           // 목록 갱신
});

test('unarchiveRun posts to unarchive then refreshes the list',async()=>{
  const {ctx,calls}=setup();
  await ctx.unarchiveRun('r1');
  assert(calls.some(c=>c.path==='/runs/r1/unarchive'));
  assert(calls.some(c=>c.path==='/runs'));
});
