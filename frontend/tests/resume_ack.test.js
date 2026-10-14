const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const vm=require('node:vm');
const source=fs.readFileSync(path.join(__dirname,'../static/js/agent.js'),'utf8');

function setup() {
  const nodes=new Map(); const get=id=>{if(!nodes.has(id))nodes.set(id,{textContent:'',dataset:{}});return nodes.get(id);};
  const calls=[];
  const ctx=vm.createContext({
    document:{getElementById:get,createElement:()=>({}),createTextNode:()=>({}),querySelector:()=>null,querySelectorAll:()=>[]},
    window:{}, console,
    getHeadersObj:()=>({}), pollAgent:async()=>{}, loadAgentList:async()=>{},
    confirm:(..._a)=>ctx._confirm!==false, _confirm:true,
  });
  vm.runInContext(source,ctx);
  vm.runInContext('agentRunId="r1"',ctx);
  // agent.js declares its own agentApi; override after load with a recording stub.
  ctx.agentApi=async(pathStr,data)=>{
    calls.push({path:pathStr,data});
    if (pathStr.endsWith('/resume') && !(data && data.acknowledge_writes)) throw new Error('처리 여부가 불명확한 쓰기 … 재전송될 수 있어 …');
    return {};
  };
  return {ctx,calls,get};
}

test('resume retries with acknowledge_writes after an ambiguous-write warning (user confirms)',async()=>{
  const {ctx,calls}=setup();
  ctx._confirm=true;
  await ctx.agentControl('resume');
  const resumes=calls.filter(c=>c.path.endsWith('/resume'));
  assert.equal(resumes.length,2);
  assert.equal(resumes[0].data.acknowledge_writes,false);   // 첫 시도는 확인 없이
  assert.equal(resumes[1].data.acknowledge_writes,true);    // 경고 → 확인 → 재전송 수용 재개
});

test('declining the warning does not retry and surfaces the message',async()=>{
  const {ctx,calls,get}=setup();
  ctx._confirm=false;
  await ctx.agentControl('resume');
  assert.equal(calls.filter(c=>c.path.endsWith('/resume')).length,1);   // 재시도 없음
  assert.match(get('agentStatus').textContent,/재전송/);
});

test('a non-write resume succeeds on the first try',async()=>{
  const {ctx,calls}=setup();
  ctx.agentApi=async(pathStr,data)=>{calls.push({path:pathStr,data});return {};};  // 서버가 경고하지 않음
  await ctx.agentControl('resume');
  assert.equal(calls.filter(c=>c.path.endsWith('/resume')).length,1);
});
