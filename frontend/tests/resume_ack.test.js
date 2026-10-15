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
    prompt:()=>ctx._reason, _reason:'검사 범위 변경으로 건너뜀',
    _awRun:{data:{plan_checkpoint:{current:'step-two'}}},
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

test('skip sends an audited reason and never resumes automatically',async()=>{
  const {ctx,calls}=setup();
  await ctx.skipAgentPlanStep();
  assert.equal(calls.length,1);
  assert.equal(calls[0].path,'/runs/r1/plan/skip');
  assert.equal(calls[0].data.reason,'검사 범위 변경으로 건너뜀');
});

test('revoke sends an audited reason and never resumes automatically',async()=>{
  const {ctx,calls}=setup();
  ctx._reason='정책 변경으로 승인 철회';
  await ctx.revokeAgentPlan();
  assert.equal(calls.length,1);
  assert.equal(calls[0].path,'/runs/r1/plan/revoke');
  assert.equal(calls[0].data.reason,'정책 변경으로 승인 철회');
});

test('hold sends an audited reason and never resumes automatically',async()=>{
  const {ctx,calls}=setup();
  ctx._reason='범위 확인 필요';
  await ctx.holdAgentPlan();
  assert.equal(calls.length,1);
  assert.equal(calls[0].path,'/runs/r1/plan/hold');
  assert.equal(calls[0].data.reason,'범위 확인 필요');
});

test('step approval and denial only record decisions',async()=>{
  const {ctx,calls}=setup();
  ctx._reason='로컬 범위 검토';
  await ctx.reviewAgentPlanStep(true);
  await ctx.reviewAgentPlanStep(false);
  assert.deepEqual(calls.map(call=>call.path),
    ['/runs/r1/plan/step/approve','/runs/r1/plan/step/deny']);
  assert(calls.every(call=>call.data.reason==='로컬 범위 검토'));
});
