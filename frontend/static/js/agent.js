/* Context agent UI. All target/AI strings are rendered as text. */
let agentRunId = null, agentTimer = null, agentBusy = false;
const agentEl = id => document.getElementById(id);

function initAgentDialog() {
  if (agentEl('agentDialog')) return;
  const dialog = document.createElement('dialog');
  dialog.id = 'agentDialog';
  dialog.innerHTML = `
    <div class="agent-header"><strong>맥락 에이전트</strong><span class="agent-help">현재 요청 · 관측 · 가설 · 검증</span>
      <button class="btn btn-secondary" style="margin-left:auto" id="agentClose">닫기</button></div>
    <div class="agent-layout"><div class="agent-config">
      <p class="agent-help">현재 요청 폼에서 시작합니다. 같은 출처의 링크·GET 폼을 발견하고, 계정별 세션으로 테스트합니다.</p>
      <label for="agentGoal">테스트 목표</label><textarea id="agentGoal">현재 요청에서 취약 신호를 확인하고 근거가 있는 후속 테스트를 진행해줘.</textarea>
      <label for="agentSteps">최대 단계</label><input id="agentSteps" type="number" min="1" max="50" value="8">
      <label for="agentRequests">최대 HTTP 요청</label><input id="agentRequests" type="number" min="1" max="150" value="24">
      <label for="agentAiCalls">최대 AI 호출</label><input id="agentAiCalls" type="number" min="0" max="50" value="8">
      <label for="agentSeconds">최대 실행 시간(초)</label><input id="agentSeconds" type="number" min="10" max="1800" value="300">
      <label><input id="agentWrite" type="checkbox"> POST·PUT·PATCH·DELETE 허용</label>
      <label><input id="agentShare" type="checkbox"> 응답 발췌를 AI 제공자에 전달</label>
      <p class="agent-help">기본 AI 입력은 경로·필드명·판정 라벨입니다. 발췌를 켜면 응답 데이터 일부도 전달됩니다. 요청·응답 증거는 이 PC에 저장됩니다.</p>
      <details><summary>계정과 객체 접근 정책</summary>
        <label for="agentActors">계정 목록(JSON)</label><textarea id="agentActors" rows="5">[{"id":"current","label":"현재 계정","headers":{}}]</textarea>
        <p class="agent-help">첫 계정은 현재 요청의 인증을 이어받습니다. 다른 계정은 각각 Cookie 또는 Authorization 헤더를 지정합니다.</p>
        <label for="agentObjects">객체 정책(JSON)</label><textarea id="agentObjects" rows="4">[]</textarea>
        <p class="agent-help">예: {"id":"orderB","url":"시작 URL과 같은 출처의 주문 URL","owner_actor":"userB","allowed_actors":[],"identity_pointer":"/id","identity_value":"42","description":"주문 소유자만 조회 가능"}</p>
      </details>
      <div class="agent-buttons"><button class="btn btn-success" id="agentStart">현재 요청으로 시작</button></div>
      <label for="agentHistory">저장된 실행</label><select id="agentHistory"><option value="">실행 선택</option></select>
      <div class="agent-buttons"><button class="btn btn-secondary" id="agentRefresh">목록 새로고침</button>
      <button class="btn btn-secondary" id="agentExport">기록 다운로드</button></div>
    </div><div class="agent-results">
      <div id="agentStatus" role="status">테스트를 시작하거나 저장된 실행을 선택하세요.</div>
      <div class="agent-buttons"><button class="btn btn-secondary" id="agentStop" disabled>중단</button>
      <button class="btn btn-secondary" id="agentResume" disabled>재개</button></div>
      <div id="agentSummary"></div><div id="agentEvents"></div>
    </div></div>`;
  document.body.appendChild(dialog);
  agentEl('agentClose').onclick = () => dialog.close();
  dialog.addEventListener('close', () => { clearTimeout(agentTimer); agentTimer = null; });
  agentEl('agentStart').onclick = startAgent;
  agentEl('agentStop').onclick = () => agentControl('stop');
  agentEl('agentResume').onclick = () => agentControl('resume');
  agentEl('agentRefresh').onclick = agentHistory;
  agentEl('agentExport').onclick = exportAgent;
  agentEl('agentHistory').onchange = e => { agentRunId = e.target.value; if (agentRunId) pollAgent(); };
}

async function agentApi(path, data) {
  const options = data === undefined ? {} : { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(data) };
  return _asJson(await fetch('/api/agent' + path, options), '에이전트');
}

async function openAgent() {
  initAgentDialog();
  if (!agentEl('agentDialog').open) agentEl('agentDialog').showModal();
  await agentHistory();
  if (agentRunId) pollAgent();
}

async function agentHistory() {
  try {
    const data = await agentApi('/runs');
    const select = agentEl('agentHistory');
    select.replaceChildren(new Option('실행 선택', ''));
    for (const run of data.runs) select.add(new Option(`${run.state} · ${run.goal.slice(0,60)}`, run.id));
    select.value = agentRunId || '';
  } catch(e) { agentEl('agentStatus').textContent = e.message; }
}

async function startAgent() {
  if (agentBusy) return;
  agentBusy = true;
  agentEl('agentStart').disabled = true;
  try {
    const form = _currentRequestForm();
    const headers = { ...(getUseDefaults() ? getDefaultHeaderProfile() : {}), ...getHeadersObj() };
    const run = await agentApi('/runs', {
      goal:agentEl('agentGoal').value, request:{ method:form.method,url:form.url,params:form.params,body:form.body || '',headers },
      actors:JSON.parse(agentEl('agentActors').value), objects:JSON.parse(agentEl('agentObjects').value),
      max_steps:Number(agentEl('agentSteps').value),max_requests:Number(agentEl('agentRequests').value),
      max_ai_calls:Number(agentEl('agentAiCalls').value),max_seconds:Number(agentEl('agentSeconds').value),
      allow_write_methods:agentEl('agentWrite').checked,share_response_context:agentEl('agentShare').checked
    });
    agentRunId = run.id;
    agentEl('agentEvents').replaceChildren();
    await agentHistory();
    await pollAgent();
  } catch(e) { agentEl('agentStatus').textContent = e.message; }
  finally { agentBusy = false; agentEl('agentStart').disabled = false; }
}

async function agentControl(action) {
  if (!agentRunId) return;
  try {
    const data = action === 'resume' ? {
      request_headers:getHeadersObj(), actor_headers:Object.fromEntries(JSON.parse(agentEl('agentActors').value).map(a => [a.id,a.headers || {}]))
    } : {};
    await agentApi(`/runs/${agentRunId}/${action}`, data);
    await pollAgent();
  } catch(e) { agentEl('agentStatus').textContent = e.message; }
}

function renderAgent(run) {
  const labels = {running:'실행 중',paused:'일시정지',interrupted:'서버 재시작으로 중단됨',completed:'실행 종료',limited:'한도 도달'};
  agentEl('agentStatus').textContent = `${labels[run.state] || run.state} — ${run.data.reason || run.data.spec.goal}`;
  agentEl('agentStop').disabled = run.state !== 'running';
  agentEl('agentResume').disabled = !['paused','interrupted'].includes(run.state);
  agentEl('agentSummary').textContent = `단계 ${run.data.steps}/${run.data.spec.max_steps} · HTTP ${run.data.requests}/${run.data.spec.max_requests} · AI ${run.data.ai_calls}/${run.data.spec.max_ai_calls} · ${Math.round(run.data.elapsed)}초 · 발견 경로 ${Object.keys(run.data.endpoints).length}개`;
  const container = agentEl('agentEvents');
  // Append-only evidence avoids collapsing an open response during polling.
  if (container.dataset.run !== run.id) { container.replaceChildren(); container.dataset.run = run.id; }
  const existing = new Set([...container.children].map(el => el.dataset.event));
  for (const event of run.events) {
    if (existing.has(event.id)) continue;
    const card = document.createElement('details'); card.className = 'agent-event'; card.dataset.event = event.id;
    const title = document.createElement('summary');
    const d = event.data;
    const text = event.kind === 'action' ? `${d.kind} — ${d.hypothesis}` :
      event.kind === 'observation' ? `${d.actor_id} · HTTP ${d.response.status} · ${d.request.method} ${d.request.url}` :
      event.kind === 'verification' ? `검증: ${d.status} · 증거 ${(d.evidence_ids || []).length}개` :
      `${event.kind} — ${d.reason || d.message || d.protocol || ''}`;
    title.textContent = text;
    const pre = document.createElement('pre'); pre.textContent = JSON.stringify(d,null,2);
    card.append(title,pre); container.append(card);
  }
}

async function pollAgent() {
  clearTimeout(agentTimer);
  const id = agentRunId;
  if (!id || !agentEl('agentDialog')?.open) return;
  try {
    const run = await agentApi('/runs/' + id);
    if (id !== agentRunId) return;
    renderAgent(run);
    if (run.state === 'running' || run.events.some(e => e.kind === 'oob_pending')) agentTimer = setTimeout(pollAgent,2000);
  } catch(e) { agentEl('agentStatus').textContent = e.message; }
}

async function exportAgent() {
  if (!agentRunId) return;
  try {
    const run = await agentApi('/runs/' + agentRunId);
    const url = URL.createObjectURL(new Blob([JSON.stringify(run,null,2)],{type:'application/json'}));
    const a = document.createElement('a'); a.href = url; a.download = 'agent-' + run.id + '.json'; a.click(); URL.revokeObjectURL(url);
  } catch(e) { agentEl('agentStatus').textContent = e.message; }
}
