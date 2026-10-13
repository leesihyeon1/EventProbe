/* 자율 검증 작업 UI — 목록 + 상세(전용 페이지 뷰). 모든 대상/AI 문자열은 텍스트로 렌더.
   이전엔 모달이었으나(리뷰 agent.js:7) 장시간 작업에 맞게 작업 목록 + 상세 타임라인 뷰로 분리. */
let agentRunId = null, agentTimer = null, agentBusy = false, agentInited = false, agentPolicy = null;
const agentEl = id => document.getElementById(id);

async function agentApi(path, data) {
  const options = data === undefined ? {} : { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(data) };
  return _asJson(await fetch('/api/agent' + path, options), '에이전트');
}

function initAgentView() {
  if (agentInited) return;
  agentInited = true;
  agentEl('agentStart').onclick = startAgent;
  agentEl('agentStop').onclick = () => agentControl('stop');
  agentEl('agentResume').onclick = () => agentControl('resume');
  agentEl('agentRefresh').onclick = () => { loadEgressPolicy(); loadAgentList(); };
  agentEl('agentExport').onclick = exportAgent;
}

// 자율 검증 탭으로 전환할 때(switchView 훅) 호출된다.
async function openAgentView() {
  initAgentView();
  await Promise.all([loadEgressPolicy(), loadAgentList()]);
  const hashId = (location.hash.match(/^#agent\/(\w+)/) || [])[1];
  if (hashId && hashId !== agentRunId) selectRun(hashId);
  else if (agentRunId) pollAgent();
}
window.openAgentView = openAgentView;

// 이전 진입점 호환 — 모달 대신 뷰로 전환한다.
function openAgent() { switchView('agent'); }
window.openAgent = openAgent;

// 서버가 강제하는 반출 정책을 표시하고, 응답 공유 옵션을 정책에 맞춰 잠근다(리뷰 agent.js:20).
async function loadEgressPolicy() {
  const banner = agentEl('egressPolicyBanner');
  try {
    agentPolicy = await _asJson(await fetch('/api/egress/policy'), '반출 정책');
  } catch (e) {
    if (banner) banner.textContent = '반출 정책을 불러오지 못했습니다: ' + e.message;
    return;
  }
  const strict = !!agentPolicy.strict;
  if (banner) {
    banner.className = 'egress-banner ' + (strict ? 'egress-strict' : 'egress-permissive');
    banner.textContent = strict
      ? '🔒 반출 모드: STRICT — 서버가 외부 AI 전송을 제한합니다(응답 유래 근거·외부 임베딩 차단, 비식별 요청 구조만 전송).'
      : '🌐 반출 모드: PERMISSIVE — 외부 AI 전송이 허용됩니다(요청 구조·판정 근거가 전송될 수 있음). 서버 .env 의 AI_EXPORT_MODE=strict 로 강화.';
  }
  const share = agentEl('agentShare'), note = agentEl('agentShareNote');
  if (share) {
    if (strict) {
      share.checked = false; share.disabled = true;
      if (note) note.textContent = '서버 정책(STRICT): 응답 발췌 전송이 금지되어 이 옵션은 비활성화됩니다 — 클라이언트에서 완화할 수 없습니다.';
    } else {
      share.disabled = false;
      if (note) note.textContent = '기본 AI 입력은 경로·필드명·판정 라벨입니다. 발췌를 켜면 응답 데이터 일부도 전달됩니다. 요청·응답 증거는 이 PC에 저장됩니다.';
    }
  }
}

const AGENT_STATE_LABELS = {
  running: '실행 중', paused: '일시정지', interrupted: '중단됨', completed: '종료', limited: '한도',
};

async function loadAgentList() {
  const list = agentEl('agentList');
  if (!list) return;
  try {
    const data = await agentApi('/runs');
    if (!data.runs.length) {
      list.innerHTML = '<div class="empty-state" style="padding:16px"><div class="msg">저장된 작업이 없습니다.</div></div>';
      return;
    }
    list.replaceChildren();
    for (const run of data.runs) {
      const row = document.createElement('button');
      row.type = 'button';
      row.className = 'agent-row' + (run.id === agentRunId ? ' active' : '');
      row.dataset.run = run.id;
      const st = document.createElement('span');
      st.className = 'agent-row-state state-' + run.state;
      st.textContent = AGENT_STATE_LABELS[run.state] || run.state;
      const goal = document.createElement('span');
      goal.className = 'agent-row-goal';
      goal.textContent = run.goal || '(목표 없음)';
      row.append(st, goal);
      row.onclick = () => selectRun(run.id);
      list.append(row);
    }
  } catch (e) { list.textContent = e.message; }
}

function selectRun(id) {
  agentRunId = id;
  try { history.replaceState(null, '', '#agent/' + id); } catch (e) {}
  document.querySelectorAll('.agent-row').forEach(r => r.classList.toggle('active', r.dataset.run === id));
  const ev = agentEl('agentEvents');
  if (ev) { ev.replaceChildren(); ev.dataset.run = ''; }
  pollAgent();
}

async function startAgent() {
  if (agentBusy) return;
  agentBusy = true;
  agentEl('agentStart').disabled = true;
  try {
    const form = _currentRequestForm();
    const headers = { ...(getUseDefaults() ? getDefaultHeaderProfile() : {}), ...getHeadersObj() };
    // strict 모드면 응답 공유를 요청하지 않는다(서버도 context 에서 발췌를 제거하지만 이중 방어).
    const share = agentEl('agentShare').checked && !(agentPolicy && agentPolicy.strict);
    const run = await agentApi('/runs', {
      goal: agentEl('agentGoal').value,
      request: { method: form.method, url: form.url, params: form.params, body: form.body || '', headers },
      actors: JSON.parse(agentEl('agentActors').value), objects: JSON.parse(agentEl('agentObjects').value),
      max_steps: Number(agentEl('agentSteps').value), max_requests: Number(agentEl('agentRequests').value),
      max_ai_calls: Number(agentEl('agentAiCalls').value), max_seconds: Number(agentEl('agentSeconds').value),
      allow_write_methods: agentEl('agentWrite').checked, share_response_context: share,
    });
    agentEl('agentNew').open = false;
    await loadAgentList();
    selectRun(run.id);
  } catch (e) { agentEl('agentStatus').textContent = e.message; }
  finally { agentBusy = false; agentEl('agentStart').disabled = false; }
}

async function agentControl(action) {
  if (!agentRunId) return;
  try {
    const data = action === 'resume' ? {
      request_headers: getHeadersObj(),
      actor_headers: Object.fromEntries(JSON.parse(agentEl('agentActors').value).map(a => [a.id, a.headers || {}])),
    } : {};
    await agentApi(`/runs/${agentRunId}/${action}`, data);
    await pollAgent();
    loadAgentList();
  } catch (e) { agentEl('agentStatus').textContent = e.message; }
}

function renderAgent(run) {
  const labels = { running: '실행 중', paused: '일시정지', interrupted: '서버 재시작으로 중단됨', completed: '실행 종료', limited: '한도 도달' };
  agentEl('agentStatus').textContent = `${labels[run.state] || run.state} — ${run.data.reason || run.data.spec.goal}`;
  agentEl('agentStop').disabled = run.state !== 'running';
  agentEl('agentResume').disabled = !['paused', 'interrupted'].includes(run.state);
  agentEl('agentExport').disabled = false;
  agentEl('agentSummary').textContent = `단계 ${run.data.steps}/${run.data.spec.max_steps} · HTTP ${run.data.requests}/${run.data.spec.max_requests} · AI ${run.data.ai_calls}/${run.data.spec.max_ai_calls} · ${Math.round(run.data.elapsed)}초 · 발견 경로 ${Object.keys(run.data.endpoints).length}개`;
  const container = agentEl('agentEvents');
  // 추가 전용 렌더 — 폴링 중 열어둔 응답이 접히지 않게 한다.
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
    const pre = document.createElement('pre'); pre.textContent = JSON.stringify(d, null, 2);
    card.append(title, pre); container.append(card);
  }
}

function _agentViewActive() {
  const v = document.querySelector('.view[data-view="agent"]');
  return v && v.classList.contains('active');
}

async function pollAgent() {
  clearTimeout(agentTimer);
  const id = agentRunId;
  if (!id || !_agentViewActive()) return;   // 다른 뷰면 폴링 중단(자원 절약)
  try {
    const run = await agentApi('/runs/' + id);
    if (id !== agentRunId) return;
    renderAgent(run);
    if (run.state === 'running' || run.events.some(e => e.kind === 'oob_pending')) agentTimer = setTimeout(pollAgent, 2000);
    else loadAgentList();
  } catch (e) { agentEl('agentStatus').textContent = e.message; }
}

async function exportAgent() {
  if (!agentRunId) return;
  try {
    const run = await agentApi('/runs/' + agentRunId);
    const url = URL.createObjectURL(new Blob([JSON.stringify(run, null, 2)], { type: 'application/json' }));
    const a = document.createElement('a'); a.href = url; a.download = 'agent-' + run.id + '.json'; a.click(); URL.revokeObjectURL(url);
  } catch (e) { agentEl('agentStatus').textContent = e.message; }
}

// URL 해시로 특정 작업에 바로 진입 가능(리뷰: UI 상태를 URL 로 접근).
window.addEventListener('hashchange', () => {
  if (/^#agent\/\w+/.test(location.hash) && !_agentViewActive()) switchView('agent');
});
window.addEventListener('DOMContentLoaded', () => {
  if (/^#agent\/\w+/.test(location.hash)) switchView('agent');
});
