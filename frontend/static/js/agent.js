/* 자율 검증 작업 UI — 목록 + 상세(전용 페이지 뷰). 모든 대상/AI 문자열은 텍스트로 렌더.
   이전엔 모달이었으나(리뷰 agent.js:7) 장시간 작업에 맞게 작업 목록 + 상세 타임라인 뷰로 분리. */
let agentRunId = null, agentTimer = null, agentBusy = false, agentInited = false, agentPolicy = null;
const agentEl = id => document.getElementById(id);

async function agentApi(path, data, method) {
  const options = method ? { method, headers:{'Content-Type':'application/json'}, body: data === undefined ? undefined : JSON.stringify(data) }
    : data === undefined ? {} : { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(data) };
  return _asJson(await fetch('/api/agent' + path, options), '에이전트');
}

/* ── 계정/객체 정책 폼 — 자유 JSON 입력 대신 구조화 입력(리뷰). DOM 은 createElement 로만
   만들어 값이 항상 텍스트로 들어가게 한다(마크업 주입 방지). ── */
function _mkInput(cls, ph, val) {
  const i = document.createElement('input'); i.type = 'text'; i.className = cls; i.placeholder = ph; i.setAttribute('aria-label', ph); i.value = val || ''; return i;
}
function _hdrsToText(h) { return Object.entries(h || {}).map(([k, v]) => `${k}: ${v}`).join('\n'); }
function _textToHdrs(t) {
  const out = {};
  for (const line of (t || '').split('\n')) {
    const i = line.indexOf(':'); if (i < 0) continue;
    const k = line.slice(0, i).trim(); if (k) out[k] = line.slice(i + 1).trim();
  }
  return out;
}
function _delBtn(row) {
  const b = document.createElement('button'); b.type = 'button'; b.className = 'icon-button'; b.append(epIcon('X')); b.title = '행 삭제'; b.setAttribute('aria-label', '행 삭제');
  b.onclick = () => row.remove(); return b;
}
function addActorRow(a = {}) {
  const row = document.createElement('div'); row.className = 'actor-row agent-row-form';
  const top = document.createElement('div'); top.className = 'agent-row-grid';
  top.append(_mkInput('actor-id', 'id (예: current)', a.id), _mkInput('actor-label', '라벨(선택)', a.label), _delBtn(row));
  const hdr = document.createElement('textarea');
  hdr.className = 'actor-headers'; hdr.rows = 2; hdr.placeholder = 'Cookie: sid=...\nAuthorization: Bearer ...'; hdr.value = _hdrsToText(a.headers);
  hdr.setAttribute('aria-label', '계정 인증 헤더');
  row.append(top, hdr);
  agentEl('agentActorsForm').append(row);
}
function addObjectRow(o = {}) {
  const row = document.createElement('div'); row.className = 'object-row agent-row-form';
  const g1 = document.createElement('div'); g1.className = 'agent-row-grid';
  g1.append(_mkInput('obj-id', 'id', o.id), _mkInput('obj-url', '객체 URL(같은 출처)', o.url), _delBtn(row));
  const g2 = document.createElement('div'); g2.className = 'agent-row-grid3';
  g2.append(_mkInput('obj-owner', '소유 계정 id', o.owner_actor),
            _mkInput('obj-allowed', '허용 계정(쉼표)', (o.allowed_actors || []).join(',')),
            _mkInput('obj-ptr', '식별 포인터 /id', o.identity_pointer));
  const g3 = document.createElement('div'); g3.className = 'agent-row-grid';
  g3.append(_mkInput('obj-val', '식별 값(예: 42)', o.identity_value), _mkInput('obj-desc', '설명', o.description));
  row.append(g1, g2, g3);
  agentEl('agentObjectsForm').append(row);
}
function collectActors() {
  const actors = [];
  for (const r of document.querySelectorAll('#agentActorsForm .actor-row')) {
    const id = r.querySelector('.actor-id').value.trim();
    if (!id) continue;
    actors.push({ id, label: r.querySelector('.actor-label').value.trim(), headers: _textToHdrs(r.querySelector('.actor-headers').value) });
  }
  return actors.length ? actors : [{ id: 'current', label: '현재 계정', headers: {} }];
}
function collectObjects() {
  const objs = [];
  for (const r of document.querySelectorAll('#agentObjectsForm .object-row')) {
    const id = r.querySelector('.obj-id').value.trim();
    const url = r.querySelector('.obj-url').value.trim();
    if (!id && !url && ![...r.querySelectorAll('input')].some(i => i.value.trim())) continue;
    if (!id || !url) throw new Error('객체 정책의 ID와 URL을 모두 입력하세요.');
    objs.push({ id, url, owner_actor: r.querySelector('.obj-owner').value.trim(),
      allowed_actors: r.querySelector('.obj-allowed').value.split(',').map(s => s.trim()).filter(Boolean),
      identity_pointer: r.querySelector('.obj-ptr').value.trim(),
      identity_value: r.querySelector('.obj-val').value.trim(), description: r.querySelector('.obj-desc').value.trim() });
  }
  return objs;
}

function initAgentView() {
  if (agentInited) return;
  agentInited = true;
  agentEl('agentStart').onclick = startAgent;
  agentEl('agentStop').onclick = () => agentControl('stop');
  agentEl('agentResume').onclick = () => agentControl('resume');
  agentEl('agentRefresh').onclick = () => { loadEgressPolicy(); loadAgentList(); };
  agentEl('agentExport').onclick = exportAgent;
  agentEl('agentAddActor').onclick = () => addActorRow();
  agentEl('agentAddObject').onclick = () => addObjectRow();
  initAgentWorkspace();
  addActorRow({ id: 'current', label: '현재 계정', headers: {} });   // 기본 계정 1행
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
    agentPolicy = null;
    banner.dataset.mode = 'error';
    agentEl('agentShare').checked = false;
    agentEl('agentShare').disabled = true;
    if (banner) banner.textContent = '반출 정책을 불러오지 못했습니다: ' + e.message;
    return;
  }
  const strict = !!agentPolicy.strict;
  if (banner) {
    banner.dataset.mode = strict ? 'strict' : 'permissive';
    let text = strict
      ? 'STRICT · 외부 전송 제한 정책 적용 중'
      : 'PERMISSIVE · 외부 AI 전송 허용 상태';
    const o = agentPolicy.oob;   // AI 외 반출 경로(OOB 콜백) 상태(리뷰 F5)
    if (o && o.enabled && !o.minting_allowed) text += ' · OOB: 공개 수집기 차단(블라인드 검사 미검증).';
    else if (o && o.enabled && o.public_server) text += ' · OOB: 공개 수집기 사용 중(콜백이 제3자로 나감).';
    banner.replaceChildren(epIcon(strict ? 'LockKeyhole' : 'CircleAlert'), document.createTextNode(text));
    banner.title = '현재 서버 설정입니다. STRICT 표시는 모든 내부 데이터의 비반출 보증을 의미하지 않습니다.';
  }
  const share = agentEl('agentShare'), note = agentEl('agentShareNote');
  if (share) {
    if (strict) {
      share.checked = false; share.disabled = true;
      if (note) note.textContent = 'STRICT 정책으로 잠김';
    } else {
      share.disabled = false;
      if (note) note.textContent = '활성화하면 내부 응답 일부가 외부 제공자에 전달됩니다.';
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
    renderAgentList(data.runs);
  } catch (e) { renderAgentListError(e.message); }
}

function selectRun(id) {
  agentRunId = id;
  showAgentDetail();
  try { history.replaceState(null, '', '#agent/' + id); } catch (e) {}
  const ev = agentEl('agentEvents');
  if (ev) { ev.replaceChildren(); ev.dataset.run = ''; }
  pollAgent();
}

async function deleteRun(id) {
  if (!confirm('이 검증 작업과 저장된 증거를 영구 삭제할까요? 되돌릴 수 없습니다.')) return;
  try {
    await _asJson(await fetch('/api/agent/runs/' + id, { method: 'DELETE' }), '에이전트');
    if (agentRunId === id) {   // 선택 중이던 작업이면 상세 패널 비우기
      agentRunId = null; clearTimeout(agentTimer);
      agentEl('agentEvents').replaceChildren();
      agentEl('agentStatus').textContent = '작업을 선택하거나 새로 시작하세요.';
      agentEl('agentSummary').textContent = ''; agentEl('agentResults').textContent = '';
      agentEl('agentStop').disabled = agentEl('agentResume').disabled = agentEl('agentExport').disabled = true;
      try { history.replaceState(null, '', '#agent'); } catch (e) {}
      showAgentList();
    }
    loadAgentList();
  } catch (e) { agentEl('agentStatus').textContent = e.message; }
}

async function startAgent() {
  if (agentBusy) return;
  agentBusy = true;
  agentEl('agentStart').disabled = true;
  try {
    const invalid = [...agentEl('agentNew').querySelectorAll('input,textarea')].find(e => !e.checkValidity());
    if (invalid) { invalid.reportValidity(); return; }
    const form = _currentRequestForm();
    if (!/^https?:\/\//i.test(form.url)) throw new Error('요청 편집에서 HTTP(S) 대상 URL을 입력하세요.');
    const headers = { ...(getUseDefaults() ? getDefaultHeaderProfile() : {}), ...getHeadersObj() };
    // strict 모드면 응답 공유를 요청하지 않는다(서버도 context 에서 발췌를 제거하지만 이중 방어).
    const share = agentEl('agentShare').checked && !(agentPolicy && agentPolicy.strict);
    const run = await agentApi('/runs', {
      goal: agentEl('agentGoal').value,
      request: { method: form.method, url: form.url, params: form.params, body: form.body || '', headers },
      actors: collectActors(), objects: collectObjects(),
      max_steps: Number(agentEl('agentSteps').value), max_requests: Number(agentEl('agentRequests').value),
      max_ai_calls: Number(agentEl('agentAiCalls').value), max_seconds: Number(agentEl('agentSeconds').value),
      allow_write_methods: agentEl('agentWrite').checked, share_response_context: share,
      mode: agentEl('agentPlanMode').checked ? 'plan' : 'iterative',
    });
    agentEl('agentNew').close();
    await loadAgentList();
    selectRun(run.id);
  } catch (e) { agentEl('agentFormError').hidden = false; agentEl('agentFormError').textContent = e.message; }
  finally { agentBusy = false; agentEl('agentStart').disabled = false; }
}

async function agentControl(action) {
  if (!agentRunId) return;
  try {
    const data = action === 'resume' ? {
      request_headers: getHeadersObj(),
      actor_headers: Object.fromEntries(collectActors().map(a => [a.id, a.headers || {}])),
    } : {};
    await agentApi(`/runs/${agentRunId}/${action}`, data);
    await pollAgent();
    loadAgentList();
  } catch (e) { agentEl('agentStatus').textContent = e.message; }
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
    renderAgentWorkspace(run);
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
