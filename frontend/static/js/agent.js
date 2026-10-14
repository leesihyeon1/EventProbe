/* 자율 검증 작업 UI — 목록 + 상세(전용 페이지 뷰). 모든 대상/AI 문자열은 텍스트로 렌더.
   이전엔 모달이었으나(리뷰 agent.js:7) 장시간 작업에 맞게 작업 목록 + 상세 타임라인 뷰로 분리. */
let agentRunId = null, agentTimer = null, agentBusy = false, agentInited = false, agentPolicy = null;
let _approvedPlan = null;   // 미리보기에서 승인한 계획(있으면 실행에 고정, 리뷰 P3)
let _showArchived = false;  // 목록을 보관함(보관된 작업)으로 볼지 여부(리뷰 N5)
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
  agentEl('agentPlanMode').onchange = syncPlanPreview;
  agentEl('agentPlanPreviewBtn').onclick = previewPlan;
  agentEl('egressAuditBtn').onclick = openEgressAudit;
  agentEl('egressAuditClose').onclick = () => agentEl('egressAuditDialog').close();
  agentEl('agentDeletionsBtn').onclick = openDeletions;
  agentEl('deletionsClose').onclick = () => agentEl('deletionsDialog').close();
  agentEl('agentTemplatesBtn').onclick = openTemplates;
  agentEl('templatesClose').onclick = () => agentEl('templatesDialog').close();
  agentEl('agentSaveTemplate').onclick = saveTemplate;
  agentEl('agentArchivedToggle').onclick = () => {
    _showArchived = !_showArchived;
    agentEl('agentArchivedToggle').setAttribute('aria-pressed', String(_showArchived));
    workspacePage = 0; loadAgentList();
  };
  const user = agentEl('agentUser');
  try { user.value = localStorage.getItem('ep-user') || ''; } catch (e) {}
  setWorkspaceUser(user.value);     // 쿠키 동기화(보고서 new tab 포함 모든 요청에 실린다)
  user.oninput = () => setWorkspaceUser(user.value);
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

// 작업공간 이름(리뷰 P4 소유권). 쿠키 ep_user 로 심어 모든 요청·보고서 new tab 에 실린다.
// 서버에서 AGENT_SCOPE_OWNER 가 켜졌을 때만 의미가 있다(협업 작업공간 구분용, 인증 경계 아님).
function setWorkspaceUser(value) {
  // 쿠키 값과 서버가 읽는 principal 이 일치하도록 쿠키-안전 문자만 남긴다(인코딩하지 않음).
  const v = (value || '').trim().slice(0, 64).replace(/[^\w.\-]/g, '');
  try { localStorage.setItem('ep-user', v); } catch (e) {}
  try {
    document.cookie = v
      ? `ep_user=${v}; path=/; samesite=lax; max-age=31536000`
      : 'ep_user=; path=/; samesite=lax; max-age=0';
  } catch (e) {}
}

// 반출·AI 사용 감사(리뷰 P4). 서버의 읽기 전용 감사 요약/레코드를 로컬에 텍스트로만 렌더.
async function openEgressAudit() {
  const dialog = agentEl('egressAuditDialog');
  agentEl('egressAuditSummary').replaceChildren();
  agentEl('egressAuditRecords').replaceChildren(uiNode('p', 'aw-muted', '불러오는 중…'));
  dialog.showModal();
  try {
    renderEgressAudit(await _asJson(await fetch('/api/egress/audit'), '반출 감사'));
  } catch (e) {
    agentEl('egressAuditRecords').replaceChildren(uiNode('p', 'aw-form-error', e.message));
  }
}
const EA_FIELDS = [['channel', '채널'], ['model', '모델'], ['dest_host', '목적지'], ['chars', '문자'], ['findings', '발견'], ['result', '결과']];
function renderEgressAudit(data) {
  const s = data.summary || {}, records = data.records || [];
  const sum = agentEl('egressAuditSummary'); sum.replaceChildren();
  const chips = [['모드', String(s.mode || '-')], ['총 호출', String(s.count || 0)],
    ['외부 전송', String(s.external || 0)], ['차단', String(s.blocked || 0)]];
  for (const [k, c] of Object.entries(s.channels || {})) chips.push([`채널 ${k}`, String(c)]);
  for (const [k, c] of Object.entries(s.findings || {})) chips.push([`발견 ${k}`, String(c)]);
  for (const [label, value] of chips) {
    const chip = uiNode('span', 'ea-chip'); chip.append(uiNode('span', 'ea-chip-k', label), uiNode('strong', '', value));
    if (label === '차단' && Number(value) > 0) chip.dataset.alert = 'block';
    if (label === '외부 전송' && Number(value) > 0) chip.dataset.alert = 'ext';
    sum.append(chip);
  }
  const box = agentEl('egressAuditRecords'); box.replaceChildren();
  const usage = data.usage || [];
  if (usage.length) {
    box.append(uiNode('h4', 'ea-subhead', '모델 사용'));
    const ut = uiNode('table', 'ea-table'), uh = uiNode('tr');
    for (const label of ['채널', '모델', '호출', '오류', '평균 지연', '최대 지연', '토큰']) uh.append(uiNode('th', '', label));
    const uthead = uiNode('thead'); uthead.append(uh);
    const utbody = uiNode('tbody');
    for (const u of usage) {
      const tr = uiNode('tr'); if (u.errors) tr.dataset.blocked = 'true';
      tr.append(uiNode('td', '', u.channel || ''), uiNode('td', '', u.model || '-'),
        uiNode('td', '', String(u.calls ?? 0)), uiNode('td', '', String(u.errors ?? 0)),
        uiNode('td', '', `${u.avg_latency_ms ?? 0}ms`), uiNode('td', '', `${u.max_latency_ms ?? 0}ms`),
        uiNode('td', '', String(u.tokens ?? 0)));
      utbody.append(tr);
    }
    ut.append(uthead, utbody); box.append(ut);
    box.append(uiNode('h4', 'ea-subhead', '최근 전송'));
  }
  if (!records.length) { box.append(uiNode('p', 'aw-muted', '기록된 외부 전송이 없습니다.')); return; }
  const table = uiNode('table', 'ea-table'), head = uiNode('tr');
  head.append(uiNode('th', '', '시각'));
  for (const [, label] of EA_FIELDS) head.append(uiNode('th', '', label));
  const thead = uiNode('thead'); thead.append(head);
  const tbody = uiNode('tbody');
  for (const r of [...records].reverse()) {   // 최신 먼저
    const tr = uiNode('tr'); if (r.blocked) tr.dataset.blocked = 'true';
    tr.append(uiNode('td', 'ea-ts', r.ts || ''));
    tr.append(uiNode('td', '', r.channel || ''));
    tr.append(uiNode('td', '', r.model || '-'));
    tr.append(uiNode('td', '', (r.dest_host || '-') + (r.trusted_dest ? ' · 사내' : '')));
    tr.append(uiNode('td', '', String(r.chars ?? 0)));
    tr.append(uiNode('td', '', (r.findings || []).map(f => `${f.kind}:${f.severity}`).join(', ') || '-'));
    tr.append(uiNode('td', '', r.blocked ? '차단' : '전송'));
    tbody.append(tr);
  }
  table.append(thead, tbody); box.append(table);
}

// 검증 템플릿(리뷰 N1). 설정을 저장/복제. 자격증명은 저장하지 않고 실행 시 재주입.
async function saveTemplate() {
  let spec;
  try { spec = _collectSpec(); } catch (e) { agentEl('agentFormError').hidden = false; agentEl('agentFormError').textContent = e.message; return; }
  const name = (typeof prompt === 'function') ? prompt('템플릿 이름', spec.goal.slice(0, 40)) : spec.goal.slice(0, 40);
  if (name === null) return;   // 취소
  const category = (typeof prompt === 'function') ? (prompt('분류(선택)', '') || '') : '';
  try {
    await agentApi('/templates', { name: name, category: category, spec });
    agentEl('agentFormError').hidden = true;
  } catch (e) { agentEl('agentFormError').hidden = false; agentEl('agentFormError').textContent = e.message; }
}
async function openTemplates() {
  agentEl('templatesList').replaceChildren(uiNode('p', 'aw-muted', '불러오는 중…'));
  agentEl('templatesDialog').showModal();
  try {
    renderTemplates((await agentApi('/templates')).templates || []);
  } catch (e) { agentEl('templatesList').replaceChildren(uiNode('p', 'aw-form-error', e.message)); }
}
function renderTemplates(list) {
  const box = agentEl('templatesList'); box.replaceChildren();
  if (!list.length) { box.append(uiNode('p', 'aw-muted', '저장된 템플릿이 없습니다. 새 작업에서 "템플릿으로 저장"을 사용하세요.')); return; }
  for (const t of list) {
    const row = uiNode('div', 'tpl-row');
    const info = uiNode('div', 'tpl-info');
    const head = uiNode('div', 'tpl-head');
    head.append(uiNode('strong', '', t.name || '무제 템플릿'));
    if (t.category) head.append(uiNode('span', 'aw-plan-chip', t.category));
    info.append(head, uiNode('div', 'tpl-goal', t.goal || ''));
    const actions = uiNode('div', 'tpl-actions');
    const run = uiNode('button', 'aw-link', '실행'); run.type = 'button'; run.onclick = () => runTemplate(t.id);
    const del = uiCommand('Trash2', '템플릿 삭제', () => deleteTemplate(t.id), 'icon-button');
    actions.append(run, del);
    row.append(info, actions); box.append(row);
  }
}
async function runTemplate(id) {
  // 템플릿 실행은 실제 대상에 요청을 보내므로 먼저 확인하고, 현재 세션 헤더를 재주입한다(리뷰 N1).
  if (typeof confirm === 'function' && !confirm('이 템플릿으로 새 검증을 시작합니다. 대상에 실제 요청을 보냅니다. 계속할까요?')) return;
  try {
    const headers = (typeof getHeadersObj === 'function') ? getHeadersObj() : {};
    const run = await agentApi(`/templates/${encodeURIComponent(id)}/run`, { request_headers: headers });
    agentEl('templatesDialog').close();
    await loadAgentList();
    if (run && run.id) selectRun(run.id);
  } catch (e) { agentEl('templatesList').replaceChildren(uiNode('p', 'aw-form-error', e.message)); }
}
async function deleteTemplate(id) {
  if (typeof confirm === 'function' && !confirm('이 템플릿을 삭제할까요?')) return;
  try {
    await agentApi(`/templates/${encodeURIComponent(id)}`, undefined, 'DELETE');
    renderTemplates((await agentApi('/templates')).templates || []);
  } catch (e) { agentEl('templatesList').replaceChildren(uiNode('p', 'aw-form-error', e.message)); }
}

// 증거 삭제 기록(리뷰 P4). 삭제/보존 정리된 작업의 감사. 읽기 전용, 텍스트만.
const DELETION_REASON = { manual: '수동 삭제', retention: '보존 정리' };
async function openDeletions() {
  const dialog = agentEl('deletionsDialog');
  agentEl('deletionsRecords').replaceChildren(uiNode('p', 'aw-muted', '불러오는 중…'));
  dialog.showModal();
  try {
    renderDeletions((await agentApi('/deletions')).deletions || []);
  } catch (e) {
    agentEl('deletionsRecords').replaceChildren(uiNode('p', 'aw-form-error', e.message));
  }
}
function renderDeletions(records) {
  const box = agentEl('deletionsRecords'); box.replaceChildren();
  if (!records.length) { box.append(uiNode('p', 'aw-muted', '삭제 기록이 없습니다.')); return; }
  const table = uiNode('table', 'ea-table'), head = uiNode('tr');
  for (const label of ['삭제 시각', '사유', '목표', '상태', '증거 수', '작업 ID']) head.append(uiNode('th', '', label));
  const thead = uiNode('thead'); thead.append(head);
  const tbody = uiNode('tbody');
  for (const r of records) {
    const tr = uiNode('tr'); if (r.reason === 'retention') tr.dataset.reason = 'retention';
    tr.append(uiNode('td', 'ea-ts', r.deleted ? new Date(r.deleted * 1000).toLocaleString('ko-KR') : ''));
    tr.append(uiNode('td', '', DELETION_REASON[r.reason] || r.reason || ''));
    tr.append(uiNode('td', '', r.goal || '(목표 미기재)'));
    tr.append(uiNode('td', '', r.state || ''));
    tr.append(uiNode('td', '', String(r.events ?? 0)));
    tr.append(uiNode('td', 'ea-ts', r.run_id || ''));
    tbody.append(tr);
  }
  table.append(thead, tbody); box.append(table);
}

const AGENT_STATE_LABELS = {
  running: '실행 중', paused: '일시정지', interrupted: '중단됨', completed: '종료', limited: '한도',
};

async function loadAgentList() {
  const list = agentEl('agentList');
  if (!list) return;
  try {
    const data = await agentApi('/runs' + (_showArchived ? '?archived=1' : ''));
    renderAgentList(data.runs);
  } catch (e) { renderAgentListError(e.message); }
}
async function archiveRun(id) {
  try { await agentApi(`/runs/${encodeURIComponent(id)}/archive`, {}); await loadAgentList(); }
  catch (e) { agentEl('agentStatus').textContent = e.message; }
}
async function unarchiveRun(id) {
  try { await agentApi(`/runs/${encodeURIComponent(id)}/unarchive`, {}); await loadAgentList(); }
  catch (e) { agentEl('agentStatus').textContent = e.message; }
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

function _collectSpec() {
  const form = _currentRequestForm();
  if (!/^https?:\/\//i.test(form.url)) throw new Error('요청 편집에서 HTTP(S) 대상 URL을 입력하세요.');
  const headers = { ...(getUseDefaults() ? getDefaultHeaderProfile() : {}), ...getHeadersObj() };
  // strict 모드면 응답 공유를 요청하지 않는다(서버도 context 에서 발췌를 제거하지만 이중 방어).
  const share = agentEl('agentShare').checked && !(agentPolicy && agentPolicy.strict);
  return {
    goal: agentEl('agentGoal').value,
    request: { method: form.method, url: form.url, params: form.params, body: form.body || '', headers },
    actors: collectActors(), objects: collectObjects(),
    max_steps: Number(agentEl('agentSteps').value), max_requests: Number(agentEl('agentRequests').value),
    max_ai_calls: Number(agentEl('agentAiCalls').value), max_seconds: Number(agentEl('agentSeconds').value),
    allow_write_methods: agentEl('agentWrite').checked, share_response_context: share,
    mode: agentEl('agentPlanMode').checked ? 'plan' : 'iterative',
  };
}

// 새 작업 대화상자를 열 때 승인 상태를 초기화한다(리뷰 P3).
function resetPlanPreview() { _approvedPlan = null; agentEl('agentPlanSteps').replaceChildren(); syncPlanPreview(); }

// 계획 모드일 때만 미리보기 영역을 노출하고, 숨길 때 승인 상태를 비운다(리뷰 P3).
function syncPlanPreview() {
  const on = agentEl('agentPlanMode').checked;
  agentEl('agentPlanPreviewWrap').hidden = !on;
  if (!on) { _approvedPlan = null; agentEl('agentPlanSteps').replaceChildren(); }
}

async function previewPlan() {
  const btn = agentEl('agentPlanPreviewBtn'); btn.disabled = true;
  agentEl('agentFormError').hidden = true;
  try {
    const invalid = [...agentEl('agentNew').querySelectorAll('input,textarea')].find(e => !e.checkValidity());
    if (invalid) { invalid.reportValidity(); return; }
    const { plan, fingerprint } = await agentApi('/plan', _collectSpec());
    _approvedPlan = plan;   // 이 계획을 실행에 고정한다
    renderPlanPreview(plan, fingerprint);
  } catch (e) { _approvedPlan = null; agentEl('agentFormError').hidden = false; agentEl('agentFormError').textContent = e.message; agentEl('agentPlanSteps').replaceChildren(); }
  finally { btn.disabled = false; }
}

// 미리보기 계획을 텍스트로만 렌더(마크업 주입 없음). 값은 구조 설명에 한정한다.
function renderPlanPreview(plan, fingerprint) {
  const box = agentEl('agentPlanSteps'); box.replaceChildren();
  const head = document.createElement('p'); head.className = 'aw-muted';
  head.textContent = `진입 ${plan.entry} · 단계 ${plan.steps.length}개 · 지문 ${fingerprint} (이 계획이 재생성 없이 고정 실행됩니다)`;
  box.append(head);
  const list = document.createElement('ol'); list.className = 'aw-plan-list';
  for (const step of plan.steps) {
    const li = document.createElement('li');
    const title = document.createElement('div'); title.className = 'aw-plan-step-title';
    title.append(_planChip(step.action.kind), document.createTextNode(` ${step.action_id}`));
    if (step.action.category) title.append(_planChip(step.action.category, 'cat'));
    li.append(title);
    const hyp = document.createElement('div'); hyp.className = 'aw-plan-step-hyp'; hyp.textContent = step.action.hypothesis || '';
    li.append(hyp);
    const flow = (step.branches || []).map(b => `${_predicateText(b.predicate)} → ${b.next || '종료'}`);
    flow.push(`기타 → ${step.default_next || '종료'}`);
    const branch = document.createElement('div'); branch.className = 'aw-plan-step-branch'; branch.textContent = flow.join('  ·  ');
    li.append(branch); list.append(li);
  }
  box.append(list);
}
function _planChip(text, kind) { const s = document.createElement('span'); s.className = 'aw-plan-chip'; if (kind) s.dataset.kind = kind; s.textContent = text; return s; }
function _predicateText(p) {
  if (!p) return '항상';
  if (p.kind === 'always') return '항상';
  if (p.kind === 'verdict_in') return '판정 ∈ ' + (p.verdicts || []).join('/');
  if (p.kind === 'status_in') return '상태 ∈ ' + (p.statuses || []).join('/');
  if (p.kind === 'signal_present') return '신호 ' + p.signal;
  return p.kind;
}

async function startAgent() {
  if (agentBusy) return;
  agentBusy = true;
  agentEl('agentStart').disabled = true;
  try {
    const invalid = [...agentEl('agentNew').querySelectorAll('input,textarea')].find(e => !e.checkValidity());
    if (invalid) { invalid.reportValidity(); return; }
    const spec = _collectSpec();
    // 계획 모드에서 승인한 미리보기가 있으면 그 계획을 고정해 실행한다(재생성 없음, 리뷰 P3).
    if (spec.mode === 'plan' && _approvedPlan) spec.approved_plan = _approvedPlan;
    const run = await agentApi('/runs', spec);
    agentEl('agentNew').close();
    await loadAgentList();
    selectRun(run.id);
  } catch (e) { agentEl('agentFormError').hidden = false; agentEl('agentFormError').textContent = e.message; }
  finally { agentBusy = false; agentEl('agentStart').disabled = false; }
}

async function agentControl(action) {
  if (!agentRunId) return;
  await _agentControl(action, false);
}
async function _agentControl(action, acknowledgeWrites) {
  try {
    const data = action === 'resume' ? {
      request_headers: getHeadersObj(),
      actor_headers: Object.fromEntries(collectActors().map(a => [a.id, a.headers || {}])),
      acknowledge_writes: acknowledgeWrites,
    } : {};
    await agentApi(`/runs/${agentRunId}/${action}`, data);
    await pollAgent();
    loadAgentList();
  } catch (e) {
    // 재개 시 처리 여부 불명확한 쓰기 경고(리뷰 P3): 확인을 받으면 재전송 위험을 수용하고 재개한다.
    if (action === 'resume' && !acknowledgeWrites && /재전송/.test(e.message || '')
        && typeof confirm === 'function' && confirm((e.message || '') + '\n\n그래도 재개할까요?')) {
      return _agentControl('resume', true);
    }
    agentEl('agentStatus').textContent = e.message;
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
