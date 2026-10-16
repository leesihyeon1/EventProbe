/* 자율 검증 작업 UI — 목록 + 상세(전용 페이지 뷰). 모든 대상/AI 문자열은 텍스트로 렌더.
   이전엔 모달이었으나(리뷰 agent.js:7) 장시간 작업에 맞게 작업 목록 + 상세 타임라인 뷰로 분리. */
let agentRunId = null, agentTimer = null, agentBusy = false, agentInited = false, agentPolicy = null;
let _approvedPlan = null;   // 미리보기에서 승인한 계획(있으면 실행에 고정, 리뷰 P3)
let _approvedPlanExpiresAt = null;
let _approvedPolicyVersion = null;
let _showArchived = false;  // 목록을 보관함(보관된 작업)으로 볼지 여부(리뷰 N5)
let _listQuery = 0;
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
function addGoalRow(g = {}) {
  const row = document.createElement('div'); row.className = 'goal-row agent-row-form';
  const top = document.createElement('div'); top.className = 'agent-row-grid';
  top.append(_mkInput('goal-id', '목표 ID', g.id), _mkInput('goal-title', '검증 목표', g.title), _delBtn(row));
  const options = document.createElement('div'); options.className = 'agent-row-grid3';
  const select = (cls, values, value) => {
    const el = document.createElement('select'); el.className = cls;
    for (const [id, label] of values) { const option = document.createElement('option'); option.value = id; option.textContent = label; el.append(option); }
    el.value = value || values[0][0]; return el;
  };
  options.append(select('goal-category', ['sqli','xss','ssti','lfi','ssrf','cmdi','redirect','nosql','access'].map(x=>[x,x]), g.category),
    select('goal-completion', [['tested','증거 있는 검사'],['confirmed','취약성 확증']], g.completion),
    _mkInput('goal-actor', '계정 ID(선택)', g.actor_id));
  const endpoint = _mkInput('goal-endpoint', '엔드포인트 ID(선택 · seed)', g.endpoint_id);
  row.append(top, options, endpoint);
  agentEl('agentGoalsForm').append(row);
}
function collectGoals() {
  const goals = [];
  for (const row of document.querySelectorAll('#agentGoalsForm .goal-row')) {
    const id = row.querySelector('.goal-id').value.trim();
    const title = row.querySelector('.goal-title').value.trim();
    if (!id && !title) continue;
    if (!id || !title) throw new Error('세부 검증 목표의 ID와 제목을 모두 입력하세요.');
    goals.push({ id, title, category: row.querySelector('.goal-category').value,
      completion: row.querySelector('.goal-completion').value,
      actor_id: row.querySelector('.goal-actor').value.trim(),
      endpoint_id: row.querySelector('.goal-endpoint').value.trim() });
  }
  return goals;
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
  const holdPlanButton = agentEl('agentHoldPlan');
  if (holdPlanButton) holdPlanButton.onclick = holdAgentPlan;
  agentEl('agentApproveStep').onclick=()=>reviewAgentPlanStep(true);
  agentEl('agentDenyStep').onclick=()=>reviewAgentPlanStep(false);
  const skipPlanButton = agentEl('agentSkipPlan');
  if (skipPlanButton) skipPlanButton.onclick = skipAgentPlanStep;
  const revokePlanButton = agentEl('agentRevokePlan');
  if (revokePlanButton) revokePlanButton.onclick = revokeAgentPlan;
  agentEl('agentResume').onclick = () => agentControl('resume');
  agentEl('agentRefresh').onclick = () => { loadEgressPolicy(); loadAgentList(); };
  agentEl('agentBatchArchive').onclick = () => bulkRunAction(_showArchived?'unarchive':'archive');
  agentEl('agentBatchStop').onclick = () => bulkRunAction('stop');
  agentEl('agentExport').onclick = exportAgent;
  const archiveDownload = agentEl('agentArchiveDownload');
  if (archiveDownload) archiveDownload.onclick = downloadRunArchive;
  const archiveImport = agentEl('agentArchiveImportButton');
  const archiveFile = agentEl('agentArchiveFile');
  if (archiveImport && archiveFile) {
    archiveImport.onclick = () => archiveFile.click();
    archiveFile.onchange = importRunArchive;
  }
  agentEl('agentAddActor').onclick = () => addActorRow();
  agentEl('agentAddObject').onclick = () => addObjectRow();
  const addGoal = agentEl('agentAddGoal');
  if (addGoal) addGoal.onclick = () => addGoalRow();
  agentEl('agentPlanMode').onchange = syncPlanPreview;
  agentEl('agentPlanPreviewBtn').onclick = previewPlan;
  agentEl('egressAuditBtn').onclick = openEgressAudit;
  agentEl('egressAuditClose').onclick = () => agentEl('egressAuditDialog').close();
  agentEl('agentDeletionsBtn').onclick = openDeletions;
  agentEl('deletionsClose').onclick = () => agentEl('deletionsDialog').close();
  agentEl('agentTemplatesBtn').onclick = openTemplates;
  agentEl('templatesClose').onclick = () => agentEl('templatesDialog').close();
  agentEl('templatesFilter').onclick = () => loadTemplates();
  const templatesBulk=agentEl('templatesBulkCategory');
  if(templatesBulk) templatesBulk.onclick=batchTemplateCategory;
  agentEl('agentSaveTemplate').onclick = saveTemplate;
  const incidentsBtn = agentEl('agentIncidentsBtn');
  if (incidentsBtn) incidentsBtn.onclick = openIncidents;
  const incidentsClose = agentEl('incidentsClose');
  if (incidentsClose) incidentsClose.onclick = () => agentEl('incidentsDialog').close();
  const incidentsAuditButton = agentEl('incidentsAuditButton');
  if (incidentsAuditButton) incidentsAuditButton.onclick = openIncidentDeletions;
  const incidentForm = agentEl('incidentForm');
  if (incidentForm) incidentForm.onsubmit = submitIncident;
  agentEl('agentArchivedToggle').onclick = () => {
    _showArchived = !_showArchived;
    agentEl('agentArchivedToggle').setAttribute('aria-pressed', String(_showArchived));
    if(typeof saveAgentFilters==='function') saveAgentFilters();
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
// 사내 이벤트(SIEM/SOAR) 재검증(리뷰 P2/N4). 수동 JSON 계약으로 수집 → 로컬 실행에 읽기 전용
// 연결 → 연결 실행의 현재 판정에서만 상태 도출(미관측을 해결로 표시하지 않음). 본문은 AI 반출 안 함.
const INCIDENT_STATUS = { unverified: '미검증', verifying: '검증 중', reproduced: '재현됨',
  suspicious: '의심', not_reproduced: '재현 안 됨', inconclusive: '판정불가' };
let incidentCursor=null;
async function openIncidents() {
  agentEl('incidentFormError').textContent = '';
  agentEl('incidentTrace').hidden = true;
  agentEl('incidentsAudit').hidden = true;
  agentEl('incidentsList').replaceChildren(uiNode('p', 'aw-muted', '불러오는 중…'));
  agentEl('incidentsDialog').showModal();
  await loadIncidents();
}
async function loadIncidents(reset=true) {
  if(reset) { incidentCursor=null; agentEl('incidentsList').replaceChildren(); }
  const more=agentEl('incidentsMore');
  if(more) { more.disabled=true; if(reset) more.hidden=true; }
  try {
    const cursor=incidentCursor?
      `&before_created=${encodeURIComponent(incidentCursor.created)}&before_id=${encodeURIComponent(incidentCursor.id)}`:'';
    const result=await agentApi(`/incidents?limit=25${cursor}`);
    const page=result.incidents||[];
    renderIncidents(page,!reset);
    incidentCursor=result.next_cursor;
    if(more) { more.hidden=!result.has_more; more.disabled=false; more.onclick=()=>loadIncidents(false); }
  } catch (e) {
    if(more) more.disabled=false;
    agentEl('incidentsList').append(uiNode('p', 'aw-form-error', e.message));
  }
}
async function openIncidentDeletions() {
  const box = agentEl('incidentsAudit'); box.hidden = false;
  box.replaceChildren(uiNode('p', 'aw-muted', '불러오는 중…'));
  try {
    renderIncidentDeletions((await agentApi('/incidents/deletions')).deletions || []);
  } catch (e) { box.replaceChildren(uiNode('p', 'aw-form-error', e.message)); }
}
function renderIncidentDeletions(records) {
  const box = agentEl('incidentsAudit'); box.replaceChildren();
  if (!records.length) { box.append(uiNode('p', 'aw-muted', '사건 삭제 기록이 없습니다.')); return; }
  for (const record of records) {
    const when = record.deleted ? new Date(record.deleted * 1000).toLocaleString() : '';
    box.append(uiNode('div', 'tpl-row',
      `${when} · ${record.source || ''} · ${record.category || ''} · 사건 ${record.incident_id || ''}`));
  }
}
function renderIncidents(list, append=false) {
  const box = agentEl('incidentsList'); if(!append) box.replaceChildren();
  if (!list.length && !append) { box.append(uiNode('p', 'aw-muted', '수집된 사건이 없습니다. 위 폼으로 수동 수집하세요.')); return; }
  for (const i of list) {
    const row = uiNode('div', 'tpl-row');
    const info = uiNode('div', 'tpl-info'); const head = uiNode('div', 'tpl-head');
    head.append(uiNode('strong', '', i.title || '(제목 없음)'));
    if (i.category) head.append(uiNode('span', 'aw-plan-chip', i.category));
    if (i.source) head.append(uiNode('span', 'aw-plan-chip', i.source));
    const meta = [i.asset_id && ('자산 ' + i.asset_id), i.traffic_id && ('트래픽 ' + i.traffic_id),
      i.external_id].filter(Boolean).join(' · ');
    info.append(head, uiNode('div', 'tpl-goal', meta));
    const actions = uiNode('div', 'tpl-actions');
    const trace = uiNode('button', 'aw-link', '상태'); trace.type = 'button'; trace.onclick = () => showIncidentTrace(i.id);
    const verify = uiNode('button', 'aw-link', '재검증'); verify.type = 'button'; verify.onclick = () => verifyIncident(i.id, i.category);
    const del = uiCommand('Trash2', '사건 삭제', () => deleteIncident(i.id), 'icon-button');
    actions.append(trace, verify, del);
    row.append(info, actions); box.append(row);
  }
}
async function submitIncident(e) {
  if (e && e.preventDefault) e.preventDefault();
  agentEl('incidentFormError').textContent = '';
  const url = agentEl('incUrl').value.trim();
  const body = {
    source: agentEl('incSource').value.trim() || 'manual',
    category: agentEl('incCategory').value,
    external_id: agentEl('incExternalId').value.trim(),
    asset_id: agentEl('incAssetId').value.trim(),
    traffic_id: agentEl('incTrafficId').value.trim(),
    title: agentEl('incTitle').value.trim(),
    summary: agentEl('incSummary').value.trim(),
    location: agentEl('incLocation').value,
    param: agentEl('incParam').value.trim(),
  };
  if (!body.title) { agentEl('incidentFormError').textContent = '사건 제목을 입력하세요.'; return; }
  if (url) body.request = { method: (agentEl('incMethod').value.trim() || 'GET').toUpperCase(),
    url, body: agentEl('incBody').value || '' };
  try {
    await agentApi('/incidents', body);
    if (agentEl('incidentForm').reset) agentEl('incidentForm').reset();
    await loadIncidents();
  } catch (err) { agentEl('incidentFormError').textContent = err.message; }
}
function verifyIncident(id, category) {
  // 접근제어 사건은 소유자/비소유자 세션·식별자 입력이 필요하므로 전용 폼을 띄운다.
  if (category === 'access') { renderAccessVerifyForm(id); return; }
  return runIncidentVerify(id, {});
}
async function runIncidentVerify(id, extra) {
  // 재검증은 대상에 실제 요청을 보내므로 먼저 확인하고 현재 세션 헤더를 재주입한다(AI 호출 없음).
  if (typeof confirm === 'function' &&
      !confirm('이 사건을 새 검증 실행으로 재검증합니다. 대상에 실제 요청을 보냅니다. 계속할까요?')) return;
  try {
    const headers = (typeof getHeadersObj === 'function') ? getHeadersObj() : {};
    const run = await agentApi(`/incidents/${encodeURIComponent(id)}/verify`,
      { request_headers: headers, ...(extra || {}) });
    agentEl('incidentsDialog').close();
    await loadAgentList();
    if (run && run.id) selectRun(run.id);
  } catch (e) { agentEl('incidentFormError').textContent = e.message; }
}
function renderAccessVerifyForm(id) {
  const box = agentEl('incidentTrace'); box.hidden = false; box.replaceChildren();
  box.append(uiNode('div', 'tpl-head', '접근제어 재검증 — 소유자/비소유자 세션'));
  box.append(uiNode('p', 'aw-muted', '두 세션으로 같은 객체를 조회해 무단 조회 재현 여부를 확증합니다. '
    + '식별 포인터·값은 소유자 객체를 가리킵니다. 자격증명은 저장되지 않습니다.'));
  const mk = (label, ph) => {
    const l = uiNode('label', '', label); const inp = document.createElement('input');
    inp.type = 'text'; inp.placeholder = ph || ''; l.append(inp); box.append(l); return inp;
  };
  const ownerCookie = mk('소유자 세션 Cookie', 'session=...');
  const intruderCookie = mk('비소유자 세션 Cookie', 'session=...');
  const pointer = mk('식별 포인터(/로 시작)', '/id');
  const value = mk('식별 값(소유자 객체)', '7');
  const go = uiNode('button', 'btn btn-secondary', '재검증 실행'); go.type = 'button';
  go.onclick = () => submitAccessVerify(id, ownerCookie.value, intruderCookie.value, pointer.value, value.value);
  box.append(go);
}
async function submitAccessVerify(id, ownerCookie, intruderCookie, pointer, value) {
  agentEl('incidentFormError').textContent = '';
  if (!(pointer || '').trim().startsWith('/') || !(value || '').trim()) {
    agentEl('incidentFormError').textContent = '식별 포인터(/로 시작)와 식별 값을 입력하세요.'; return;
  }
  const actor_headers = {};
  if ((ownerCookie || '').trim()) actor_headers.owner = { Cookie: ownerCookie.trim() };
  if ((intruderCookie || '').trim()) actor_headers.intruder = { Cookie: intruderCookie.trim() };
  await runIncidentVerify(id, { actor_headers, access: { owner_actor: 'owner', intruder_actor: 'intruder',
    identity_pointer: pointer.trim(), identity_value: value.trim() } });
}
async function showIncidentTrace(id) {
  const box = agentEl('incidentTrace'); box.hidden = false;
  box.replaceChildren(uiNode('p', 'aw-muted', '불러오는 중…'));
  try {
    renderIncidentTrace(await agentApi(`/incidents/${encodeURIComponent(id)}`));
  } catch (e) { box.replaceChildren(uiNode('p', 'aw-form-error', e.message)); }
}
function renderIncidentTrace(trace) {
  const box = agentEl('incidentTrace'); box.replaceChildren();
  const head = uiNode('div', 'tpl-head');
  head.append(uiNode('strong', '', INCIDENT_STATUS[trace.status] || trace.status || ''));
  if (trace.category) head.append(uiNode('span', 'aw-plan-chip', trace.category));
  box.append(head);
  if (trace.reason) box.append(uiNode('p', 'aw-muted', trace.reason));
  const meta = [trace.asset_id && ('자산 ' + trace.asset_id),
    trace.traffic_id && ('트래픽 ' + trace.traffic_id)].filter(Boolean).join(' · ');
  if (meta) box.append(uiNode('p', 'aw-muted', meta));
  if (trace.asset_id) {
    const asset = uiNode('button', 'aw-link', '이 자산의 사건·발견 내역'); asset.type = 'button';
    asset.onclick = () => showAssetTrace(trace.asset_id);
    box.append(asset);
  }
  if (!trace.runs || !trace.runs.length) {
    box.append(uiNode('p', 'aw-muted', '연결된 재검증 실행이 없습니다.'));
  } else {
    const ul = uiNode('ul', 'aw-conclusion-verifications');
    for (const r of trace.runs) {
      const label = `${r.verdict || ''} · ${r.state || ''}` +
        (r.evidence_ids && r.evidence_ids.length ? ` · 증거 ${r.evidence_ids.length}` : '');
      const li = uiNode('li', '', label);
      const open = uiNode('button', 'aw-link', '실행 열기'); open.type = 'button';
      open.onclick = () => { agentEl('incidentsDialog').close(); selectRun(r.run_id); };
      li.append(open); ul.append(li);
    }
    box.append(ul);
  }
  if (trace.finding_groups && trace.finding_groups.length) {
    box.append(uiNode('h4', '', '자산별 연결 발견'));
    for (const group of trace.finding_groups) {
      const section = uiNode('div', 'tpl-row');
      const address = [group.method, group.origin, group.path].filter(Boolean).join(' ');
      section.append(uiNode('strong', '', address || group.asset_id));
      section.append(uiNode('span', 'aw-muted', ` · 자산 ${group.asset_id} · 발견 ${group.findings.length}건`));
      const refs = uiNode('ul', 'aw-conclusion-verifications');
      for (const ref of group.findings) {
        const row = uiNode('li', '', `${ref.verdict} · 발견 ${ref.finding_id} · 증거 ${ref.evidence_ids.length}`);
        const open = uiNode('button', 'aw-link', '발견 열기'); open.type = 'button';
        open.onclick = () => {
          agentEl('incidentsDialog').close();
          selectRun(ref.run_id);
          if (typeof setDetailMode === 'function') setDetailMode('findings');
        };
        row.append(open); refs.append(row);
      }
      section.append(refs); box.append(section);
    }
  }
  if (trace.note) box.append(uiNode('p', 'aw-muted', trace.note));
}
async function showAssetTrace(assetId) {
  const box = agentEl('incidentTrace'); box.hidden = false;
  box.replaceChildren(uiNode('p', 'aw-muted', '불러오는 중…'));
  try {
    renderAssetTrace(await agentApi(`/incidents/asset-trace?asset_id=${encodeURIComponent(assetId)}`));
  } catch (e) { box.replaceChildren(uiNode('p', 'aw-form-error', e.message)); }
}
function renderAssetTrace(trace) {
  const box = agentEl('incidentTrace'); box.replaceChildren();
  box.append(uiNode('h4', '', `자산 ${trace.asset_id || ''} · 사건·발견 이력`));
  if (!trace.incidents || !trace.incidents.length) {
    box.append(uiNode('p', 'aw-muted', '이 자산에 연결된 사건이 없습니다.'));
  } else {
    const list = uiNode('ul', 'aw-conclusion-verifications');
    for (const incident of trace.incidents) {
      const row = uiNode('li', '', `${incident.category || ''} · ${INCIDENT_STATUS[incident.status] || incident.status || ''} · 사건 ${incident.incident_id || ''}`);
      const open = uiNode('button', 'aw-link', '사건 열기'); open.type = 'button';
      open.onclick = () => showIncidentTrace(incident.incident_id);
      row.append(open); list.append(row);
    }
    box.append(list);
  }
  for (const group of trace.finding_groups || []) {
    const section = uiNode('div', 'tpl-row');
    section.append(uiNode('strong', '', `${group.category || ''} · ${[group.method, group.origin, group.path].filter(Boolean).join(' ')}`));
    section.append(uiNode('span', 'aw-muted', ` · 사건 ${group.incident_ids.length}건 · 연결 발견 ${group.findings.length}건`));
    const refs = uiNode('ul', 'aw-conclusion-verifications');
    for (const ref of group.findings) {
      const row = uiNode('li', '', `사건 ${ref.incident_id} · ${ref.verdict} · 발견 ${ref.finding_id}`);
      const open = uiNode('button', 'aw-link', '발견 열기'); open.type = 'button';
      open.onclick = () => {
        agentEl('incidentsDialog').close(); selectRun(ref.run_id);
        if (typeof setDetailMode === 'function') setDetailMode('findings');
      };
      row.append(open); refs.append(row);
    }
    section.append(refs); box.append(section);
  }
  if (trace.note) box.append(uiNode('p', 'aw-muted', trace.note));
}
async function deleteIncident(id) {
  if (typeof confirm === 'function' && !confirm('이 사건을 삭제할까요? 연결된 실행 기록은 유지됩니다.')) return;
  try {
    await agentApi(`/incidents/${encodeURIComponent(id)}`, undefined, 'DELETE');
    await loadIncidents();
    if (!agentEl('incidentsAudit').hidden) await openIncidentDeletions();
  } catch (e) { agentEl('incidentFormError').textContent = e.message; }
}

let templateOffset=0;
const templateSelectedIds=new Set();
async function openTemplates() {
  agentEl('templatesDialog').showModal();
  agentEl('templatesBulkResult').textContent='';
  const revisions=agentEl('templatesRevisions');if(revisions){revisions.hidden=true;revisions.replaceChildren();}
  await loadTemplates();
}
async function loadTemplates(reset=true) {
  if(reset) { templateOffset=0; agentEl('templatesList').replaceChildren(); }
  const more=agentEl('templatesMore');
  if(more) { more.disabled=true; if(reset) more.hidden=true; }
  try {
    const search = (agentEl('templatesSearch').value || '').trim();
    const category = (agentEl('templatesCategory').value || '').trim();
    const params = [];
    if (search) params.push(`search=${encodeURIComponent(search)}`);
    if (category) params.push(`category=${encodeURIComponent(category)}`);
    params.push(`offset=${templateOffset}`, 'limit=25');
    const result = await agentApi('/templates?' + params.join('&'));
    const page=result.templates||[];
    renderTemplates(page, result.policy_version || 1, !reset);
    templateOffset+=page.length;
    if(more) { more.hidden=!result.has_more; more.disabled=false; more.onclick=()=>loadTemplates(false); }
  } catch (e) {
    if(more) more.disabled=false;
    agentEl('templatesList').append(uiNode('p', 'aw-form-error', e.message));
  }
}
function renderTemplates(list, policyVersion = 1, append=false) {
  const box = agentEl('templatesList');
  if(!append) { box.replaceChildren(); templateSelectedIds.clear(); }
  const bulk=agentEl('templatesBulkCategory');if(bulk) bulk.disabled=!templateSelectedIds.size;
  if (!list.length && !append) { box.append(uiNode('p', 'aw-muted', '저장된 템플릿이 없습니다. 새 작업에서 "템플릿으로 저장"을 사용하세요.')); return; }
  for (const t of list) {
    const row = uiNode('div', 'tpl-row');
    const select=uiNode('input');select.type='checkbox';
    select.setAttribute('aria-label',`템플릿 ${t.name||t.id} 선택`);
    select.checked=templateSelectedIds.has(t.id);
    select.onchange=()=>{
      if(select.checked && templateSelectedIds.size>=50 && !templateSelectedIds.has(t.id)) {
        select.checked=false;agentEl('templatesBulkResult').textContent='한 번에 최대 50개까지 선택할 수 있습니다.';
      } else if(select.checked) templateSelectedIds.add(t.id);
      else templateSelectedIds.delete(t.id);
      if(bulk) bulk.disabled=!templateSelectedIds.size;};
    const info = uiNode('div', 'tpl-info');
    const head = uiNode('div', 'tpl-head');
    head.append(uiNode('strong', '', t.name || '무제 템플릿'));
    head.append(uiNode('span','aw-plan-chip',`v${t.version||1}`));
    if (t.category) head.append(uiNode('span', 'aw-plan-chip', t.category));
    if (t.pinned_plan && t.policy_version !== policyVersion) head.append(uiNode('span', 'aw-plan-chip', '정책 갱신 필요'));
    info.append(head, uiNode('div', 'tpl-goal', t.goal || ''));
    const actions = uiNode('div', 'tpl-actions');
    const run = uiNode('button', 'aw-link', '실행'); run.type = 'button'; run.onclick = () => runTemplate(t.id);
    if (t.pinned_plan && t.policy_version !== policyVersion) { run.disabled = true; run.title = '현재 정책으로 계획을 다시 검토해야 합니다.'; }
    const revise=uiNode('button','aw-link','개정');revise.type='button';revise.onclick=()=>reviseTemplate(t);
    const history=uiNode('button','aw-link','이력');history.type='button';history.onclick=()=>showTemplateRevisions(t);
    const del = uiCommand('Trash2', '템플릿 삭제', () => deleteTemplate(t.id), 'icon-button');
    actions.append(run,revise,history,del);
    row.append(select,info, actions); box.append(row);
  }
}
async function batchTemplateCategory() {
  if(!templateSelectedIds.size || typeof prompt!=='function') return;
  const answer=prompt(`선택한 템플릿 ${templateSelectedIds.size}개의 새 분류를 입력하세요. 각 템플릿에 개정 버전이 추가됩니다.`);
  if(answer===null) return;
  const category=answer.trim();
  const resultBox=agentEl('templatesBulkResult');
  if(category.length>40) { resultBox.textContent='분류는 40자 이하여야 합니다.'; return; }
  try {
    const result=await agentApi('/templates/batch/category',
      {ids:[...templateSelectedIds],category});
    await loadTemplates();
    resultBox.textContent=`분류 변경 ${result.succeeded||0}건 성공 · ${result.failed||0}건 실패`;
    for(const item of result.results||[]) if(!item.ok)
      resultBox.append(uiNode('p','aw-form-error',`${item.id}: ${item.error||'처리 실패'}`));
  } catch(e) { resultBox.textContent=e.message; }
}
async function reviseTemplate(template) {
  if(typeof confirm==='function' && !confirm('현재 새 작업 양식의 설정으로 이 템플릿을 개정합니다. 기존 버전은 이력으로 보존됩니다. 계속할까요?')) return;
  const name=prompt('템플릿 이름',template.name||'');if(name===null)return;
  const category=prompt('분류',template.category||'');if(category===null)return;
  try {
    const spec=_collectSpec();
    await agentApi(`/templates/${encodeURIComponent(template.id)}`,
      {name,category,spec},'PATCH');
    await loadTemplates();
  } catch(e) { agentEl('templatesList').prepend(uiNode('p','aw-form-error',e.message)); }
}
async function showTemplateRevisions(template) {
  const box=agentEl('templatesRevisions');box.hidden=false;
  box.replaceChildren(uiNode('p','aw-muted','개정 이력 불러오는 중…'));
  try {
    const result=await agentApi(`/templates/${encodeURIComponent(template.id)}/revisions`);
    box.replaceChildren(uiNode('h3','',`${template.name||'템플릿'} 개정 이력`));
    const latest=result.revisions?.[0]?.version;
    for(const row of result.revisions||[]) {
      const line=uiNode('p','',`v${row.version} · ${new Date(row.created*1000).toLocaleString('ko-KR')} · ${row.name} · ${row.category||'분류 없음'}`);
      if(row.version!==latest) {const restore=uiNode('button','aw-link','이 버전 복원');restore.type='button';
        restore.onclick=()=>restoreTemplateRevision(template,row.version);line.append(restore);}
      box.append(line);
    }
  } catch(e) {box.replaceChildren(uiNode('p','aw-form-error',e.message));}
}
async function restoreTemplateRevision(template,version) {
  if(typeof confirm==='function' && !confirm(`템플릿 v${version}을 새 최신 버전으로 복원할까요? 기존 이력은 유지됩니다.`)) return;
  try {
    await agentApi(`/templates/${encodeURIComponent(template.id)}/revisions/${version}/restore`,{});
    await loadTemplates();
    await showTemplateRevisions(template);
  } catch(e) {agentEl('templatesRevisions').replaceChildren(uiNode('p','aw-form-error',e.message));}
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
    await loadTemplates();
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
  const query=++_listQuery;
  try {
    const search=encodeURIComponent(agentEl('agentSearch').value||'');
    const state=encodeURIComponent(agentEl('agentFilter').value||'');
    const category=encodeURIComponent(agentEl('agentCategory').value||'');
    const data=await agentApi(`/history/runs?archived=${_showArchived?1:0}&offset=${workspacePage*workspacePageSize}&limit=${workspacePageSize}&search=${search}&state=${state}&category=${category}`);
    if(query!==_listQuery) return;
    if(data.total && workspacePage*workspacePageSize>=data.total) {
      workspacePage=Math.ceil(data.total/workspacePageSize)-1;
      return loadAgentList();
    }
    renderAgentList(data);
  } catch (e) { if(query===_listQuery) renderAgentListError(e.message); }
}
async function archiveRun(id) {
  try { await agentApi(`/runs/${encodeURIComponent(id)}/archive`, {}); await loadAgentList(); }
  catch (e) { agentEl('agentStatus').textContent = e.message; }
}
async function unarchiveRun(id) {
  try { await agentApi(`/runs/${encodeURIComponent(id)}/unarchive`, {}); await loadAgentList(); }
  catch (e) { agentEl('agentStatus').textContent = e.message; }
}
async function editRunMetadata(run) {
  if(run.state==='running') {agentEl('agentBatchStatus').textContent='실행 중인 작업은 이름·분류를 수정할 수 없습니다.';return;}
  const name=prompt('작업 이름 (비우면 목표 표시)',run.name||'');
  if(name===null) return;
  const category=prompt('작업 분류 (비워도 됨)',run.category||'');
  if(category===null) return;
  try {
    await agentApi(`/runs/${encodeURIComponent(run.id)}/metadata`,{name,category},'PATCH');
    await loadAgentList();
    agentEl('agentBatchStatus').textContent='작업 이름·분류를 저장했습니다.';
  } catch(e) {agentEl('agentBatchStatus').textContent=e.message;}
}
async function bulkRunAction(action) {
  const ids=[...workspaceSelectedIds];
  if (!ids.length) return;
  const label={archive:'보관',unarchive:'복원',stop:'중단'}[action];
  if (typeof confirm==='function' && !confirm(`선택한 ${ids.length}개 작업을 ${label}할까요? 항목별 결과를 표시합니다.`)) return;
  const status=agentEl('agentBatchStatus'),details=agentEl('agentBatchResults');
  status.textContent='처리 중…';details.hidden=true;details.replaceChildren();
  try {
    const result=await agentApi('/runs/batch',{ids,action});
    await loadAgentList();
    status.textContent=`${label}: 성공 ${result.succeeded}개, 실패 ${result.failed}개`;
    for(const item of result.results||[]) details.append(uiNode('div','',`${item.id.slice(0,8)} · ${item.ok?'완료':item.error||'실패'}`));
    details.hidden=false;
  } catch(e) { status.textContent=e.message; }
}
function downloadRunArchive() {
  if (!agentRunId || (typeof confirm === 'function' &&
      !confirm('보관 패키지에는 저장된 요청·응답 원문이 포함됩니다. 로컬 ZIP으로 다운로드할까요?'))) return;
  const link = document.createElement('a');
  link.href = `/api/agent/runs/${encodeURIComponent(agentRunId)}/archive.zip`;
  link.download = 'eventprobe-run-archive.zip';
  link.click();
}
async function importRunArchive() {
  const input = agentEl('agentArchiveFile');
  const file = input?.files?.[0];
  if (!file) return;
  try {
    if (file.size > 25 * 1024 * 1024) throw new Error('보관 패키지는 25 MiB 이하여야 합니다.');
    const response = await fetch('/api/agent/archives/import', {
      method: 'POST', headers: {'Content-Type': 'application/zip'}, body: await file.arrayBuffer() });
    const result = await _asJson(response, '보관 패키지');
    _showArchived = true;
    if(typeof saveAgentFilters==='function') saveAgentFilters();
    await loadAgentList();
    selectRun(result.id);
  } catch (e) { agentEl('agentStatus').textContent = e.message; }
  finally { input.value = ''; }
}

function selectRun(id) {
  agentRunId = id;
  if(typeof timelineState!=='undefined') timelineState.runId=null;
  if(typeof historyState!=='undefined') historyState.runId=null;
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
      if (agentEl('agentSkipPlan')) agentEl('agentSkipPlan').disabled = true;
      if (agentEl('agentHoldPlan')) agentEl('agentHoldPlan').disabled = true;
      agentEl('agentApproveStep').disabled = agentEl('agentDenyStep').disabled = true;
      if (agentEl('agentRevokePlan')) agentEl('agentRevokePlan').disabled = true;
      if (agentEl('agentArchiveDownload')) agentEl('agentArchiveDownload').disabled = true;
      try { history.replaceState(null, '', '#agent'); } catch (e) {}
      showAgentList();
    }
    loadAgentList();
  } catch (e) { agentEl('agentStatus').textContent = e.message; }
}

function _collectSpec() {
  const domain = agentEl('agentSourceDomain')?.checked === true;
  const form = domain ? {method:'GET',url:_agentDomainUrl(agentEl('agentDomainUrl').value),params:{},body:''} : _currentRequestForm();
  if (!/^https?:\/\//i.test(form.url)) throw new Error('요청 편집에서 HTTP(S) 대상 URL을 입력하세요.');
  const headers = domain ? {} : { ...(getUseDefaults() ? getDefaultHeaderProfile() : {}), ...getHeadersObj() };
  // strict 모드면 응답 공유를 요청하지 않는다(서버도 context 에서 발췌를 제거하지만 이중 방어).
  const share = agentEl('agentShare').checked && !(agentPolicy && agentPolicy.strict);
  const pathLines = id => (agentEl(id)?.value || '').split(/\r?\n/).map(s => s.trim()).filter(Boolean);
  const csv = id => (agentEl(id)?.value || '').split(',').map(s => s.trim().toLowerCase()).filter(Boolean);
  return {
    goal: agentEl('agentGoal').value,
    goals: collectGoals(),
    request: { method: form.method, url: form.url, params: form.params, body: form.body || '', headers },
    target_scope: domain ? 'same_origin' : (agentEl('agentTargetScope')?.value || 'request_only'),
    actors: domain ? [{id:'current',label:'새 세션',headers:{}}] : collectActors(), objects: domain ? [] : collectObjects(),
    max_steps: Number(agentEl('agentSteps').value), max_requests: Number(agentEl('agentRequests').value),
    max_ai_calls: Number(agentEl('agentAiCalls').value), max_seconds: Number(agentEl('agentSeconds').value),
    allow_write_methods: agentEl('agentWrite').checked, share_response_context: share,
    policy_version: 1,
    allowed_path_prefixes: pathLines('agentAllowedPaths'),
    denied_path_prefixes: pathLines('agentDeniedPaths'),
    allowed_methods: csv('agentAllowedMethods').map(s => s.toUpperCase()),
    allowed_categories: csv('agentAllowedCategories'),
    mode: agentEl('agentPlanMode').checked ? 'plan' : 'iterative',
  };
}

function _agentDomainUrl(value) {
  const raw=value.trim();
  if(!raw || /\s|\\/.test(raw)) throw new Error('유효한 HTTP(S) 도메인 또는 URL을 입력하세요.');
  const candidate=/^[a-z][a-z0-9+.-]*:\/\//i.test(raw)?raw:'https://'+raw;
  let url;
  try { url=new URL(candidate); } catch(e) { throw new Error('유효한 HTTP(S) 도메인 또는 URL을 입력하세요.'); }
  if(!['http:','https:'].includes(url.protocol) || !url.hostname || url.username || url.password)
    throw new Error('인증정보가 없는 HTTP(S) URL만 사용할 수 있습니다.');
  url.hash='';
  return url.href;
}

// 새 작업 대화상자를 열 때 승인 상태를 초기화한다(리뷰 P3).
function resetPlanPreview() { _approvedPlan = null; _approvedPlanExpiresAt = null; _approvedPolicyVersion = null; agentEl('agentPlanSteps').replaceChildren(); syncPlanPreview(); }

// 계획 모드일 때만 미리보기 영역을 노출하고, 숨길 때 승인 상태를 비운다(리뷰 P3).
function syncPlanPreview() {
  const on = agentEl('agentPlanMode').checked;
  agentEl('agentPlanPreviewWrap').hidden = !on;
  if (!on) { _approvedPlan = null; _approvedPlanExpiresAt = null; _approvedPolicyVersion = null; agentEl('agentPlanSteps').replaceChildren(); }
}

async function previewPlan() {
  const btn = agentEl('agentPlanPreviewBtn'); btn.disabled = true;
  agentEl('agentFormError').hidden = true;
  try {
    const invalid = [...agentEl('agentNew').querySelectorAll('input,textarea')].find(e => !e.checkValidity());
    if (invalid) { invalid.reportValidity(); return; }
    const { plan, fingerprint, policy_version } = await agentApi('/plan', _collectSpec());
    _approvedPlan = plan;   // 이 계획을 실행에 고정한다
    _approvedPlanExpiresAt = Date.now() / 1000 + 3600;
    _approvedPolicyVersion = policy_version || 1;
    renderPlanPreview(plan, fingerprint);
  } catch (e) { _approvedPlan = null; _approvedPlanExpiresAt = null; _approvedPolicyVersion = null; agentEl('agentFormError').hidden = false; agentEl('agentFormError').textContent = e.message; agentEl('agentPlanSteps').replaceChildren(); }
  finally { btn.disabled = false; }
}

// 미리보기 계획을 텍스트로만 렌더(마크업 주입 없음). 값은 구조 설명에 한정한다.
function renderPlanPreview(plan, fingerprint) {
  const box = agentEl('agentPlanSteps'); box.replaceChildren();
  const head = document.createElement('p'); head.className = 'aw-muted';
  head.textContent = `진입 ${plan.entry} · 단계 ${plan.steps.length}개 · 지문 ${fingerprint} (승인 후 1시간 동안만 유효)`;
  box.append(head);
  const list = document.createElement('ol'); list.className = 'aw-plan-list';
  for (const step of plan.steps) {
    const li = document.createElement('li');
    const title = document.createElement('div'); title.className = 'aw-plan-step-title';
    title.append(_planChip(step.action.kind), document.createTextNode(` ${step.action_id}`));
    if(step.requires_approval) title.append(_planChip('실행 전 단계 검토'));
    if (step.action.category) title.append(_planChip(step.action.category, 'cat'));
    li.append(title);
    const review=document.createElement('label');
    const toggle=document.createElement('input');toggle.type='checkbox';toggle.checked=!!step.requires_approval;
    toggle.setAttribute('aria-label',`단계 ${step.action_id} 실행 전 검토`);
    toggle.onchange=()=>setPlanStepReview(step.action_id,toggle.checked);
    review.append(toggle,document.createTextNode(' 실행 전 별도 검토'));
    li.append(review);
    const hyp = document.createElement('div'); hyp.className = 'aw-plan-step-hyp'; hyp.textContent = step.action.hypothesis || '';
    li.append(hyp);
    const flow = (step.branches || []).map(b => `${_predicateText(b.predicate)} → ${b.next || '종료'}`);
    flow.push(`기타 → ${step.default_next || '종료'}`);
    const branch = document.createElement('div'); branch.className = 'aw-plan-step-branch'; branch.textContent = flow.join('  ·  ');
    li.append(branch); list.append(li);
  }
  box.append(list);
}
async function setPlanStepReview(actionId, required) {
  if(!_approvedPlan) return;
  const candidate=JSON.parse(JSON.stringify(_approvedPlan));
  const step=candidate.steps.find(item=>item.action_id===actionId);
  if(!step) return;
  step.requires_approval=required;
  try {
    const {plan,fingerprint,policy_version}=await agentApi('/plan/review',{
      spec:_collectSpec(),plan:candidate});
    _approvedPlan=plan;_approvedPolicyVersion=policy_version;
    renderPlanPreview(plan,fingerprint);
  } catch(e) {
    agentEl('agentFormError').hidden=false;
    agentEl('agentFormError').textContent=e.message;
    renderPlanPreview(_approvedPlan,'재검토 필요');
  }
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
    if (spec.mode === 'plan' && _approvedPlan) {
      if (!_approvedPlanExpiresAt || Date.now() / 1000 >= _approvedPlanExpiresAt)
        throw new Error('승인 계획이 만료됐습니다. 계획을 다시 생성·검토하세요.');
      spec.approved_plan = _approvedPlan;
      spec.approved_plan_expires_at = _approvedPlanExpiresAt;
      spec.policy_version = _approvedPolicyVersion || 1;
    }
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
async function holdAgentPlan() {
  if (!agentRunId || typeof prompt !== 'function') return;
  const reason = prompt('진행 중인 계획을 보류하는 이유를 입력하세요. 현재 요청은 중단되며 자동 재개되지 않습니다.');
  if (reason === null) return;
  if (!reason.trim()) { agentEl('agentStatus').textContent = '보류 이유를 입력하세요.'; return; }
  try {
    await agentApi(`/runs/${agentRunId}/plan/hold`, { reason: reason.trim() });
    await pollAgent();
    loadAgentList();
  } catch (e) { agentEl('agentStatus').textContent = e.message; }
}
async function skipAgentPlanStep() {
  if (!agentRunId || typeof prompt !== 'function') return;
  const current = _awRun?.data?.plan_checkpoint?.current || '현재';
  const reason = prompt(`계획 단계 ${current}을 건너뛰는 이유를 입력하세요.\n저장된 기본 분기로 이동하며 작업은 자동 재개되지 않습니다.`);
  if (reason === null) return;
  if (!reason.trim()) { agentEl('agentStatus').textContent = '건너뛰는 이유를 입력하세요.'; return; }
  try {
    await agentApi(`/runs/${agentRunId}/plan/skip`, { reason: reason.trim() });
    await pollAgent();
    loadAgentList();
  } catch (e) { agentEl('agentStatus').textContent = e.message; }
}
async function reviewAgentPlanStep(approve) {
  if(!agentRunId || typeof prompt!=='function') return;
  const current=_awRun?.data?.plan_checkpoint?.current||'현재';
  const reason=prompt(`계획 단계 ${current}을 ${approve?'승인':'거절'}하는 이유를 입력하세요. 결정만 기록하며 요청은 자동 전송되지 않습니다.`);
  if(reason===null) return;
  if(!reason.trim()) {agentEl('agentStatus').textContent='검토 이유를 입력하세요.';return;}
  try {
    await agentApi(`/runs/${agentRunId}/plan/step/${approve?'approve':'deny'}`,{reason:reason.trim()});
    await pollAgent();loadAgentList();
  } catch(e) {agentEl('agentStatus').textContent=e.message;}
}
async function revokeAgentPlan() {
  if (!agentRunId || typeof prompt !== 'function') return;
  const reason = prompt('승인 계획을 철회하는 이유를 입력하세요. 실행 중인 요청을 중단하고 이 작업은 재개할 수 없습니다.');
  if (reason === null) return;
  if (!reason.trim()) { agentEl('agentStatus').textContent = '철회 이유를 입력하세요.'; return; }
  try {
    await agentApi(`/runs/${agentRunId}/plan/revoke`, { reason: reason.trim() });
    await pollAgent();
    loadAgentList();
  } catch (e) { agentEl('agentStatus').textContent = e.message; }
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
  const mode = agentDetailMode;
  if (!id || !_agentViewActive()) return;   // 다른 뷰면 폴링 중단(자원 절약)
  try {
    if(agentDetailMode==='history') {
      const status=await agentApi('/history/runs/'+encodeURIComponent(id)+'/status');
      if(id!==agentRunId || mode!==agentDetailMode) return;
      _awRun={...status,events:[],compact:true,view:'history'};
      renderAgentRunHeader(status);
      // Keep a page boundary until the reader asks for more; only poll at the tail.
      if(typeof historyState==='undefined' || historyState.runId!==id || !historyState.hasMore)
        await loadHistoryPage();
      if(status.state==='running' || status.has_pending_oob) agentTimer=setTimeout(pollAgent,2000);
      else loadAgentList();
      return;
    }
    if(mode==='timeline') {
      if(_awRun?.id===id && _awRun.view==='timeline') {
        const status=await agentApi('/history/runs/'+encodeURIComponent(id)+'/status');
        if(id!==agentRunId || mode!==agentDetailMode) return;
        if(status.updated===_awRun.updated && status.event_count===_awRun.event_count
            && status.state===_awRun.state) {
          if(typeof timelineState==='undefined' || timelineState.runId!==id || !timelineState.hasMore)
            await loadTimelinePage();
          if(status.state==='running' || status.has_pending_oob) agentTimer=setTimeout(pollAgent,2000);
          else loadAgentList();
          return;
        }
      }
      const view=await agentApi('/history/runs/'+encodeURIComponent(id)+'/conclusion');
      if(id!==agentRunId || mode!==agentDetailMode) return;
      _awRun={...view,events:[],compact:true,view:'timeline'};
      renderAgentRunHeader(_awRun);
      renderAgentConclusion(view.conclusion);
      if(typeof timelineState==='undefined' || timelineState.runId!==id || !timelineState.hasMore)
        await loadTimelinePage();
      if(view.state==='running' || view.has_pending_oob) agentTimer=setTimeout(pollAgent,2000);
      else loadAgentList();
      return;
    }
    if(agentDetailMode==='findings') {
      if(_awRun?.id===id) {
        const status=await agentApi('/history/runs/'+encodeURIComponent(id)+'/status');
        if(id!==agentRunId || mode!==agentDetailMode) return;
        if(status.updated===_awRun.updated &&
            status.event_count===(_awRun.event_count??_awRun.events?.length)
            && status.state===_awRun.state) {
          if(status.state==='running' || status.has_pending_oob) agentTimer=setTimeout(pollAgent,2000);
          else loadAgentList();
          return;
        }
      }
      const view=await agentApi('/history/runs/'+encodeURIComponent(id)+'/findings');
      if(id!==agentRunId || mode!==agentDetailMode) return;
      _awRun={...view,events:[],compact:true,view:'findings'};
      renderAgentRunHeader(_awRun);
      renderAgentConclusion(view.conclusion);
      renderAgentFindings(_awRun);
      if(view.state==='running' || view.has_pending_oob) agentTimer=setTimeout(pollAgent,2000);
      else loadAgentList();
      return;
    }
    if(['graph','sitemap','coverage'].includes(mode)) {
      if(_awRun?.id===id) {
        const status=await agentApi('/history/runs/'+encodeURIComponent(id)+'/status');
        if(id!==agentRunId || mode!==agentDetailMode) return;
        if(status.updated===_awRun.updated &&
            status.event_count===(_awRun.event_count??_awRun.events?.length)
            && status.state===_awRun.state) {
          if(status.state==='running' || status.has_pending_oob) agentTimer=setTimeout(pollAgent,2000);
          else loadAgentList();
          return;
        }
      }
      const view=await agentApi('/history/runs/'+encodeURIComponent(id)+'/map');
      if(id!==agentRunId || mode!==agentDetailMode) return;
      _awRun=view;
      renderAgentRunHeader(view);
      renderAgentConclusion(view.conclusion);
      syncDetailMode();
      if(view.state==='running' || view.has_pending_oob) agentTimer=setTimeout(pollAgent,2000);
      else loadAgentList();
      return;
    }
    // A full snapshot includes every event body. Check the small status first on
    // subsequent polls and leave the rendered evidence intact when nothing changed.
    if(_awRun && !_awRun.compact && _awRun.id===id) {
      const status=await agentApi('/history/runs/'+encodeURIComponent(id)+'/status');
      if(id!==agentRunId || mode!==agentDetailMode) return;
      if(status.updated===_awRun.updated && status.event_count===_awRun.events.length
          && status.state===_awRun.state) {
        if(status.state==='running' || status.has_pending_oob) agentTimer=setTimeout(pollAgent,2000);
        else loadAgentList();
        return;
      }
    }
    const run = await agentApi('/runs/' + id);
    if (id !== agentRunId || mode!==agentDetailMode) return;
    renderAgentWorkspace(run);
    if (run.state === 'running' || run.events.some(e => e.kind === 'oob_pending')) agentTimer = setTimeout(pollAgent, 2000);
    else loadAgentList();
  } catch (e) { if(id===agentRunId && mode===agentDetailMode) agentEl('agentStatus').textContent = e.message; }
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
