/* ── SecAPITester — Main App ── */

const API = {
  async request(data) {
    const r = await fetch('/api/request', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(data) });
    return r.json();
  },
  async payloads() {
    const r = await fetch('/api/payloads');
    return r.json();
  },
  async bulkTest(data) {
    const r = await fetch('/api/bulk-test', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(data) });
    return r.json();
  },
};

/* ── State ── */
const state = {
  payloads: null,
  selectedPayload: null,
  selectedCategory: null,
  lastResult: null,
  bulkResults: null,
  kvHeaders: [],
  kvParams: [],
  activeView: 'request',  // request / results / report
  activeReqTab: 'params',
  activeResTab: 'body',
};

/* ── Utils ── */
function toast(msg, type='info') {
  const el = document.createElement('div');
  el.className = `toast ${type}`;
  el.textContent = msg;
  document.getElementById('toastContainer').appendChild(el);
  setTimeout(() => el.remove(), 3000);
}

function escapeHtml(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function verdictBadge(verdict) {
  const labels = { blocked:'차단됨', passed:'통과됨', bypass:'우회 성공', error:'에러', unknown:'미확인', timeout:'타임아웃' };
  return `<span class="status-badge status-${verdict}">${labels[verdict] ?? verdict}</span>`;
}

function riskBadge(risk) {
  const map = { critical:'tag-red', high:'tag-orange', medium:'tag-yellow', low:'tag-blue', info:'tag-gray' };
  return `<span class="tag ${map[risk] ?? 'tag-gray'}">${risk?.toUpperCase()}</span>`;
}

function httpColor(code) {
  if (code >= 500) return 'var(--danger)';
  if (code >= 400) return 'var(--warning)';
  if (code >= 300) return 'var(--purple)';
  if (code >= 200) return 'var(--success)';
  return 'var(--text-muted)';
}

/* ── Headers 모드 전환 (KV ↔ Raw) ── */
let headerMode = 'kv';   // 'kv' | 'raw'

function switchHeaderMode(mode) {
  if (mode === headerMode) return;

  if (mode === 'raw') {
    // KV → Raw : 현재 KV를 "Key: Value\n" 형식 텍스트로 변환
    const raw = state.kvHeaders
      .filter(r => r.key)
      .map(r => `${r.key}: ${r.value}`)
      .join('\n');
    document.getElementById('headersRawEditor').value = raw;
    document.getElementById('headersKvWrap').style.display  = 'none';
    document.getElementById('headersRawWrap').style.display = 'block';
  } else {
    // Raw → KV : 텍스트를 파싱해서 KV 배열로 변환
    const raw = document.getElementById('headersRawEditor').value;
    state.kvHeaders = parseRawHeaders(raw);
    renderKvEditor('headersKv', state.kvHeaders);
    document.getElementById('headersKvWrap').style.display  = 'block';
    document.getElementById('headersRawWrap').style.display = 'none';
  }

  headerMode = mode;
  document.getElementById('hdrModeKv').classList.toggle('active', mode === 'kv');
  document.getElementById('hdrModeRaw').classList.toggle('active', mode === 'raw');
}

function parseRawHeaders(raw) {
  return raw.split('\n')
    .map(line => line.trim())
    .filter(line => line && !line.startsWith('#'))
    .map(line => {
      const idx = line.indexOf(':');
      if (idx === -1) return { key: line.trim(), value: '' };
      return {
        key:   line.slice(0, idx).trim(),
        value: line.slice(idx + 1).trim(),
      };
    })
    .filter(r => r.key);
}

// sendRequest 전 호출 — 현재 모드에서 헤더 객체를 읽어옴
function getHeadersObj() {
  if (headerMode === 'raw') {
    const raw = document.getElementById('headersRawEditor').value;
    const parsed = parseRawHeaders(raw);
    const o = {};
    parsed.forEach(r => { if (r.key) o[r.key] = r.value; });
    return o;
  }
  return kvToObj(state.kvHeaders);
}

/* ── KV Editor ── */
function renderKvEditor(containerId, rows) {
  const el = document.getElementById(containerId);
  el.innerHTML = '';
  rows.forEach((row, i) => {
    const div = document.createElement('div');
    div.className = 'kv-row';
    div.innerHTML = `
      <input placeholder="Key" value="${escapeHtml(row.key)}" oninput="updateKv('${containerId}', ${i}, 'key', this.value)">
      <input placeholder="Value" value="${escapeHtml(row.value)}" oninput="updateKv('${containerId}', ${i}, 'value', this.value)">
      <button class="btn-icon" onclick="removeKv('${containerId}', ${i})">×</button>`;
    el.appendChild(div);
  });
  const add = document.createElement('button');
  add.className = 'kv-add-btn';
  add.textContent = '+ 항목 추가';
  add.onclick = () => { rows.push({key:'',value:''}); renderKvEditor(containerId, rows); };
  el.appendChild(add);
}

function updateKv(id, idx, field, val) {
  (id === 'headersKv' ? state.kvHeaders : state.kvParams)[idx][field] = val;
}

function removeKv(id, idx) {
  const arr = id === 'headersKv' ? state.kvHeaders : state.kvParams;
  arr.splice(idx, 1);
  renderKvEditor(id, arr);
}

function kvToObj(arr) {
  const o = {};
  arr.forEach(r => { if (r.key) o[r.key] = r.value; });
  return o;
}

/* ── Sidebar ── */
async function loadSidebar() {
  state.payloads = await API.payloads();

  // 커스텀 페이로드 병합
  loadCustomPayloads();
  const allCategories = [
    ...state.payloads.categories,
    ...customState.categories.filter(c => c.payloads.length > 0).map(c => ({
      ...c, _custom: true
    })),
  ];
  // 벌크 모달용 전체 목록 저장
  state.payloads._allCategories = allCategories;

  const container = document.getElementById('sidebarList');
  container.innerHTML = '';

  allCategories.forEach(cat => {
    const group = document.createElement('div');
    group.className = 'category-group';
    group.dataset.catId = cat.id;

    const customBadge = cat._custom
      ? `<span style="font-size:9px;color:var(--accent);background:rgba(88,166,255,.12);border:1px solid rgba(88,166,255,.3);border-radius:4px;padding:1px 5px;margin-right:2px">커스텀</span>`
      : '';

    group.innerHTML = `
      <div class="category-header" onclick="toggleCategory(this)">
        <span>${cat.icon || '📝'}</span>
        <span style="font-size:12px;font-weight:600;color:var(--text-primary)">${cat.name}</span>
        ${customBadge}
        <span class="category-badge">${cat.payloads.length}</span>
        <span class="category-chevron">▶</span>
      </div>
      <div class="payload-list">
        ${cat.payloads.map(p => `
          <div class="payload-item" data-pid="${p.id}" data-catid="${cat.id}" onclick="selectPayload('${cat.id}','${p.id}')">
            <span class="risk-dot ${p.risk || 'medium'}"></span>
            <span class="payload-name" title="${escapeHtml(p.payload)}">${p.name}</span>
          </div>`).join('')}
      </div>`;
    container.appendChild(group);
  });
}

function toggleCategory(header) {
  header.parentElement.classList.toggle('open');
}

function filterSidebar(query) {
  const q = query.toLowerCase();
  document.querySelectorAll('.category-group').forEach(group => {
    let hasVisible = false;
    group.querySelectorAll('.payload-item').forEach(item => {
      const name = item.querySelector('.payload-name').textContent.toLowerCase();
      const pid = item.dataset.pid.toLowerCase();
      const show = !q || name.includes(q) || pid.includes(q);
      item.style.display = show ? '' : 'none';
      if (show) hasVisible = true;
    });
    group.style.display = (!q || hasVisible) ? '' : 'none';
  });
}

function selectPayload(catId, payloadId) {
  // 선택 표시
  document.querySelectorAll('.payload-item').forEach(el => el.classList.remove('selected'));
  const el = document.querySelector(`.payload-item[data-pid="${payloadId}"]`);
  if (el) el.classList.add('selected');

  // 상태 업데이트 (기본 + 커스텀 통합 탐색)
  const allCats = state.payloads?._allCategories || state.payloads?.categories || [];
  const cat     = allCats.find(c => c.id === catId);
  const payload = cat?.payloads.find(p => p.id === payloadId);
  if (!payload) return;

  state.selectedPayload = payload;
  state.selectedCategory = cat;

  // Inject Bar 업데이트
  document.getElementById('injectPayloadPreview').textContent = payload.payload;
  document.getElementById('injectPayloadName').textContent = `${cat.icon} ${payload.name}`;
  document.getElementById('injectBar').style.display = 'flex';
}

function injectPayload() {
  if (!state.selectedPayload) return;
  const payload = state.selectedPayload.payload;
  const target = document.getElementById('injectTarget').value;

  if (target === 'url') {
    const urlInput = document.getElementById('urlInput');
    const pos = urlInput.selectionStart;
    const val = urlInput.value;
    urlInput.value = val.slice(0, pos) + payload + val.slice(pos);
    toast('URL에 페이로드 삽입됨', 'success');
  } else if (target === 'body') {
    const bodyEl = document.getElementById('bodyEditor');
    const pos = bodyEl.selectionStart;
    bodyEl.value = bodyEl.value.slice(0, pos) + payload + bodyEl.value.slice(pos);
    // body 탭으로 전환
    switchReqTab('body');
    toast('Body에 페이로드 삽입됨', 'success');
  } else if (target === 'header') {
    state.kvHeaders.push({ key: 'X-Test-Payload', value: payload });
    renderKvEditor('headersKv', state.kvHeaders);
    switchReqTab('headers');
    toast('Header에 페이로드 삽입됨', 'success');
  } else if (target === 'param') {
    state.kvParams.push({ key: 'q', value: payload });
    renderKvEditor('paramsKv', state.kvParams);
    switchReqTab('params');
    toast('Query Param에 페이로드 삽입됨', 'success');
  }
}

/* ── Tab Switching ── */
function switchReqTab(tab) {
  state.activeReqTab = tab;
  document.querySelectorAll('.req-tab').forEach(t => t.classList.toggle('active', t.dataset.tab === tab));
  document.querySelectorAll('.req-tab-content').forEach(c => c.classList.toggle('active', c.dataset.tab === tab));
}

function switchResTab(tab) {
  state.activeResTab = tab;
  document.querySelectorAll('.res-tab').forEach(t =>
    t.classList.toggle('active', t.dataset.tab === tab)
  );
  document.querySelectorAll('.res-tab-content').forEach(c =>
    c.classList.toggle('active', c.dataset.tab === tab)
  );
  // Diff 탭 진입 시 렌더링
  if (tab === 'diff') renderDiff();
}

/* ── Send Request ── */
async function sendRequest() {
  const url = document.getElementById('urlInput').value.trim();
  if (!url) { toast('URL을 입력하세요', 'error'); return; }

  const method = document.getElementById('methodSelect').value;
  const body = document.getElementById('bodyEditor').value.trim() || null;

  const btn = document.getElementById('sendBtn');
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span> 전송 중';

  // 응답 초기화
  document.getElementById('responseBody').textContent = '요청 중...';
  document.getElementById('responseHeadersBody').textContent = '';
  document.getElementById('analysisContent').innerHTML = '<div class="empty-state"><div class="msg">분석 중...</div></div>';

  try {
    const reqPayload = {
      method,
      url,
      headers: getHeadersObj(),
      params: kvToObj(state.kvParams),
      body,
      payload: state.selectedPayload?.payload,
      category: state.selectedCategory?.id,
    };

    const result = await API.request(reqPayload);
    result._req = reqPayload;   // 요청 원본 첨부

    state.lastResult = result;
    renderResponse(result);
    renderAnalysis(result.analysis, result);
    addHistory(reqPayload, result);   // 히스토리 저장
  } catch(e) {
    toast('요청 실패: ' + e.message, 'error');
    document.getElementById('responseBody').textContent = '요청 실패: ' + e.message;
  } finally {
    btn.disabled = false;
    btn.innerHTML = '▶ 전송';
  }
}

/* ══════════════════════════════════════════════════════════════════
   Diff — 베이스라인 저장 & 응답 비교
   ══════════════════════════════════════════════════════════════════ */
let baseline = null;   // { status_code, response_time, body_size, body, headers }

function saveBaseline() {
  if (!state.lastResult) { toast('먼저 요청을 전송하세요', 'error'); return; }
  baseline = {
    status_code:   state.lastResult.status_code,
    response_time: state.lastResult.response_time,
    body_size:     state.lastResult.body_size,
    body:          state.lastResult.body || '',
    headers:       state.lastResult.headers || {},
  };
  // 버튼 시각적 표시
  const btn = document.getElementById('baselineBtn');
  btn.textContent = '📌 베이스라인 ✓';
  btn.style.borderColor = 'var(--success)';
  btn.style.color       = 'var(--success)';
  // 초기화 버튼 표시
  document.getElementById('baselineClearBtn').style.display = 'inline-flex';
  // Diff 탭에 뱃지 활성화
  document.getElementById('diffBadge').style.display = 'inline';
  toast('베이스라인 저장됨 — 다음 요청과 비교합니다', 'success');
}

function clearBaseline() {
  baseline = null;
  // 저장 버튼 원래대로
  const btn = document.getElementById('baselineBtn');
  btn.textContent   = '📌 베이스라인 저장';
  btn.style.borderColor = '';
  btn.style.color       = '';
  // 초기화 버튼 숨김
  document.getElementById('baselineClearBtn').style.display = 'none';
  // Diff 탭 뱃지 끄기
  document.getElementById('diffBadge').style.display = 'none';
  // Diff 뷰 초기화
  if (state.activeResTab === 'diff') renderDiff();
  toast('베이스라인 초기화됨', 'success');
}

function renderDiff() {
  const view = document.getElementById('diffView');

  if (!baseline) {
    view.innerHTML = `
      <div class="empty-state" style="height:100%">
        <div class="icon">📌</div>
        <div class="msg">먼저 기준 응답을 <strong>베이스라인 저장</strong> 하세요</div>
        <div style="font-size:11px;color:var(--text-muted);margin-top:4px">기준 요청 전송 → 베이스라인 저장 → 페이로드 삽입 후 재전송</div>
      </div>`;
    return;
  }

  if (!state.lastResult) {
    view.innerHTML = `<div class="empty-state" style="height:100%"><div class="msg">비교할 응답이 없습니다</div></div>`;
    return;
  }

  const cur = state.lastResult;

  // ── 메타 비교 ──────────────────────────────────────────────────
  const metaItems = [
    { label: '상태 코드',  base: baseline.status_code,   cur: cur.status_code,   fmt: v => v || '-' },
    { label: '응답 시간',  base: baseline.response_time, cur: cur.response_time, fmt: v => v + 'ms' },
    { label: '응답 크기',  base: baseline.body_size,     cur: cur.body_size,     fmt: formatBytes },
  ];

  const metaHtml = metaItems.map(m => {
    const changed = m.base !== m.cur;
    const diff = (typeof m.base === 'number' && typeof m.cur === 'number')
      ? (() => {
          const d = m.cur - m.base;
          return (d > 0 ? '+' : '') + (m.label === '응답 크기' ? formatBytes(Math.abs(d)) : d + (m.label === '응답 시간' ? 'ms' : '')) + (d > 0 ? ' ↑' : d < 0 ? ' ↓' : '');
        })()
      : '';
    return `
      <div class="diff-meta-item">
        <div class="diff-meta-label">${m.label}</div>
        <div class="diff-meta-value ${changed ? 'changed' : 'same'}">
          <span style="color:var(--text-muted)">${m.fmt(m.base)}</span>
          <span style="color:var(--text-muted);margin:0 4px">→</span>
          <span style="color:${changed ? 'var(--warning)' : 'var(--text-secondary)'}">${m.fmt(m.cur)}</span>
          ${changed && diff ? `<span style="font-size:10px;color:${m.cur > m.base ? 'var(--danger)' : 'var(--success)'};margin-left:4px">${diff}</span>` : ''}
        </div>
      </div>`;
  }).join('');

  // ── 바디 Diff 계산 (최대 400줄만 비교) ───────────────────────────
  const DIFF_MAX = 400;
  const baseLines = formatForDiff(baseline.body).split('\n').slice(0, DIFF_MAX);
  const curLines  = formatForDiff(cur.body || '').split('\n').slice(0, DIFF_MAX);
  const truncated = formatForDiff(baseline.body).split('\n').length > DIFF_MAX
                 || formatForDiff(cur.body || '').split('\n').length > DIFF_MAX;
  const diffLines = computeDiff(baseLines, curLines);

  const addedCount   = diffLines.filter(l => l.type === 'added').length;
  const removedCount = diffLines.filter(l => l.type === 'removed').length;

  const diffHtml = addedCount === 0 && removedCount === 0
    ? `<div class="diff-no-change">✅ 응답 바디 변경 없음</div>`
    : diffLines.map((l, i) => `
        <div class="diff-line ${l.type}">
          <span class="diff-line-num">${l.type !== 'added' ? l.baseNum ?? '' : ''}</span>
          <span class="diff-line-num">${l.type !== 'removed' ? l.curNum ?? '' : ''}</span>
          <span class="diff-line-sign">${l.type === 'added' ? '+' : l.type === 'removed' ? '-' : ' '}</span>
          <span class="diff-line-text">${escapeHtml(l.text)}</span>
        </div>`).join('');

  view.innerHTML = `
    <div style="display:flex;flex-direction:column;height:100%">
      <!-- 메타 비교 -->
      <div class="diff-meta-bar">${metaHtml}</div>

      <!-- 범례 -->
      <div class="diff-legend">
        <span><span style="display:inline-block;width:10px;height:10px;background:rgba(63,185,80,.3);border-radius:2px"></span> 추가 ${addedCount}줄</span>
        <span><span style="display:inline-block;width:10px;height:10px;background:rgba(248,81,73,.3);border-radius:2px"></span> 제거 ${removedCount}줄</span>
        <span style="margin-left:auto;color:var(--text-muted)">
          베이스라인 <span class="baseline-indicator">📌</span> vs 현재 응답
        </span>
      </div>

      <!-- 바디 Diff -->
      ${truncated ? `<div style="padding:6px 14px;font-size:11px;color:var(--warning);background:rgba(210,153,34,.08);border-bottom:1px solid rgba(210,153,34,.2)">⚠️ 응답이 너무 커서 앞 ${DIFF_MAX}줄만 비교합니다</div>` : ''}
      <div class="diff-body">${diffHtml}</div>
    </div>`;
}

function formatForDiff(body) {
  if (!body) return '';
  try { return JSON.stringify(JSON.parse(body), null, 2); } catch { return body; }
}

/* LCS 기반 간단 Diff 알고리즘 */
function computeDiff(aLines, bLines) {
  const MAX = 200;  // 성능 제한: LCS는 O(m*n)이므로 200줄로 제한
  if (aLines.length > MAX || bLines.length > MAX) {
    return simpleDiff(
      aLines.slice(0, MAX * 2),
      bLines.slice(0, MAX * 2)
    );
  }

  const m = aLines.length, n = bLines.length;
  // DP 테이블
  const dp = Array.from({ length: m + 1 }, () => new Array(n + 1).fill(0));
  for (let i = 1; i <= m; i++)
    for (let j = 1; j <= n; j++)
      dp[i][j] = aLines[i-1] === bLines[j-1] ? dp[i-1][j-1] + 1 : Math.max(dp[i-1][j], dp[i][j-1]);

  // 역추적
  const result = [];
  let i = m, j = n, baseNum = m, curNum = n;
  const ops = [];

  while (i > 0 || j > 0) {
    if (i > 0 && j > 0 && aLines[i-1] === bLines[j-1]) {
      ops.push({ type: 'same', text: aLines[i-1], baseNum: i, curNum: j });
      i--; j--;
    } else if (j > 0 && (i === 0 || dp[i][j-1] >= dp[i-1][j])) {
      ops.push({ type: 'added', text: bLines[j-1], curNum: j });
      j--;
    } else {
      ops.push({ type: 'removed', text: aLines[i-1], baseNum: i });
      i--;
    }
  }

  return ops.reverse();
}

function simpleDiff(aLines, bLines) {
  const result = [];
  const maxLen = Math.max(aLines.length, bLines.length);
  for (let i = 0; i < maxLen; i++) {
    const a = aLines[i], b = bLines[i];
    if (a === b)          result.push({ type: 'same',    text: a || '', baseNum: i+1, curNum: i+1 });
    else {
      if (a !== undefined) result.push({ type: 'removed', text: a, baseNum: i+1 });
      if (b !== undefined) result.push({ type: 'added',   text: b, curNum: i+1 });
    }
  }
  return result;
}

/* ── Render Response ── */
function renderResponse(result) {
  // 상태 표시줄
  const statusEl = document.getElementById('resStatusCode');
  statusEl.textContent = result.status_code || '-';
  statusEl.style.color = httpColor(result.status_code);

  document.getElementById('resTime').textContent = `${result.response_time}ms`;
  document.getElementById('resSize').textContent = formatBytes(result.body_size);

  // 응답 바디
  const bodyEl = document.getElementById('responseBody');
  if (result.body) {
    let formatted = result.body;
    try { formatted = JSON.stringify(JSON.parse(result.body), null, 2); } catch {}
    bodyEl.textContent = formatted;
  } else {
    bodyEl.textContent = '(응답 없음)';
  }

  // 응답 헤더
  const hdrEl = document.getElementById('responseHeadersBody');
  hdrEl.textContent = Object.entries(result.headers || {})
    .map(([k,v]) => `${k}: ${v}`).join('\n');

  // 요청 요약 (보낸 내용)
  renderRequestSummary(result._req);
}

function renderRequestSummary(req) {
  if (!req) return;
  const el = document.getElementById('reqSummaryBody');

  const method  = req.method?.toUpperCase() || '-';
  const url     = req.url || '-';
  const params  = Object.entries(req.params || {});
  const headers = Object.entries(req.headers || {});
  const body    = req.body || null;

  // 최종 URL 조립 (params 포함)
  let fullUrl = url;
  if (params.length) {
    const qs = params.map(([k,v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`).join('&');
    fullUrl += (url.includes('?') ? '&' : '?') + qs;
  }

  el.innerHTML = `
    <!-- Request Line -->
    <div style="margin-bottom:12px">
      <div style="font-size:10px;color:var(--text-muted);text-transform:uppercase;letter-spacing:.6px;margin-bottom:4px">Request Line</div>
      <div style="background:var(--bg-tertiary);border:1px solid var(--border);border-radius:var(--radius);padding:8px 10px;word-break:break-all">
        <span style="color:var(--accent);font-weight:700">${escapeHtml(method)}</span>
        <span style="color:var(--text-primary);margin-left:8px">${escapeHtml(fullUrl)}</span>
        <span style="color:var(--text-muted);margin-left:6px">HTTP/1.1</span>
      </div>
    </div>

    <!-- 전송 헤더 -->
    <div style="margin-bottom:12px">
      <div style="font-size:10px;color:var(--text-muted);text-transform:uppercase;letter-spacing:.6px;margin-bottom:4px">
        Request Headers
        <span style="color:var(--text-muted);font-weight:400;text-transform:none;letter-spacing:0"> (${headers.length}개)</span>
      </div>
      ${headers.length ? `
        <div style="background:var(--bg-tertiary);border:1px solid var(--border);border-radius:var(--radius);padding:8px 10px">
          ${headers.map(([k,v]) => `
            <div style="display:flex;gap:8px;padding:2px 0;border-bottom:1px solid var(--border)">
              <span style="color:var(--purple);min-width:160px;flex-shrink:0">${escapeHtml(k)}</span>
              <span style="color:var(--text-secondary)">${escapeHtml(v)}</span>
            </div>`).join('')}
        </div>` :
        `<div style="color:var(--text-muted);font-size:11px;padding:4px 2px">(헤더 없음)</div>`}
    </div>

    <!-- Query Params -->
    <div style="margin-bottom:12px">
      <div style="font-size:10px;color:var(--text-muted);text-transform:uppercase;letter-spacing:.6px;margin-bottom:4px">
        Query Parameters
        <span style="color:var(--text-muted);font-weight:400;text-transform:none;letter-spacing:0"> (${params.length}개)</span>
      </div>
      ${params.length ? `
        <div style="background:var(--bg-tertiary);border:1px solid var(--border);border-radius:var(--radius);padding:8px 10px">
          ${params.map(([k,v]) => `
            <div style="display:flex;gap:8px;padding:2px 0;border-bottom:1px solid var(--border)">
              <span style="color:var(--orange);min-width:160px;flex-shrink:0">${escapeHtml(k)}</span>
              <span style="color:var(--text-secondary)">${escapeHtml(v)}</span>
            </div>`).join('')}
        </div>` :
        `<div style="color:var(--text-muted);font-size:11px;padding:4px 2px">(파라미터 없음)</div>`}
    </div>

    <!-- Request Body -->
    <div>
      <div style="font-size:10px;color:var(--text-muted);text-transform:uppercase;letter-spacing:.6px;margin-bottom:4px">Request Body</div>
      ${body ? `
        <pre style="background:var(--bg-tertiary);border:1px solid var(--border);border-radius:var(--radius);padding:8px 10px;color:var(--text-secondary);white-space:pre-wrap;word-break:break-all;margin:0">${escapeHtml((() => { try { return JSON.stringify(JSON.parse(body), null, 2); } catch { return body; } })())}</pre>` :
        `<div style="color:var(--text-muted);font-size:11px;padding:4px 2px">(바디 없음)</div>`}
    </div>
  `;
}

function formatBytes(bytes) {
  if (!bytes) return '0 B';
  if (bytes < 1024) return bytes + ' B';
  return (bytes/1024).toFixed(1) + ' KB';
}

/* ── Render Analysis ── */
/* ── 분석 카드 헤더 클릭 → 접기/펼치기 ── */
function toggleAnalysisCard(header) {
  const card = header.closest('.analysis-card');
  card.classList.toggle('collapsed');
  // 접힌 상태 localStorage 저장
  const id = card.dataset.cardId;
  if (id) {
    const collapsed = JSON.parse(localStorage.getItem('collapsedCards') || '{}');
    collapsed[id] = card.classList.contains('collapsed');
    localStorage.setItem('collapsedCards', JSON.stringify(collapsed));
  }
}

/* innerHTML 삽입 후 모든 카드 헤더에 chevron + 클릭 이벤트 바인딩 */
function bindAnalysisCardToggles(container) {
  const collapsed = JSON.parse(localStorage.getItem('collapsedCards') || '{}');
  container.querySelectorAll('.analysis-card').forEach(card => {
    const header = card.querySelector('.analysis-card-header');
    if (!header) return;
    // chevron 없으면 추가
    if (!header.querySelector('.analysis-card-chevron')) {
      const chev = document.createElement('span');
      chev.className = 'analysis-card-chevron';
      chev.textContent = '▼';
      header.appendChild(chev);
    }
    // 저장된 접힘 상태 복원
    const id = card.dataset.cardId;
    if (id && collapsed[id]) card.classList.add('collapsed');
    // 이벤트 중복 방지
    header.onclick = () => toggleAnalysisCard(header);
  });
}

function renderAnalysis(a, result) {
  if (!a) return;

  // 헤더 verdict badge
  document.getElementById('analysisVerdict').innerHTML = verdictBadge(a.verdict);

  const container = document.getElementById('analysisContent');

  const confidenceColor = a.confidence >= 70 ? 'var(--success)' : a.confidence >= 40 ? 'var(--warning)' : 'var(--danger)';

  container.innerHTML = `
    <!-- 판정 카드 -->
    <div class="analysis-card" data-card-id="verdict">
      <div class="analysis-card-header">판정 결과</div>
      <div class="analysis-card-body">
        <div class="verdict-display">
          ${verdictBadge(a.verdict)}
          <div style="flex:1">
            <div style="font-size:10px;color:var(--text-muted);margin-bottom:3px">신뢰도 ${a.confidence}%</div>
            <div class="confidence-bar">
              <div class="confidence-fill" style="width:${a.confidence}%;background:${confidenceColor}"></div>
            </div>
          </div>
          ${riskBadge(a.risk_level)}
        </div>
      </div>
    </div>

    <!-- 응답 메타 -->
    <div class="analysis-card" data-card-id="res-info">
      <div class="analysis-card-header">응답 정보</div>
      <div class="analysis-card-body">
        <div class="meta-grid">
          <div class="meta-item">
            <div class="meta-label">상태코드</div>
            <div class="meta-value" style="color:${httpColor(result?.status_code)}">${result?.status_code || '-'}</div>
          </div>
          <div class="meta-item">
            <div class="meta-label">응답 시간</div>
            <div class="meta-value">${result?.response_time || 0}ms</div>
          </div>
          <div class="meta-item">
            <div class="meta-label">WAF 탐지</div>
            <div class="meta-value" style="font-size:11px;color:${a.waf_detected ? 'var(--warning)' : 'var(--text-muted)'}">${a.waf_detected || '없음'}</div>
          </div>
          <div class="meta-item">
            <div class="meta-label">응답 크기</div>
            <div class="meta-value">${formatBytes(result?.body_size)}</div>
          </div>
        </div>
      </div>
    </div>

    <!-- 차단 이유 -->
    ${a.block_reason?.length ? `
    <div class="analysis-card" data-card-id="block-reason">
      <div class="analysis-card-header">차단 이유</div>
      <div class="analysis-card-body">
        <div class="tag-list">
          ${a.block_reason.map(r => `<span class="tag tag-orange">${escapeHtml(r)}</span>`).join('')}
        </div>
      </div>
    </div>` : ''}

    <!-- 에러 누출 -->
    ${a.error_leaks?.length ? `
    <div class="analysis-card" style="border-color:rgba(248,81,73,.4)">
      <div class="analysis-card-header" style="color:var(--danger)">⚠️ 에러 정보 누출</div>
      <div class="analysis-card-body">
        <div class="tag-list">
          ${a.error_leaks.map(l => `<span class="tag tag-red">${escapeHtml(l)}</span>`).join('')}
        </div>
      </div>
    </div>` : ''}

    <!-- 민감 정보 -->
    ${a.sensitive_data?.length ? `
    <div class="analysis-card" style="border-color:rgba(255,107,107,.5)">
      <div class="analysis-card-header" style="color:var(--critical)">🔴 민감 정보 노출</div>
      <div class="analysis-card-body">
        <div class="tag-list">
          ${a.sensitive_data.map(s => `<span class="tag tag-red">${escapeHtml(s)}</span>`).join('')}
        </div>
      </div>
    </div>` : ''}

    <!-- 이상 징후 -->
    ${a.response_anomalies?.length ? `
    <div class="analysis-card" data-card-id="anomaly">
      <div class="analysis-card-header">이상 징후</div>
      <div class="analysis-card-body">
        <div class="detail-list">
          ${a.response_anomalies.map(x => `<div class="detail-item">⚡ ${escapeHtml(x)}</div>`).join('')}
        </div>
      </div>
    </div>` : ''}

    <!-- 상세 -->
    ${a.details?.length ? `
    <div class="analysis-card" data-card-id="details">
      <div class="analysis-card-header">상세 분석</div>
      <div class="analysis-card-body">
        <div class="detail-list">
          ${a.details.map(d => `<div class="detail-item">${escapeHtml(d)}</div>`).join('')}
        </div>
      </div>
    </div>` : ''}
  `;

  // 카드 접기/펼치기 바인딩
  bindAnalysisCardToggles(container);

  // 커스텀 Alert 룰 실행 후 내장 Alert과 병합
  const headersLower = Object.fromEntries(
    Object.entries(result?.headers || {}).map(([k,v]) => [k.toLowerCase(), (v||'').toLowerCase()])
  );
  const body      = result?.body || '';
  const bodyLower = body.toLowerCase();
  const customAlerts  = runCustomAlertRules(headersLower, body, bodyLower, result?.status_code || 0);
  const riskOrder     = { high:0, medium:1, low:2, informational:3 };
  const mergedAlerts  = [...(a.alerts || []), ...customAlerts]
    .sort((x, y) => (riskOrder[x.risk] ?? 9) - (riskOrder[y.risk] ?? 9));

  // Alert 섹션은 별도 렌더링 (클릭 이벤트 필요)
  renderAlerts(mergedAlerts);
}

/* ══════════════════════════════════════════════════════════════════
   커스텀 Alert 룰 관리
   ══════════════════════════════════════════════════════════════════ */
const ALERT_RULE_KEY = 'eventprobe_alert_rules';
let editingRuleId = null;

function loadAlertRules() {
  try { return JSON.parse(localStorage.getItem(ALERT_RULE_KEY) || '[]'); }
  catch { return []; }
}

function saveAlertRules(rules) {
  localStorage.setItem(ALERT_RULE_KEY, JSON.stringify(rules));
}

/* ── 커스텀 룰 실행 ── */
function runCustomAlertRules(headersLower, body, bodyLower, statusCode) {
  const rules   = loadAlertRules().filter(r => r.enabled !== false);
  const results = [];
  for (const rule of rules) {
    try {
      let matched = false;
      const val   = (rule.value || '').toLowerCase();

      if (rule.target === 'header_key') {
        const exists = Object.keys(headersLower).some(k => {
          if (rule.method === 'contains')     return k.includes(val);
          if (rule.method === 'not_contains') return false;
          if (rule.method === 'equals')       return k === val;
          if (rule.method === 'regex')        return new RegExp(rule.value,'i').test(k);
          return false;
        });
        matched = rule.method === 'not_contains'
          ? !Object.keys(headersLower).some(k => k.includes(val))
          : exists;

      } else if (rule.target === 'header_value') {
        const allVals = Object.values(headersLower).join('\n');
        if (rule.method === 'contains')     matched = allVals.includes(val);
        if (rule.method === 'not_contains') matched = !allVals.includes(val);
        if (rule.method === 'equals')       matched = Object.values(headersLower).some(v => v === val);
        if (rule.method === 'regex')        matched = new RegExp(rule.value,'i').test(allVals);

      } else if (rule.target === 'body') {
        if (rule.method === 'contains')     matched = bodyLower.includes(val);
        if (rule.method === 'not_contains') matched = !bodyLower.includes(val);
        if (rule.method === 'equals')       matched = body === rule.value;
        if (rule.method === 'regex')        matched = new RegExp(rule.value,'i').test(body);

      } else if (rule.target === 'status') {
        const sc = String(statusCode);
        if (rule.method === 'equals')       matched = sc === rule.value;
        if (rule.method === 'contains')     matched = sc.includes(rule.value);
        if (rule.method === 'not_contains') matched = !sc.includes(rule.value);
        if (rule.method === 'regex')        matched = new RegExp(rule.value).test(sc);
      }

      if (matched) {
        results.push({
          id:          rule.id,
          name:        rule.name,
          risk:        rule.risk,
          confidence:  rule.confidence,
          description: rule.description || '',
          solution:    rule.solution || '',
          reference:   '',
          _custom:     true,
        });
      }
    } catch { /* 정규식 오류 등 무시 */ }
  }
  return results;
}

/* ── 모달 열기/닫기 ── */
function openAlertRuleModal() {
  editingRuleId = null;
  resetAlertRuleForm();
  renderAlertRuleList();
  document.getElementById('alertRuleModal').classList.remove('hidden');
}

function closeAlertRuleModal() {
  document.getElementById('alertRuleModal').classList.add('hidden');
}

/* ── 룰 목록 렌더링 ── */
function renderAlertRuleList() {
  const rules     = loadAlertRules();
  const container = document.getElementById('alertRuleList');
  document.getElementById('alertRuleCount').textContent = `${rules.length}개`;

  if (!rules.length) {
    container.innerHTML = `<div style="color:var(--text-muted);font-size:12px;text-align:center;padding:14px">등록된 룰이 없습니다</div>`;
    return;
  }

  const targetLabels = { header_key:'헤더 키', header_value:'헤더 값', body:'바디', status:'상태코드' };
  const methodLabels = { contains:'포함', not_contains:'미포함', equals:'일치', regex:'정규식' };

  container.innerHTML = rules.map(r => `
    <div class="alert-rule-item ${editingRuleId === r.id ? 'editing' : ''}" id="arItem-${r.id}">
      <span class="alert-risk-bar ${r.risk}" style="width:3px;border-radius:2px;align-self:stretch;flex-shrink:0"></span>
      <span class="alert-rule-name">${escapeHtml(r.name)}</span>
      <span class="alert-rule-cond">${targetLabels[r.target]||r.target} ${methodLabels[r.method]||r.method} "${escapeHtml(r.value)}"</span>
      <div class="alert-rule-actions">
        <button class="btn-toggle" onclick="toggleAlertRule('${r.id}')" title="${r.enabled===false?'활성화':'비활성화'}">${r.enabled===false?'●':'○'}</button>
        <button class="btn-edit"   onclick="startEditAlertRule('${r.id}')">✏️</button>
        <button class="btn-del"    onclick="deleteAlertRule('${r.id}')">🗑</button>
      </div>
    </div>`).join('');
}

/* ── 룰 저장 (추가/수정) ── */
function saveAlertRule() {
  const name   = document.getElementById('arName').value.trim();
  const target = document.getElementById('arTarget').value;
  const method = document.getElementById('arMethod').value;
  const value  = document.getElementById('arValue').value.trim();

  if (!name)  { toast('룰 이름을 입력하세요', 'error'); return; }
  if (!value) { toast('체크 값을 입력하세요', 'error'); return; }

  // 정규식 유효성 검사
  if (method === 'regex') {
    try { new RegExp(value); } catch { toast('유효하지 않은 정규식입니다', 'error'); return; }
  }

  const rule = {
    id:          editingRuleId || genId(),
    name,
    risk:        document.getElementById('arRisk').value,
    confidence:  document.getElementById('arConfidence').value,
    target,
    method,
    value,
    description: document.getElementById('arDesc').value.trim(),
    solution:    document.getElementById('arSolution').value.trim(),
    enabled:     true,
  };

  const rules = loadAlertRules();
  if (editingRuleId) {
    const idx = rules.findIndex(r => r.id === editingRuleId);
    if (idx >= 0) rules[idx] = rule;
  } else {
    rules.push(rule);
  }
  saveAlertRules(rules);
  editingRuleId = null;
  resetAlertRuleForm();
  renderAlertRuleList();
  toast(editingRuleId ? '룰 수정 완료' : '룰 추가 완료', 'success');
}

/* ── 편집 시작 ── */
function startEditAlertRule(ruleId) {
  const rule = loadAlertRules().find(r => r.id === ruleId);
  if (!rule) return;
  editingRuleId = ruleId;

  document.getElementById('arName').value      = rule.name;
  document.getElementById('arRisk').value      = rule.risk;
  document.getElementById('arConfidence').value= rule.confidence;
  document.getElementById('arTarget').value    = rule.target;
  document.getElementById('arMethod').value    = rule.method;
  document.getElementById('arValue').value     = rule.value;
  document.getElementById('arDesc').value      = rule.description || '';
  document.getElementById('arSolution').value  = rule.solution || '';
  document.getElementById('alertRuleFormTitle').textContent = '룰 편집';
  document.getElementById('arCancelEdit').style.display = 'inline-flex';
  renderAlertRuleList();
}

function cancelEditAlertRule() {
  editingRuleId = null;
  resetAlertRuleForm();
  renderAlertRuleList();
}

function resetAlertRuleForm() {
  ['arName','arValue','arDesc','arSolution'].forEach(id => document.getElementById(id).value = '');
  document.getElementById('arRisk').value       = 'medium';
  document.getElementById('arConfidence').value = 'firm';
  document.getElementById('arTarget').value     = 'header_key';
  document.getElementById('arMethod').value     = 'not_contains';
  document.getElementById('alertRuleFormTitle').textContent = '새 룰 추가';
  document.getElementById('arCancelEdit').style.display = 'none';
}

/* ── 활성화 토글 ── */
function toggleAlertRule(ruleId) {
  const rules = loadAlertRules();
  const rule  = rules.find(r => r.id === ruleId);
  if (!rule) return;
  rule.enabled = rule.enabled === false ? true : false;
  saveAlertRules(rules);
  renderAlertRuleList();
}

/* ── 룰 삭제 ── */
function deleteAlertRule(ruleId) {
  if (!confirm('이 룰을 삭제할까요?')) return;
  saveAlertRules(loadAlertRules().filter(r => r.id !== ruleId));
  if (editingRuleId === ruleId) cancelEditAlertRule();
  renderAlertRuleList();
  toast('삭제됨', 'success');
}

/* ── Alert 룰 내보내기 ── */
function exportAlertRules() {
  const rules = loadAlertRules();
  if (!rules.length) { toast('내보낼 룰이 없습니다', 'error'); return; }
  const data = JSON.stringify({ alert_rules: rules }, null, 2);
  const blob = new Blob([data], { type: 'application/json' });
  const url  = URL.createObjectURL(blob);
  const ts   = new Date().toISOString().slice(0, 10);
  const a    = document.createElement('a');
  a.href     = url;
  a.download = `eventprobe_alert_rules_${ts}.json`;
  a.click();
  URL.revokeObjectURL(url);
  toast('내보내기 완료', 'success');
}

/* ── Alert 룰 가져오기 ── */
function importAlertRules(input) {
  const file = input.files[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = (e) => {
    try {
      const data = JSON.parse(e.target.result);
      const imported = data.alert_rules;
      if (!Array.isArray(imported)) throw new Error('올바른 형식이 아닙니다 (alert_rules 배열 필요)');

      const existing = loadAlertRules();
      const conflicts = imported.filter(nr => existing.some(er => er.name === nr.name));
      let msg = `${imported.length}개 룰을 가져올까요?`;
      if (conflicts.length) msg += `\n\n⚠️ "${conflicts.map(r=>r.name).join(', ')}" 룰이 이미 존재합니다. 덮어쓰시겠습니까?`;
      if (!confirm(msg)) { input.value = ''; return; }

      // 병합: 동일 이름 덮어쓰기, 새 항목 추가
      imported.forEach(nr => {
        nr.id = genId();
        const idx = existing.findIndex(er => er.name === nr.name);
        if (idx >= 0) existing[idx] = nr;
        else existing.push(nr);
      });

      saveAlertRules(existing);
      renderAlertRuleList();
      toast(`가져오기 완료: ${imported.length}개 룰`, 'success');
    } catch(err) {
      toast('가져오기 실패: ' + err.message, 'error');
    }
    input.value = '';
  };
  reader.readAsText(file);
}

/* ── Render ZAP-style Alerts ── */
function renderAlerts(alerts) {
  const container = document.getElementById('analysisContent');
  if (!alerts.length) return;

  // 위험도별 카운트
  const counts = { high:0, medium:0, low:0, informational:0 };
  alerts.forEach(a => { if (counts[a.risk] !== undefined) counts[a.risk]++; });

  const section = document.createElement('div');
  section.className = 'analysis-card';
  section.dataset.cardId = 'sec-alerts';
  section.style.borderColor = 'rgba(88,166,255,.25)';

  const countChips = Object.entries(counts)
    .filter(([,n]) => n > 0)
    .map(([r, n]) => `<span class="alert-count-chip chip-${r}">${riskIcon(r)} ${n}</span>`)
    .join('');

  const customCount = alerts.filter(a => a._custom).length;

  section.innerHTML = `
    <div class="analysis-card-header" style="color:var(--accent)">
      🔔 보안 Alert <span style="color:var(--text-muted);font-weight:400;margin-left:4px">(${alerts.length}건${customCount ? ` · 커스텀 ${customCount}` : ''})</span>
      <button onclick="event.stopPropagation();openAlertRuleModal()"
        style="margin-left:auto;background:transparent;border:1px solid rgba(88,166,255,.4);border-radius:4px;color:var(--accent);cursor:pointer;font-size:10px;padding:2px 7px;margin-right:6px">
        + 커스텀 룰
      </button>
      <span class="analysis-card-chevron">▼</span>
    </div>
    <div class="analysis-card-body" style="padding:10px 12px">
      <div class="alert-summary-bar">${countChips}</div>
      <div id="alertList"></div>
    </div>`;

  container.appendChild(section);
  const alertHeader = section.querySelector('.analysis-card-header');
  if (alertHeader) alertHeader.onclick = () => toggleAnalysisCard(alertHeader);

  const listEl = section.querySelector('#alertList');
  alerts.forEach((alert, idx) => {
    const card = document.createElement('div');
    card.className = 'alert-card';
    card.dataset.idx = idx;

    const confidenceLabel = { certain:'확실', firm:'높음', tentative:'보통' };

    card.innerHTML = `
      <div class="alert-card-header" onclick="toggleAlert(this)">
        <div class="alert-risk-bar ${alert.risk}"></div>
        <div class="alert-title">${escapeHtml(alert.name)}</div>
        <div class="alert-badges">
          ${alert._custom ? '<span class="custom-alert-badge">커스텀</span>' : ''}
          <span class="alert-risk-badge badge-${alert.risk}">${riskKo(alert.risk)}</span>
          <span class="alert-confidence-badge">${confidenceLabel[alert.confidence] ?? alert.confidence}</span>
        </div>
        <span class="alert-chevron">▶</span>
      </div>
      <div class="alert-body">
        <div class="alert-section">
          <div class="alert-section-label">설명</div>
          <div class="alert-section-text">${escapeHtml(alert.description)}</div>
        </div>
        <div class="alert-section">
          <div class="alert-section-label">해결 방법</div>
          <div class="alert-section-text">${escapeHtml(alert.solution)}</div>
        </div>
        ${alert.reference ? `
        <div class="alert-section">
          <div class="alert-section-label">참고</div>
          <a class="alert-ref-link" href="${escapeHtml(alert.reference)}" target="_blank" rel="noopener">${escapeHtml(alert.reference)}</a>
        </div>` : ''}
        <div style="margin-top:6px">
          <span class="tag tag-gray" style="font-size:10px">Alert ID: ${escapeHtml(alert.id)}</span>
        </div>
      </div>`;

    listEl.appendChild(card);
  });
}

function toggleAlert(header) {
  header.parentElement.classList.toggle('open');
}

function riskIcon(risk) {
  return { high:'🔴', medium:'🟠', low:'🟡', informational:'🔵' }[risk] ?? '⚪';
}

function riskKo(risk) {
  return { high:'높음', medium:'중간', low:'낮음', informational:'정보' }[risk] ?? risk;
}

/* ── Bulk Test Modal 탭 전환 ── */
function switchModalTab(tab) {
  document.querySelectorAll('.modal-tab').forEach(t =>
    t.classList.toggle('active', t.dataset.mtab === tab)
  );
  document.querySelectorAll('.modal-tab-content').forEach(c => {
    c.style.display = c.id === `mtab-${tab}` ? 'block' : 'none';
  });
}

/* ── Bulk Test Modal ── */
function openBulkModal() {
  if (!state.payloads) { toast('페이로드를 먼저 로드하세요', 'error'); return; }

  const opts = state.payloads.categories.map(c =>
    `<option value="${c.id}">${c.icon} ${c.name}</option>`
  ).join('');
  document.getElementById('bulkCategory').innerHTML  = opts;
  document.getElementById('multiCategory').innerHTML = opts;

  // URL 자동 채우기
  const currentUrl = document.getElementById('urlInput').value.trim();
  if (currentUrl) {
    document.getElementById('bulkUrl').value    = currentUrl;
    document.getElementById('multiUrls').value  = currentUrl;
    document.getElementById('scanHosts').value   =
      currentUrl.replace(/^https?:\/\//, '').split('/')[0];
  }

  loadBulkPayloadList(document.getElementById('bulkCategory').value);
  loadMultiPayloadList(document.getElementById('multiCategory').value);
  switchModalTab('single');
  document.getElementById('bulkModal').classList.remove('hidden');
}

function closeBulkModal() {
  document.getElementById('bulkModal').classList.add('hidden');
}

function loadBulkPayloadList(catId) {
  const cat = state.payloads.categories.find(c => c.id === catId);
  const container = document.getElementById('bulkPayloadChecklist');
  if (!cat) return;

  container.innerHTML = cat.payloads.map(p => `
    <label class="payload-check-item">
      <input type="checkbox" value="${p.id}" checked>
      <span class="risk-dot ${p.risk}" style="flex-shrink:0"></span>
      <span class="item-name">${p.name}</span>
      <span class="item-payload">${escapeHtml(p.payload)}</span>
    </label>`).join('');
}

function selectAllPayloads(checked) {
  document.querySelectorAll('#bulkPayloadChecklist input[type="checkbox"]')
    .forEach(cb => cb.checked = checked);
}

/* ── 다중 타겟 페이로드 목록 ── */
function loadMultiPayloadList(catId) {
  const cat = state.payloads?.categories.find(c => c.id === catId);
  const container = document.getElementById('multiPayloadChecklist');
  if (!cat || !container) return;
  container.innerHTML = cat.payloads.map(p => `
    <label class="payload-check-item">
      <input type="checkbox" value="${p.id}" checked>
      <span class="risk-dot ${p.risk}" style="flex-shrink:0"></span>
      <span class="item-name">${p.name}</span>
      <span class="item-payload">${escapeHtml(p.payload)}</span>
    </label>`).join('');
}

function selectAllMultiPayloads(checked) {
  document.querySelectorAll('#multiPayloadChecklist input[type="checkbox"]')
    .forEach(cb => cb.checked = checked);
}

/* ── 다중 타겟 일괄 테스트 ── */
async function runMultiTargetTest() {
  const urlsRaw = document.getElementById('multiUrls').value.trim();
  if (!urlsRaw) { toast('URL을 입력하세요', 'error'); return; }

  const urls = urlsRaw.split('\n').map(u => u.trim()).filter(Boolean);
  if (!urls.length) { toast('유효한 URL이 없습니다', 'error'); return; }

  const catId       = document.getElementById('multiCategory').value;
  const targetParam = document.getElementById('multiTargetParam').value.trim() || 'q';
  const injectIn    = document.getElementById('multiInjectIn').value;
  const method      = document.getElementById('multiMethod').value;

  const checkedIds = [...document.querySelectorAll('#multiPayloadChecklist input[type="checkbox"]:checked')]
    .map(cb => cb.value);
  if (!checkedIds.length) { toast('페이로드를 선택하세요', 'error'); return; }

  closeBulkModal();
  showLoadingOverlay(`0 / ${urls.length} 대상 테스트 중...`);

  try {
    const res = await fetch('/api/multi-target-test', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        method, urls, target_param: targetParam,
        inject_in: injectIn, headers: kvToObj(state.kvHeaders),
        category: catId, payload_ids: checkedIds,
      }),
    });
    const data = await res.json();
    hideLoadingOverlay();
    renderMultiTargetResults(data);
    switchView('results');
  } catch(e) {
    hideLoadingOverlay();
    toast('다중 테스트 실패: ' + e.message, 'error');
  }
}

function renderMultiTargetResults(data) {
  const container = document.querySelector('.results-view');
  // 기존 단일 결과 숨기기 — 다중 결과 전용 영역 표시
  const existing = document.getElementById('multiResultsArea');
  if (existing) existing.remove();

  const area = document.createElement('div');
  area.id = 'multiResultsArea';

  const totalTargets = data.targets?.length || 0;
  const allResults   = data.targets?.flatMap(t => t.results) || [];
  const globalSummary = generateClientSummary(allResults);

  // 글로벌 요약 업데이트
  document.getElementById('summaryTotal').textContent   = globalSummary.total;
  document.getElementById('summaryBlocked').textContent = globalSummary.blocked;
  document.getElementById('summaryPassed').textContent  = globalSummary.passed;
  document.getElementById('summaryBypass').textContent  = globalSummary.bypass;
  document.getElementById('summaryRate').textContent    = globalSummary.detection_rate + '%';

  area.innerHTML = `
    <div style="font-size:12px;color:var(--text-secondary);margin-bottom:12px">
      🎯 <strong>${totalTargets}개</strong> 대상 | 총 <strong>${globalSummary.total}회</strong> 테스트
    </div>
    ${(data.targets || []).map((t, i) => `
      <div class="target-result-block" id="trb-${i}">
        <div class="target-result-header" onclick="toggleTargetBlock(${i})">
          <span style="font-size:11px;color:var(--text-muted);flex-shrink:0">#${i+1}</span>
          <span class="target-url">${escapeHtml(t.url)}</span>
          <div class="multi-summary-chips">
            <span class="alert-count-chip chip-high">차단 ${t.summary?.blocked||0}</span>
            <span class="alert-count-chip chip-medium">통과 ${t.summary?.passed||0}</span>
            ${t.summary?.bypass ? `<span class="alert-count-chip" style="background:rgba(255,107,107,.1);color:var(--critical);border-color:rgba(255,107,107,.3)">우회 ${t.summary.bypass}</span>` : ''}
            <span class="alert-count-chip chip-informational">${t.summary?.detection_rate||0}%</span>
          </div>
          <span class="target-chevron">▼</span>
        </div>
        <div class="target-result-body">
          <table class="results-table">
            <thead><tr><th>#</th><th>페이로드</th><th>상태</th><th>응답시간</th><th>판정</th><th>위험도</th></tr></thead>
            <tbody>
              ${t.results.map((r, j) => `
                <tr>
                  <td style="color:var(--text-muted)">${j+1}</td>
                  <td><span class="payload-code" title="${escapeHtml(r.payload)}">${escapeHtml(r.payload_name)}</span></td>
                  <td style="color:${httpColor(r.status_code)};font-weight:600">${r.status_code||'-'}</td>
                  <td>${r.response_time}ms</td>
                  <td>${verdictBadge(r.analysis?.verdict)}</td>
                  <td>${riskBadge(r.risk)}</td>
                </tr>`).join('')}
            </tbody>
          </table>
        </div>
      </div>`).join('')}`;

  // 기존 테이블 숨기고 다중 결과 표시
  const table = container.querySelector('.results-table');
  if (table) table.style.display = 'none';
  container.appendChild(area);
}

function toggleTargetBlock(i) {
  document.getElementById(`trb-${i}`)?.classList.toggle('collapsed');
}

function generateClientSummary(results) {
  const total    = results.length;
  const blocked  = results.filter(r => r.analysis?.verdict === 'blocked').length;
  const passed   = results.filter(r => r.analysis?.verdict === 'passed').length;
  const bypass   = results.filter(r => r.analysis?.verdict === 'bypass').length;
  return { total, blocked, passed, bypass,
    detection_rate: total ? Math.round(blocked/total*100) : 0 };
}

/* ── 포트 스캔 ── */
/* 포트 파싱: 쉼표 구분 + 범위(80-100) + 혼합(22,80-90,443) */
function parsePorts(raw) {
  const result = new Set();
  raw.split(',').forEach(token => {
    token = token.trim();
    if (!token) return;
    if (token.includes('-')) {
      const [s, e] = token.split('-').map(n => parseInt(n.trim()));
      if (!isNaN(s) && !isNaN(e) && s > 0 && e <= 65535 && s <= e) {
        // 범위 최대 1000개까지만 허용
        const limit = Math.min(e, s + 999);
        for (let p = s; p <= limit; p++) result.add(p);
      }
    } else {
      const n = parseInt(token);
      if (!isNaN(n) && n > 0 && n <= 65535) result.add(n);
    }
  });
  return [...result].sort((a, b) => a - b);
}

async function runPortScan() {
  const hostsRaw = document.getElementById('scanHosts').value.trim();
  if (!hostsRaw) { toast('호스트를 입력하세요', 'error'); return; }

  const hosts    = hostsRaw.split('\n').map(h => h.trim()).filter(Boolean);
  const portsRaw = document.getElementById('scanPorts').value.trim();
  const ports    = portsRaw ? parsePorts(portsRaw) : [];
  const timeout  = parseFloat(document.getElementById('scanTimeout').value) || 2;

  closeBulkModal();
  showLoadingOverlay(`${hosts.length}개 호스트 포트 스캔 중...`);

  try {
    const res  = await fetch('/api/port-scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ hosts, ports, timeout }),
    });
    const data = await res.json();
    if (data.detail) throw new Error(data.detail);
    hideLoadingOverlay();
    renderPortScanResults(data);
    switchView('results');
  } catch(e) {
    hideLoadingOverlay();
    toast('포트 스캔 실패: ' + e.message, 'error');
  }
}

function renderPortScanResults(data) {
  const hostList = data.hosts || [];

  // 요약 카드 업데이트 (포트 스캔 용도)
  const totalScanned = hostList.reduce((s, h) => s + (h.total_scanned || 0), 0);
  document.getElementById('summaryTotal').textContent   = data.host_count;
  document.getElementById('summaryBlocked').textContent = data.total_open;
  document.getElementById('summaryPassed').textContent  = data.total_risky;
  document.getElementById('summaryBypass').textContent  = totalScanned;
  document.getElementById('summaryRate').textContent    = data.total_open;

  document.querySelector('.num-total   + .lbl').textContent = '대상 수';
  document.querySelector('.num-blocked + .lbl').textContent = '열린 포트';
  document.querySelector('.num-passed  + .lbl').textContent = '위험 포트';
  document.querySelector('.num-bypass  + .lbl').textContent = '스캔 포트 수';
  document.querySelector('.num-rate    + .lbl').textContent = '오픈 합계';

  const container = document.querySelector('.results-view');
  ['portScanArea', 'multiResultsArea'].forEach(id => document.getElementById(id)?.remove());
  const table = container.querySelector('.results-table');
  if (table) table.style.display = 'none';

  const area = document.createElement('div');
  area.id = 'portScanArea';

  area.innerHTML = `
    <div style="font-size:12px;color:var(--text-secondary);margin-bottom:12px">
      🔌 <strong>${data.host_count}개</strong> 호스트 스캔 완료
      &nbsp;|&nbsp; 열린 포트 합계: <strong style="color:var(--success)">${data.total_open}</strong>
      &nbsp;|&nbsp; 위험 포트: <strong style="color:var(--danger)">${data.total_risky}</strong>
    </div>
    ${hostList.map((h, i) => renderHostPortResult(h, i)).join('')}`;

  container.appendChild(area);
}

function renderHostPortResult(h, idx) {
  if (h.error && !h.results) {
    return `
      <div class="target-result-block" style="border-color:rgba(248,81,73,.3)">
        <div class="target-result-header" style="cursor:default">
          <span style="font-size:11px;color:var(--text-muted)">#${idx+1}</span>
          <span class="target-url">${escapeHtml(h.host)}</span>
          <span class="tag tag-red" style="font-size:10px">오류</span>
        </div>
        <div class="target-result-body" style="padding:10px 14px;font-size:12px;color:var(--danger)">${escapeHtml(h.error)}</div>
      </div>`;
  }

  const openPorts  = h.open_ports  || [];
  const riskyPorts = openPorts.filter(p => p.risk === 'high');

  return `
    <div class="target-result-block" id="psb-${idx}">
      <div class="target-result-header" onclick="toggleTargetBlock('psb-${idx}')">
        <span style="font-size:11px;color:var(--text-muted)">#${idx+1}</span>
        <span class="target-url">${escapeHtml(h.host)}</span>
        <span style="font-size:11px;color:var(--text-muted)">${escapeHtml(h.ip || '')}</span>
        <div class="multi-summary-chips">
          <span class="alert-count-chip chip-high">열림 ${h.open_count}</span>
          ${riskyPorts.length ? `<span class="alert-count-chip" style="background:rgba(248,81,73,.1);color:var(--danger);border-color:rgba(248,81,73,.3)">위험 ${riskyPorts.length}</span>` : ''}
          <span class="alert-count-chip chip-informational">스캔 ${h.total_scanned}</span>
        </div>
        <span class="target-chevron">▼</span>
      </div>
      <div class="target-result-body" style="padding:10px 14px">
        ${riskyPorts.length ? `
          <div style="margin-bottom:10px">
            <div style="font-size:11px;font-weight:600;color:var(--danger);margin-bottom:5px">🔴 위험 포트</div>
            <div class="port-scan-results">${riskyPorts.map(p => renderPortItem(p)).join('')}</div>
          </div>` : ''}
        <div>
          <div style="font-size:11px;font-weight:600;color:var(--text-muted);margin-bottom:5px;text-transform:uppercase;letter-spacing:.5px">전체 결과</div>
          <div class="port-scan-results">${(h.results || []).map(p => renderPortItem(p)).join('')}</div>
        </div>
      </div>
    </div>`;
}

function toggleTargetBlock(id) {
  document.getElementById(id)?.classList.toggle('collapsed');
}

function renderPortItem(p) {
  const cls = p.state === 'open' ? (p.risk === 'high' ? 'risky' : 'open') : '';
  return `
    <div class="port-result-item ${cls}">
      <span class="port-num">${p.port}</span>
      <span class="port-svc">${escapeHtml(p.service || '-')}</span>
      <span class="port-state-badge ${p.state === 'open' ? 'state-open' : 'state-closed'}">${p.state === 'open' ? '열림' : '닫힘'}</span>
      <span class="port-time">${p.response_time != null ? p.response_time + 'ms' : '-'}</span>
      <span class="port-note">${p.note ? escapeHtml(p.note) : ''}</span>
    </div>`;
}

async function runBulkTest() {
  const url = document.getElementById('bulkUrl').value.trim();
  if (!url) { toast('URL을 입력하세요', 'error'); return; }

  const catId = document.getElementById('bulkCategory').value;
  const targetParam = document.getElementById('bulkTargetParam').value.trim() || 'q';
  const injectIn = document.getElementById('bulkInjectIn').value;
  const method = document.getElementById('bulkMethod').value;

  const checkedIds = [...document.querySelectorAll('#bulkPayloadChecklist input[type="checkbox"]:checked')]
    .map(cb => cb.value);

  if (!checkedIds.length) { toast('페이로드를 선택하세요', 'error'); return; }

  closeBulkModal();
  showLoadingOverlay(`0 / ${checkedIds.length} 테스트 중...`);

  try {
    const result = await API.bulkTest({
      method,
      url,
      target_param: targetParam,
      inject_in: injectIn,
      headers: kvToObj(state.kvHeaders),
      category: catId,
      payload_ids: checkedIds,
    });

    state.bulkResults = result;
    hideLoadingOverlay();
    renderBulkResults(result);
    switchView('results');
  } catch(e) {
    hideLoadingOverlay();
    toast('일괄 테스트 실패: ' + e.message, 'error');
  }
}

/* ── Loading Overlay ── */
function showLoadingOverlay(msg) {
  const el = document.getElementById('loadingOverlay');
  el.querySelector('.loading-msg').textContent = msg;
  el.classList.remove('hidden');
}

function hideLoadingOverlay() {
  document.getElementById('loadingOverlay').classList.add('hidden');
}

/* ── Bulk Results ── */
function renderBulkResults(data) {
  const { results, summary } = data;

  document.getElementById('summaryTotal').textContent = summary.total;
  document.getElementById('summaryBlocked').textContent = summary.blocked;
  document.getElementById('summaryPassed').textContent = summary.passed;
  document.getElementById('summaryBypass').textContent = summary.bypass;
  document.getElementById('summaryRate').textContent = summary.detection_rate + '%';

  const tbody = document.getElementById('resultsTableBody');
  tbody.innerHTML = results.map((r, i) => {
    const a = r.analysis;
    return `
      <tr>
        <td style="color:var(--text-muted)">${i+1}</td>
        <td>
          <div style="font-size:11px;font-weight:600">${escapeHtml(r.payload_name)}</div>
          <div style="font-size:10px;color:var(--text-muted)">${escapeHtml(r.description)}</div>
        </td>
        <td><span class="payload-code" title="${escapeHtml(r.payload)}">${escapeHtml(r.payload)}</span></td>
        <td style="color:${httpColor(r.status_code)};font-weight:600">${r.status_code || '-'}</td>
        <td>${r.response_time}ms</td>
        <td>${verdictBadge(a.verdict)}</td>
        <td>${riskBadge(r.risk)}</td>
        <td style="font-size:11px;color:var(--text-muted);max-width:150px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">
          ${a.details?.join(' / ') || '-'}
        </td>
      </tr>`;
  }).join('');
}

/* ── Report Generation ── */
function generateReport() {
  if (!state.bulkResults) { toast('먼저 일괄 테스트를 실행하세요', 'error'); return; }
  switchView('report');
  renderReport(state.bulkResults);
}

function renderReport(data) {
  const { results, summary } = data;
  const container = document.getElementById('reportContent');

  const bypassList = results.filter(r => r.analysis.verdict === 'bypass');
  const passedList = results.filter(r => r.analysis.verdict === 'passed');
  const leakList   = results.filter(r => r.analysis.error_leaks?.length > 0);
  const sensitiveList = results.filter(r => r.analysis.sensitive_data?.length > 0);

  const overallRisk = sensitiveList.length || bypassList.length ? 'CRITICAL'
    : leakList.length ? 'HIGH'
    : passedList.length > summary.total * 0.3 ? 'MEDIUM'
    : 'LOW';

  const riskColor = { CRITICAL:'var(--critical)', HIGH:'var(--danger)', MEDIUM:'var(--warning)', LOW:'var(--success)' };

  container.innerHTML = `
    <div class="report-section">
      <h3>📊 종합 요약</h3>
      <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:16px">
        <div class="summary-card">
          <div class="num" style="color:${riskColor[overallRisk]}">${overallRisk}</div>
          <div class="lbl">전체 위험도</div>
        </div>
        <div class="summary-card">
          <div class="num num-rate">${summary.detection_rate}%</div>
          <div class="lbl">WAF 탐지율</div>
        </div>
        <div class="summary-card">
          <div class="num num-bypass">${summary.bypass}</div>
          <div class="lbl">우회 성공</div>
        </div>
        <div class="summary-card">
          <div class="num num-total">${summary.total}</div>
          <div class="lbl">총 테스트</div>
        </div>
      </div>
      ${summary.waf_detected?.length ? `<div style="font-size:12px;color:var(--text-secondary)">감지된 보안 장비: <strong>${summary.waf_detected.join(', ')}</strong></div>` : ''}
    </div>

    <div class="report-section">
      <h3>📈 탐지 현황</h3>
      <div style="display:flex;flex-direction:column;gap:8px">
        ${renderProgressBar('차단 (Blocked)', summary.blocked, summary.total, 'var(--success)')}
        ${renderProgressBar('통과 (Passed)', summary.passed, summary.total, 'var(--warning)')}
        ${renderProgressBar('우회 성공 (Bypass)', summary.bypass, summary.total, 'var(--critical)')}
        ${renderProgressBar('에러/타임아웃', summary.error, summary.total, 'var(--text-muted)')}
      </div>
    </div>

    ${bypassList.length ? `
    <div class="report-section">
      <h3>🚨 우회 성공 페이로드</h3>
      ${bypassList.map(r => `
        <div style="background:rgba(255,107,107,.08);border:1px solid rgba(255,107,107,.3);border-radius:6px;padding:10px 12px;margin-bottom:6px">
          <div style="font-weight:600;font-size:12px;margin-bottom:4px">${escapeHtml(r.payload_name)}</div>
          <code style="font-size:11px;color:var(--orange)">${escapeHtml(r.payload)}</code>
          <div style="font-size:11px;color:var(--text-muted);margin-top:4px">${r.analysis.details?.join(' | ') || ''}</div>
        </div>`).join('')}
    </div>` : ''}

    ${leakList.length ? `
    <div class="report-section">
      <h3>⚠️ 에러 정보 누출</h3>
      ${leakList.map(r => `
        <div style="background:rgba(248,81,73,.05);border:1px solid rgba(248,81,73,.2);border-radius:6px;padding:10px 12px;margin-bottom:6px">
          <div style="font-weight:600;font-size:12px;margin-bottom:4px">${escapeHtml(r.payload_name)}</div>
          <div class="tag-list">${r.analysis.error_leaks.map(l => `<span class="tag tag-red">${escapeHtml(l)}</span>`).join('')}</div>
        </div>`).join('')}
    </div>` : ''}

    <div class="report-section">
      <h3>📋 권고 사항</h3>
      <div style="display:flex;flex-direction:column;gap:6px">
        ${summary.bypass > 0 ? `<div class="detail-item">🔴 WAF 룰셋 즉시 보완 필요 — ${summary.bypass}개 페이로드 우회 성공</div>` : ''}
        ${leakList.length > 0 ? `<div class="detail-item">🟠 에러 메시지 노출 차단 — 서버 에러 응답 커스터마이징 필요</div>` : ''}
        ${summary.passed > 0 ? `<div class="detail-item">🟡 탐지 미적용 페이로드 ${summary.passed}개 — 추가 룰 검토 권장</div>` : ''}
        ${summary.detection_rate >= 90 ? `<div class="detail-item">✅ 탐지율 ${summary.detection_rate}% — 양호한 수준 유지</div>` : ''}
        <div class="detail-item">📌 정기적인 WAF 룰셋 검토 및 업데이트 권장</div>
        <div class="detail-item">📌 탐지 우회 기법 지속 모니터링 필요</div>
      </div>
    </div>

    <div style="text-align:right;font-size:11px;color:var(--text-muted);margin-top:20px">
      생성일시: ${new Date().toLocaleString('ko-KR')} | SecAPITester v1.0
    </div>
  `;
}

function renderProgressBar(label, value, total, color) {
  const pct = total ? Math.round(value / total * 100) : 0;
  return `
    <div>
      <div style="display:flex;justify-content:space-between;font-size:11px;margin-bottom:3px">
        <span style="color:var(--text-secondary)">${label}</span>
        <span style="color:var(--text-muted)">${value} / ${total} (${pct}%)</span>
      </div>
      <div class="risk-meter">
        <div class="risk-meter-fill" style="width:${pct}%;background:${color}"></div>
      </div>
    </div>`;
}

/* ── View Switching ── */
function switchView(view) {
  state.activeView = view;
  document.querySelectorAll('.view').forEach(v => v.classList.toggle('active', v.dataset.view === view));
  document.querySelectorAll('.topbar-tab').forEach(t => t.classList.toggle('active', t.dataset.view === view));
}

/* ══════════════════════════════════════════════════════════════════
   수직 리사이저 — 요청 패널 ↕ 응답 패널 세로 크기 조정
   ══════════════════════════════════════════════════════════════════ */
function initRowResizer() {
  const divider    = document.getElementById('rowDivider');
  const reqPanel   = document.getElementById('requestPanel');
  if (!divider || !reqPanel) return;

  // 저장된 높이 복원
  const saved = localStorage.getItem('requestPanelHeight');
  if (saved) reqPanel.style.height = saved + 'px';

  let dragging = false;
  let startY   = 0;
  let startH   = 0;

  divider.addEventListener('mousedown', e => {
    dragging = true;
    startY   = e.clientY;
    startH   = reqPanel.getBoundingClientRect().height;
    divider.classList.add('dragging');
    document.body.style.cursor     = 'row-resize';
    document.body.style.userSelect = 'none';
    e.preventDefault();
  });

  document.addEventListener('mousemove', e => {
    if (!dragging) return;
    const delta = e.clientY - startY;
    const newH  = Math.min(Math.max(startH + delta, 80), window.innerHeight * 0.6);
    reqPanel.style.height = newH + 'px';
  });

  document.addEventListener('mouseup', () => {
    if (!dragging) return;
    dragging = false;
    divider.classList.remove('dragging');
    document.body.style.cursor     = '';
    document.body.style.userSelect = '';
    localStorage.setItem('requestPanelHeight',
      reqPanel.getBoundingClientRect().height);
  });

  // Ctrl + 휠로도 조정
  reqPanel.addEventListener('wheel', e => {
    if (!e.ctrlKey) return;
    e.preventDefault();
    const curH = reqPanel.getBoundingClientRect().height;
    const step = e.deltaY > 0 ? -20 : 20;
    const newH = Math.min(Math.max(curH + step, 80), window.innerHeight * 0.6);
    reqPanel.style.height = newH + 'px';
    localStorage.setItem('requestPanelHeight', newH);
  }, { passive: false });
}

/* ══════════════════════════════════════════════════════════════════
   드래그 리사이저 — 응답 패널 ↔ 보안 분석 패널 가로 크기 조정
   ══════════════════════════════════════════════════════════════════ */
function initPaneResizer() {
  const divider     = document.getElementById('paneDivider');
  const resArea     = document.getElementById('responseArea');
  const analysisEl  = document.getElementById('analysisPanel');
  if (!divider || !resArea || !analysisEl) return;

  // 저장된 너비 복원
  const saved = localStorage.getItem('analysisPanelWidth');
  if (saved) analysisEl.style.width = saved + 'px';

  let dragging = false;
  let startX   = 0;
  let startW   = 0;

  divider.addEventListener('mousedown', e => {
    dragging = true;
    startX   = e.clientX;
    startW   = analysisEl.getBoundingClientRect().width;
    divider.classList.add('dragging');
    document.body.style.cursor    = 'col-resize';
    document.body.style.userSelect = 'none';
    e.preventDefault();
  });

  document.addEventListener('mousemove', e => {
    if (!dragging) return;
    // 마우스를 왼쪽으로 이동 → 분석 패널 넓어짐
    // 오른쪽으로 드래그 → 분석 패널 좁아짐 / 왼쪽으로 드래그 → 넓어짐
    const delta  = startX - e.clientX;
    const areaW  = resArea.getBoundingClientRect().width;
    const newW   = Math.min(Math.max(startW + delta, 260), areaW - 200);
    analysisEl.style.width = newW + 'px';
  });

  document.addEventListener('mouseup', () => {
    if (!dragging) return;
    dragging = false;
    divider.classList.remove('dragging');
    document.body.style.cursor     = '';
    document.body.style.userSelect = '';
    // 너비 저장
    localStorage.setItem('analysisPanelWidth',
      analysisEl.getBoundingClientRect().width);
  });

  // 마우스 휠로 크기 조정 (Ctrl + 휠)
  resArea.addEventListener('wheel', e => {
    if (!e.ctrlKey) return;
    e.preventDefault();
    const areaW = resArea.getBoundingClientRect().width;
    const curW  = analysisEl.getBoundingClientRect().width;
    const step  = e.deltaY > 0 ? -20 : 20;  // 아래 = 좁힘, 위 = 넓힘
    const newW  = Math.min(Math.max(curW + step, 220), areaW - 200);
    analysisEl.style.width = newW + 'px';
    localStorage.setItem('analysisPanelWidth', newW);
  }, { passive: false });
}

/* ══════════════════════════════════════════════════════════════════
   사이드바 탭 전환
   ══════════════════════════════════════════════════════════════════ */
/* ══════════════════════════════════════════════════════════════════
   커스텀 페이로드 관리
   ══════════════════════════════════════════════════════════════════ */
const CUSTOM_KEY = 'eventprobe_custom_payloads';
let customState = { categories: [], selectedCatId: null };

function loadCustomPayloads() {
  try {
    const d = JSON.parse(localStorage.getItem(CUSTOM_KEY) || '{"categories":[]}');
    customState.categories = d.categories || [];
  } catch { customState.categories = []; }
}

function saveCustomPayloads() {
  localStorage.setItem(CUSTOM_KEY, JSON.stringify({ categories: customState.categories }));
}

function genId() {
  return 'c_' + Date.now().toString(36) + Math.random().toString(36).slice(2, 6);
}

/* ── 모달 열기/닫기 ── */
function openCustomModal() {
  loadCustomPayloads();
  renderCustomCategoryList();
  selectCustomCategory(customState.selectedCatId);
  document.getElementById('customModal').classList.remove('hidden');
}

function closeCustomModal() {
  document.getElementById('customModal').classList.add('hidden');
  // 사이드바에 커스텀 카테고리 반영
  loadSidebar();
}

/* ── 내보내기 (JSON 다운로드) ── */
function exportCustomPayloads() {
  loadCustomPayloads();
  if (!customState.categories.length) {
    toast('내보낼 커스텀 페이로드가 없습니다', 'error');
    return;
  }
  const data = JSON.stringify({ categories: customState.categories }, null, 2);
  const blob = new Blob([data], { type: 'application/json' });
  const url  = URL.createObjectURL(blob);
  const ts   = new Date().toISOString().slice(0,10);
  const a    = document.createElement('a');
  a.href     = url;
  a.download = `eventprobe_custom_payloads_${ts}.json`;
  a.click();
  URL.revokeObjectURL(url);
  toast('내보내기 완료', 'success');
}

/* ── 가져오기 (JSON 파일 로드) ── */
function importCustomPayloads(input) {
  const file = input.files[0];
  if (!file) return;

  const reader = new FileReader();
  reader.onload = (e) => {
    try {
      const data = JSON.parse(e.target.result);
      if (!data.categories || !Array.isArray(data.categories)) {
        throw new Error('올바른 형식이 아닙니다 (categories 배열 필요)');
      }

      const imported = data.categories.length;
      const payloadCount = data.categories.reduce((s, c) => s + (c.payloads?.length || 0), 0);

      // 기존 카테고리와 병합 (ID 충돌 방지: 동일 이름 덮어쓰기 확인)
      const existing = customState.categories;
      const conflicts = data.categories.filter(nc =>
        existing.some(ec => ec.name === nc.name)
      );

      let msg = `${imported}개 카테고리 / ${payloadCount}개 페이로드를 가져올까요?`;
      if (conflicts.length) {
        msg += `\n\n⚠️ "${conflicts.map(c=>c.name).join(', ')}" 카테고리가 이미 존재합니다. 덮어쓰시겠습니까?`;
      }

      if (!confirm(msg)) {
        input.value = '';
        return;
      }

      // 병합: 동일 이름이면 덮어쓰기, 새 항목이면 추가
      data.categories.forEach(nc => {
        // 새 ID 부여 (충돌 방지)
        nc.id = genId();
        nc.payloads = (nc.payloads || []).map(p => ({ ...p, id: genId() }));
        nc.custom = true;

        const existIdx = customState.categories.findIndex(ec => ec.name === nc.name);
        if (existIdx >= 0) {
          customState.categories[existIdx] = nc;
        } else {
          customState.categories.push(nc);
        }
      });

      saveCustomPayloads();
      renderCustomCategoryList();
      selectCustomCategory(customState.categories[0]?.id || null);
      toast(`가져오기 완료: ${imported}개 카테고리, ${payloadCount}개 페이로드`, 'success');
    } catch (err) {
      toast('가져오기 실패: ' + err.message, 'error');
    }
    input.value = '';  // 동일 파일 재선택 가능하도록
  };
  reader.readAsText(file);
}

/* ── 카테고리 목록 렌더링 ── */
function renderCustomCategoryList() {
  const list = document.getElementById('customCategoryList');
  if (!customState.categories.length) {
    list.innerHTML = `<div style="padding:20px;text-align:center;color:var(--text-muted);font-size:12px">카테고리를 추가하세요</div>`;
    return;
  }
  list.innerHTML = customState.categories.map(cat => `
    <div class="custom-cat-item ${cat.id === customState.selectedCatId ? 'active' : ''}"
         onclick="selectCustomCategory('${cat.id}')">
      <span class="cat-icon">${escapeHtml(cat.icon || '📝')}</span>
      <span class="cat-name">${escapeHtml(cat.name)}</span>
      <span class="cat-count">${cat.payloads.length}</span>
    </div>`).join('');
}

/* ── 카테고리 선택 ── */
function selectCustomCategory(catId) {
  customState.selectedCatId = catId;
  const cat = customState.categories.find(c => c.id === catId);
  document.getElementById('customNoCategory').style.display  = cat ? 'none'  : 'flex';
  document.getElementById('customEditArea').style.display    = cat ? 'flex'  : 'none';
  if (!cat) return;
  document.getElementById('customCatIcon').value = cat.icon || '';
  document.getElementById('customCatName').value = cat.name;
  renderCustomPayloadList(cat);
  // 카테고리 목록 active 갱신
  document.querySelectorAll('.custom-cat-item').forEach(el =>
    el.classList.toggle('active', el.onclick?.toString().includes(`'${catId}'`))
  );
  renderCustomCategoryList();
}

/* ── 카테고리 메타 저장 ── */
function saveCategoryMeta() {
  const cat = customState.categories.find(c => c.id === customState.selectedCatId);
  if (!cat) return;
  cat.icon = document.getElementById('customCatIcon').value.trim() || '📝';
  cat.name = document.getElementById('customCatName').value.trim() || '새 카테고리';
  saveCustomPayloads();
  renderCustomCategoryList();
  toast('카테고리 저장 완료', 'success');
}

/* ── 카테고리 추가 ── */
function addCustomCategory() {
  const newCat = {
    id: genId(),
    name: '새 카테고리',
    icon: '📝',
    color: '#58a6ff',
    payloads: [],
    custom: true,
  };
  customState.categories.push(newCat);
  saveCustomPayloads();
  renderCustomCategoryList();
  selectCustomCategory(newCat.id);
}

/* ── 카테고리 삭제 ── */
function deleteCustomCategory() {
  if (!confirm('이 카테고리와 모든 페이로드를 삭제할까요?')) return;
  customState.categories = customState.categories.filter(c => c.id !== customState.selectedCatId);
  customState.selectedCatId = null;
  saveCustomPayloads();
  renderCustomCategoryList();
  selectCustomCategory(null);
  toast('카테고리 삭제됨', 'success');
}

/* ── 페이로드 목록 렌더링 ── */
function renderCustomPayloadList(cat) {
  const list = document.getElementById('customPayloadList');
  if (!cat.payloads.length) {
    list.innerHTML = `<div style="color:var(--text-muted);font-size:12px;text-align:center;padding:16px">페이로드를 추가하세요</div>`;
    return;
  }
  list.innerHTML = cat.payloads.map((p, i) => `
    <div class="custom-payload-item" id="cpi-${p.id}">
      <div class="custom-payload-item-top">
        <span class="risk-dot ${p.risk}" style="flex-shrink:0"></span>
        <span class="custom-payload-name">${escapeHtml(p.name)}</span>
        <div class="custom-payload-actions">
          <button class="btn-edit" onclick="startEditPayload('${p.id}')">✏️ 편집</button>
          <button class="btn-del"  onclick="deleteCustomPayload('${p.id}')">🗑</button>
        </div>
      </div>
      <div class="custom-payload-value">${escapeHtml(p.payload)}</div>
      ${p.description ? `<div class="custom-payload-desc">${escapeHtml(p.description)}</div>` : ''}
    </div>`).join('');
}

/* ── 페이로드 추가 ── */
function addCustomPayload() {
  const name  = document.getElementById('newPayloadName').value.trim();
  const value = document.getElementById('newPayloadValue').value.trim();
  const risk  = document.getElementById('newPayloadRisk').value;
  const desc  = document.getElementById('newPayloadDesc').value.trim();
  if (!name)  { toast('이름을 입력하세요', 'error'); return; }
  if (!value) { toast('페이로드 값을 입력하세요', 'error'); return; }

  const cat = customState.categories.find(c => c.id === customState.selectedCatId);
  if (!cat) return;

  cat.payloads.push({ id: genId(), name, payload: value, description: desc, risk });
  saveCustomPayloads();
  renderCustomCategoryList();
  renderCustomPayloadList(cat);

  // 입력 초기화
  document.getElementById('newPayloadName').value  = '';
  document.getElementById('newPayloadValue').value = '';
  document.getElementById('newPayloadDesc').value  = '';
  toast('페이로드 추가됨', 'success');
}

/* ── 페이로드 인라인 편집 ── */
function startEditPayload(payloadId) {
  const cat = customState.categories.find(c => c.id === customState.selectedCatId);
  const p   = cat?.payloads.find(x => x.id === payloadId);
  if (!p) return;

  const el = document.getElementById(`cpi-${payloadId}`);
  el.innerHTML = `
    <div class="custom-payload-edit-form">
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:6px">
        <input class="form-input" id="ep-name-${p.id}"  value="${escapeHtml(p.name)}"  placeholder="이름">
        <select class="form-select" id="ep-risk-${p.id}">
          ${['critical','high','medium','low'].map(r =>
            `<option value="${r}" ${r===p.risk?'selected':''}>${{critical:'🔴 Critical',high:'🟠 High',medium:'🟡 Medium',low:'🟢 Low'}[r]}</option>`
          ).join('')}
        </select>
      </div>
      <textarea class="code-editor" id="ep-val-${p.id}" rows="2" style="font-size:12px">${escapeHtml(p.payload)}</textarea>
      <input class="form-input" id="ep-desc-${p.id}" value="${escapeHtml(p.description||'')}" placeholder="설명 (선택)">
      <div style="display:flex;gap:6px;justify-content:flex-end">
        <button class="btn btn-secondary" style="font-size:11px;padding:4px 10px" onclick="cancelEditPayload('${p.id}')">취소</button>
        <button class="btn btn-primary"   style="font-size:11px;padding:4px 10px" onclick="saveEditPayload('${p.id}')">저장</button>
      </div>
    </div>`;
}

function saveEditPayload(payloadId) {
  const cat = customState.categories.find(c => c.id === customState.selectedCatId);
  const p   = cat?.payloads.find(x => x.id === payloadId);
  if (!p) return;

  const name  = document.getElementById(`ep-name-${payloadId}`).value.trim();
  const value = document.getElementById(`ep-val-${payloadId}`).value.trim();
  const risk  = document.getElementById(`ep-risk-${payloadId}`).value;
  const desc  = document.getElementById(`ep-desc-${payloadId}`).value.trim();

  if (!name || !value) { toast('이름과 값을 입력하세요', 'error'); return; }
  p.name = name; p.payload = value; p.risk = risk; p.description = desc;
  saveCustomPayloads();
  renderCustomPayloadList(cat);
  toast('수정 완료', 'success');
}

function cancelEditPayload(payloadId) {
  const cat = customState.categories.find(c => c.id === customState.selectedCatId);
  if (cat) renderCustomPayloadList(cat);
}

/* ── 페이로드 삭제 ── */
function deleteCustomPayload(payloadId) {
  if (!confirm('이 페이로드를 삭제할까요?')) return;
  const cat = customState.categories.find(c => c.id === customState.selectedCatId);
  if (!cat) return;
  cat.payloads = cat.payloads.filter(p => p.id !== payloadId);
  saveCustomPayloads();
  renderCustomCategoryList();
  renderCustomPayloadList(cat);
  toast('삭제됨', 'success');
}

function switchSidebarTab(tab) {
  document.querySelectorAll('.sidebar-tab').forEach(t =>
    t.classList.toggle('active', t.dataset.stab === tab)
  );
  document.querySelectorAll('.sidebar-panel').forEach(p =>
    p.classList.toggle('active', p.id === (tab === 'payloads' ? 'sidebarPayloads' : 'sidebarHistory'))
  );
  if (tab === 'history') renderHistoryList();
}

/* ══════════════════════════════════════════════════════════════════
   요청 히스토리
   ══════════════════════════════════════════════════════════════════ */
const HISTORY_KEY  = 'eventprobe_history';
const HISTORY_MAX  = 100;

function loadHistory() {
  try { return JSON.parse(localStorage.getItem(HISTORY_KEY) || '[]'); }
  catch { return []; }
}

function saveHistory(list) {
  localStorage.setItem(HISTORY_KEY, JSON.stringify(list.slice(0, HISTORY_MAX)));
}

function addHistory(req, result) {
  const list = loadHistory();
  list.unshift({
    id:           Date.now(),
    ts:           new Date().toISOString(),
    method:       req.method?.toUpperCase() || 'GET',
    url:          req.url || '',
    headers:      req.headers || {},
    params:       req.params  || {},
    body:         req.body    || null,
    status:       result.status_code || 0,
    response_time:result.response_time || 0,
    body_size:    result.body_size || 0,
    verdict:      result.analysis?.verdict || 'unknown',
    risk_level:   result.analysis?.risk_level || 'info',
    alert_count:  result.analysis?.alerts?.length || 0,
    payload:      req.payload || null,
    category:     req.category || null,
  });
  saveHistory(list);
  // 히스토리 탭이 열려있으면 즉시 갱신
  if (document.querySelector('.sidebar-tab[data-stab="history"]')?.classList.contains('active')) {
    renderHistoryList();
  }
}

function deleteHistoryItem(id, e) {
  e.stopPropagation();
  const list = loadHistory().filter(h => h.id !== id);
  saveHistory(list);
  renderHistoryList();
}

function clearHistory() {
  if (!confirm('히스토리를 모두 삭제할까요?')) return;
  localStorage.removeItem(HISTORY_KEY);
  renderHistoryList();
}

function formatRelTime(iso) {
  const diff = Date.now() - new Date(iso).getTime();
  if (diff < 60000)  return `${Math.floor(diff/1000)}초 전`;
  if (diff < 3600000) return `${Math.floor(diff/60000)}분 전`;
  if (diff < 86400000) return `${Math.floor(diff/3600000)}시간 전`;
  return new Date(iso).toLocaleDateString('ko-KR', { month:'short', day:'numeric', hour:'2-digit', minute:'2-digit' });
}

function methodClass(m) {
  const map = { GET:'method-get', POST:'method-post', PUT:'method-put', DELETE:'method-delete', PATCH:'method-patch' };
  return map[m] || 'method-other';
}

function renderHistoryList() {
  const list = loadHistory();
  const container = document.getElementById('historyList');
  const countEl   = document.getElementById('historyCount');
  countEl.textContent = `${list.length}건`;

  if (!list.length) {
    container.innerHTML = `
      <div class="empty-state" id="historyEmpty">
        <div class="icon">🕓</div>
        <div class="msg">요청 기록이 없습니다</div>
      </div>`;
    return;
  }

  container.innerHTML = list.map(h => {
    const shortUrl = h.url.length > 32 ? h.url.slice(0, 32) + '…' : h.url;
    const statusColor = httpColor(h.status);
    return `
      <div class="history-item" onclick="restoreHistory(${h.id})">
        <button class="history-delete" onclick="deleteHistoryItem(${h.id}, event)" title="삭제">×</button>
        <div class="history-item-top">
          <span class="history-method ${methodClass(h.method)}">${h.method}</span>
          <span class="history-url" title="${escapeHtml(h.url)}">${escapeHtml(shortUrl)}</span>
        </div>
        <div class="history-item-bottom">
          <span class="history-status" style="color:${statusColor}">${h.status || '-'}</span>
          <span class="history-time">${formatRelTime(h.ts)}</span>
          <span class="history-verdict verdict-${h.verdict}">${{blocked:'차단',passed:'통과',bypass:'우회',timeout:'타임아웃',error:'에러',unknown:'미확인'}[h.verdict]||h.verdict}</span>
          ${h.alert_count ? `<span class="history-alert-count">🔔${h.alert_count}</span>` : ''}
        </div>
      </div>`;
  }).join('');
}

function restoreHistory(id) {
  const item = loadHistory().find(h => h.id === id);
  if (!item) return;

  // URL / Method 복원
  document.getElementById('urlInput').value    = item.url;
  document.getElementById('methodSelect').value = item.method;

  // Headers / Params 복원 (KV 모드로 전환 후 채움)
  if (headerMode !== 'kv') switchHeaderMode('kv');
  state.kvHeaders = Object.entries(item.headers || {}).map(([k,v]) => ({key:k, value:v}));
  state.kvParams  = Object.entries(item.params  || {}).map(([k,v]) => ({key:k, value:v}));
  renderKvEditor('headersKv', state.kvHeaders);
  renderKvEditor('paramsKv',  state.kvParams);

  // Body 복원
  document.getElementById('bodyEditor').value = item.body || '';

  // 요청/분석 뷰로 전환
  switchView('request');
  toast(`히스토리 복원: ${item.method} ${item.url.slice(0,40)}`, 'success');
}

/* ── Init ── */
document.addEventListener('DOMContentLoaded', () => {
  loadSidebar();
  renderKvEditor('headersKv', state.kvHeaders);
  renderKvEditor('paramsKv', state.kvParams);

  // Enter key on URL
  document.getElementById('urlInput').addEventListener('keydown', e => {
    if (e.key === 'Enter') sendRequest();
  });

  // 메서드 변경 시 페이로드 삽입 위치 자동 전환
  document.getElementById('methodSelect').addEventListener('change', e => {
    const bodyMethods = ['POST', 'PUT', 'PATCH', 'DELETE'];
    const target = document.getElementById('injectTarget');
    if (bodyMethods.includes(e.target.value)) {
      target.value = 'body';
      // Body 탭도 자동 전환
      switchReqTab('body');
    } else {
      target.value = 'param';
      switchReqTab('params');
    }
  });

  // Sidebar search
  document.getElementById('sidebarSearchInput').addEventListener('input', e => {
    filterSidebar(e.target.value);
  });

  // Bulk category change
  document.getElementById('bulkCategory').addEventListener('change', e => {
    loadBulkPayloadList(e.target.value);
  });

  document.getElementById('multiCategory').addEventListener('change', e => {
    loadMultiPayloadList(e.target.value);
  });

  // 패널 리사이저 초기화
  initRowResizer();
  initPaneResizer();
});
