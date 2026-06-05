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
  const container = document.getElementById('sidebarList');
  container.innerHTML = '';

  state.payloads.categories.forEach(cat => {
    const group = document.createElement('div');
    group.className = 'category-group open';
    group.dataset.catId = cat.id;

    group.innerHTML = `
      <div class="category-header" onclick="toggleCategory(this)">
        <span>${cat.icon}</span>
        <span style="font-size:12px;font-weight:600;color:var(--text-primary)">${cat.name}</span>
        <span class="category-badge">${cat.payloads.length}</span>
        <span class="category-chevron">▶</span>
      </div>
      <div class="payload-list">
        ${cat.payloads.map(p => `
          <div class="payload-item" data-pid="${p.id}" data-catid="${cat.id}" onclick="selectPayload('${cat.id}','${p.id}')">
            <span class="risk-dot ${p.risk}"></span>
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

  // 상태 업데이트
  const cat = state.payloads.categories.find(c => c.id === catId);
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
  document.querySelectorAll('.res-tab').forEach(t => t.classList.toggle('active', t.dataset.tab === tab));
  document.querySelectorAll('[data-tab]').forEach(c => {
    if (c.classList.contains('res-tab-content')) c.classList.toggle('active', c.dataset.tab === tab);
  });
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
      headers: kvToObj(state.kvHeaders),
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
  } catch(e) {
    toast('요청 실패: ' + e.message, 'error');
    document.getElementById('responseBody').textContent = '요청 실패: ' + e.message;
  } finally {
    btn.disabled = false;
    btn.innerHTML = '▶ 전송';
  }
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
function renderAnalysis(a, result) {
  if (!a) return;

  // 헤더 verdict badge
  document.getElementById('analysisVerdict').innerHTML = verdictBadge(a.verdict);

  const container = document.getElementById('analysisContent');

  const confidenceColor = a.confidence >= 70 ? 'var(--success)' : a.confidence >= 40 ? 'var(--warning)' : 'var(--danger)';

  container.innerHTML = `
    <!-- 판정 카드 -->
    <div class="analysis-card">
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
    <div class="analysis-card">
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
    <div class="analysis-card">
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
    <div class="analysis-card">
      <div class="analysis-card-header">이상 징후</div>
      <div class="analysis-card-body">
        <div class="detail-list">
          ${a.response_anomalies.map(x => `<div class="detail-item">⚡ ${escapeHtml(x)}</div>`).join('')}
        </div>
      </div>
    </div>` : ''}

    <!-- 상세 -->
    ${a.details?.length ? `
    <div class="analysis-card">
      <div class="analysis-card-header">상세 분석</div>
      <div class="analysis-card-body">
        <div class="detail-list">
          ${a.details.map(d => `<div class="detail-item">${escapeHtml(d)}</div>`).join('')}
        </div>
      </div>
    </div>` : ''}
  `;
}

/* ── Bulk Test Modal ── */
function openBulkModal() {
  if (!state.payloads) { toast('페이로드를 먼저 로드하세요', 'error'); return; }

  const catSelect = document.getElementById('bulkCategory');
  catSelect.innerHTML = state.payloads.categories.map(c =>
    `<option value="${c.id}">${c.icon} ${c.name}</option>`
  ).join('');

  // URL 자동 채우기
  const currentUrl = document.getElementById('urlInput').value.trim();
  if (currentUrl) document.getElementById('bulkUrl').value = currentUrl;

  loadBulkPayloadList(catSelect.value);
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

/* ── Init ── */
document.addEventListener('DOMContentLoaded', () => {
  loadSidebar();
  renderKvEditor('headersKv', state.kvHeaders);
  renderKvEditor('paramsKv', state.kvParams);

  // Enter key on URL
  document.getElementById('urlInput').addEventListener('keydown', e => {
    if (e.key === 'Enter') sendRequest();
  });

  // Sidebar search
  document.getElementById('sidebarSearchInput').addEventListener('input', e => {
    filterSidebar(e.target.value);
  });

  // Bulk category change
  document.getElementById('bulkCategory').addEventListener('change', e => {
    loadBulkPayloadList(e.target.value);
  });
});
