/* 로컬 탐색 그래프 (리뷰 2026-10-14 F1, Stage 1).
   자율 검증 실행의 Run→Action→Request→Observation→Verification 관계를 "그림"으로 보여준다.
   - 데이터는 이미 받아 둔 스냅샷(run.events)만 사용 — 그래프 표시로 외부/네트워크/AI 호출 0.
   - 간선은 '실제 링크'(step_id·request_id·evidence_ids·basis·plan_branch)에서만 파생.
     시간 인접만으로 인과관계를 만들지 않는다.
   - 조건부 계획(plan)은 '예정 경로'로 별도 레인에 구분 표시(실제 실행 경로와 혼동 금지).
   - 증거는 텍스트(textContent/<pre>)로만 렌더 — target/응답 문자열을 HTML 로 실행하지 않는다.
   - 노드 id = 영속 이벤트 id(새로고침/재개 후 유지). 합성 id(run:/plan:)도 영속 id 파생. */

/* ── 공통 헬퍼 ─────────────────────────────────────────────────────────────── */
function _gPath(url) {
  if (!url) return '';
  try { const u = new URL(url); return u.pathname + (u.search || ''); }
  catch (e) { const m = String(url).match(/^[a-z]+:\/\/[^/]+(\/[^\s]*)?$/i); return m ? (m[1] || '/') : String(url); }
}
function _gHttpClass(status, truncated) {
  if (truncated) return 'trunc';
  const s = Number(status);
  if (!s) return 'none';
  return (Math.floor(s / 100)) + 'xx';
}
function _gPredText(p) {
  if (!p || typeof p !== 'object') return '';
  if (p.kind === 'always') return '항상';
  if (p.kind === 'verdict_in') return 'verdict∈[' + (p.verdicts || []).join(',') + ']';
  if (p.kind === 'status_in') return 'status∈[' + (p.statuses || []).join(',') + ']';
  if (p.kind === 'signal_present') return 'signal:' + (p.signal || '');
  return String(p.kind || '');
}
function _gShort(id) { return String(id || '').slice(0, 8); }

/* ── 1. 순수 빌더 ─────────────────────────────────────────────────────────────
   events(=run.events, 스냅샷 순서) + run → {nodes:Map, edges:[], lanes, warnings}.
   DOM·네트워크 없음 — node:test 로 단위 검증. */
function buildGraphModel(events, run) {
  events = events || [];
  run = run || {};
  const nodes = new Map();
  const edges = [];
  const warnings = [];
  const lanes = { exec: [], plan: [], meta: [] };

  function add(node) {
    if (nodes.has(node.id)) return nodes.get(node.id);
    nodes.set(node.id, node);
    (lanes[node.lane] || lanes.meta).push(node.id);
    return node;
  }
  function node(id, type, lane, order, extra) {
    return Object.assign({ id, type, lane, order, layer: 0, x: 0, y: 0,
      step_id: '', event_id: null, label: '', sub: '', state: '' }, extra || {});
  }

  const spec = (run.data && run.data.spec) || {};
  const runId = 'run:' + (run.id || '');
  add(node(runId, 'run', 'exec', -1, { label: spec.goal || '실행',
    sub: (spec.mode === 'plan' ? '계획 모드' : '반복 모드'), state: run.state || '' }));

  const actionByStep = {};            // step_id → action node id
  const errorByReq = {};              // request_error.data.request_id → reason
  const oobPendingStep = {};          // step_id → true (마커 발급 배지)
  const planBranches = [];            // {action_id, step_id, verdict, next, segment, order}
  let segment = null;                 // 가장 최근 plan 이벤트 id (재개 시 복수, 세그먼트 분리) [C2]
  let order = 0;

  for (const ev of events) {
    const d = ev.data || {};
    const idx = order++;
    switch (ev.kind) {
      case 'action':
        add(node(ev.id, 'action', 'exec', idx, { step_id: ev.step_id || '', event_id: ev.id,
          label: d.kind || 'action', sub: d.hypothesis || '', state: d.kind || '' }));
        if (ev.step_id) actionByStep[ev.step_id] = ev.id;
        break;
      case 'request_started':
        add(node(ev.id, 'request', 'exec', idx, { step_id: ev.step_id || '', event_id: ev.id,
          label: ((d.request && d.request.method) || '') + ' ' + _gPath(d.request && d.request.url),
          state: 'sent' }));
        break;
      case 'observation': {
        const st = d.response && d.response.status;
        add(node(ev.id, 'observation', 'exec', idx, { step_id: ev.step_id || '', event_id: ev.id,
          label: 'HTTP ' + (st == null ? '—' : st),
          sub: (d.analysis && d.analysis.attack_outcome) || '',
          state: _gHttpClass(st, d.response && d.response.truncated),
          requestId: d.request_id || '' }));
        break;
      }
      case 'verification':
        add(node(ev.id, 'verification', 'exec', idx, { step_id: ev.step_id || '', event_id: ev.id,
          label: d.status || '판정', sub: '증거 ' + ((d.evidence_ids || []).length) + '개', state: d.status || '' }));
        break;
      case 'plan': {
        segment = ev.id;
        add(node('plan:' + ev.id, 'plan_root', 'plan', idx, { event_id: ev.id,
          label: '조건부 계획(예정)', sub: 'entry=' + (d.entry || ''), state: 'planned', planSeg: ev.id }));
        for (const step of (d.steps || [])) {
          add(node('plan:' + ev.id + ':' + step.action_id, 'plan_step', 'plan', idx, { event_id: ev.id,
            label: (step.action && step.action.kind) || 'step', sub: (step.action && step.action.hypothesis) || '',
            state: 'planned', planSeg: ev.id, action_id: step.action_id,
            branches: step.branches || [], default_next: step.default_next || '', terminal: false, realized: false }));
        }
        break;
      }
      case 'plan_branch':
        planBranches.push({ action_id: d.action_id, step_id: ev.step_id || '', verdict: d.verdict,
          next: d.next, segment, order: idx });
        break;
      case 'plan_result':
        add(node('planresult:' + ev.id, 'plan_result', 'meta', idx, { event_id: ev.id,
          label: '계획 결과', sub: d.outcome || '', state: '' }));
        break;
      case 'oob':
        add(node(ev.id, 'oob', 'exec', idx, { step_id: ev.step_id || '', event_id: ev.id,
          label: 'OOB 콜백', sub: (d.protocol || (d.data && d.data.protocol) || ''), state: 'oob' }));
        break;
      case 'error':
        add(node(ev.id, 'error', 'meta', idx, { step_id: ev.step_id || '', event_id: ev.id,
          label: '오류', sub: d.reason || '', state: 'error' }));
        break;
      case 'request_error':
        if (d.request_id) errorByReq[d.request_id] = d.reason || '요청 실패';
        break;
      case 'oob_pending':
        if (ev.step_id) oobPendingStep[ev.step_id] = true;
        break;
      default: break;   // session 등 무시
    }
  }

  // request 노드에 실패 주석 반영, action 노드에 OOB 마커 배지
  for (const n of nodes.values()) {
    if (n.type === 'request' && errorByReq[n.id]) { n.state = 'error'; n.sub = errorByReq[n.id]; }
    if (n.type === 'action' && oobPendingStep[n.step_id]) n.oobPending = true;
  }

  const edgeKeys = new Set();
  function edge(source, target, type, via, extra) {
    if (!nodes.has(source)) { warnings.push(type + ': 미해결 source ' + source); return; }
    if (!nodes.has(target)) { warnings.push(type + ': 미해결 target ' + target); return; }
    const key = source + '|' + target + '|' + type;
    if (edgeKeys.has(key)) return;
    edgeKeys.add(key);
    edges.push(Object.assign({ source, target, type, via }, extra || {}));
  }

  // ── Pass B: 실제 링크 기반 간선 ──
  for (const ev of events) {
    const d = ev.data || {};
    if (ev.kind === 'request_started') {
      const a = actionByStep[ev.step_id];
      if (a) edge(a, ev.id, 'action_request', 'step_id');
    } else if (ev.kind === 'observation' && d.request_id) {
      edge(d.request_id, ev.id, 'request_observation', 'request_id');
    } else if (ev.kind === 'verification') {
      for (const eid of (d.evidence_ids || [])) edge(eid, ev.id, 'cited', 'evidence_ids');
    } else if (ev.kind === 'action') {
      for (const bid of (d.basis || [])) edge(bid, ev.id, 'basis', 'basis');
    } else if (ev.kind === 'oob' || ev.kind === 'error') {
      const a = actionByStep[ev.step_id];
      if (a) edge(a, ev.id, 'step_marker', 'step_id');
    }
  }

  // ── 계획 세그먼트별 actual_flow / realized (plan_branch 로만 해결) [C1·C2] ──
  const bySeg = {};
  for (const pb of planBranches) (bySeg[pb.segment] = bySeg[pb.segment] || []).push(pb);
  for (const seg of Object.keys(bySeg)) {
    const execByDsl = {};   // DSL action_id → 실행된 step_id (이 세그먼트)
    for (const pb of bySeg[seg]) if (pb.step_id) execByDsl[pb.action_id] = pb.step_id;
    for (const pb of bySeg[seg]) {
      const srcAction = actionByStep[pb.step_id];
      const planStepId = 'plan:' + seg + ':' + pb.action_id;
      if (srcAction && nodes.has(planStepId)) {
        edge(planStepId, srcAction, 'realized', 'plan_branch', { dashed: true, nonCausal: true });
        nodes.get(planStepId).realized = true;
      }
      if (srcAction && pb.next && pb.next !== '(stop)') {
        const tgtAction = actionByStep[execByDsl[pb.next]];
        if (tgtAction) edge(srcAction, tgtAction, 'actual_flow', 'plan_branch.next');
        else warnings.push('actual_flow 미해결 next=' + pb.next);
      }
    }
  }

  // ── 계획 레인 내부(예정 경로) — 대시, 실행과 구분 ──
  for (const ev of events) {
    if (ev.kind !== 'plan') continue;
    const seg = ev.id, d = ev.data || {};
    if (d.entry) edge('plan:' + seg, 'plan:' + seg + ':' + d.entry, 'plan_entry', 'plan.entry', { dashed: true });
    const taken = new Set((bySeg[seg] || []).map(pb => pb.action_id + '→' + (pb.next || '')));
    for (const step of (d.steps || [])) {
      const from = 'plan:' + seg + ':' + step.action_id;
      const outs = [];
      for (const b of (step.branches || [])) outs.push({ next: b.next, predicate: _gPredText(b.predicate) });
      if (step.default_next) outs.push({ next: step.default_next, predicate: '기본' });
      let hasOut = false;
      for (const o of outs) {
        if (!o.next) continue;                 // STOP
        hasOut = true;
        edge(from, 'plan:' + seg + ':' + o.next, 'planned', 'plan.branches',
          { dashed: true, predicate: o.predicate, taken: taken.has(step.action_id + '→' + o.next) });
      }
      if (!hasOut && nodes.has(from)) nodes.get(from).terminal = true;
    }
  }

  // ── run → 루트 action (basis/actual_flow 유입이 없는 action). 구조적, 시간 아님 ──
  const hasIncoming = new Set(edges.filter(e => e.type === 'basis' || e.type === 'actual_flow').map(e => e.target));
  for (const n of nodes.values()) {
    if (n.type === 'action' && !hasIncoming.has(n.id)) edge(runId, n.id, 'contains', 'run-membership');
  }

  // ── meta 노드(계획 결과·고아 오류)는 run 에 비인과(dim) 연결 [C3·M3] ──
  for (const n of nodes.values()) {
    if (n.lane !== 'meta') continue;
    if (!edges.some(e => e.source === n.id || e.target === n.id)) {
      edge(runId, n.id, 'meta', 'run', { dashed: true, nonCausal: true });
    }
  }

  return { nodes, edges, lanes, warnings };
}

/* ── 2. 레이아웃(순수) — 최장경로 레이어링(위상정렬), 레인별 밴드 ──────────────── */
function layoutGraph(model) {
  const COL_W = 210, ROW_H = 72, PAD = 28, NODE_W = 176, NODE_H = 48;
  const FWD = new Set(['contains', 'action_request', 'request_observation', 'cited', 'basis', 'actual_flow', 'step_marker']);
  model.NODE_W = NODE_W; model.NODE_H = NODE_H;

  function layerBand(ids, yBase) {
    const set = new Set(ids);
    const adj = {}, indeg = {};
    ids.forEach(id => { adj[id] = []; indeg[id] = 0; });
    for (const e of model.edges) if (FWD.has(e.type) && set.has(e.source) && set.has(e.target)) adj[e.source].push(e.target);
    for (const s of ids) for (const t of adj[s]) indeg[t]++;
    const layer = {}, q = [], work = Object.assign({}, indeg);
    ids.forEach(id => { if (!indeg[id]) { layer[id] = 0; q.push(id); } });
    for (let h = 0; h < q.length; h++) {
      const u = q[h];
      for (const v of adj[u]) {
        layer[v] = Math.max(layer[v] || 0, (layer[u] || 0) + 1);
        if (--work[v] === 0) q.push(v);
      }
    }
    const byLayer = {};
    for (const id of ids) {
      const n = model.nodes.get(id);
      n.layer = layer[id] === undefined ? 0 : layer[id];   // 사이클 방어: 미방문은 0
      (byLayer[n.layer] = byLayer[n.layer] || []).push(n);
    }
    let maxRow = 0;
    Object.keys(byLayer).forEach(L => {
      byLayer[L].sort((a, b) => a.order - b.order);
      byLayer[L].forEach((n, row) => { n.x = PAD + Number(L) * COL_W; n.y = yBase + row * ROW_H; });
      maxRow = Math.max(maxRow, byLayer[L].length);
    });
    return yBase + Math.max(1, maxRow) * ROW_H;
  }

  // 계획 레인(예정)을 위 밴드에, 실행 레인을 아래 밴드에, meta 는 그 아래 한 줄.
  let y = PAD;
  if (model.lanes.plan.length) y = layerBand(model.lanes.plan, PAD) + 24;
  const execTop = y;
  const execBottom = layerBand(model.lanes.exec, execTop);
  let metaY = execBottom + 16;
  model.lanes.meta.forEach((id, i) => { const n = model.nodes.get(id); n.x = PAD + i * COL_W; n.y = metaY; });

  // bbox
  let maxX = 0, maxYb = 0;
  for (const n of model.nodes.values()) { maxX = Math.max(maxX, n.x + NODE_W); maxYb = Math.max(maxYb, n.y + NODE_H); }
  model.width = maxX + PAD; model.height = maxYb + PAD;
  model.planBandBottom = model.lanes.plan.length ? execTop - 12 : 0;
  return model;
}

/* ── 3. 렌더(인라인 SVG, createElementNS 만) ───────────────────────────────────
   폴링(2초)마다 호출: 노드 집합이 바뀌면 재레이아웃, 이벤트만 바뀌면 간선/주석만 갱신,
   pan/zoom/선택은 보존. href/src/xlink:href 를 target URL 로 만들지 않는다(클릭 반출 방지)[M2]. */
const SVGNS = 'http://www.w3.org/2000/svg';
let graphView = { runId: null, tx: 0, ty: 0, k: 1, selectedId: null, nodeCount: -1, eventCount: -1 };
let _graphModel = null, _graphRun = null;

function _svg(tag, attrs) {
  const el = document.createElementNS(SVGNS, tag);
  for (const k in (attrs || {})) el.setAttribute(k, attrs[k]);
  return el;
}

function renderAgentGraph(run) {
  _graphRun = run;
  const svg = agentEl('agentGraphSvg');
  if (!svg) return;
  const model = layoutGraph(buildGraphModel(run.events || [], run));
  _graphModel = model;
  const sameRun = graphView.runId === run.id;
  const nodeChanged = model.nodes.size !== graphView.nodeCount;
  graphView.runId = run.id;
  graphView.nodeCount = model.nodes.size;
  graphView.eventCount = (run.events || []).length;

  svg.setAttribute('viewBox', '0 0 ' + Math.max(1, model.width) + ' ' + Math.max(1, model.height));
  svg.replaceChildren();

  // defs: 간선 종류별 화살표 마커(로컬 fragment url(#..) 만)
  const defs = _svg('defs');
  for (const t of ['exec', 'basis', 'actual', 'plan', 'meta']) {
    const m = _svg('marker', { id: 'gm-' + t, viewBox: '0 0 10 10', refX: '9', refY: '5',
      markerWidth: '7', markerHeight: '7', orient: 'auto-start-reverse' });
    m.append(_svg('path', { d: 'M0,0 L10,5 L0,10 z', class: 'gmarker gmarker--' + t }));
    defs.append(m);
  }
  svg.append(defs);

  const vp = _svg('g', { id: 'gViewport' });
  svg.append(vp);

  // 계획 밴드 배경(예정 경로 구분)
  if (model.planBandBottom) {
    vp.append(_svg('rect', { class: 'gband', x: 0, y: 0, width: model.width, height: model.planBandBottom, rx: 8 }));
    const lbl = _svg('text', { class: 'gband-label', x: 10, y: 18 });
    lbl.textContent = '조건부 계획 (예정 경로 · 실행 아님)';
    vp.append(lbl);
  }

  const edgeLayer = _svg('g', { class: 'gedges' });
  const nodeLayer = _svg('g', { class: 'gnodes' });
  vp.append(edgeLayer, nodeLayer);

  for (const e of model.edges) edgeLayer.append(_edgePath(model, e));
  for (const n of model.nodes.values()) nodeLayer.append(_nodeG(n));

  _applyGraphTransform();
  _bindGraphInteractions(svg);
  if (!sameRun) { graphView.selectedId = null; _fitGraph(); }
  if (graphView.selectedId && model.nodes.has(graphView.selectedId)) selectGraphNode(graphView.selectedId, true);
  const warn = agentEl('agentGraphWarn');
  if (warn) { warn.hidden = !model.warnings.length; warn.textContent = model.warnings.length ? ('미해결 링크 ' + model.warnings.length + '개는 생략됨') : ''; }
}

const _EDGE_MARKER = { basis: 'basis', actual_flow: 'actual', planned: 'plan', plan_entry: 'plan', realized: 'plan', meta: 'meta' };
function _edgePath(model, e) {
  const s = model.nodes.get(e.source), t = model.nodes.get(e.target);
  const x1 = s.x + model.NODE_W, y1 = s.y + model.NODE_H / 2, x2 = t.x, y2 = t.y + model.NODE_H / 2;
  const dx = Math.max(30, Math.abs(x2 - x1) / 2);
  const p = _svg('path', {
    class: 'gedge gedge--' + e.type + (e.dashed ? ' gedge--dashed' : '') + (e.taken ? ' gedge--taken' : ''),
    d: 'M' + x1 + ',' + y1 + ' C' + (x1 + dx) + ',' + y1 + ' ' + (x2 - dx) + ',' + y2 + ' ' + x2 + ',' + y2,
    'marker-end': 'url(#gm-' + (_EDGE_MARKER[e.type] || 'exec') + ')',
    fill: 'none',
  });
  const title = _svg('title');
  title.textContent = e.type + (e.predicate ? (' · ' + e.predicate) : '') + ' · via ' + e.via + (e.nonCausal ? ' (비인과)' : '');
  p.append(title);
  return p;
}

function _nodeG(n) {
  const g = _svg('g', { class: 'gnode gnode--' + n.type + ' gstate--' + n.state + (n.realized ? ' gnode--realized' : ''),
    transform: 'translate(' + n.x + ',' + n.y + ')', 'data-node': n.id, tabindex: '0', role: 'button' });
  const label = (n.label || n.type) + (n.sub ? (' · ' + n.sub) : '');
  g.setAttribute('aria-label', label);
  g.append(_svg('rect', { class: 'gnode-box', x: 0, y: 0, width: 176, height: 48, rx: 9 }));
  g.append(_svg('circle', { class: 'gnode-dot', cx: 13, cy: 24, r: 4 }));
  const t1 = _svg('text', { class: 'gnode-label', x: 26, y: 20 });
  t1.textContent = _truncate(n.label || n.type, 20);
  g.append(t1);
  if (n.sub) { const t2 = _svg('text', { class: 'gnode-sub', x: 26, y: 36 }); t2.textContent = _truncate(n.sub, 22); g.append(t2); }
  if (n.oobPending) { const b = _svg('text', { class: 'gnode-badge', x: 168, y: 14, 'text-anchor': 'end' }); b.textContent = 'OOB'; g.append(b); }
  const title = _svg('title'); title.textContent = label; g.append(title);
  g.addEventListener('click', () => selectGraphNode(n.id));
  g.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); selectGraphNode(n.id); } });
  return g;
}

function _truncate(s, n) { s = String(s == null ? '' : s); return s.length > n ? s.slice(0, n - 1) + '…' : s; }

/* ── pan/zoom (라이브러리 없음) ───────────────────────────────────────────────── */
function _applyGraphTransform() {
  const vp = agentEl('agentGraphSvg') && agentEl('agentGraphSvg').querySelector('#gViewport');
  if (vp) vp.setAttribute('transform', 'translate(' + graphView.tx + ',' + graphView.ty + ') scale(' + graphView.k + ')');
}
function _fitGraph() {
  const svg = agentEl('agentGraphSvg'); if (!svg || !_graphModel) return;
  const rect = svg.getBoundingClientRect ? svg.getBoundingClientRect() : { width: 900, height: 520 };
  const w = rect.width || 900, h = rect.height || 520;
  const k = Math.min(1.4, Math.max(0.25, Math.min(w / (_graphModel.width || w), h / (_graphModel.height || h))));
  graphView.k = k; graphView.tx = (w - (_graphModel.width || w) * k) / 2; graphView.ty = 12;
  _applyGraphTransform();
}
function _zoomGraph(factor, cx, cy) {
  const k2 = Math.min(2.5, Math.max(0.25, graphView.k * factor));
  if (cx != null) { graphView.tx = cx - (cx - graphView.tx) * (k2 / graphView.k); graphView.ty = cy - (cy - graphView.ty) * (k2 / graphView.k); }
  graphView.k = k2; _applyGraphTransform();
}
let _graphBound = null;
function _bindGraphInteractions(svg) {
  if (_graphBound === svg) return;      // 재렌더마다 리스너 중복 방지
  _graphBound = svg;
  let drag = null;
  svg.addEventListener('wheel', (e) => {
    e.preventDefault();
    const r = svg.getBoundingClientRect();
    _zoomGraph(e.deltaY < 0 ? 1.12 : 0.89, e.clientX - r.left, e.clientY - r.top);
  }, { passive: false });
  svg.addEventListener('pointerdown', (e) => {
    if (e.target.closest && e.target.closest('.gnode')) return;
    drag = { x: e.clientX, y: e.clientY, tx: graphView.tx, ty: graphView.ty };
    svg.setPointerCapture && svg.setPointerCapture(e.pointerId);
  });
  svg.addEventListener('pointermove', (e) => {
    if (!drag) return;
    graphView.tx = drag.tx + (e.clientX - drag.x); graphView.ty = drag.ty + (e.clientY - drag.y);
    _applyGraphTransform();
  });
  svg.addEventListener('pointerup', () => { drag = null; });
  svg.addEventListener('pointerleave', () => { drag = null; });
}

/* ── 선택 + 증거 상세(로컬 텍스트만) ──────────────────────────────────────────── */
function selectGraphNode(id, keepView) {
  graphView.selectedId = id;
  const svg = agentEl('agentGraphSvg'); if (!svg) return;
  svg.querySelectorAll('.gnode.selected').forEach(el => el.classList.remove('selected'));
  const g = svg.querySelector('.gnode[data-node="' + _cssEscape(id) + '"]');
  if (g) g.classList.add('selected');
  if (!keepView && g && _graphModel && _graphModel.nodes.has(id)) {
    const n = _graphModel.nodes.get(id);
    const r = svg.getBoundingClientRect ? svg.getBoundingClientRect() : { width: 900, height: 520 };
    graphView.tx = (r.width || 900) / 2 - (n.x + 88) * graphView.k;
    graphView.ty = (r.height || 520) / 2 - (n.y + 24) * graphView.k;
    _applyGraphTransform();
  }
  if (_graphModel && _graphModel.nodes.has(id)) showGraphDetail(_graphModel.nodes.get(id), _graphRun);
}

function _detailEl(tag, cls, text) {
  const el = document.createElement(tag);
  if (cls) el.className = cls;
  if (text !== undefined) el.textContent = text;   // 항상 textContent — HTML 실행 금지
  return el;
}
function _evSection(title, data) {
  const s = _detailEl('section', 'aw-graph-ev');
  s.append(_detailEl('h4', '', title));
  const pre = _detailEl('pre'); pre.textContent = typeof data === 'string' ? data : JSON.stringify(data, null, 2);
  s.append(pre); return s;
}
function _chip(label, targetId) {
  const b = _detailEl('button', 'aw-chip', label); b.type = 'button';
  const exists = _graphRun && (_graphRun.events || []).some(e => e.id === targetId);
  if (!exists) { b.disabled = true; b.title = '이벤트를 찾을 수 없습니다'; }
  else b.onclick = () => navigateToEvidence(targetId);
  return b;
}

function showGraphDetail(n, run) {
  const panel = agentEl('agentGraphDetail'); if (!panel) return;
  panel.hidden = false;
  panel.replaceChildren();
  const evById = new Map((run.events || []).map(e => [e.id, e]));
  const head = _detailEl('div', 'aw-graph-detail-head');
  head.append(_detailEl('span', 'aw-badge gstate--' + n.state, n.type));
  head.append(_detailEl('strong', '', n.label || n.type));
  const close = _detailEl('button', 'icon-button', '✕'); close.title = '닫기'; close.setAttribute('aria-label', '상세 닫기');
  close.onclick = () => { panel.hidden = true; };
  head.append(close);
  panel.append(head);

  const d = (n.event_id && evById.get(n.event_id) && evById.get(n.event_id).data) || {};
  if (n.type === 'observation') {
    panel.append(_detailEl('p', 'aw-muted', 'HTTP ' + ((d.response && d.response.status) || '—') + ' · ' + ((d.response && d.response.time_ms) || 0) + 'ms' + ((d.response && d.response.truncated) ? ' · 응답 잘림' : '')));
    panel.append(_evSection('요청', d.request || {}));
    panel.append(_evSection('응답 본문', (d.response && d.response.body) || ''));
    const findings = (d.analysis && d.analysis.findings) || [];
    if (findings.length) { const ul = _detailEl('ul'); for (const f of findings) ul.append(_detailEl('li', '', (f.name || '') + ' · ' + (f.verdict || ''))); panel.append(_detailEl('h4', '', '탐지'), ul); }
  } else if (n.type === 'verification') {
    panel.append(_detailEl('p', 'aw-muted', '판정: ' + (d.status || '')));
    const ul = _detailEl('ul');
    for (const c of (d.confirmed || [])) ul.append(_detailEl('li', '', (c.scope || c.kind || JSON.stringify(c))));
    for (const l of (d.limitations || [])) ul.append(_detailEl('li', 'aw-muted', l));
    if (ul.childNodes.length) panel.append(ul);
    const ids = d.evidence_ids || [];
    if (ids.length) { const wrap = _detailEl('div', 'aw-chips'); wrap.append(_detailEl('span', 'aw-muted', '증거: ')); for (const id of ids) wrap.append(_chip(_gShort(id), id)); panel.append(wrap); }
  } else if (n.type === 'action') {
    panel.append(_detailEl('p', '', d.hypothesis || ''));
    if (d.expected) panel.append(_detailEl('p', 'aw-muted', '기대: ' + d.expected));
    if (d.category || d.param) panel.append(_detailEl('p', 'aw-muted', [d.category, d.location, d.param].filter(Boolean).join(' · ')));
    if (d.payload) panel.append(_evSection('테스트 입력(payload)', d.payload));
    const basis = d.basis || [];
    if (basis.length) { const wrap = _detailEl('div', 'aw-chips'); wrap.append(_detailEl('span', 'aw-muted', '근거: ')); for (const id of basis) wrap.append(_chip(_gShort(id), id)); panel.append(wrap); }
  } else if (n.type === 'request') {
    panel.append(_evSection('요청', d.request || {}));
  } else if (n.type === 'plan_step') {
    panel.append(_detailEl('p', 'aw-muted', '예정 단계 — 실행 사실이 아님'));
    panel.append(_detailEl('p', '', n.sub || ''));
    const ul = _detailEl('ul');
    for (const b of (n.branches || [])) ul.append(_detailEl('li', '', _gPredText(b.predicate) + ' → ' + (b.next || '(종료)')));
    if (n.default_next) ul.append(_detailEl('li', 'aw-muted', '기본 → ' + n.default_next));
    if (ul.childNodes.length) panel.append(_detailEl('h4', '', '분기'), ul);
    panel.append(_detailEl('p', n.realized ? '' : 'aw-muted', n.realized ? '실행됨' : '미실행(예정 경로)'));
  } else {
    panel.append(_evSection('데이터', n.event_id && evById.get(n.event_id) ? d : { label: n.label, sub: n.sub, state: n.state }));
  }
}

function navigateToEvidence(id) {
  if (_graphModel && _graphModel.nodes.has(id)) { selectGraphNode(id); return; }
  // 그래프에 없으면 타임라인에서 해당 이벤트 카드를 연다(폴백)
  if (typeof setDetailMode === 'function') setDetailMode('timeline');
  const card = document.querySelector('.aw-event[data-event="' + _cssEscape(id) + '"]');
  if (card) { card.open = true; card.scrollIntoView({ block: 'center' }); card.classList.add('aw-flash'); setTimeout(() => card.classList.remove('aw-flash'), 1200); }
}

function _cssEscape(s) {
  if (window.CSS && CSS.escape) return CSS.escape(s);
  return String(s).replace(/["\\\]]/g, '\\$&');
}

if (typeof window !== 'undefined') {
  window.buildGraphModel = buildGraphModel;
  window.layoutGraph = layoutGraph;
  window.renderAgentGraph = renderAgentGraph;
  window.selectGraphNode = selectGraphNode;
  window.navigateToEvidence = navigateToEvidence;
}
