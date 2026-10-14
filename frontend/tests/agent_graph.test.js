/* 탐색 그래프 빌더(agent_graph.js) 단위 검증 — node:test + vm, DOM 없이 순수 buildGraphModel 중심.
   간선이 '실제 링크'에서만 나오고 시간 인접으로 인과를 만들지 않음, 계획/실행 구분, 재개 세그먼트,
   고아 처리, 그리고 외부 통신·innerHTML 부재(정적 가드)를 고정한다. */
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const SRC = path.join(__dirname, '..', 'static', 'js', 'agent_graph.js');

class El {
  constructor(tag = 'div') { this.tagName = tag; this.children = []; this.dataset = {}; this.attributes = {}; this.className = ''; this._text = ''; this.hidden = false; this.disabled = false; this.onclick = null; }
  set textContent(v) { this._text = v == null ? '' : String(v); this.children = []; }
  get textContent() { return this._text; }
  set title(v) { this.attributes.title = v; } get title() { return this.attributes.title; }
  append(...n) { for (const x of n) this.children.push(x); }
  replaceChildren(...n) { this.children = [...n]; }
  setAttribute(k, v) { this.attributes[k] = v; } getAttribute(k) { return this.attributes[k]; }
  querySelector() { return null; } querySelectorAll() { return []; }
  get innerHTML() { return undefined; }   // innerHTML 사용 시 즉시 드러나도록
}
function loadCtx() {
  const panel = new El();
  const ctx = vm.createContext({
    URL, JSON, Math, Set, Map, Array, Object, String, Number, console,
    document: { createElement: (t) => new El(t), createElementNS: (_ns, t) => new El(t) },
    agentEl: (id) => (id === 'agentGraphDetail' ? panel : new El()),
    window: { CSS: { escape: (s) => s } },
  });
  vm.runInContext(fs.readFileSync(SRC, 'utf8'), ctx);
  ctx.__panel = panel;
  return ctx;
}
const ctx = loadCtx();
const build = (events, run) => ctx.buildGraphModel(events, run || RUN);
const ev = (id, kind, step_id, data) => ({ id, kind, step_id: step_id || '', data: data || {}, created: 0 });
const RUN = { id: 'R', state: 'completed', data: { spec: { goal: 'g', mode: 'iterative', max_steps: 8 } } };
const etypes = (m) => new Set(m.edges.map(e => e.type));

test('1. canonical chain: nodes, edges by real link, ids == event ids', () => {
  const m = build([
    ev('a1', 'action', 'S1', { kind: 'probe', hypothesis: 'h', basis: [] }),
    ev('r1', 'request_started', 'S1', { request: { method: 'GET', url: 'https://t/x?q=1' } }),
    ev('o1', 'observation', 'S1', { id: 'o1', request_id: 'r1', response: { status: 200 } }),
    ev('v1', 'verification', 'S1', { status: 'suspicious', evidence_ids: ['o1'] }),
  ]);
  assert.equal(m.nodes.size, 5);              // run + a1 + r1 + o1 + v1
  assert.deepEqual(etypes(m), new Set(['contains', 'action_request', 'request_observation', 'cited']));
  assert.equal(m.nodes.get('o1').event_id, 'o1');
  assert.equal(m.edges.find(e => e.type === 'request_observation').via, 'request_id');
});

test('2. basis edge observation -> action (via basis)', () => {
  const m = build([
    ev('a1', 'action', 'S1', { kind: 'observe', basis: [] }),
    ev('o1', 'observation', 'S1', { id: 'o1', request_id: 'r1', response: { status: 200 } }),
    ev('a2', 'action', 'S2', { kind: 'probe', basis: ['o1'] }),
  ]);
  const b = m.edges.filter(e => e.type === 'basis');
  assert.equal(b.length, 1);
  assert.deepEqual([b[0].source, b[0].target, b[0].via], ['o1', 'a2', 'basis']);
});

test('3. no causality from time adjacency (F1 core guard)', () => {
  const m = build([
    ev('a1', 'action', 'S1', { kind: 'probe', basis: [] }),
    ev('x', 'session', '', {}),                // 무관 이벤트, 사이에 끼움
    ev('a2', 'action', 'S2', { kind: 'probe', basis: [] }),
  ]);
  assert.ok(!m.nodes.has('x'));
  assert.ok(!m.edges.some(e => (e.source === 'a1' && e.target === 'a2') || (e.source === 'a2' && e.target === 'a1')));
});

test('4. orphan evidence_ids: no cited edge, no ghost node, recorded in warnings', () => {
  const m = build([ev('v1', 'verification', 'S1', { status: 'inconclusive', evidence_ids: ['ghost'] })]);
  assert.ok(!m.nodes.has('ghost'));
  assert.ok(!m.edges.some(e => e.type === 'cited'));
  assert.ok(m.warnings.some(w => w.includes('ghost')));
});

test('5. plan distinct lane; realized is the only cross-lane edge; predicate+taken on planned', () => {
  const plan = { entry: 'p1', steps: [
    { action_id: 'p1', action: { kind: 'probe', hypothesis: 'h' }, branches: [{ predicate: { kind: 'verdict_in', verdicts: ['suspicious'] }, next: 'p2' }], default_next: '' },
    { action_id: 'p2', action: { kind: 'confirm', hypothesis: 'h2' }, branches: [{ predicate: { kind: 'verdict_in', verdicts: ['confirmed'] }, next: '' }], default_next: '' },
  ] };
  const m = build([
    ev('pl', 'plan', '', plan),
    ev('a1', 'action', 'S1', { kind: 'probe', basis: [] }),
    ev('pb1', 'plan_branch', 'S1', { action_id: 'p1', verdict: 'suspicious', next: 'p2' }),
  ]);
  assert.equal(m.nodes.get('plan:pl').lane, 'plan');
  assert.equal(m.nodes.get('plan:pl:p1').lane, 'plan');
  const planned = m.edges.find(e => e.type === 'planned' && e.source === 'plan:pl:p1' && e.target === 'plan:pl:p2');
  assert.ok(planned && planned.predicate.includes('suspicious') && planned.taken === true);
  const realized = m.edges.filter(e => e.type === 'realized');
  assert.deepEqual([...realized.map(e => e.source + '->' + e.target)], ['plan:pl:p1->a1']);
  assert.ok(!m.edges.some(e => ['basis', 'cited', 'request_observation'].includes(e.type) &&
    (String(e.source).startsWith('plan:') || String(e.target).startsWith('plan:'))));
});

test('6. actual_flow via plan_branch.next; (stop) yields no edge', () => {
  const plan = { entry: 'p1', steps: [
    { action_id: 'p1', action: { kind: 'probe' }, branches: [], default_next: '' },
    { action_id: 'p2', action: { kind: 'confirm' }, branches: [], default_next: '' }] };
  const m = build([
    ev('pl', 'plan', '', plan),
    ev('a1', 'action', 'S1', { kind: 'probe', basis: [] }),
    ev('pb1', 'plan_branch', 'S1', { action_id: 'p1', verdict: 'suspicious', next: 'p2' }),
    ev('a2', 'action', 'S2', { kind: 'confirm', basis: [] }),
    ev('pb2', 'plan_branch', 'S2', { action_id: 'p2', verdict: 'confirmed', next: '(stop)' }),
  ]);
  const af = m.edges.filter(e => e.type === 'actual_flow');
  assert.deepEqual([...af.map(e => e.source + '->' + e.target + ':' + e.via)], ['a1->a2:plan_branch.next']);
});

test('7. unrealized plan step: realized=false, no realized edge', () => {
  const m = build([ev('pl', 'plan', '', { entry: 'p1', steps: [{ action_id: 'p1', action: { kind: 'probe' }, branches: [], default_next: '' }] })]);
  assert.equal(m.nodes.get('plan:pl:p1').realized, false);
  assert.ok(!m.edges.some(e => e.type === 'realized'));
});

test('8. stable ids across rebuild and resume append', () => {
  const base = [ev('a1', 'action', 'S1', { kind: 'observe', basis: [] }), ev('o1', 'observation', 'S1', { id: 'o1', request_id: 'r1', response: { status: 200 } })];
  const ids1 = [...build(base).nodes.keys()];
  const m2 = build(base.concat([ev('a2', 'action', 'S2', { kind: 'probe', basis: ['o1'] })]));
  for (const id of ids1) assert.ok(m2.nodes.has(id), 'prior id kept: ' + id);
});

test('12. resume: realized maps per plan segment (dup action_id across plans)', () => {
  const p = (k) => ({ entry: 'p1', steps: [{ action_id: 'p1', action: { kind: k }, branches: [], default_next: '' }] });
  const m = build([
    ev('plA', 'plan', '', p('probe')),
    ev('aA', 'action', 'SA', { kind: 'probe', basis: [] }),
    ev('pbA', 'plan_branch', 'SA', { action_id: 'p1', verdict: 'x', next: '(stop)' }),
    ev('plB', 'plan', '', p('confirm')),
    ev('aB', 'action', 'SB', { kind: 'confirm', basis: [] }),
    ev('pbB', 'plan_branch', 'SB', { action_id: 'p1', verdict: 'y', next: '(stop)' }),
  ]);
  const r = [...m.edges.filter(e => e.type === 'realized').map(e => e.source + '->' + e.target)].sort();
  assert.deepEqual(r, ['plan:plA:p1->aA', 'plan:plB:p1->aB']);
});

test('13. plan-mode error with empty step_id lands in meta (not dropped), linked to run', () => {
  const m = build([ev('e1', 'error', '', { reason: 'boom' })]);
  assert.ok(m.nodes.has('e1') && m.nodes.get('e1').lane === 'meta');
  assert.ok(m.edges.some(e => e.type === 'meta' && e.target === 'e1'));
});

test('9. evidence detail renders response body as text, never HTML (XSS-safe)', () => {
  const payload = '<script>alert(1)</script>';
  const run = { id: 'R', state: 'running', data: { spec: { goal: 'g' } },
    events: [ev('o1', 'observation', 'S1', { id: 'o1', request_id: 'r1', response: { status: 200, body: payload } })] };
  const node = build(run.events, run).nodes.get('o1');
  ctx.showGraphDetail(node, run);
  const flat = [];
  (function walk(n) { if (!n || typeof n !== 'object') return; flat.push(n); (n.children || []).forEach(walk); })(ctx.__panel);
  const pre = flat.find(n => n.tagName === 'pre' && n._text === payload);
  assert.ok(pre, '응답 본문이 <pre> 텍스트로 들어가야 한다');
  assert.ok(flat.every(n => n.innerHTML === undefined), 'innerHTML 미사용');
});

test('14. loop/self plan branch draws NO actual_flow (planned-only); target keeps run contains', () => {
  const plan = { entry: 'A', steps: [
    { action_id: 'A', action: { kind: 'observe' }, branches: [{ predicate: { kind: 'always' }, next: 'B' }], default_next: '' },
    { action_id: 'B', action: { kind: 'probe' }, branches: [{ predicate: { kind: 'always' }, next: 'A' }], default_next: '' }] };
  const m = build([
    ev('pl', 'plan', '', plan),
    ev('aA', 'action', 'SA', { kind: 'observe', basis: [] }),
    ev('pbA', 'plan_branch', 'SA', { action_id: 'A', verdict: 'x', next: 'B' }),   // 정방향
    ev('aB', 'action', 'SB', { kind: 'probe', basis: [] }),
    ev('pbB', 'plan_branch', 'SB', { action_id: 'B', verdict: 'y', next: 'A' }),   // 되돌이 — A 재실행 안 됨
  ]);
  const af = [...m.edges.filter(e => e.type === 'actual_flow').map(e => e.source + '->' + e.target)];
  assert.deepEqual(af, ['aA->aB']);                                  // 되돌이 B->A 는 미표시
  assert.ok(m.edges.some(e => e.type === 'contains' && e.target === 'aA'));  // 거짓 유입 없어 contains 유지
});

test('15. plan lane layers horizontally (entry→steps across columns)', () => {
  const plan = { entry: 'p1', steps: [
    { action_id: 'p1', action: { kind: 'probe' }, branches: [{ predicate: { kind: 'always' }, next: 'p2' }], default_next: '' },
    { action_id: 'p2', action: { kind: 'confirm' }, branches: [], default_next: '' }] };
  const m = ctx.layoutGraph(build([ev('pl', 'plan', '', plan)]));
  const root = m.nodes.get('plan:pl'), s1 = m.nodes.get('plan:pl:p1'), s2 = m.nodes.get('plan:pl:p2');
  assert.ok(root.layer < s1.layer && s1.layer < s2.layer, '예정 경로가 가로로 레이어링');
  assert.ok(root.x < s1.x && s1.x < s2.x, 'x 가 경로를 따라 증가');
});

test('11. static guard: no egress / innerHTML in agent_graph.js and agent.css', () => {
  const src = fs.readFileSync(SRC, 'utf8');
  assert.ok(!/\bfetch\s*\(/.test(src), 'no fetch');
  assert.ok(!/\bimport\s*\(/.test(src), 'no dynamic import');
  assert.ok(!/\.innerHTML|insertAdjacentHTML|document\.write/.test(src), 'no HTML injection APIs');
  // 외부 호스트 금지 — SVG 네임스페이스(w3.org)만 허용
  assert.ok(!/https?:\/\/(?!www\.w3\.org)/.test(src), 'no external http(s) host');
  assert.ok(/createElementNS/.test(src) && /textContent/.test(src), 'uses safe DOM APIs');
  const css = fs.readFileSync(path.join(__dirname, '..', 'static', 'css', 'agent.css'), 'utf8');
  assert.ok(!/@import|url\(\s*["']?https?:/i.test(css), 'css: no remote @import/url');
  assert.ok(!/https?:\/\//.test(css), 'css: no external URL');
});
