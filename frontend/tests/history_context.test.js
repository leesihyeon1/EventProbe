const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');

test('confirmation history links to its request and AI context stays in session/origin', () => {
  const persisted = new Map();
  const tab = new Map();
  let seq = 0;
  const storage = map => ({
    getItem: key => map.has(key) ? map.get(key) : null,
    setItem: (key, value) => map.set(key, String(value)),
    removeItem: key => map.delete(key),
  });
  const context = vm.createContext({
    localStorage: storage(persisted), sessionStorage: storage(tab),
    crypto: { randomUUID: () => `id-${++seq}` }, URL,
    document: { addEventListener() {}, querySelector() { return null; } },
  });
  const code = fs.readFileSync(path.join(__dirname, '..', 'static', 'js', 'app.js'), 'utf8');
  vm.runInContext(code, context);
  const value = vm.runInContext(`(() => {
    const req = {method:'GET', url:'https://target.invalid/private?id=1', headers:{}, params:{}, body:null};
    const result = {_verificationId:'case-1', _req:req, status_code:403,
      analysis:{verdict:'blocked',attack_outcome:'blocked',baseline_check:{valid:true}}};
    state.lastResult = result;
    addHistory(req, result);
    recordConfirmHistory(req, {category:'authbypass',confirmed:true,probes_sent:2,
      techniques:[{name:'보호 자원 확인'}],observations:[]}, true);
    const linked = loadHistory()[0];
    const same = _contextEvents({_verificationId:'case-2',_req:{url:'https://target.invalid/private?id=2'}});
    const other = _contextEvents({_verificationId:'case-3',_req:{url:'https://other.invalid/private'}});
    return {linked, same, other};
  })()`, context);
  assert.equal(value.linked.verification_id, 'case-1');
  assert.equal(value.linked.confirm_runs.length, 1);
  assert.equal(value.linked.confirmed, true);
  assert.equal(value.same.length, 1);
  assert.equal(value.same[0].outcome, 'success');
  assert.equal(value.other.length, 0);
});
