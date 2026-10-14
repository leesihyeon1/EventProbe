const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const vm=require('node:vm');
const source=fs.readFileSync(path.join(__dirname,'../static/js/agent.js'),'utf8');

function setup() {
  const store={}; let cookie='';
  const document={getElementById:()=>({}), createElement:()=>({}), createTextNode:()=>({}),
    querySelector:()=>null, querySelectorAll:()=>[]};
  Object.defineProperty(document,'cookie',{get(){return cookie;}, set(v){cookie=v;}});
  const ctx=vm.createContext({document, window:{}, console,
    localStorage:{getItem:k=>(k in store?store[k]:null), setItem:(k,v)=>{store[k]=v;}}});
  vm.runInContext(source,ctx);
  return {ctx, store, getCookie:()=>cookie};
}

test('setWorkspaceUser persists to localStorage and a path-wide cookie',()=>{
  const {ctx,store,getCookie}=setup();
  ctx.setWorkspaceUser('alice');
  assert.equal(store['ep-user'],'alice');
  assert(getCookie().startsWith('ep_user=alice;'));
  assert(getCookie().includes('path=/'));
});

test('workspace name is sanitized to a cookie-safe charset (matches what the server reads)',()=>{
  const {ctx,store,getCookie}=setup();
  ctx.setWorkspaceUser('  team a; drop=1  ');
  assert.equal(store['ep-user'],'teamadrop1');       // spaces + separators stripped
  assert(getCookie().startsWith('ep_user=teamadrop1;'));
});

test('clearing the name expires the cookie',()=>{
  const {ctx,store,getCookie}=setup();
  ctx.setWorkspaceUser('bob');
  ctx.setWorkspaceUser('');
  assert.equal(store['ep-user'],'');
  assert(getCookie().includes('max-age=0'));
});
