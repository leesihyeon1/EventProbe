const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const vm=require('node:vm');

class Element {
  constructor(tag='div'){this.tagName=tag;this.children=[];this.value='';this.checked=false;this.textContent='';this.dataset={};}
  append(...children){this.children.push(...children);}
  replaceChildren(...children){this.children=[...children];}
}
const nodes=new Map();
const get=id=>{if(!nodes.has(id))nodes.set(id,new Element());return nodes.get(id);};
const calls=[];
const context=vm.createContext({
  agentEl:get,uiNode:(tag,cls,text)=>{const node=new Element(tag);node.className=cls;node.textContent=text||'';return node;},
  agentApi:async url=>{
    calls.push(url);
    if(url.includes('/events/'))return {data:{request:{body:'PRIVATE_BODY'}}};
    return {items:[{id:'ob1',run_id:'run1',created:1,method:'POST',origin:'https://example.test',
      path:'/login',source:'agent',status:302}],total:1,has_more:false};
  },
  URLSearchParams,Date,setTimeout,clearTimeout,Promise,fetch:async()=>({ok:true,json:async()=>({})}),
  _asJson:async response=>response.json(),openEgressAudit(){},switchView(){},selectRun(){},setDetailMode(){},
});
vm.runInContext(fs.readFileSync(path.join(__dirname,'../static/js/global_lookup.js'),'utf8'),context);

test('traffic list pages metadata and opens raw evidence only on disclosure',async()=>{
  await context.openGlobalLookup('traffic');
  assert.equal(calls.length,1);
  assert.match(calls[0],/history\/traffic/);
  const row=get('globalTrafficRows').children[0];
  assert.equal(row.children[0].children[0].textContent,'POST https://example.test/login');
  const details=row.children[1].children.find(child=>child.tagName==='details');
  details.open=true;
  await details.ontoggle();
  assert.equal(calls.length,2);
  assert.match(calls[1],/history\/runs\/run1\/events\/ob1/);
  assert.match(details.children[1].textContent,/PRIVATE_BODY/);
});

test('form view shows types and states without displaying saved values',()=>{
  context.renderAgentExplore({recon:{form_candidates:[{endpoint_id:'login',login:true,
    source:'html',status:'untested',fields:['user','password'],field_schema:[
      {name:'user',type:'text',required:true},{name:'password',type:'password',required:true}]}]},
    data:{endpoints:{login:{method:'POST',url:'https://example.test/login'}}}});
  const row=get('agentExploreForms').children[0];
  assert.match(row.children[1].textContent,/미검사/);
  assert.match(row.children[2].children[1].textContent,/password · password · 필수/);
  assert(!JSON.stringify(row).includes('PRIVATE_BODY'));
});
