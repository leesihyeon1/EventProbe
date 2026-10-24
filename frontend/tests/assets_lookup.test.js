const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const vm=require('node:vm');

test('global asset detail opens traffic and findings for the selected asset',()=>{
  const nodes=new Map();
  const node=(tag,text='')=>({tagName:tag,textContent:text,children:[],append(...items){this.children.push(...items);},replaceChildren(...items){this.children=[...items];}});
  const get=id=>{if(!nodes.has(id))nodes.set(id,node('div'));return nodes.get(id);};
  const actions=[];
  const context=vm.createContext({
    agentEl:get,uiNode:(tag,className,text)=>Object.assign(node(tag,text),{className}),siteMapBadge:()=>node('span'),
    uiCommand:(_icon,label,onclick)=>Object.assign(node('button',label),{onclick}),
    document:{createTextNode:text=>node('text',text)},
    setGlobalLookupAssetFilter:(kind,id)=>actions.push([kind,id]),
    switchView:kind=>actions.push(['view',kind]),Date,
  });
  vm.runInContext(fs.readFileSync(path.join(__dirname,'../static/js/assets.js'),'utf8'),context);
  vm.runInContext('assets.global=true',context);
  const id='a'.repeat(64);
  context.showAssetDetail({id,method:'GET',path:'/item',origin:'https://example.test',
    run_count:0,query:[],fields:[],first_seen:1,last_seen:1,runs:[]});
  const links=get('assetDetail').children.find(child=>child.className==='lookup-actions');
  links.children[0].onclick();
  links.children[1].onclick();
  assert.deepEqual(actions,[['traffic',id],['view','traffic'],['findings',id],['view','findings']]);
});

test('focused asset route accepts only a valid identifier',()=>{
  const context=vm.createContext({});
  vm.runInContext(fs.readFileSync(path.join(__dirname,'../static/js/assets.js'),'utf8'),context);
  const id='A'.repeat(64);
  context.setAssetFocus(id);
  assert.equal(context.assetRoute(),'#assets/'+'a'.repeat(64));
  context.setAssetFocus('invalid');
  assert.equal(context.assetRoute(),'#assets');
});

test('global asset dates filter stored traffic and restore from a link',async()=>{
  const nodes=new Map(),calls=[];
  const get=id=>{if(!nodes.has(id))nodes.set(id,{value:'',checked:false,
    replaceChildren(){},append(){},textContent:'',hidden:false});return nodes.get(id);};
  const context=vm.createContext({agentEl:get,URLSearchParams,Date,
    uiNode:()=>({}),drawAssets(){},agentApi:async url=>{
      calls.push(url);return {assets:[],total:0};
    }});
  vm.runInContext(fs.readFileSync(path.join(__dirname,'../static/js/assets.js'),'utf8'),context);
  get('assetFrom').value='2026-10-21';
  get('assetThrough').value='2026-10-22';
  assert.equal(context.assetRoute(),'#assets?from=2026-10-21&through=2026-10-22');
  await context.loadAssetMap();
  const query=new URLSearchParams(calls[0].split('?')[1]);
  assert.equal(Number(query.get('since')),new Date(2026,9,21).getTime()/1000);
  assert.equal(Number(query.get('before')),new Date(2026,9,23).getTime()/1000);
  const count=calls.length;
  get('assetFrom').value='2026-10-24';
  await context.loadAssetMap();
  assert.equal(calls.length,count);
  context.restoreAssetFilters('from=2026-10-21&through=2026-10-22&archived=1');
  assert.equal(context.assetRoute(),'#assets?from=2026-10-21&through=2026-10-22&archived=1');
});


test('asset scope link round trips a selected run and rejects malformed IDs',()=>{
  const nodes=new Map();const get=id=>{if(!nodes.has(id))nodes.set(id,{value:'',checked:false});return nodes.get(id);};
  const context=vm.createContext({agentEl:get,URLSearchParams,Date});
  vm.runInContext(fs.readFileSync(path.join(__dirname,'../static/js/assets.js'),'utf8'),context);
  context.restoreAssetFilters('run=run-123&archived=1');
  assert.equal(get('assetScope').value,'run');
  assert.equal(context.assetRoute(),'#assets?archived=1&run=run-123');
  context.restoreAssetFilters('run=bad%2Fid');
  assert.equal(get('assetScope').value,'all');assert.equal(context.assetRoute(),'#assets');
});

test('asset state contains a real discovered option and a labeled scope selector',()=>{
  const html=fs.readFileSync(path.join(__dirname,'../templates/index.html'),'utf8');
  assert.match(html,/<option value="discovered">발견 · 미요청<\/option>/);
  assert(!html.includes('</option value='));
  assert.match(html,/id="assetScope"/);
});
