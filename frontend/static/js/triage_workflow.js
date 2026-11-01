/* Pure presentation/selection helpers; never performs network requests. */
(function(root){
  function overview(result){
    const events=result.events||[];
    const count=key=>events.filter(e=>e.action===key).length;
    const blocked=count('blocked'),allowed=count('allowed'),unknown=count('unknown');
    const paths=new Set(events.map(e=>e.path)).size;
    let conclusion=events.length?`${events.length}개 이벤트에서 ${paths}개 요청 경로를 확인했습니다.`:'분석할 이벤트가 없습니다.';
    if(events.length&&blocked===events.length)conclusion+=' 모든 이벤트에 장비 차단 기록이 있습니다. 우선 동일 대상의 허용 이벤트와 서비스 이상 여부를 확인하세요.';
    else if(allowed)conclusion+=` 허용 기록 ${allowed}건이 있어 요청 내용과 대상의 실제 응답을 먼저 확인해야 합니다.`;
    else if(unknown)conclusion+=' 차단 여부가 불명인 이벤트는 장비 동작과 응답 기록 보완이 필요합니다.';
    return {blocked,allowed,unknown,paths,conclusion};
  }
  function inferredOrigin(e){
    if((e.reasons||[]).some(r=>['HOST_CONFLICT','HOST_MISSING','PCAP_NOT_INSPECTED'].includes(r)))return '';
    const f=e.fields||{};
    try {
      for(const k of ['url','uri','request','request_uri'])if(/^https?:\/\//i.test(f[k]||''))return new URL(f[k]).origin;
      const port=String(f.dport||f.destination_port||f.dpt||'');
      const scheme=String(f.scheme||f.url_scheme||'').toLowerCase()||({'80':'http','443':'https'}[port]);
      if(!scheme||!e.host)return '';
      const u=new URL(scheme+'://'+e.host);
      if(port&&!u.port&&!['80','443'].includes(port))u.port=port;
      return u.origin;
    }catch{return '';}
  }
  function originKey(e){return e.host||e.destination||`event:${e.id}`;}
  function rows(events){
    const groups=new Map();
    for(const e of events){
      const key=JSON.stringify([e.host,e.destination,e.method,e.path,e.signature,e.action,e.status,e.priority,e.assessment,e.screening]);
      if(!groups.has(key))groups.set(key,{...e,items:[]});groups.get(key).items.push(e);
    }
    return [...groups.values()].sort((a,b)=>(a.assessment?.rank??4)-(b.assessment?.rank??4)||({review:0,information:1,low:2}[a.priority]-{review:0,information:1,low:2}[b.priority]));
  }
  const TECH_PATTERNS=[
    [/^\/wp-(?:admin|content|includes|login\.php)|^\/xmlrpc\.php/i,'wordpress'],
    [/^\/phpmyadmin(?:\/|$)/i,'phpmyadmin'],
    [/^\/_next(?:\/|$)|^\/next\.js(?:\/|$)/i,'next.js'],
    [/^\/actuator(?:\/|$)/i,'spring'],
    [/^\/owa(?:\/|$)|^\/ecp(?:\/|$)/i,'exchange']
  ];
  function impliedTechnology(event){
    const path=event.path||'';
    for(const [pattern,name] of TECH_PATTERNS)if(pattern.test(path))return name;
    return '';
  }
  function technologyMatch(event){
    const technologies=(event.technologies||[]).join(' ').toLowerCase();
    const name=impliedTechnology(event);
    return name&&technologies.includes(name)?name:'';
  }
  function targets(events,selected,origins){
    const urls=[],links=[],errors=[];
    for(const e of events.filter(e=>selected.has(e.id))){
      if(e.method!=='GET'){errors.push(`${e.line}번: GET 요청만 일괄 연결할 수 있습니다.`);continue;}
      try {
        const origin=new URL(origins[originKey(e)]||inferredOrigin(e)||'');
        if(!['http:','https:'].includes(origin.protocol)||origin.username||origin.password||origin.pathname!=='/'||origin.search||origin.hash)throw Error();
        if(!e.path.startsWith('/')||e.path.startsWith('//')||/[\\\x00-\x20]/.test(e.path))throw Error();
        const u=new URL(e.path,origin.origin);
        if(u.origin!==origin.origin||u.hash)throw Error();
        if(!urls.includes(u.href))urls.push(u.href);
        links.push({event_id:e.id,line:e.line,url:u.href,priority:e.priority});
      }catch{errors.push(`${e.line}번: 접속 주소 또는 요청 경로를 확인하세요.`);}
    }
    return {urls,links,errors};
  }
  function technologySummary(events,profiles={}){
    const groups=new Map();
    for(const e of events){
      const key=e.inventory?.origin||e.host||e.destination||'(대상 불명)';
      if(!groups.has(key))groups.set(key,{target:key,hosts:new Set(),destinations:new Set(),records:0,inventory:new Set(),stale:false,profile:profiles[key]||null});
      const g=groups.get(key);g.records++;
      if(e.host)g.hosts.add(e.host);if(e.destination)g.destinations.add(e.destination);
      if(e.inventory?.stack)g.inventory.add(e.inventory.stack);if(e.inventory?.stale)g.stale=true;
    }
    const rows=[...groups.values()].map(g=>({...g,hosts:[...g.hosts].sort(),destinations:[...g.destinations].sort(),inventory:[...g.inventory].sort()}));
    const observed=new Map();
    for(const row of rows)if(row.profile&&!row.profile.error)for(const tech of new Set(row.profile.technologies||[]))observed.set(tech,(observed.get(tech)||0)+1);
    return {rows,targets:rows.length,checked:rows.filter(g=>g.profile&&!g.profile.error).length,failed:rows.filter(g=>g.profile?.error).length,
      identified:rows.filter(g=>!g.profile?.error&&g.profile?.technologies?.length).length,
      technologies:[...observed].map(([label,count])=>({label,count})).sort((a,b)=>b.count-a.count||a.label.localeCompare(b.label))};
  }
  async function probeTargets(events,probe,onProgress=()=>{},stopped=()=>false){
    const origins=[...new Set(events.map(e=>e.inventory?.origin).filter(Boolean))];
    const queue=origins.slice(0,20);let cursor=0,completed=0,failed=0;
    async function worker(){
      while(cursor<queue.length&&!stopped()){
        const origin=queue[cursor++];let profile;
        try{profile=await probe(origin);}catch(error){profile={error:error.message};failed++;}
        completed++;onProgress({origin,profile,completed,total:queue.length,failed});
      }
    }
    await Promise.all([worker(),worker()]);
    return {completed,total:queue.length,failed,deferred:origins.length-queue.length,stopped:stopped()};
  }
  function noiseKind(event){
    const code=event.screening?.code;
    if(code==='IPS_BLOCKED')return 'ips';
    if(['SIMPLE_SCAN_4XX','ORIGIN_NOT_FOUND_SCAN'].includes(code))return 'scan';
    if(code==='TECH_MISMATCH')return 'tech';
    return '';
  }
  function recommended(event){
    return event.action!=='blocked'&&(event.priority==='review'||event.action==='allowed');
  }
  function queue(events,origins={},filters={ips:true,scan:true}){
    const ready=[],excluded=[],unresolved=[];
    for(const e of events){
      const kind=noiseKind(e);
      if(kind&&filters[kind]){excluded.push(e);continue;}
      const target=targets([e],new Set([e.id]),origins);
      if(target.errors.length||!target.urls.length){unresolved.push({...e,queue_reason:e.method!=='GET'?'일괄 연결은 GET 요청만 지원': '접속 주소 또는 경로 확인 필요'});continue;}
      ready.push({...e,verification_url:target.urls[0]});
    }
    return {ready,excluded,unresolved,unique_urls:[...new Set(ready.map(e=>e.verification_url))]};
  }
  const api={overview,targets,inferredOrigin,originKey,rows,technologyMatch,impliedTechnology,technologySummary,probeTargets,noiseKind,queue,recommended};root.TriageWorkflow=api;
  if(typeof module!=='undefined')module.exports=api;
})(globalThis);
