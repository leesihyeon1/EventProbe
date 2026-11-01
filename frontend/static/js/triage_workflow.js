/* Pure presentation/selection helpers; never performs network requests. */
(function(root){
  function overview(result){
    const events=result.events||[];
    const count=key=>events.filter(e=>e.action===key).length;
    const blocked=count('blocked'),allowed=count('allowed'),unknown=count('unknown');
    const paths=new Set(events.map(e=>e.path)).size;
    let conclusion=events.length?`${events.length}개 HTTP 이벤트에서 ${paths}개 경로를 확인했습니다.`:'검증할 HTTP 요청이 없습니다.';
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
  function rows(events){
    const groups=new Map();
    for(const e of events){
      const key=JSON.stringify([e.host,e.destination,e.method,e.path,e.signature,e.action,e.status,e.priority,e.assessment,e.screening]);
      if(!groups.has(key))groups.set(key,{...e,items:[]});groups.get(key).items.push(e);
    }
    return [...groups.values()].sort((a,b)=>(a.assessment?.rank??4)-(b.assessment?.rank??4)||({review:0,information:1,low:2}[a.priority]-{review:0,information:1,low:2}[b.priority]));
  }
  function technologyMatch(event){
    const path=event.path||'';
    const technologies=(event.technologies||[]).join(' ').toLowerCase();
    for(const [pattern,name] of [
      [/^\/wp-(?:admin|content|includes|login\.php)|^\/xmlrpc\.php/i,'wordpress'],
      [/^\/phpmyadmin(?:\/|$)/i,'phpmyadmin'],
      [/^\/_next(?:\/|$)|^\/next\.js(?:\/|$)/i,'next.js'],
      [/^\/actuator(?:\/|$)/i,'spring'],
      [/^\/owa(?:\/|$)|^\/ecp(?:\/|$)/i,'exchange']
    ])if(pattern.test(path)&&technologies.includes(name))return name;
    return '';
  }
  function targets(events,selected,origins){
    const urls=[],links=[],errors=[];
    for(const e of events.filter(e=>selected.has(e.id))){
      if(e.method!=='GET'){errors.push(`${e.line}번: GET 요청만 일괄 연결할 수 있습니다.`);continue;}
      try {
        const origin=new URL(origins[e.host]||inferredOrigin(e)||'');
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
  const api={overview,targets,inferredOrigin,rows,technologyMatch};root.TriageWorkflow=api;
  if(typeof module!=='undefined')module.exports=api;
})(globalThis);
