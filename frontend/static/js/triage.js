/* Session-only triage: untrusted log values are always rendered as text. */
(() => {
  const el = id => document.getElementById(id);
  let result = null, busy = false, analyzedText = null;
  const selected=new Set(), origins={};
  let shownResult=null;
  const labels = {review:'검토 필요',information:'정보 보완',low:'재요청 저우선'};
  const reasons = {DEVICE_BLOCKED:'장비 차단 기록',SIMPLE_NOT_FOUND:'단순 조회 · 404/410',ATTACK_REVIEW:'공격 유형/민감파일 검토',INSUFFICIENT_EVIDENCE:'판단 근거 부족',HOST_CONFLICT:'호스트 불일치',HOST_MISSING:'호스트 없음',PCAP_NOT_INSPECTED:'PCAP 미분석 · 대상 확인 필요',INVENTORY_STALE:'자산 정보 갱신 필요',IMPORTANT_ASSET:'중요 운영 자산',MIXED_ALLOWED_BLOCKED:'같은 시간대 허용·차단 혼재'};
  function node(tag,text,cls) { const n=document.createElement(tag); n.textContent=text; if(cls)n.className=cls; return n; }

  async function triageApi(path, body) {
    return _asJson(await fetch('/api/triage'+path, body===undefined?{}:{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)}),'검증 준비');
  }

  function render() {
    el('triageSummary').replaceChildren(); el('triageResults').replaceChildren();
    el('triageImport').open=!result;
    el('triageAssessment').hidden=!result;el('triageHandoff').hidden=!result;
    if(!result)return;
    if(shownResult!==result){selected.clear();for(const key of Object.keys(origins))delete origins[key];shownResult=result;renderOrigins();for(const e of result.events)if(e.priority==='review'&&e.method==='GET'&&TriageWorkflow.inferredOrigin(e))selected.add(e.id);}
    renderAssessment();updateSelection();
    const s=result.summary;
    for(const [k,title] of Object.entries({records:'입력',parsed:'분석 성공',errors:'분석 실패',unsupported:'HTTP 요청 없음',groups:'대상 묶음',review:'검토 필요',information:'정보 보완',low:'재요청 저우선'})) el('triageSummary').append(node('div',`${title} ${s[k]??0}`));
    const filter=el('triageFilter').value;
    const table=node('table','','triage-table');const head=node('thead','');const tr=node('tr','');
    for(const title of ['검증','대상 / 요청','어떤 이벤트인가','장비 처리 / 응답','분석 판단','로그 수'])tr.append(node('th',title));head.append(tr);table.append(head);
    const body=node('tbody','');
    for(const row of TriageWorkflow.rows(result.events).filter(e=>!filter||e.priority===filter)){
      const line=node('tr','');line.dataset.priority=row.priority;
      const checkCell=node('td','');const check=node('input','');check.type='checkbox';check.disabled=row.method!=='GET';check.checked=row.items.every(e=>selected.has(e.id));check.indeterminate=!check.checked&&row.items.some(e=>selected.has(e.id));check.setAttribute('aria-label',`${row.host} ${row.path} 검증 선택`);
      check.onchange=()=>{for(const e of row.items){if(check.checked)selected.add(e.id);else selected.delete(e.id);}updateSelection();};checkCell.append(check);
      const target=node('td','');target.append(node('strong',row.host||'대상 확인 필요'),node('div',`${row.method} ${row.path}`,'triage-path'));
      const origin=TriageWorkflow.inferredOrigin(row);target.append(node('small',origin?`접속 주소: ${origin} (로그 기준)`:'접속 주소 확인 필요'));
      const detail=node('details','');detail.append(node('summary','원문과 상세 근거'));detail.append(node('pre',JSON.stringify(row.items,null,2)));target.append(detail);
      const attack=node('td',row.signature||row.category||'탐지명 없음');
      const outcome=node('td',`${({blocked:'차단',allowed:'허용',unknown:'불명'})[row.action]||'불명'} / ${row.status??'응답 코드 없음'}`);
      const decision=node('td','');decision.append(node('strong',labels[row.priority]));
      const why=row.priority==='low'?(row.action==='blocked'?'장비가 차단한 기록입니다. 기본 검증 대상에서 제외합니다.':'단순 미존재 조회로 재요청 우선순위가 낮습니다.'):row.priority==='review'?'공격 징후 또는 중요 자산 관련 이벤트입니다. 응답과 재현 여부를 검증하세요.':'성공·차단 판단 근거가 부족합니다. 장비/응답 정보를 확인하세요.';
      decision.append(node('p',why),node('small',row.reasons.map(r=>reasons[r]||r).join(' · ')));
      const latest=row.items.find(e=>e.latest_verification)?.latest_verification;if(latest)decision.append(node('p',`검증 응답: ${latest.statuses.map(c=>c||'무응답').join(', ')}`,'triage-verification'));
      line.append(checkCell,target,attack,outcome,decision,node('td',String(row.items.length)));body.append(line);
    }
    table.append(body);const wrap=node('div','','triage-table-wrap');wrap.append(table);el('triageResults').append(wrap);
    if(result.unsupported?.length) {
      const skipped=node('details','');skipped.append(node('summary',`HTTP 요청이 없어 검증에서 제외한 레코드 ${result.unsupported.length}건`));
      for(const e of result.unsupported)skipped.append(node('p',`${e.line}번: ${e.reason}`));
      el('triageResults').append(skipped);
    }
    if(result.errors.length) {
      const errors=node('details','');errors.append(node('summary',`분석하지 못한 레코드 ${result.errors.length}건`));
      for(const e of result.errors)errors.append(node('p',`${e.line}번: ${e.reason}`));
      el('triageResults').append(errors);
    }
  }

  function updateSelection(){el('triageSelectedCount').textContent=`검증할 로그 ${selected.size}건 선택 (같은 URL은 1회 전달)`;el('triageSendBulk').disabled=!selected.size;}
  function renderOrigins(){
    el('triageOrigins').replaceChildren();
    for(const host of new Set(result.events.filter(e=>e.method==='GET'&&!TriageWorkflow.inferredOrigin(e)).map(e=>e.host))){
      const label=node('label',`${host||'대상 불명'} → 실제 접속 주소`);
      const input=node('input','');input.type='url';input.placeholder='https://example.com (프로토콜·포트 확인)';input.setAttribute('aria-label',`${host} 접속 주소`);
      input.oninput=()=>{origins[host]=input.value.trim();};label.append(input);el('triageOrigins').append(label);
    }
  }
  window.addEventListener('triage-bulk-complete',event=>{
    if(!result)return;
    for(const link of event.detail.source.events){
      const item=result.events.find(e=>e.id===link.event_id);const target=event.detail.targets.find(t=>t.url===link.url);
      if(item&&target)item.latest_verification={at:new Date().toISOString(),url:link.url,statuses:(target.results||[]).map(r=>r.status_code||0)};
    }
    render();
  });
  function campaignPanel(){
    const scan=result.scan_analysis;const panel=node('section','','triage-campaigns');
    panel.append(node('h2','대량 탐색 행위와 대응 우선순위'));
    if(!scan){panel.append(node('p','최신 로그 분석을 실행하면 스캔 행위를 묶어 확인할 수 있습니다.'));return panel;}
    if(!scan.campaigns.length)panel.append(node('p','현재 입력에서 설정 기준을 넘는 대량 탐색 묶음은 없습니다. 탐지가 없다는 것이 정상 통신을 의미하지는 않습니다.'));
    for(const c of scan.campaigns){
      const card=node('article','','triage-assessment');
      card.append(node('h3',`${c.axis==='target'?'대상':'출발지'} ${c.entity} · ${c.signals.join(' / ')}`));
      card.append(node('p',`${new Date(Number(c.window)*900000).toLocaleString()}부터 15분 · 로그 ${c.record_count} · 경로 ${c.path_count} · 출발지 ${c.source_count} · 자산 ${c.host_count}`));
      card.append(node('p',`차단 ${c.actions.blocked||0} / 허용 ${c.actions.allowed||0} / 불명 ${c.actions.unknown||0}`));
      card.append(node('p',c.response));
      const button=node('button',`대표 검증 후보 ${c.representative_ids.length}건 선택`,'btn btn-primary');button.disabled=!c.representative_ids.length;
      button.onclick=()=>{selected.clear();for(const id of c.representative_ids)selected.add(id);el('triageFilter').value='';render();el('triageHandoff').scrollIntoView({block:'start'});};card.append(button);
      const details=node('details','');details.append(node('summary','판단 기준과 한계'),node('p',c.ai_attribution+' · '+scan.limitations));card.append(details);panel.append(card);
    }
    panel.append(node('p',`시간 정보가 부족해 시간대 상관분석에서 제외된 이벤트 ${scan.unknown_time_events}건. 출발지와 대상 묶음은 중복될 수 있습니다.`));
    return panel;
  }
  function renderAssessment(){
    const box=el('triageAssessment');box.replaceChildren();const o=TriageWorkflow.overview(result);
    box.append(campaignPanel());
    box.append(node('h2','이벤트 요약'),node('p',o.conclusion,'triage-conclusion'));
    const actions=node('div','','triage-recommendations');
    for(const [title,body] of [
      ['먼저 확인',`${result.summary.review}건의 검토 필요 이벤트를 우선 확인하세요. 허용·차단 혼재와 중요 자산은 상세 근거를 확인합니다.`],
      ['보완할 근거',`${result.summary.information}건은 정보 보완이 필요합니다. 상태 코드·장비 동작·자산 소유자와 실제 접속 주소를 확인하세요.`],
      ['재검증 줄이기',`${result.summary.low}건은 재요청 저우선입니다. 차단 기록을 검토하고 필요한 예외만 선택하세요. 저우선은 안전 판정이 아닙니다.`]
    ]){const item=node('div','');item.append(node('h3',title),node('p',body));actions.append(item);}
    const verified=result.events.filter(e=>e.latest_verification);
    if(verified.length)box.append(node('p',`선택 검증 결과가 연결된 이벤트 ${verified.length}건. 이벤트 상세의 최신 응답 코드와 일괄 테스트 결과를 함께 확인하세요.`));
    box.append(actions,node('p',`장비 기록: 차단 ${o.blocked} · 허용 ${o.allowed} · 불명 ${o.unknown} / HTTP 요청 없는 로그 ${result.summary.unsupported||0}건은 별도 확인`));
  }
  el('triageSelectReview').onclick=()=>{for(const e of result?.events||[])if(e.priority==='review'&&e.method==='GET')selected.add(e.id);render();};
  el('triageSelectNone').onclick=()=>{selected.clear();render();};
  el('triageSendBulk').onclick=()=>{
    const transfer=TriageWorkflow.targets(result.events,selected,origins);
    if(transfer.errors.length){el('triageHandoffStatus').textContent=transfer.errors.join(' / ');return;}
    if(!transfer.urls.length)return;
    if(!state.payloads){el('triageHandoffStatus').textContent='일괄 테스트 구성을 불러오는 중입니다. 잠시 후 다시 시도하세요.';return;}
    switchView('bulk');switchModalTab('multi');switchMultiPayloadMode('custom');
    el('multiUrls').value=transfer.urls.join('\n');el('multiMethod').value='GET';el('multiCustomPayloads').value='';el('multiTargetParam').value='';el('multiInjectIn').value='params';el('multiConcurrency').value='1';
    window.triageBulkContext={events:transfer.links,urls:transfer.urls,created:new Date().toISOString()};
    let banner=el('triageBulkBanner');if(!banner){banner=node('section','','triage-assessment');banner.id='triageBulkBanner';el('mtab-multi').prepend(banner);}
    banner.replaceChildren(node('h3',`이벤트 분석에서 선택한 ${transfer.links.length}건 → URL ${transfer.urls.length}개`),node('p','기본 준비는 GET 단순 요청 · 동시 1개입니다. 기존 요청 헤더와 기본 헤더 설정을 확인한 뒤 아래 테스트 시작 버튼을 누르세요. 요청 재현은 과거 침해 성공을 확정하지 않습니다.'));
    const back=node('button','이벤트 판단으로 돌아가기','btn btn-secondary');back.onclick=()=>switchView('triage');banner.append(back);
    banner.scrollIntoView({block:'start'});
  };

  async function loadLogFiles(files) {
    if(busy){el('triageStatus').textContent='현재 작업이 끝난 뒤 파일을 넣어주세요.';return;}
    if(!files?.length)return;
    if(files.length!==1){el('triageStatus').textContent='로그 파일은 한 번에 1개씩 넣어주세요.';return;}
    const file=files[0];
    if(file.size>2000000){el('triageStatus').textContent='파일이 너무 큽니다. 2MB 이하 파일을 넣어주세요.';return;}
    if(!/\.(csv|log|txt|json|jsonl|ndjson)$/i.test(file.name)){el('triageStatus').textContent='CSV, LOG, TXT, JSON, JSONL, NDJSON 파일을 넣어주세요.';return;}
    busy=true;el('triageAnalyze').disabled=true;el('triageFile').disabled=true;
    try {
      const text=await file.text();
      if(!text.trim())throw new Error('빈 파일입니다. 로그가 포함된 파일을 넣어주세요.');
      el('triageInput').value=text;
      result=null;analyzedText=null;selected.clear();
      el('triageSave').disabled=true;el('triageExport').disabled=true;
      render();el('triageImport').open=true;
      el('triageStatus').textContent=`${file.name} 불러오기 완료 · ‘로그 분석’을 눌러 시작하세요.`;
    }catch(error){el('triageStatus').textContent='파일을 불러오지 못했습니다. '+error.message;}
    finally{busy=false;el('triageAnalyze').disabled=false;el('triageFile').disabled=false;el('triageFile').value='';}
  }
  el('triageFile').onchange=ev=>loadLogFiles(ev.target.files);
  const dropArea=el('triageImport');let dragDepth=0;
  const isFileDrag=ev=>Array.from(ev.dataTransfer?.types||[]).includes('Files');
  dropArea.addEventListener('dragenter',ev=>{
    if(!isFileDrag(ev))return;ev.preventDefault();dragDepth++;
    dropArea.open=true;dropArea.classList.add('triage-drag-active');
  });
  dropArea.addEventListener('dragover',ev=>{
    if(!isFileDrag(ev))return;ev.preventDefault();ev.dataTransfer.dropEffect=busy?'none':'copy';
  });
  dropArea.addEventListener('dragleave',ev=>{
    if(!isFileDrag(ev))return;dragDepth=Math.max(0,dragDepth-1);
    if(!dragDepth)dropArea.classList.remove('triage-drag-active');
  });
  dropArea.addEventListener('drop',ev=>{
    if(!isFileDrag(ev))return;ev.preventDefault();ev.stopPropagation();dragDepth=0;
    dropArea.classList.remove('triage-drag-active');loadLogFiles(ev.dataTransfer.files);
  });
  el('triageAnalyze').onclick=async()=>{
    if(busy)return; busy=true; el('triageAnalyze').disabled=true;
    el('triageExport').disabled=true;el('triageSave').disabled=true;analyzedText=null; result=null;render();
    el('triageStatus').textContent='로그 분석 중…';
    try {
      const text=el('triageInput').value;
      if(new TextEncoder().encode(text).length>2000000)throw new Error('입력은 2MB 이하로 제한됩니다.');
      const response=await fetch('/api/triage/analyze',{method:'POST',headers:{'Content-Type':'text/plain; charset=utf-8'},body:text});
      result=await _asJson(response,'로그 분석');analyzedText=text;el('triageSave').disabled=false; render(); el('triageExport').disabled=false;
      el('triageStatus').textContent='분석 완료 · 대상 요청 0건 · 저우선은 안전 판정이 아닙니다. 이벤트 상세에서 자산 대조와 선택 검증을 준비할 수 있습니다.';
    } catch(e) {el('triageStatus').textContent=e.message;}
    finally {busy=false;el('triageAnalyze').disabled=false;}
  };

  async function textPost(path,text) {
    if(new TextEncoder().encode(text).length>2000000)throw new Error('입력은 2MB 이하로 제한됩니다.');
    return _asJson(await fetch('/api/triage'+path,{method:'POST',headers:{'Content-Type':'text/plain; charset=utf-8'},body:text}),'기록 관리');
  }
  async function refreshHistory() {
    const r=await triageApi('/batches');el('triageHistory').replaceChildren();
    if(!r.batches.length)el('triageHistory').append(node('p','저장 기록이 없습니다.'));
    for(const b of r.batches) {
      const row=node('p',`${new Date(b.created*1000).toLocaleString()} · ${b.summary.records}건 · 만료 ${new Date(b.expires*1000).toLocaleString()} `);
      const load=node('button','불러오기','btn btn-secondary');
      load.onclick=async()=>{if(busy)return;busy=true;try{result=await triageApi('/batches/'+b.id);analyzedText=null;el('triageSave').disabled=true;el('triageExport').disabled=false;render();el('triageStatus').textContent='저장 당시 분석 결과를 불러왔습니다. 현재 인벤토리와 다를 수 있습니다.';}catch(err){el('triageStatus').textContent=err.message;}finally{busy=false;}};
      const del=node('button','삭제','btn btn-secondary');del.onclick=async()=>{if(!confirm('이 기록의 원문과 분석 결과를 삭제할까요?'))return;try{await _asJson(await fetch('/api/triage/batches/'+b.id,{method:'DELETE'}),'삭제');await refreshHistory();}catch(err){el('triageStatus').textContent=err.message;}};
      row.append(load,del);el('triageHistory').append(row);
    }
  }
  el('triageSave').onclick=async()=>{
    if(analyzedText===null||busy)return;const button=el('triageSave');button.disabled=true;
    try{const saved=await textPost('/batches?days='+encodeURIComponent(el('triageRetention').value),analyzedText);el('triageStatus').textContent=saved.duplicate?'같은 원문이 이미 저장되어 있습니다. 보존 기한은 연장하지 않았습니다.':`저장 완료 · 기존 기록과 겹치는 이벤트 ${saved.overlap_events}건 (원본은 유지)`;await refreshHistory();}catch(err){el('triageStatus').textContent=err.message;}finally{button.disabled=analyzedText===null;}
  };
  async function refreshInventory() {
    const r=await triageApi('/inventory');el('triageInventoryList').replaceChildren();
    if(!r.assets.length)el('triageInventoryList').append(node('p','등록한 운영 자산이 없습니다.'));
    for(const a of r.assets) {
      const row=node('p',`${a.origin} · ${a.service} · ${a.importance} · 확인 ${new Date(a.verified_at*1000).toLocaleString()} `);
      const del=node('button','삭제','btn btn-secondary');del.onclick=async()=>{if(!confirm('이 자산 정보를 삭제할까요?'))return;try{await _asJson(await fetch('/api/triage/inventory?origin='+encodeURIComponent(a.origin),{method:'DELETE'}),'자산 삭제');await refreshInventory();}catch(err){el('triageStatus').textContent=err.message;}};
      row.append(del);el('triageInventoryList').append(row);
    }
  }
  el('triageHistoryRefresh').onclick=()=>refreshHistory().catch(err=>{el('triageStatus').textContent=err.message;});
  el('triageInventoryRefresh').onclick=()=>refreshInventory().catch(err=>{el('triageStatus').textContent=err.message;});
  el('triageInventoryImport').onclick=async()=>{const button=el('triageInventoryImport');button.disabled=true;try{const r=await textPost('/inventory',el('triageInventoryInput').value);el('triageStatus').textContent=`자산 ${r.imported}건 반영. 로그를 다시 분석하면 최신 정보를 적용합니다.`;await refreshInventory();}catch(err){el('triageStatus').textContent=err.message;}finally{button.disabled=false;}};

  el('triageFilter').onchange=render;
  el('triageClear').onclick=()=>{if(busy)return;result=null;analyzedText=null;el('triageSave').disabled=true;el('triageInput').value='';el('triageFile').value='';el('triageStatus').textContent='';el('triageExport').disabled=true;render();};
  el('triageExport').onclick=()=>{
    if(!result)return;
    const url=URL.createObjectURL(new Blob([JSON.stringify(result,null,2)],{type:'application/json'}));
    const a=node('a','');a.href=url;a.download='event-analysis.json';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);
  };
})();
