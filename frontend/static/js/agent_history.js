/* Cursor-based local event browser. Bodies are fetched only on disclosure. */
let historyState={runId:null,cursor:0,seen:new Set(),hasMore:false,loading:false};
let timelineState={runId:null,cursor:0,seen:new Set(),groups:new Map(),hasMore:false,loading:false};

function initHistory() {
  agentEl('ahRefresh').onclick=()=>loadHistoryPage();
  agentEl('ahMore').onclick=()=>loadHistoryPage();
  agentEl('timelineMore').onclick=()=>loadTimelinePage();
}

function timelineRun() {
  const runId=agentRunId;
  if(timelineState.runId!==runId) {
    timelineState={runId,cursor:0,seen:new Set(),groups:new Map(),hasMore:false,loading:false};
    agentEl('agentEvents').replaceChildren();
    agentEl('timelineMore').hidden=true;
  }
  return runId;
}

function timelineRow(runId,event) {
  const row=uiNode('details','aw-event');row.dataset.event=event.id;
  const labels={action:'실행 계획',request_started:'HTTP 요청',observation:'응답 관측',verification:'검증 판정',error:'오류',conclusion:'결론',discovery:'경로 발견',planner_retry:'재계획'};
  const summary=uiNode('summary','',`${labels[event.kind]||event.kind} · ${new Date(event.created*1000).toLocaleTimeString('ko-KR')} · ${event.id.slice(0,8)}`);
  row.append(summary);
  row.ontoggle=async()=>{
    if(!row.open || row.dataset.loaded) return;
    row.dataset.loaded='loading';
    try {
      const full=await agentApi(`/history/runs/${encodeURIComponent(runId)}/events/${encodeURIComponent(event.id)}`);
      if(timelineState.runId!==runId) return;
      const rendered=renderWorkspaceEvent(full);rendered.open=true;row.replaceWith(rendered);
    } catch(error) {row.dataset.loaded='';row.append(uiNode('p','aw-muted',error.message));}
  };
  return row;
}

async function loadTimelinePage() {
  const runId=timelineRun();
  if(!runId || agentDetailMode!=='timeline' || timelineState.loading) return;
  const state=timelineState;state.loading=true;
  const more=agentEl('timelineMore');more.disabled=true;
  try {
    const page=await agentApi(`/history/runs/${encodeURIComponent(runId)}/events?after=${state.cursor}&limit=50`);
    if(state!==timelineState) return;
    for(const event of page.events) if(!state.seen.has(event.id)) {
      state.seen.add(event.id);
      const key=event.step_id||'run';
      let group=state.groups.get(key);
      if(!group) {
        group=uiNode('section','aw-timeline-step');
        const title=uiNode('h4','',key==='run'?'작업 전체 기록':`검증 단계 ${[...state.groups.keys()].filter(id=>id!=='run').length+1}`);
        if(key!=='run') title.title=`단계 ID: ${key}`;
        const count=uiNode('span','aw-muted','0개 이벤트');
        const rows=uiNode('div','aw-events');
        group.append(title,count,rows);
        group._count=count;group._rows=rows;group._size=0;
        state.groups.set(key,group);agentEl('agentEvents').append(group);
      }
      group._rows.append(timelineRow(runId,event));
      group._count.textContent=`${++group._size}개 이벤트`;
    }
    state.cursor=page.cursor;state.hasMore=page.has_more;
    more.hidden=!page.has_more;
    agentEl('agentEventCount').textContent=`${state.seen.size}개 이벤트 표시`;
  } catch(error) {
    if(state===timelineState) agentEl('agentEventCount').textContent=error.message;
  } finally {state.loading=false;if(state===timelineState) more.disabled=false;}
}

function historyRun() {
  const runId=agentRunId;
  if(historyState.runId!==runId) {
    historyState={runId,cursor:0,seen:new Set(),hasMore:false,loading:false};
    agentEl('ahEvents').replaceChildren();
    agentEl('ahCount').textContent='';
    agentEl('ahMore').hidden=true;
  }
  return runId;
}

function historyRow(runId,event) {
  const row=uiNode('details','aw-event');row.dataset.event=event.id;
  const summary=uiNode('summary');
  const date=new Date(event.created*1000);
  summary.append(epIcon('FileSearch'),uiNode('span','aw-event-title',`${event.kind} · ${date.toLocaleString('ko-KR')} · ${event.id.slice(0,8)}`));
  row.append(summary);
  row.ontoggle=async()=>{
    if(!row.open || row.dataset.loaded) return;
    row.dataset.loaded='loading';
    row.replaceChildren(summary);
    const detail=uiNode('p','aw-muted','불러오는 중');row.append(detail);
    try {
      const full=await agentApi(`/history/runs/${encodeURIComponent(runId)}/events/${encodeURIComponent(event.id)}`);
      if(historyState.runId!==runId) return;
      const rendered=renderWorkspaceEvent(full);rendered.open=true;
      row.replaceWith(rendered);
    } catch(error) {
      row.dataset.loaded='';detail.textContent=error.message;
    }
  };
  return row;
}

async function loadHistoryPage() {
  const runId=historyRun();
  if(!runId || agentDetailMode!=='history' || historyState.loading) return;
  const state=historyState;
  state.loading=true;
  agentEl('ahRefresh').disabled=true;agentEl('ahMore').disabled=true;
  try {
    const page=await agentApi(`/history/runs/${encodeURIComponent(runId)}/events?after=${state.cursor}&limit=50`);
    if(historyState!==state) return;
    for(const event of page.events) {
      if(state.seen.has(event.id)) continue;
      state.seen.add(event.id);
      agentEl('ahEvents').append(historyRow(runId,event));
    }
    state.cursor=page.cursor;state.hasMore=page.has_more;
    agentEl('ahCount').textContent=`${state.seen.size}개 이벤트`;
    agentEl('ahMore').hidden=!page.has_more;
  } catch(error) {
    if(historyState===state) agentEl('ahCount').textContent=error.message;
  } finally {
    state.loading=false;
    if(historyState===state) {agentEl('ahRefresh').disabled=false;agentEl('ahMore').disabled=false;}
  }
}

async function openHistoryEvidence(id) {
  const runId=agentRunId;
  setDetailMode('history');
  historyRun();
  const state=historyState, box=agentEl('ahEvents');
  try {
    const full=await agentApi(`/history/runs/${encodeURIComponent(runId)}/events/${encodeURIComponent(id)}`);
    if(runId!==agentRunId || state!==historyState) return;
    const rendered=renderWorkspaceEvent(full), existing=[...box.children].find(el=>el.dataset.event===id);
    if(existing) existing.replaceWith(rendered); else box.append(rendered);
    state.seen.add(id);
    rendered.open=true;rendered.scrollIntoView({block:'center'});rendered.querySelector('summary')?.focus();
  } catch(error) {
    if(state===historyState) agentEl('ahCount').textContent=error.message;
  }
}
