/* Cursor-based local event browser. Bodies are fetched only on disclosure. */
let historyState={runId:null,cursor:0,seen:new Set(),hasMore:false,loading:false};

function initHistory() {
  agentEl('ahRefresh').onclick=()=>loadHistoryPage();
  agentEl('ahMore').onclick=()=>loadHistoryPage();
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
