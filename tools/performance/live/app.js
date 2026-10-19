'use strict';
const $ = id => document.getElementById(id);
const text = (tag, value, cls) => { const e=document.createElement(tag); e.textContent=value; if(cls)e.className=cls; return e; };
const number = value => value == null ? 'unknown' : Number(value).toLocaleString(undefined,{maximumFractionDigits:3});
const date = seconds => seconds == null ? 'never' : new Date(seconds*1000).toISOString();
function field(dl, label, value) { dl.append(text('dt',label),text('dd',value)); }
function card(member, windowSeconds) {
  const e=text('article','', 'card');
  e.append(text('h3',member.id),text('p',member.state,member.state));
  const last=member.last;
  e.append(text('div',last?.revision == null ? 'No revision' : `Revision ${number(last.revision)}`,'revision'));
  const dl=document.createElement('dl');
  field(dl,'Last observation',date(last?.observed_at));
  field(dl,'Observation age',member.age_seconds == null ? 'unknown' : `${number(member.age_seconds)} seconds`);
  field(dl,'Finality evidence',last?.authentication || 'unverified');
  field(dl,'Peer connectivity',last?.peer_count == null ? 'unknown' : `${number(last.peer_count)} reported peers (status not authenticated)`);
  field(dl,'Restarts observed',number(member.restarts));
  field(dl,'Last revision change age',member.progress_age_seconds == null ? 'unknown' : `${number(member.progress_age_seconds)} seconds`);
  field(dl,'Block clock offset',last?.block_clock_offset_seconds == null ? 'unknown' : `${number(last.block_clock_offset_seconds)} seconds (not latency)`);
  const intervals=member.revisions.map(r=>r.interval_seconds).filter(v=>v != null);
  field(dl,`Adjacent observed revision intervals · ${windowSeconds}s window`,intervals.length ? `${intervals.length} samples; latest ${number(intervals.at(-1))} seconds` : 'No adjacent samples');
  e.append(dl);
  if(member.revisions.length>1){
    const rows=member.revisions, min=Math.min(...rows.map(r=>r.height)), max=Math.max(...rows.map(r=>r.height));
    const svg=document.createElementNS('http://www.w3.org/2000/svg','svg');
    svg.setAttribute('viewBox','0 0 300 70');svg.setAttribute('role','img');svg.setAttribute('aria-label','Observed revision changes in the sample window; gaps not filled');
    const points=document.createElementNS(svg.namespaceURI,'polyline');
    points.setAttribute('points',rows.map(r=>`${300*(1-r.seconds_ago/windowSeconds)},${65-60*(r.height-min)/Math.max(1,max-min)}`).join(' '));
    svg.append(points);e.append(svg);
  }
  if(member.error)e.append(text('p',member.error,'notice'));
  return e;
}
function render(data){
  $('connection').textContent=`Collector reachable · ${date(data.generated_at)} · ${data.mode}`;
  $('scope').textContent=`Placement: ${data.environment || 'unknown'} (${data.environment_authority || 'recorded benchmark only'}). Sample window: ${number(data.window_seconds)} seconds.`;
  $('members').replaceChildren(...data.members.map(m=>card(m,data.window_seconds)));
  const b=$('benchmark');b.replaceChildren();
  if(data.benchmark){
    const run=data.benchmark;b.append(text('h3',`Benchmark replay · ${run.status}`),text('p',`Not live. Full recorded window: ${number(run.window_seconds)} seconds. ${run.environment}. Not a capacity qualification.`));
    if(run.metrics){
      const table=document.createElement('table');
      for(const [label,key] of [['Client scheduled-to-certified receipt latency (ms)','scheduled_to_certified_receipt_ms'],['Permission read latency (ms)','permission_read_ms'],['Scheduled-to-completed workflow latency (ms)','scheduled_to_workflow_ms'],['Completed workflow rate (/second)','completed_workflows_per_second']]){
        const tr=document.createElement('tr'), value=run.metrics[key];tr.append(text('th',label),text('td',value == null ? 'unavailable' : typeof value==='object' ? Object.entries(value).map(([k,v])=>`${k}: ${number(v)}`).join(' · ') : number(value)));table.append(tr);
      }b.append(table);
    }
  }else b.append(text('p','No benchmark replay loaded.'));
  $('provenance').textContent=JSON.stringify({configuration_sha256:data.configuration_sha256,source_sha256:data.source_sha256,verifier_sha256:data.verifier_sha256,trust_sha256:data.trust_sha256,replay_inputs:data.benchmark?.input_sha256},null,2);
}
async function tick(){
  try{const response=await fetch('/api/status',{cache:'no-store',signal:AbortSignal.timeout(5000)});if(!response.ok)throw Error('collector unavailable');render(await response.json());}
  catch(_){$('connection').textContent='Collector disconnected — displayed observations are historical, not current.';document.querySelectorAll('.connected').forEach(e=>{e.className='disconnected';e.textContent='collector disconnected';});}
  finally{setTimeout(tick,2000);}
}
tick();
