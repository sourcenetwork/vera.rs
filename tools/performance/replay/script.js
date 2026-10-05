(() => {
  'use strict';
  const data = JSON.parse(document.getElementById('replay-data').textContent);
  const m = data.manifest, c = data.configuration, s = data.summary;
  const get = id => document.getElementById(id);
  const text = (id, value) => { get(id).textContent = value; };
  const numeric = value => typeof value === 'number' && Number.isFinite(value);
  const fmt = (value, digits = 0) => numeric(value) ? value.toLocaleString('en-US', {maximumFractionDigits: digits}) : 'Unknown';
  const shown = value => value === null || value === undefined ? 'Unknown' : String(value);
  const pair = (list, label, value) => {
    const dt = document.createElement('dt'), dd = document.createElement('dd');
    dt.textContent = label; dd.textContent = value; list.append(dt, dd);
  };
  const state = get('status');
  state.className = 'status ' + data.status;
  state.textContent = data.status === 'passed' ? 'Passed recorded workload gates' : data.status === 'failed' ? 'Failed or incomplete workload' : 'Invalid or incomplete evidence';
  text('run-name', shown(c.workload).replaceAll('_', ' '));
  text('run-date', shown(m.measurement_date || m.started_at));
  text('source-short', 'Source ' + (typeof m.source === 'string' ? m.source.slice(0, 12) : 'unknown') + ' · ' + shown(m.history));
  if (data.issue) { get('issue').hidden = false; text('issue', data.issue); }
  text('throughput', fmt(s.completed_workflows_per_second, 2));
  text('offered', fmt(c.arrivals_per_second, 2));
  const p95 = (s.scheduled_to_certified_receipt_ms || {}).p95;
  text('p95', fmt(p95, 2) + (numeric(p95) ? ' ms' : ''));
  text('completed', fmt(s.completed_workflows) + ' / ' + fmt(s.offered));
  text('elapsed', 'Measured workload interval: ' + fmt(s.elapsed_seconds, 2) + (numeric(s.elapsed_seconds) ? ' s' : ''));
  const outcomes = get('outcomes');
  for (const [label, key] of [['Confirmed receipts', 'confirmed'], ['Completed workflows', 'completed_workflows'], ['Not sent', 'not_sent'], ['Unknown outcome', 'unknown'], ['Rejected', 'rejected'], ['Reverted', 'reverted'], ['Confirmed, incomplete workflow', 'confirmed_incomplete_workflows'], ['Verification failures', 'verification_failures']]) pair(outcomes, label, fmt(s[key]));
  const v = data.verification, r = data.recovery;
  function gate(id, evidence, ok, detail) {
    const present = Object.keys(evidence).length > 0;
    text(id + '-status', present ? ok ? 'Passed recorded check' : 'Failed / incomplete' : 'Unknown · not recorded');
    get(id + '-status').className = present ? ok ? 'good' : 'bad' : '';
    text(id + '-detail', present ? detail : 'No evidence available.');
  }
  gate('proof', v, v.verified === c.count && v.unresolved === 0 && v.replicas === c.nodes,
       fmt(v.verified) + ' verified · ' + fmt(v.unresolved) + ' unresolved · ' + fmt(v.replicas) + ' replicas');
  gate('recovery', r, r.inspected_operations === c.count && r.receipt_mismatches === 0 && r.state_mismatches === 0,
       fmt(r.inspected_operations) + ' inspected · ' + fmt(r.receipt_mismatches) + ' receipt / ' + fmt(r.state_mismatches) + ' state mismatches. Restart → probe: ' + fmt(r.restart_to_probe_observed_ms, 2) + (numeric(r.restart_to_probe_observed_ms) ? ' ms.' : '.'));
  const facts = get('provenance');
  for (const [label, value] of [
    ['Node source', m.source], ['Node checkout dirty', m.dirty], ['Workload runner source', m.runner_source], ['Runner checkout dirty', m.runner_dirty],
    ['Node binary SHA256', m.node_sha256], ['Runner binary SHA256', m.runner_sha256],
    ['Node build profile', m.build_profile], ['Runner debug assertions', c.runner_debug_assertions],
    ['Source / binary binding', m.source_binding], ['Backend', m.history], ['Consensus configuration', c.simplex ? JSON.stringify(c.simplex) : null],
    ['CPU', m.cpu_model], ['Logical CPUs', m.logical_cpus], ['Host memory', numeric(m.physical_memory_bytes) ? fmt(m.physical_memory_bytes / 2 ** 30, 2) + ' GiB' : null],
    ['Platform', m.platform], ['Architecture', m.architecture], ['Runner image', m.runner_image],
    ['Recorded run URL', m.run_url], ['Process exit code', m.exit_code]
  ]) pair(facts, label, shown(value));
  text('raw', JSON.stringify({manifest: m, configuration: c, summary: s, verification: v, recovery: r, input_sha256: data.input_sha256}, null, 2));

  const NS = 'http://www.w3.org/2000/svg';
  function svgNode(parent, name, attrs = {}, content = null) {
    const node = document.createElementNS(NS, name);
    Object.entries(attrs).forEach(([key, value]) => node.setAttribute(key, String(value)));
    if (content !== null) node.textContent = content;
    parent.append(node); return node;
  }
  const duration = data.duration || 1;
  function axes(svg, width, height, maximum, time) {
    svg.replaceChildren();
    const left = 42, top = 12, right = width - 12, bottom = height - 24;
    const x = t => left + t / duration * (right - left);
    const y = value => bottom - value / maximum * (bottom - top);
    for (const fraction of [0, .5, 1]) {
      const yy = y(maximum * fraction);
      svgNode(svg, 'line', {x1:left, x2:right, y1:yy, y2:yy, class:'grid'});
      svgNode(svg, 'text', {x:left - 7, y:yy + 3, 'text-anchor':'end'}, fmt(maximum * fraction, 0));
      svgNode(svg, 'text', {x:x(duration * fraction), y:height - 4, 'text-anchor':fraction === 1 ? 'end' : 'start'}, fmt(duration * fraction, 1) + 's');
    }
    svgNode(svg, 'line', {x1:x(time), x2:x(time), y1:top, y2:bottom, class:'cursor'});
    return {x, y};
  }
  const colors = ['#12644c', '#7160a9', '#28728c', '#af7136'];
  const members = data.members.map((member, index) => {
    const card = document.createElement('article'); card.className = 'member';
    const head = document.createElement('div'); head.className = 'member-head';
    const name = document.createElement('b'); name.textContent = 'Member ' + member.index;
    const pid = document.createElement('span'); pid.textContent = 'PID ' + member.pid;
    head.append(name, pid);
    const value = document.createElement('div'); value.className = 'rss';
    const note = document.createElement('div'); note.className = 'sample-note';
    const svg = document.createElementNS(NS, 'svg');
    svg.setAttribute('viewBox', '0 0 260 120'); svg.setAttribute('role', 'img');
    svg.setAttribute('aria-label', 'Member ' + member.index + ' recorded RSS in MiB');
    card.append(head, value, note, svg); get('members').append(card);
    return {member, value, note, svg, color:colors[index % colors.length]};
  });
  if (!members.length) {
    const empty = document.createElement('p'); empty.className = 'empty'; empty.textContent = 'Member memory measurements unavailable.'; get('members').append(empty);
  }
  text('memory-coverage', members.length + ' PID series / ' + fmt(c.nodes) + ' configured members · ' + fmt(data.missing_member_samples) + ' missing samples');
  const rssMax = data.members.reduce((maximum, member) => member.rss_mib.reduce((peak, value) => numeric(value) ? Math.max(peak, value) : peak, maximum), 1) * 1.1;
  const latencyMax = data.events.reduce((maximum, event) => Math.max(maximum, event.latency_ms), 1) * 1.1;
  const scrubber = get('scrubber'); scrubber.max = duration; scrubber.value = duration;
  scrubber.disabled = !data.duration;
  get('play').disabled = !data.duration;
  get('speed').disabled = !data.duration;
  text('untimed', data.timeline_available ? fmt(data.untimed_observations) + ' observations without a receipt time' : 'Receipt timeline unavailable for this schedule');
  get('latency-empty').hidden = data.events.length > 0;
  function draw(time) {
    if (data.status === 'unavailable') {
      text('clock', 'Unknown');
      text('receipts', 'Receipt observation times unknown');
      text('workflows', 'Workflow completion times unknown');
      get('latency').replaceChildren();
      return;
    }
    text('clock', time.toFixed(2) + ' s');
    const observed = data.events.filter(event => event.at <= time);
    text('receipts', observed.length + ' / ' + data.events.length + ' timed receipt observations');
    text('workflows', data.events.filter(event => event.completed_at !== null && event.completed_at <= time).length + ' recorded workflow completion times');
    const {x, y} = axes(get('latency'), 960, 235, latencyMax, time);
    // Bound drawing cost; selected dots are actual observations, never averages.
    const stride = Math.max(1, Math.ceil(data.events.length / 1000));
    observed.filter((_, index) => index % stride === 0).forEach(event => {
      const circle = svgNode(get('latency'), 'circle', {cx:x(event.at), cy:y(event.latency_ms), r:2.5,
        fill:event.outcome === 'confirmed' && event.verification_failure === false && event.error === null ? '#12644c' : '#a23b31', opacity:.7});
      svgNode(circle, 'title', {}, 'Operation ' + event.index + ' · ' + fmt(event.latency_ms, 3) + ' ms · ' + shown(event.outcome));
    });
    get('latency').setAttribute('aria-label', observed.length + ' receipt observations by ' + time.toFixed(2) + ' seconds; at most 1000 actual dots shown, totals use every observation.');
    let sample = -1;
    data.sample_times.forEach((at, index) => { if (at <= time) sample = index; });
    members.forEach(({member, value, note, svg, color}) => {
      const measured = sample >= 0 ? member.rss_mib[sample] : null;
      value.textContent = numeric(measured) ? fmt(measured, 1) + ' MiB' : 'Unknown';
      note.textContent = sample < 0 ? 'No sample yet' : (numeric(measured) ? 'Sample at ' : 'Missing sample at ') + fmt(data.sample_times[sample], 2) + ' s';
      const scale = axes(svg, 260, 120, rssMax, time);
      let segment = [];
      function flush() { if (segment.length) svgNode(svg, 'polyline', {points:segment.join(' '), fill:'none', stroke:color, 'stroke-width':2}); segment = []; }
      member.rss_mib.forEach((rss, index) => {
        if (index > sample || !numeric(rss)) { flush(); return; }
        segment.push(scale.x(data.sample_times[index]) + ',' + scale.y(rss));
        svgNode(svg, 'circle', {cx:scale.x(data.sample_times[index]), cy:scale.y(rss), r:2, fill:color});
      }); flush();
    });
    get('recent').replaceChildren();
    observed.slice(-6).reverse().forEach(event => {
      const row = document.createElement('tr');
      for (const value of ['#' + event.index, fmt(event.at, 3) + ' s', fmt(event.latency_ms, 2) + ' ms', shown(event.outcome)]) {
        const cell = document.createElement('td'); cell.textContent = value; row.append(cell);
      }
      get('recent').append(row);
    });
  }
  let playing = false, frame = null, last = null;
  function pause() { playing = false; if (frame !== null) cancelAnimationFrame(frame); frame = null; last = null; text('play', 'Play replay'); }
  function tick(now) {
    if (!playing) return;
    if (last === null) last = now;
    if (now - last >= 100) {
      const time = Math.min(duration, Number(scrubber.value) + (now - last) / 1000 * Number(get('speed').value));
      last = now; scrubber.value = time; draw(time);
      if (time >= duration) { pause(); return; }
    }
    frame = requestAnimationFrame(tick);
  }
  get('play').addEventListener('click', () => {
    if (playing) { pause(); return; }
    if (Number(scrubber.value) >= duration) scrubber.value = 0;
    playing = true; text('play', 'Pause replay'); draw(Number(scrubber.value)); frame = requestAnimationFrame(tick);
  });
  scrubber.addEventListener('input', () => { pause(); draw(Number(scrubber.value)); });
  document.addEventListener('visibilitychange', () => { if (document.hidden) pause(); });
  draw(Number(scrubber.value));
})();
