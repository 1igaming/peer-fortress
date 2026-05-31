/**
 * Peer Fortress — Operator Dashboard JavaScript
 * Milestone 3: Read-only local UI consuming CLI JSON output
 *
 * Usage:
 *   1. Run: python -m peer_fortress --json --rpc http://127.0.0.1:18081/json_rpc > report.json
 *   2. Open ui/index.html in browser and click "Load JSON" to load report.json
 *   OR: Click "Refresh" to attempt to fetch from the configured RPC URL (requires CORS or local proxy)
 */

'use strict';

// ── State ──────────────────────────────────────────────────────────────────
let currentReport = null;

// ── Tab routing ────────────────────────────────────────────────────────────
document.querySelectorAll('.nav-item').forEach(el => {
  el.addEventListener('click', e => {
    e.preventDefault();
    const tab = el.dataset.tab;
    switchTab(tab);
  });
});

function switchTab(tabId) {
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
  document.getElementById(`nav-${tabId}`)?.classList.add('active');
  document.getElementById(`tab-${tabId}`)?.classList.add('active');
  document.getElementById('page-title').textContent = {
    overview:  'Overview',
    peers:     'Peer Map',
    spy:       'Spy Audit',
    playbooks: 'Playbooks',
    tor:       'Tor Health',
    raw:       'Raw JSON',
  }[tabId] || tabId;
}

// ── Load from file ─────────────────────────────────────────────────────────
function loadFromFile(event) {
  const file = event.target.files[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = e => {
    try {
      const data = JSON.parse(e.target.result);
      renderReport(data);
    } catch (err) {
      alert('Failed to parse JSON: ' + err.message);
    }
  };
  reader.readAsText(file);
}

// ── Load from RPC (requires no CORS restriction — use local monerod only) ──
async function loadReport() {
  const url = document.getElementById('rpc-url').value.trim();
  if (!url) {
    alert('Enter an RPC URL first (e.g. http://127.0.0.1:18081/json_rpc)');
    return;
  }
  const icon = document.getElementById('refresh-icon');
  icon.style.animation = 'spin 1s linear infinite';
  try {
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 0, method: 'sync_info', params: {} }),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const raw = await res.json();
    // Wrap raw sync_info into diversity analysis (client-side port of Python logic)
    const report = clientSideAnalyze(raw);
    renderReport(report);
  } catch (err) {
    alert(
      'Could not fetch from monerod RPC.\n\n' +
      'TIP: Use the CLI to generate a report JSON file:\n' +
      '  python -m peer_fortress --json --rpc ' + url + ' > report.json\n' +
      'Then click "Load JSON" to open it.\n\n' +
      'Error: ' + err.message
    );
  } finally {
    icon.style.animation = '';
  }
}

// ── Minimal client-side peer analysis (mirrors diversity.py logic) ─────────
function clientSideAnalyze(syncInfo) {
  const peers = (syncInfo?.result?.peers || syncInfo?.peers || []);
  const total = peers.length;

  const buckets = {};
  let onion = 0, clearnet = 0, dups = 0;
  const hostSeen = {};

  peers.forEach(p => {
    const addr = String(p.address || '');
    const host = String(p.host || extractHost(addr));
    if (host in hostSeen) dups++;
    hostSeen[host] = (hostSeen[host] || 0) + 1;

    if (addr.includes('.onion') || host.endsWith('.onion')) {
      onion++;
      buckets['onion'] = (buckets['onion'] || 0) + 1;
    } else {
      clearnet++;
      const bucket = ipv4Bucket(host) || ipv6Bucket(host) || 'unknown';
      if (bucket !== 'unknown') buckets[bucket] = (buckets[bucket] || 0) + 1;
    }
  });

  const uniqueBuckets = Object.keys(buckets).length;
  const maxBucket = Object.entries(buckets).sort((a,b) => b[1]-a[1])[0] || ['n/a', 0];
  const maxShare = total ? maxBucket[1] / total : 0;

  let score = 100;
  const warnings = [];
  if (maxShare > 0.5) { score -= 35; warnings.push(`Over 50% of peers share bucket ${maxBucket[0]} (${pct(maxShare)}).`); }
  else if (maxShare > 0.35) { score -= 20; warnings.push(`Subnet concentration high: ${pct(maxShare)} in ${maxBucket[0]}.`); }
  else if (maxShare > 0.25) score -= 10;

  const spread = total ? uniqueBuckets / total : 0;
  if (spread < 0.3 && total >= 8) { score -= 15; warnings.push(`Low bucket spread (${uniqueBuckets} buckets for ${total} peers).`); }
  if (dups) { score -= Math.min(25, dups * 8); warnings.push(`${dups} duplicate host entries detected.`); }
  if (total < 8) { score -= 10; warnings.push(`Low peer count (${total}) — diversity score less meaningful.`); }

  score = Math.max(0, Math.min(100, Math.round(score)));

  return {
    schema_version: '1.0',
    tool_version: 'ui-client',
    report_type: 'diversity',
    source: 'client-side RPC analysis',
    total_peers: total,
    onion_peers: onion,
    clearnet_peers: clearnet,
    onion_ratio: total ? onion / total : 0,
    unique_buckets: uniqueBuckets,
    max_bucket_share: maxShare,
    max_bucket_label: maxBucket[0],
    duplicate_hosts: dups,
    score,
    grade: grade(score),
    warnings,
    bucket_counts: buckets,
    spy_report: analyzeSpy(syncInfo, buckets, total, clearnet),
  };
}

function extractHost(raw) {
  if (raw.startsWith('[')) {
    const end = raw.indexOf(']');
    if (end !== -1) return raw.slice(1, end);
  }
  const parts = raw.split(':');
  if (parts.length === 2 && /^\d+$/.test(parts[1])) return parts[0];
  return raw;
}

function ipv4Bucket(host) {
  const m = host.match(/^(\d+\.\d+\.\d+)\.\d+$/);
  return m ? m[1] + '.0/24' : null;
}

function ipv6Bucket(host) {
  // Rough /48: first 3 groups
  const m = host.match(/^([0-9a-f]+:[0-9a-f]+:[0-9a-f]+):/i);
  return m ? m[1] + '::/48' : null;
}

function grade(s) {
  if (s >= 80) return 'good';
  if (s >= 60) return 'fair';
  if (s >= 40) return 'weak';
  return 'poor';
}

function pct(r) { return (r * 100).toFixed(0) + '%'; }

function analyzeSpy(syncInfo, buckets, total, clearnetCount) {
  const peers = (syncInfo?.result?.peers || syncInfo?.peers || []);
  const clearPeers = peers.filter(p => !String(p.address || '').includes('.onion'));
  const signals = [];
  const warnings = [];
  let score = 0;

  if (clearPeers.length >= 5) {
    const flagMap = {};
    clearPeers.forEach(p => {
      const f = p.support_flags ?? 0;
      flagMap[f] = (flagMap[f] || 0) + 1;
    });
    const topFlag = Object.entries(flagMap).sort((a,b) => b[1]-a[1])[0];
    if (topFlag) {
      const ratio = topFlag[1] / clearPeers.length;
      if (ratio > 0.8) {
        score += 15;
        signals.push({ type: 'support_flags_concentration', severity: 'medium',
          description: `${pct(ratio)} of clearnet peers share uniform support_flags (${topFlag[0]}).` });
        warnings.push('High uniformity in peer support flags; possible automated sybil cluster.');
      }
    }

    const seeds = clearPeers.map(p => p.pruning_seed || 0).filter(s => s !== 0);
    if (seeds.length) {
      const seedMap = {};
      seeds.forEach(s => { seedMap[s] = (seedMap[s] || 0) + 1; });
      const topSeed = Object.entries(seedMap).sort((a,b) => b[1]-a[1])[0];
      if (topSeed && topSeed[1] > 1 && topSeed[1] / seeds.length > 0.5) {
        score += 20;
        signals.push({ type: 'duplicate_pruning_seeds', severity: 'high',
          description: `Multiple peers sharing identical active pruning seed (${topSeed[0]}).` });
        warnings.push('Identical pruning seeds across distinct P2P addresses; highly suspicious.');
      }
    }
  }

  let sybilClusters = 0;
  Object.entries(buckets).forEach(([bucket, count]) => {
    if (bucket !== 'onion' && count >= 3) {
      score += Math.min(25, count * 5);
      sybilClusters++;
      signals.push({ type: 'subnet_sybil_cluster', severity: 'high',
        description: `Subnet ${bucket} has ${count} active connections.` });
      warnings.push(`Subnet ${bucket} has ${count} active clearnet peer connections (potential sybil group).`);
    }
  });

  if (total >= 10) {
    const onionRatio = (total - clearnetCount) / total;
    if (onionRatio < 0.05) {
      score += 10;
      signals.push({ type: 'clearnet_saturation', severity: 'low',
        description: 'Fewer than 5% of connections are over Tor (.onion).' });
      warnings.push('Extremely low Tor path ratio; node is clearnet-heavy, increasing macro eclipse risks.');
    }
  }

  return {
    spy_saturation_score: Math.max(0, Math.min(100, score)),
    sybil_clusters_detected: sybilClusters,
    warnings,
    signals,
    advisory_only: true,
  };
}

// ── Playbook generator (mirrors playbook.py logic) ─────────────────────────
function generatePlaybooks(report) {
  const books = [];
  const buckets = report.bucket_counts || {};
  const total = report.total_peers || 1;

  Object.entries(buckets).forEach(([bucket, count]) => {
    if (bucket === 'onion') return;
    const share = count / total;
    if (share > 0.35) {
      books.push({
        name: 'Subnet Concentration Remediation',
        trigger: `Bucket ${bucket} holds ${count}/${total} peers (${pct(share)}) — eclipse risk elevated.`,
        severity: share > 0.5 ? 'critical' : 'high',
        steps: [
          { step: 1, action: `Identify which peers occupy subnet ${bucket}.`, rationale: 'Confirm this is not a legitimate Tor exit/relay cluster.', risk: 'low' },
          { step: 2, action: 'Add priority_nodes from diverse /24 subnets.', command: 'monerod --add-priority-node=<diverse_ip>:18080', rationale: 'New priority peers pre-empt slot exhaustion from concentrated subnets.', risk: 'low' },
          { step: 3, action: `Consider banning hosts in ${bucket} if confirmed adversarial.`, command: `# Ban ${bucket} hosts manually after operator review`, rationale: 'Eclipse attacks require all slots controlled; banning breaks monopoly.', risk: 'medium' },
          { step: 4, action: 'Re-run peer-fortress after 30 min to confirm recovery.', command: 'python -m peer_fortress --rpc http://127.0.0.1:18081/json_rpc --report', rationale: 'Verify max_bucket_share has dropped.', risk: 'low' },
        ],
      });
    }
  });

  const spy = report.spy_report || {};
  (spy.signals || []).forEach(sig => {
    if (sig.type === 'duplicate_pruning_seeds') {
      books.push({
        name: 'Sybil Pruning-Seed Flood Remediation',
        trigger: sig.description,
        severity: 'high',
        steps: [
          { step: 1, action: 'List all peer IPs with the duplicate pruning seed from the JSON report.', rationale: 'Build adversarial set to target for rotation.', risk: 'low' },
          { step: 2, action: 'Connect to 3+ trusted priority nodes before banning.', command: 'monerod --add-priority-node=<trusted_node>:18080', rationale: 'Maintain connectivity before evicting suspected sybil cluster.', risk: 'low' },
          { step: 3, action: 'Ban peers sharing the duplicate seed after operator review.', command: '# Add IPs to ban_list in monerod config after review\n# See MRL Issue #1124 / Rucknium research.', rationale: 'Identical non-zero pruning seeds across distinct IPs indicate shared control.', risk: 'medium' },
          { step: 4, action: 'Monitor for 24 hours and report persistent patterns to getmonero.org/forum.', rationale: 'Community awareness enables coordinated defenses.', risk: 'low' },
        ],
      });
    }
  });

  const onionRatio = report.onion_ratio || 0;
  if (total >= 10 && onionRatio < 0.05) {
    books.push({
      name: 'Low Tor Egress Ratio Remediation',
      trigger: `Only ${pct(onionRatio)} of peers are .onion — clearnet exposure is high.`,
      severity: 'medium',
      steps: [
        { step: 1, action: 'Verify monerod is configured with --proxy=127.0.0.1:9050.', command: 'monerod --proxy=127.0.0.1:9050 --anonymous-inbound=<onion>:18083', rationale: 'Without --proxy monerod cannot make outgoing .onion connections.', risk: 'low' },
        { step: 2, action: 'Run --tor-check to verify SOCKS5 proxy reachability.', command: 'python -m peer_fortress --tor-check', rationale: 'A stale/dead Tor process silently drops all .onion connections.', risk: 'low' },
        { step: 3, action: 'Add known-good .onion seed nodes to monerod config.', command: '# add-peer=<onionaddr>.onion:18080  (verify independently)', rationale: 'Bootstrapping the .onion peer pool speeds Tor peer discovery.', risk: 'low' },
      ],
    });
  }

  return books;
}

// ── Render ─────────────────────────────────────────────────────────────────
function renderReport(report) {
  currentReport = report;
  document.getElementById('last-updated').textContent =
    'Updated: ' + new Date().toLocaleTimeString();

  renderOverview(report);
  renderPeerMap(report);
  renderSpyAudit(report);
  renderPlaybooks(report);
  renderRawJson(report);
}

function renderOverview(r) {
  const score = r.score ?? 0;
  const gradeStr = r.grade ?? 'unknown';

  // Score card
  setEl('val-score', score + '/100');
  setEl('val-grade', gradeStr.toUpperCase());
  // Score ring
  const circ = 2 * Math.PI * 50; // 314.16
  const filled = (score / 100) * circ;
  const ring = document.getElementById('ring-fill');
  if (ring) ring.setAttribute('stroke-dasharray', `${filled.toFixed(1)} ${(circ - filled).toFixed(1)}`);

  // Color card by score
  const scoreCard = document.getElementById('card-score');
  scoreCard.style.borderColor = score >= 80 ? 'rgba(34,197,94,0.4)' : score >= 60 ? 'rgba(250,204,21,0.4)' : 'rgba(239,68,68,0.4)';

  setEl('val-total', r.total_peers ?? '—');
  setEl('val-onion', r.onion_peers ?? '—');
  setEl('val-clearnet', r.clearnet_peers ?? '—');
  setEl('val-buckets', r.unique_buckets ?? '—');
  setEl('val-max-share', r.max_bucket_share != null ? pct(r.max_bucket_share) + ' in ' + (r.max_bucket_label || 'n/a') : '—');

  const spy = r.spy_report || {};
  const spyScore = spy.spy_saturation_score ?? 0;
  setEl('val-spy-score', spyScore + '/100');
  setEl('val-sybil-clusters', spy.sybil_clusters_detected ?? 0);
  const spyCard = document.getElementById('card-spy');
  spyCard.style.borderColor = spyScore > 40 ? 'rgba(239,68,68,0.4)' : spyScore > 20 ? 'rgba(250,204,21,0.4)' : 'rgba(34,197,94,0.3)';

  // Warnings
  const wl = document.getElementById('warnings-list');
  wl.innerHTML = '';
  const warns = r.warnings || [];
  if (warns.length === 0) {
    const li = document.createElement('li');
    li.className = 'ok';
    li.textContent = 'No warnings — peer health looks clean.';
    wl.appendChild(li);
  } else {
    warns.forEach(w => {
      const li = document.createElement('li');
      if (w.toLowerCase().includes('over 50%') || w.toLowerCase().includes('duplicate')) li.classList.add('danger');
      li.textContent = w;
      wl.appendChild(li);
    });
  }

  // Bucket bars
  const bb = document.getElementById('bucket-bars');
  bb.innerHTML = '';
  const buckets = r.bucket_counts || {};
  const total = r.total_peers || 1;
  Object.entries(buckets)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 8)
    .forEach(([bucket, count]) => {
      const share = count / total;
      const row = document.createElement('div');
      row.className = 'bucket-row';
      row.innerHTML = `
        <span class="bucket-name" title="${bucket}">${bucket}</span>
        <div class="bucket-bar-wrap">
          <div class="bucket-bar-fill" style="width:${pct(share)}"></div>
        </div>
        <span class="bucket-count">${count}</span>
      `;
      bb.appendChild(row);
    });
  if (Object.keys(buckets).length === 0) bb.innerHTML = '<span class="empty-state">No bucket data.</span>';
}

function renderPeerMap(r) {
  const tbody = document.getElementById('peer-tbody');
  tbody.innerHTML = '';
  const buckets = r.bucket_counts || {};
  const total = r.total_peers || 1;

  if (Object.keys(buckets).length === 0) {
    tbody.innerHTML = '<tr><td colspan="5" class="empty-state">No peer data loaded.</td></tr>';
    return;
  }

  Object.entries(buckets)
    .sort((a, b) => b[1] - a[1])
    .forEach(([bucket, count]) => {
      const share = count / total;
      const riskClass = share > 0.4 ? 'risk-high' : share > 0.25 ? 'risk-medium' : 'risk-low';
      const riskLabel = share > 0.4 ? 'HIGH' : share > 0.25 ? 'MEDIUM' : 'LOW';
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td>${bucket}</td>
        <td>${count}</td>
        <td>${pct(share)}</td>
        <td><span class="risk-badge ${riskClass}">${riskLabel}</span></td>
        <td><div style="background:rgba(255,255,255,0.04);border-radius:4px;height:6px;overflow:hidden">
          <div style="height:100%;width:${pct(share)};background:linear-gradient(90deg,#f97316,#fb923c);border-radius:4px;transition:width .8s"></div>
        </div></td>
      `;
      tbody.appendChild(tr);
    });
}

function renderSpyAudit(r) {
  const spy = r.spy_report || {};
  const signals = spy.signals || [];

  const sigList = document.getElementById('spy-signals');
  sigList.innerHTML = '';
  if (signals.length === 0) {
    sigList.innerHTML = '<p class="empty-state">No spy signals detected — clean!</p>';
  } else {
    signals.forEach(sig => {
      const div = document.createElement('div');
      div.className = `signal-card severity-${sig.severity || 'low'}`;
      div.innerHTML = `
        <div class="signal-type">${sig.type || ''} · ${(sig.severity || 'low').toUpperCase()}</div>
        <div class="signal-desc">${sig.description || ''}</div>
      `;
      sigList.appendChild(div);
    });
  }

  // Summary stats
  const grid = document.getElementById('spy-summary');
  grid.innerHTML = `
    <div class="spy-stat">
      <div class="spy-stat-val" style="color:${(spy.spy_saturation_score||0)>40?'#ef4444':'#22c55e'}">${spy.spy_saturation_score ?? '—'}</div>
      <div class="spy-stat-label">Spy Score / 100</div>
    </div>
    <div class="spy-stat">
      <div class="spy-stat-val">${spy.sybil_clusters_detected ?? '—'}</div>
      <div class="spy-stat-label">Sybil Clusters</div>
    </div>
    <div class="spy-stat">
      <div class="spy-stat-val">${signals.length}</div>
      <div class="spy-stat-label">Total Signals</div>
    </div>
  `;
}

function renderPlaybooks(r) {
  const container = document.getElementById('playbooks-container');
  container.innerHTML = '';
  const books = generatePlaybooks(r);

  if (books.length === 0) {
    container.innerHTML = '<p class="empty-state" style="margin-top:16px">No playbooks triggered — node looks healthy.</p>';
    return;
  }

  books.forEach(book => {
    const card = document.createElement('div');
    card.className = 'playbook-card';
    const sevClass = { critical: 'risk-high', high: 'risk-high', medium: 'risk-medium', low: 'risk-low' }[book.severity] || 'risk-low';
    card.innerHTML = `
      <div class="playbook-header">
        <div>
          <div class="playbook-name">${book.name}</div>
          <div class="playbook-trigger">${book.trigger}</div>
        </div>
        <span class="risk-badge ${sevClass}">${book.severity.toUpperCase()}</span>
      </div>
      <div class="playbook-steps">
        ${(book.steps || []).map(s => `
          <div class="playbook-step">
            <div class="step-num">${s.step}</div>
            <div class="step-body">
              <div class="step-action">${s.action}</div>
              ${s.rationale ? `<div class="step-rationale">${s.rationale}</div>` : ''}
              ${s.command ? `<div class="step-cmd">${escHtml(s.command)}</div>` : ''}
              <div style="margin-top:6px"><span class="risk-badge ${({ low: 'risk-low', medium: 'risk-medium', high: 'risk-high' }[s.risk]||'risk-low')}">${(s.risk||'low').toUpperCase()} RISK</span></div>
            </div>
          </div>
        `).join('')}
      </div>
    `;
    container.appendChild(card);
  });
}

function renderRawJson(r) {
  document.getElementById('raw-json').textContent = JSON.stringify(r, null, 2);
}

function parseTorJson() {
  try {
    const data = JSON.parse(document.getElementById('tor-json-input').value.trim());
    renderTorHealth(data);
  } catch (e) {
    alert('Invalid JSON: ' + e.message);
  }
}

function renderTorHealth(tor) {
  const el = document.getElementById('tor-status-display');
  const reachable = tor.reachable === true;
  el.innerHTML = `
    <div class="tor-row"><span class="tor-key">Status</span><span class="tor-val ${reachable ? 'tor-reachable' : 'tor-unreachable'}">${reachable ? '✔ REACHABLE' : '✖ UNREACHABLE'}</span></div>
    ${tor.host ? `<div class="tor-row"><span class="tor-key">Endpoint</span><span class="tor-val">${tor.host}:${tor.port || 9050}</span></div>` : ''}
    ${tor.latency_ms != null ? `<div class="tor-row"><span class="tor-key">Latency</span><span class="tor-val">${Number(tor.latency_ms).toFixed(1)} ms (handshake)</span></div>` : ''}
    ${tor.error ? `<div class="tor-row"><span class="tor-key">Error</span><span class="tor-val" style="color:#ef4444">${escHtml(String(tor.error))}</span></div>` : ''}
    <div class="tor-row" style="margin-top:14px"><span class="tor-key" style="color:#94a3b8;font-size:12px;width:auto">NOTE: Tor health is a prerequisite for trusting .onion peer ratios. Run diversity report with --expect-tor when monerod uses --proxy.</span></div>
  `;
}

// ── Helpers ────────────────────────────────────────────────────────────────
function setEl(id, value) {
  const el = document.getElementById(id);
  if (el) el.textContent = value;
}

function escHtml(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

// Add spin keyframe for refresh button
const style = document.createElement('style');
style.textContent = '@keyframes spin { to { transform: rotate(360deg); } }';
document.head.appendChild(style);

// ── Load demo fixture on startup ───────────────────────────────────────────
// Try to auto-load a report.json from the same directory if served via HTTP
(async () => {
  try {
    const res = await fetch('./report.json');
    if (res.ok) {
      const data = await res.json();
      renderReport(data);
    }
  } catch (_) {
    // Silent — user will load manually
  }
})();
