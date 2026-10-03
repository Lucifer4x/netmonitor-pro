/* NetMonitor Pro - Dashboard JavaScript */
let protoChart = null;

function initChart() {
  const ctx = document.getElementById('protoChart').getContext('2d');
  protoChart = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: ['TCP', 'UDP', 'ICMP', 'ARP', 'DNS'],
      datasets: [{
        label: 'Packets',
        data: [0, 0, 0, 0, 0],
        backgroundColor: ['#06b6d4', '#3b82f6', '#10b981', '#f59e0b', '#a855f7'],
        borderWidth: 0,
        borderRadius: 4
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { grid: { color: 'rgba(255, 255, 255, 0.05)' }, ticks: { color: '#9ca3af' } },
        y: { grid: { color: 'rgba(255, 255, 255, 0.05)' }, ticks: { color: '#9ca3af', stepSize: 5 } }
      }
    }
  });
}

function formatBps(bps) {
  if (bps < 1000) return `${bps.toFixed(0)} bps`;
  if (bps < 1000000) return `${(bps / 1000).toFixed(1)} Kbps`;
  return `${(bps / 1000000).toFixed(1)} Mbps`;
}

async function updateDashboardData() {
  try {
    const [statsRes, pktsRes] = await Promise.all([
      fetch('/api/stats'),
      fetch('/api/packets?count=15')
    ]);
    const stats = await statsRes.json();
    const packets = await pktsRes.json();

    const telem = stats.telemetry || {};
    document.getElementById('stat-pps').innerText = (telem.packets_per_second || 0).toFixed(1);
    document.getElementById('stat-bps').innerText = formatBps(telem.bits_per_second || 0);
    document.getElementById('stat-flows').innerText = telem.active_flows || 0;
    document.getElementById('stat-threats').innerText = (stats.threat_alert_count || 0) + (stats.deauth_alert_count || 0);

    // Protocol Chart Update
    const pdist = telem.protocol_distribution || {};
    if (protoChart) {
      protoChart.data.datasets[0].data = [
        pdist['TCP'] || 0,
        pdist['UDP'] || 0,
        pdist['ICMP'] || 0,
        pdist['ARP'] || 0,
        pdist['DNS'] || 0
      ];
      protoChart.update();
    }

    // Quick Threats List
    const threatsBox = document.getElementById('quick-threats-list');
    const allThreats = [...(stats.threats || []), ...(stats.wifi_alerts || [])];
    if (allThreats.length > 0) {
      threatsBox.innerHTML = allThreats.slice(0, 4).map(t => `
        <div style="background: var(--bg-tertiary); padding: 8px 12px; border-radius: 6px; border-left: 3px solid var(--red-critical);">
          <div style="display: flex; justify-content: space-between; font-weight: 600;">
            <span style="color: #fff;">${t.threat_type || t.frame_type + ' Attack'}</span>
            <span class="badge badge-critical">${t.severity}</span>
          </div>
          <div style="font-size: 0.78rem; color: var(--text-muted); margin-top: 2px;">${t.source_ip || t.target_bssid}</div>
        </div>
      `).join('');
    }

    // Packets Table Update
    const tbody = document.getElementById('packets-tbody');
    const pktList = packets.packets || [];
    if (pktList.length > 0) {
      tbody.innerHTML = pktList.map(p => `
        <tr>
          <td><code>#${p.id}</code></td>
          <td><code>${p.timestamp}</code></td>
          <td><span class="badge badge-${(p.protocol || 'other').toLowerCase()}">${p.protocol}</span></td>
          <td><code>${p.src_ip}</code></td>
          <td><code>${p.dst_ip}</code></td>
          <td>${p.frame_length} B</td>
          <td style="font-family: monospace; font-size: 0.8rem;">${p.info}</td>
        </tr>
      `).join('');
    }
  } catch (err) {
    console.error("Dashboard update error:", err);
  }
}

document.addEventListener('DOMContentLoaded', () => {
  initChart();
  updateDashboardData();
  setInterval(updateDashboardData, 2000);
});
