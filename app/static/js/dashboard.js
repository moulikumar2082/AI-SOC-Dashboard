/* AI SOC Dashboard JavaScript & Ultra-Visible Cyber Visualizers */

document.addEventListener('DOMContentLoaded', function () {
    // Sidebar Toggle
    const sidebarToggle = document.getElementById('sidebarToggle');
    const sidebar = document.getElementById('sidebar');
    if (sidebarToggle && sidebar) {
        sidebarToggle.addEventListener('click', function () {
            sidebar.classList.toggle('active');
        });
    }

    // Initialize Chart.js Dashboards
    initCharts();
});

function initCharts() {
    const sevCanvas = document.getElementById('severityChart');
    const attackCanvas = document.getElementById('attackChart');
    const dailyCanvas = document.getElementById('dailyChart');
    const topIpCanvas = document.getElementById('topIpChart');

    if (!sevCanvas && !attackCanvas && !dailyCanvas && !topIpCanvas) {
        return; // Not on dashboard page
    }

    // Ultra-Visible Cyber Chart Defaults
    Chart.defaults.color = '#00f2fe';
    Chart.defaults.font.family = "'Orbitron', 'JetBrains Mono', sans-serif";
    Chart.defaults.font.weight = '800';

    fetch('/api/chart-data')
        .then(response => response.json())
        .then(data => {
            // 1. Severity Distribution (Doughnut Chart)
            if (sevCanvas) {
                new Chart(sevCanvas, {
                    type: 'doughnut',
                    data: {
                        labels: data.severity.labels,
                        datasets: [{
                            data: data.severity.data,
                            backgroundColor: [
                                '#ff007f', // Critical - Neon Magenta
                                '#ff9f43', // High - Neon Orange
                                '#c77dff', // Medium - Neon Purple
                                '#00f2fe', // Low - Neon Cyan
                                '#94a3b8'  # Info - Bright Slate
                            ],
                            borderWidth: 2,
                            borderColor: '#040814'
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {
                            legend: {
                                position: 'bottom',
                                labels: {
                                    boxWidth: 14,
                                    padding: 12,
                                    color: '#00f2fe',
                                    font: { family: 'Orbitron', size: 11, weight: '800' }
                                }
                            }
                        },
                        cutout: '68%'
                    }
                });
            }

            // 2. Attack Types (Bar Chart)
            if (attackCanvas) {
                new Chart(attackCanvas, {
                    type: 'bar',
                    data: {
                        labels: data.attack_types.labels,
                        datasets: [{
                            label: 'Vector Count',
                            data: data.attack_types.data,
                            backgroundColor: 'rgba(0, 242, 254, 0.85)',
                            borderColor: '#00f2fe',
                            borderWidth: 2,
                            borderRadius: 4
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: { legend: { display: false } },
                        scales: {
                            x: { grid: { display: false }, ticks: { color: '#ffffff', font: { family: 'Rajdhani', size: 13, weight: '800' } } },
                            y: { grid: { color: 'rgba(0, 242, 254, 0.25)' }, ticks: { color: '#00f2fe', font: { weight: '800' } }, beginAtZero: true }
                        }
                    }
                });
            }

            // 3. Daily Alert Volume (Neon Line Chart)
            if (dailyCanvas) {
                new Chart(dailyCanvas, {
                    type: 'line',
                    data: {
                        labels: data.daily_alerts.labels,
                        datasets: [{
                            label: 'Alert Telemetry',
                            data: data.daily_alerts.data,
                            borderColor: '#05ffa1',
                            backgroundColor: 'rgba(5, 255, 161, 0.25)',
                            fill: true,
                            tension: 0.35,
                            pointBackgroundColor: '#00f2fe',
                            pointBorderColor: '#ffffff',
                            pointRadius: 6,
                            pointHoverRadius: 8
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: { legend: { display: false } },
                        scales: {
                            x: { grid: { color: 'rgba(0, 242, 254, 0.25)' }, ticks: { color: '#ffffff', font: { weight: '800' } } },
                            y: { grid: { color: 'rgba(0, 242, 254, 0.25)' }, ticks: { color: '#00f2fe', font: { weight: '800' } }, beginAtZero: true }
                        }
                    }
                });
            }

            // 4. Top Source IPs (Horizontal Bar Chart)
            if (topIpCanvas) {
                new Chart(topIpCanvas, {
                    type: 'bar',
                    data: {
                        labels: data.top_ips.labels,
                        datasets: [{
                            label: 'Log Count',
                            data: data.top_ips.data,
                            backgroundColor: 'rgba(255, 0, 127, 0.85)',
                            borderColor: '#ff007f',
                            borderWidth: 2,
                            borderRadius: 4
                        }]
                    },
                    options: {
                        indexAxis: 'y',
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: { legend: { display: false } },
                        scales: {
                            x: { grid: { color: 'rgba(0, 242, 254, 0.25)' }, ticks: { color: '#00f2fe', font: { weight: '800' } }, beginAtZero: true },
                            y: { grid: { display: false }, ticks: { color: '#ffffff', font: { family: 'JetBrains Mono', size: 12, weight: '800' } } }
                        }
                    }
                });
            }
        })
        .catch(err => console.error("Failed to load SOC chart statistics:", err));
}

// Trigger AI Threat Analysis Modal Dynamically via AJAX
function triggerAIAnalysis(logId) {
    const modalBody = document.getElementById('aiModalBody');
    if (!modalBody) return;

    modalBody.innerHTML = `
        <div class="text-center py-4">
            <div class="spinner-border text-cyan mb-3" role="status" style="width: 3rem; height: 3rem;">
                <span class="visually-hidden">Analyzing...</span>
            </div>
            <h5 class="text-cyan font-cyber">AI THREAT ENGINE ANALYZING...</h5>
            <p class="text-light small font-weight-bold">Interrogating security rules & MITRE ATT&CK database...</p>
        </div>
    `;

    const myModal = new bootstrap.Modal(document.getElementById('aiAnalysisModal'));
    myModal.show();

    const csrfToken = document.querySelector('meta[name="csrf-token"]').getAttribute('content');

    fetch(`/api/ai-analyze/${logId}?refresh=true`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': csrfToken
        }
    })
    .then(res => res.json())
    .then(res => {
        if (res.status === 'success') {
            const ai = res.analysis;
            let actionsHtml = '';
            if (ai.recommended_actions && ai.recommended_actions.length > 0) {
                actionsHtml = '<ul class="mb-0 ps-3">' + ai.recommended_actions.map(act => `<li class="mb-1">${act}</li>`).join('') + '</ul>';
            } else {
                actionsHtml = '<p class="text-muted mb-0">No immediate remediation required.</p>';
            }

            modalBody.innerHTML = `
                <div class="ai-box mb-3">
                    <div class="ai-header">
                        <i class="fas fa-brain fs-4"></i>
                        <span class="fs-5">AI THREAT INTELLIGENCE SUMMARY</span>
                        <span class="badge bg-danger ms-auto">${ai.threat_level || 'High'}</span>
                    </div>
                    <p class="fs-6 mb-2 text-white font-weight-bold"><strong>${ai.threat_summary}</strong></p>
                    <p class="text-cyan small mb-1 font-weight-bold"><strong>Attack Vector:</strong> ${ai.attack_type}</p>
                    <p class="text-white small mb-0 font-weight-bold"><strong>MITRE ATT&CK Mapping:</strong> <span class="badge bg-dark text-cyan border border-cyan font-mono">${ai.mitre_attack}</span></p>
                </div>

                <div class="card bg-dark border-cyan mb-3">
                    <div class="card-header bg-dark text-cyan font-cyber small">
                        <i class="fas fa-info-circle me-1"></i> Technical Threat Analysis
                    </div>
                    <div class="card-body small text-white font-mono font-weight-bold">
                        ${ai.explanation}
                    </div>
                </div>

                <div class="card bg-dark border-success">
                    <div class="card-header bg-dark text-success font-cyber small">
                        <i class="fas fa-shield-halved me-1"></i> Actionable Remediation Steps
                    </div>
                    <div class="card-body small text-white font-mono font-weight-bold">
                        ${actionsHtml}
                    </div>
                </div>
            `;
        } else {
            modalBody.innerHTML = `<div class="alert alert-danger">Failed to generate AI analysis.</div>`;
        }
    })
    .catch(err => {
        modalBody.innerHTML = `<div class="alert alert-danger">Error reaching AI service API.</div>`;
    });
}
