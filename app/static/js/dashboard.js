/* AI SOC Dashboard JavaScript & High-Contrast Visualizers */

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

    // High Contrast Chart Defaults
    Chart.defaults.color = '#000000';
    Chart.defaults.font.family = "'Inter', sans-serif";
    Chart.defaults.font.weight = '700';

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
                                '#b91c1c', // Critical - Dark Red
                                '#c2410c', // High - Dark Orange
                                '#7e22ce', // Medium - Dark Purple
                                '#1d4ed8', // Low - Dark Blue
                                '#475569'  # Info - Slate
                            ],
                            borderWidth: 2,
                            borderColor: '#ffffff'
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {
                            legend: {
                                position: 'bottom',
                                labels: {
                                    boxWidth: 12,
                                    padding: 12,
                                    color: '#000000',
                                    font: { size: 11, weight: '700' }
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
                            backgroundColor: '#1d4ed8',
                            borderColor: '#1e40af',
                            borderWidth: 1,
                            borderRadius: 6
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: { legend: { display: false } },
                        scales: {
                            x: { grid: { display: false }, ticks: { color: '#000000', font: { weight: '700' } } },
                            y: { grid: { color: '#cbd5e1' }, ticks: { color: '#000000', font: { weight: '700' } }, beginAtZero: true }
                        }
                    }
                });
            }

            // 3. Daily Alert Volume (Line Chart)
            if (dailyCanvas) {
                new Chart(dailyCanvas, {
                    type: 'line',
                    data: {
                        labels: data.daily_alerts.labels,
                        datasets: [{
                            label: 'Alert Telemetry',
                            data: data.daily_alerts.data,
                            borderColor: '#15803d',
                            backgroundColor: 'rgba(21, 128, 61, 0.18)',
                            fill: true,
                            tension: 0.35,
                            pointBackgroundColor: '#15803d',
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
                            x: { grid: { color: '#cbd5e1' }, ticks: { color: '#000000', font: { weight: '700' } } },
                            y: { grid: { color: '#cbd5e1' }, ticks: { color: '#000000', font: { weight: '700' } }, beginAtZero: true }
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
                            backgroundColor: '#b91c1c',
                            borderColor: '#991b1b',
                            borderWidth: 1,
                            borderRadius: 6
                        }]
                    },
                    options: {
                        indexAxis: 'y',
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: { legend: { display: false } },
                        scales: {
                            x: { grid: { color: '#cbd5e1' }, ticks: { color: '#000000', font: { weight: '700' } }, beginAtZero: true },
                            y: { grid: { display: false }, ticks: { color: '#000000', font: { weight: '700', family: 'JetBrains Mono' } } }
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
            <div class="spinner-border text-primary mb-3" role="status" style="width: 3rem; height: 3rem;">
                <span class="visually-hidden">Analyzing...</span>
            </div>
            <h5 class="text-dark fw-bold">AI THREAT ENGINE ANALYZING...</h5>
            <p class="text-secondary small font-weight-bold">Interrogating security rules & MITRE ATT&CK database...</p>
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
                    <p class="fs-6 mb-2 text-dark font-weight-bold"><strong>${ai.threat_summary}</strong></p>
                    <p class="text-dark small mb-1 font-weight-bold"><strong>Attack Vector:</strong> ${ai.attack_type}</p>
                    <p class="text-dark small mb-0 font-weight-bold"><strong>MITRE ATT&CK Mapping:</strong> <span class="badge bg-dark text-white font-mono">${ai.mitre_attack}</span></p>
                </div>

                <div class="card bg-white border-secondary mb-3">
                    <div class="card-header bg-light text-dark font-weight-bold small">
                        <i class="fas fa-info-circle me-1"></i> Technical Threat Analysis
                    </div>
                    <div class="card-body small text-dark font-mono font-weight-bold">
                        ${ai.explanation}
                    </div>
                </div>

                <div class="card bg-white border-success">
                    <div class="card-header bg-light text-success font-weight-bold small">
                        <i class="fas fa-shield-halved me-1"></i> Actionable Remediation Steps
                    </div>
                    <div class="card-body small text-dark font-mono font-weight-bold">
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
