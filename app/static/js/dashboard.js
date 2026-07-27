/* AI SOC Dashboard JavaScript & Chart.js Visualizers */

document.addEventListener('DOMContentLoaded', function () {
    // Sidebar Toggle
    const sidebarToggle = document.getElementById('sidebarToggle');
    const sidebar = document.getElementById('sidebar');
    if (sidebarToggle && sidebar) {
        sidebarToggle.addEventListener('click', function () {
            sidebar.classList.toggle('active');
        });
    }

    // Initialize Chart.js Dashboards if chart elements exist
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

    // Common Chart Defaults
    Chart.defaults.color = '#94a3b8';
    Chart.defaults.font.family = "'Inter', sans-serif";

    fetch('/api/chart-data')
        .then(response => response.json())
        .then(data => {
            // 1. Severity Distribution (Doughnut)
            if (sevCanvas) {
                new Chart(sevCanvas, {
                    type: 'doughnut',
                    data: {
                        labels: data.severity.labels,
                        datasets: [{
                            data: data.severity.data,
                            backgroundColor: [
                                '#ff4d4d', // Critical
                                '#ff9f43', // High
                                '#a855f7', // Medium
                                '#3b82f6', // Low
                                '#64748b'  # Info
                            ],
                            borderWidth: 2,
                            borderColor: '#141c2e'
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {
                            legend: { position: 'bottom', labels: { boxWidth: 12, padding: 15 } }
                        },
                        cutout: '70%'
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
                            label: 'Incidents Count',
                            data: data.attack_types.data,
                            backgroundColor: 'rgba(0, 242, 254, 0.65)',
                            borderColor: '#00f2fe',
                            borderWidth: 1,
                            borderRadius: 6
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: { legend: { display: false } },
                        scales: {
                            x: { grid: { display: false } },
                            y: { grid: { color: '#1e2d4a' }, beginAtZero: true }
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
                            label: 'Security Alerts',
                            data: data.daily_alerts.data,
                            borderColor: '#4facfe',
                            backgroundColor: 'rgba(79, 172, 254, 0.15)',
                            fill: true,
                            tension: 0.35,
                            pointBackgroundColor: '#00f2fe',
                            pointRadius: 4
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: { legend: { display: false } },
                        scales: {
                            x: { grid: { color: '#1e2d4a' } },
                            y: { grid: { color: '#1e2d4a' }, beginAtZero: true }
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
                            label: 'Log Volume',
                            data: data.top_ips.data,
                            backgroundColor: 'rgba(255, 77, 77, 0.65)',
                            borderColor: '#ff4d4d',
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
                            x: { grid: { color: '#1e2d4a' }, beginAtZero: true },
                            y: { grid: { display: false } }
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
            <div class="spinner-border text-info mb-3" role="status" style="width: 3rem; height: 3rem;">
                <span class="visually-hidden">Analyzing...</span>
            </div>
            <h5 class="text-light">AI Threat Analyzer in Progress...</h5>
            <p class="text-muted">Querying security intelligence rules & MITRE ATT&CK engine...</p>
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
                        <span class="fs-5">AI Threat Summary</span>
                        <span class="badge bg-danger ms-auto">${ai.threat_level || 'High'}</span>
                    </div>
                    <p class="fs-6 mb-2"><strong>${ai.threat_summary}</strong></p>
                    <p class="text-muted small mb-0"><strong>Attack Type:</strong> ${ai.attack_type}</p>
                    <p class="text-muted small mb-0"><strong>MITRE ATT&CK Mapping:</strong> <span class="badge bg-secondary">${ai.mitre_attack}</span></p>
                </div>

                <div class="card bg-dark border-secondary mb-3">
                    <div class="card-header bg-dark text-info font-monospace small">
                        <i class="fas fa-info-circle me-1"></i> Technical Analysis & Root Cause
                    </div>
                    <div class="card-body small text-light">
                        ${ai.explanation}
                    </div>
                </div>

                <div class="card bg-dark border-success">
                    <div class="card-header bg-dark text-success font-monospace small">
                        <i class="fas fa-shield-alt me-1"></i> Recommended Incident Remediation Actions
                    </div>
                    <div class="card-body small text-light">
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
