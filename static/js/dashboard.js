/**
 * Dashboard JavaScript for Insider Threat Detection
 * Handles real-time monitoring, charts, and threat visualization
 */

// Global variables
let threatTrendChart = null;
let severityChart = null;
let realTimeChart = null;
let autoRefreshInterval = null;
let isAutoRefresh = false;
let websocket = null;

// Initialize dashboard on page load
document.addEventListener('DOMContentLoaded', function() {
    initializeDashboard();
    setupWebSocket();
    startPeriodicUpdates();
});

/**
 * Initialize the dashboard
 */
function initializeDashboard() {
    console.log('Initializing dashboard...');
    
    // Initialize charts
    initializeCharts();
    
    // Setup event listeners
    setupEventListeners();
    
    // Load initial data
    loadInitialData();
    
    // Setup auto-refresh controls
    setupAutoRefresh();
}

/**
 * Initialize all charts
 */
function initializeCharts() {
    initializeThreatTrendChart();
    initializeSeverityChart();
    initializeRealTimeChart();
}

/**
 * Initialize threat trend chart
 */
function initializeThreatTrendChart() {
    const ctx = document.getElementById('threatTrendChart');
    if (!ctx) return;
    
    threatTrendChart = new Chart(ctx.getContext('2d'), {
        type: 'line',
        data: {
            labels: [],
            datasets: [{
                label: 'Threat Detections',
                data: [],
                borderColor: 'rgb(255, 99, 132)',
                backgroundColor: 'rgba(255, 99, 132, 0.1)',
                borderWidth: 2,
                fill: true,
                tension: 0.4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                title: {
                    display: true,
                    text: 'Threat Detection Trend'
                },
                legend: {
                    display: true,
                    position: 'top'
                }
            },
            scales: {
                x: {
                    title: {
                        display: true,
                        text: 'Time'
                    }
                },
                y: {
                    title: {
                        display: true,
                        text: 'Number of Threats'
                    },
                    beginAtZero: true
                }
            },
            interaction: {
                intersect: false,
                mode: 'index'
            }
        }
    });
}

/**
 * Initialize severity distribution chart
 */
function initializeSeverityChart() {
    const ctx = document.getElementById('severityChart');
    if (!ctx) return;
    
    severityChart = new Chart(ctx.getContext('2d'), {
        type: 'doughnut',
        data: {
            labels: ['Critical', 'High', 'Medium', 'Low'],
            datasets: [{
                data: [0, 0, 0, 0],
                backgroundColor: [
                    '#dc3545', // Critical - Red
                    '#fd7e14', // High - Orange
                    '#ffc107', // Medium - Yellow
                    '#6c757d'  // Low - Gray
                ],
                borderWidth: 2,
                borderColor: '#fff'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                title: {
                    display: true,
                    text: 'Alert Severity Distribution'
                },
                legend: {
                    display: true,
                    position: 'bottom'
                },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            const total = context.dataset.data.reduce((a, b) => a + b, 0);
                            const percentage = total > 0 ? ((context.parsed / total) * 100).toFixed(1) : 0;
                            return `${context.label}: ${context.parsed} (${percentage}%)`;
                        }
                    }
                }
            }
        }
    });
}

/**
 * Initialize real-time activity chart
 */
function initializeRealTimeChart() {
    const ctx = document.getElementById('realTimeChart');
    if (!ctx) return;
    
    realTimeChart = new Chart(ctx.getContext('2d'), {
        type: 'bar',
        data: {
            labels: [],
            datasets: [{
                label: 'Events per Minute',
                data: [],
                backgroundColor: 'rgba(54, 162, 235, 0.6)',
                borderColor: 'rgba(54, 162, 235, 1)',
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                title: {
                    display: true,
                    text: 'Real-time Activity'
                }
            },
            scales: {
                x: {
                    title: {
                        display: true,
                        text: 'Time'
                    }
                },
                y: {
                    title: {
                        display: true,
                        text: 'Events'
                    },
                    beginAtZero: true
                }
            }
        }
    });
}

/**
 * Setup event listeners
 */
function setupEventListeners() {
    // Auto-refresh toggle
    const autoRefreshBtn = document.getElementById('autoRefreshBtn');
    if (autoRefreshBtn) {
        autoRefreshBtn.addEventListener('click', toggleAutoRefresh);
    }
    
    // Clear events button
    const clearEventsBtn = document.getElementById('clearEventsBtn');
    if (clearEventsBtn) {
        clearEventsBtn.addEventListener('click', clearEventFeed);
    }
    
    // Refresh button
    const refreshBtn = document.getElementById('refreshBtn');
    if (refreshBtn) {
        refreshBtn.addEventListener('click', refreshDashboard);
    }
    
    // Export button
    const exportBtn = document.getElementById('exportBtn');
    if (exportBtn) {
        exportBtn.addEventListener('click', exportDashboardData);
    }
}

/**
 * Setup WebSocket connection for real-time updates
 */
function setupWebSocket() {
    try {
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${protocol}//${window.location.host}/ws/dashboard`;
        
        websocket = new WebSocket(wsUrl);
        
        websocket.onopen = function(event) {
            console.log('WebSocket connected');
            updateConnectionStatus('connected');
        };
        
        websocket.onmessage = function(event) {
            const data = JSON.parse(event.data);
            handleWebSocketMessage(data);
        };
        
        websocket.onclose = function(event) {
            console.log('WebSocket disconnected');
            updateConnectionStatus('disconnected');
            
            // Attempt to reconnect after 5 seconds
            setTimeout(setupWebSocket, 5000);
        };
        
        websocket.onerror = function(error) {
            console.error('WebSocket error:', error);
            updateConnectionStatus('error');
        };
    } catch (error) {
        console.error('WebSocket setup failed:', error);
        updateConnectionStatus('error');
    }
}

/**
 * Handle WebSocket messages
 */
function handleWebSocketMessage(data) {
    switch (data.type) {
        case 'threat_detected':
            handleThreatDetection(data.payload);
            break;
        case 'stats_update':
            updateDashboardStats(data.payload);
            break;
        case 'alert_generated':
            handleNewAlert(data.payload);
            break;
        case 'model_update':
            updateModelStatus(data.payload);
            break;
        default:
            console.log('Unknown WebSocket message type:', data.type);
    }
}

/**
 * Handle threat detection event
 */
function handleThreatDetection(threat) {
    // Add to real-time feed
    addToEventFeed(threat);
    
    // Update charts
    updateThreatTrendChart(threat);
    updateSeverityChart(threat);
    
    // Update counters
    incrementThreatCounter(threat.severity);
    
    // Show notification for high-severity threats
    if (threat.severity === 'critical' || threat.severity === 'high') {
        showThreatNotification(threat);
    }
}

/**
 * Add event to real-time feed
 */
function addToEventFeed(event) {
    const eventFeed = document.getElementById('eventFeed');
    if (!eventFeed) return;
    
    const eventElement = document.createElement('div');
    eventElement.className = `alert alert-${getSeverityClass(event.severity)} border-start border-3 mb-2`;
    
    // Create DOM elements safely without innerHTML
    const container = document.createElement('div');
    container.className = 'd-flex justify-content-between align-items-start';
    
    // Left side content
    const leftDiv = document.createElement('div');
    
    const userStrong = document.createElement('strong');
    userStrong.textContent = event.user || 'Unknown User';
    leftDiv.appendChild(userStrong);
    
    const eventTypeSpan = document.createElement('span');
    eventTypeSpan.className = 'badge bg-info ms-2';
    eventTypeSpan.textContent = event.event_type || 'Unknown';
    leftDiv.appendChild(eventTypeSpan);
    
    leftDiv.appendChild(document.createElement('br'));
    
    const timestampSmall = document.createElement('small');
    timestampSmall.className = 'text-muted';
    timestampSmall.textContent = formatTimestamp(event.timestamp);
    leftDiv.appendChild(timestampSmall);
    
    leftDiv.appendChild(document.createElement('br'));
    
    const descriptionSmall = document.createElement('small');
    descriptionSmall.textContent = event.description || 'No description available';
    leftDiv.appendChild(descriptionSmall);
    
    // Right side content
    const rightDiv = document.createElement('div');
    rightDiv.className = 'text-end';
    
    const severitySpan = document.createElement('span');
    severitySpan.className = `badge bg-${getSeverityClass(event.severity)}`;
    severitySpan.textContent = event.severity;
    rightDiv.appendChild(severitySpan);
    
    rightDiv.appendChild(document.createElement('br'));
    
    const scoreSmall = document.createElement('small');
    scoreSmall.className = `fw-bold text-${getThreatScoreClass(event.threat_score)}`;
    scoreSmall.textContent = event.threat_score ? event.threat_score.toFixed(3) : 'N/A';
    rightDiv.appendChild(scoreSmall);
    
    // Assemble the complete structure
    container.appendChild(leftDiv);
    container.appendChild(rightDiv);
    eventElement.appendChild(container);
    
    // Add to top of feed
    eventFeed.insertBefore(eventElement, eventFeed.firstChild);
    
    // Remove old events (keep only last 50)
    while (eventFeed.children.length > 50) {
        eventFeed.removeChild(eventFeed.lastChild);
    }
    
    // Auto-scroll to top
    eventFeed.scrollTop = 0;
}

/**
 * Update threat trend chart
 */
function updateThreatTrendChart(threat) {
    if (!threatTrendChart) return;
    
    const now = new Date();
    const timeLabel = now.toLocaleTimeString();
    
    // Add new data point
    threatTrendChart.data.labels.push(timeLabel);
    threatTrendChart.data.datasets[0].data.push(1);
    
    // Keep only last 20 data points
    if (threatTrendChart.data.labels.length > 20) {
        threatTrendChart.data.labels.shift();
        threatTrendChart.data.datasets[0].data.shift();
    }
    
    threatTrendChart.update('none');
}

/**
 * Update severity chart
 */
function updateSeverityChart(threat) {
    if (!severityChart) return;
    
    const severityIndex = getSeverityIndex(threat.severity);
    if (severityIndex >= 0) {
        severityChart.data.datasets[0].data[severityIndex]++;
        severityChart.update('none');
    }
}

/**
 * Update dashboard statistics
 */
function updateDashboardStats(stats) {
    updateCounter('totalEvents', stats.total_events);
    updateCounter('threatsDetected', stats.threats_detected);
    updateCounter('alertsGenerated', stats.alerts_generated);
    updateCounter('detectionRate', stats.detection_rate, '%');
    
    // Update last detection time
    if (stats.last_detection) {
        updateLastDetection(stats.last_detection);
    }
}

/**
 * Update counter element
 */
function updateCounter(elementId, value, suffix = '') {
    const element = document.getElementById(elementId);
    if (element) {
        element.textContent = value + suffix;
    }
}

/**
 * Update last detection time
 */
function updateLastDetection(timestamp) {
    const element = document.getElementById('lastDetection');
    if (element) {
        element.textContent = formatTimestamp(timestamp);
    }
}

/**
 * Show threat notification
 */
function showThreatNotification(threat) {
    // Check if browser supports notifications
    if ('Notification' in window && Notification.permission === 'granted') {
        new Notification('High Severity Threat Detected', {
            body: `User: ${threat.user}\nThreat Score: ${threat.threat_score?.toFixed(3)}`,
            icon: '/static/img/threat-icon.png',
            tag: 'threat-detection'
        });
    }
    
    // Show in-app notification
    showAlert(
        `High severity threat detected for user ${threat.user} (Score: ${threat.threat_score?.toFixed(3)})`,
        'warning'
    );
}

/**
 * Toggle auto-refresh
 */
function toggleAutoRefresh() {
    const button = document.getElementById('autoRefreshBtn');
    const icon = button.querySelector('i');
    const text = button.querySelector('span');
    
    if (isAutoRefresh) {
        // Stop auto-refresh
        clearInterval(autoRefreshInterval);
        isAutoRefresh = false;
        icon.className = 'fas fa-play';
        text.textContent = 'Start Auto-refresh';
        button.classList.remove('btn-warning');
        button.classList.add('btn-success');
    } else {
        // Start auto-refresh
        autoRefreshInterval = setInterval(refreshDashboard, 30000); // 30 seconds
        isAutoRefresh = true;
        icon.className = 'fas fa-pause';
        text.textContent = 'Stop Auto-refresh';
        button.classList.remove('btn-success');
        button.classList.add('btn-warning');
    }
}

/**
 * Clear event feed
 */
function clearEventFeed() {
    const eventFeed = document.getElementById('eventFeed');
    if (eventFeed) {
        eventFeed.innerHTML = `
            <div class="text-center text-muted">
                <i class="fas fa-info-circle me-2"></i>Real-time events will appear here
            </div>
        `;
    }
}

/**
 * Refresh dashboard data
 */
function refreshDashboard() {
    console.log('Refreshing dashboard...');
    
    // Show loading indicator
    showLoadingIndicator();
    
    // Fetch latest data
    Promise.all([
        fetchThreatSummary(),
        fetchRecentThreats(),
        fetchModelMetrics()
    ]).then(([summary, threats, metrics]) => {
        // Update dashboard with new data
        updateDashboardStats(summary);
        updateRecentThreats(threats);
        updateModelMetrics(metrics);
        
        hideLoadingIndicator();
        showAlert('Dashboard refreshed successfully', 'success');
    }).catch(error => {
        console.error('Error refreshing dashboard:', error);
        hideLoadingIndicator();
        showAlert('Error refreshing dashboard: ' + error.message, 'danger');
    });
}

/**
 * Fetch threat summary
 */
async function fetchThreatSummary() {
    const response = await fetch('/api/threat_summary');
    if (!response.ok) {
        throw new Error('Failed to fetch threat summary');
    }
    return response.json();
}

/**
 * Fetch recent threats
 */
async function fetchRecentThreats() {
    const response = await fetch('/api/recent_threats');
    if (!response.ok) {
        throw new Error('Failed to fetch recent threats');
    }
    return response.json();
}

/**
 * Fetch model metrics
 */
async function fetchModelMetrics() {
    const response = await fetch('/api/model_metrics');
    if (!response.ok) {
        throw new Error('Failed to fetch model metrics');
    }
    return response.json();
}

/**
 * Export dashboard data
 */
function exportDashboardData() {
    const exportBtn = document.getElementById('exportBtn');
    const originalText = exportBtn.textContent;
    
    // Safely set loading state
    exportBtn.textContent = '';
    const spinner = document.createElement('i');
    spinner.className = 'fas fa-spinner fa-spin me-2';
    exportBtn.appendChild(spinner);
    exportBtn.appendChild(document.createTextNode('Exporting...'));
    exportBtn.disabled = true;
    
    fetch('/api/export_dashboard', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        }
    })
    .then(response => response.blob())
    .then(blob => {
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `dashboard_export_${new Date().toISOString().split('T')[0]}.csv`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        window.URL.revokeObjectURL(url);
        
        showAlert('Dashboard data exported successfully', 'success');
    })
    .catch(error => {
        console.error('Export failed:', error);
        showAlert('Export failed: ' + error.message, 'danger');
    })
    .finally(() => {
        // Safely restore original text
        exportBtn.textContent = originalText;
        exportBtn.disabled = false;
    });
}

/**
 * Load initial dashboard data
 */
function loadInitialData() {
    refreshDashboard();
}

/**
 * Start periodic updates
 */
function startPeriodicUpdates() {
    // Update stats every 30 seconds
    setInterval(() => {
        if (!isAutoRefresh) return;
        
        fetch('/api/stats')
            .then(response => response.json())
            .then(data => {
                updateDashboardStats(data);
            })
            .catch(error => {
                console.error('Error updating stats:', error);
            });
    }, 30000);
}

/**
 * Utility functions
 */
function getSeverityClass(severity) {
    switch (severity) {
        case 'critical': return 'danger';
        case 'high': return 'warning';
        case 'medium': return 'info';
        case 'low': return 'secondary';
        default: return 'secondary';
    }
}

function getSeverityIndex(severity) {
    switch (severity) {
        case 'critical': return 0;
        case 'high': return 1;
        case 'medium': return 2;
        case 'low': return 3;
        default: return -1;
    }
}

function getThreatScoreClass(score) {
    if (score > 0.8) return 'danger';
    if (score > 0.5) return 'warning';
    if (score > 0.3) return 'info';
    return 'success';
}

function formatTimestamp(timestamp) {
    return new Date(timestamp).toLocaleString();
}

function updateConnectionStatus(status) {
    const statusElement = document.getElementById('connectionStatus');
    if (statusElement) {
        statusElement.className = `badge bg-${status === 'connected' ? 'success' : 'danger'}`;
        statusElement.textContent = status;
    }
}

function showLoadingIndicator() {
    const indicator = document.getElementById('loadingIndicator');
    if (indicator) {
        indicator.style.display = 'block';
    }
}

function hideLoadingIndicator() {
    const indicator = document.getElementById('loadingIndicator');
    if (indicator) {
        indicator.style.display = 'none';
    }
}

function showAlert(message, type) {
    const alertDiv = document.createElement('div');
    alertDiv.className = `alert alert-${type} alert-dismissible fade show position-fixed`;
    alertDiv.style.cssText = 'top: 20px; right: 20px; z-index: 9999; max-width: 400px;';
    
    // Create message text node safely
    const messageText = document.createTextNode(message);
    alertDiv.appendChild(messageText);
    
    // Add dismiss button safely
    const dismissBtn = document.createElement('button');
    dismissBtn.type = 'button';
    dismissBtn.className = 'btn-close';
    dismissBtn.setAttribute('data-bs-dismiss', 'alert');
    alertDiv.appendChild(dismissBtn);
    
    document.body.appendChild(alertDiv);
    
    // Auto dismiss after 5 seconds
    setTimeout(() => {
        alertDiv.remove();
    }, 5000);
}

// Request notification permission on page load
if ('Notification' in window && Notification.permission === 'default') {
    Notification.requestPermission();
}
