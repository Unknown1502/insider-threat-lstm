/**
 * Model Training JavaScript for Insider Threat Detection
 * Handles model training, configuration, and performance monitoring
 */

// Global variables
let trainingStatusInterval = null;
let trainingHistoryChart = null;
let modelMetricsChart = null;
let lossChart = null;
let accuracyChart = null;
let currentTrainingConfig = {};
let trainingHistory = [];

// Initialize on page load
document.addEventListener('DOMContentLoaded', function() {
    initializeModelTraining();
});

/**
 * Initialize model training page
 */
function initializeModelTraining() {
    console.log('Initializing model training...');
    
    // Initialize charts
    initializeCharts();
    
    // Setup event listeners
    setupEventListeners();
    
    // Load training configuration
    loadTrainingConfiguration();
    
    // Check if training is already in progress
    checkTrainingStatus();
    
    // Load training history
    loadTrainingHistory();
}

/**
 * Initialize all charts
 */
function initializeCharts() {
    initializeTrainingHistoryChart();
    initializeModelMetricsChart();
    initializeLossChart();
    initializeAccuracyChart();
}

/**
 * Initialize training history chart
 */
function initializeTrainingHistoryChart() {
    const ctx = document.getElementById('trainingHistoryChart');
    if (!ctx) return;
    
    trainingHistoryChart = new Chart(ctx.getContext('2d'), {
        type: 'line',
        data: {
            labels: [],
            datasets: [{
                label: 'Training Loss',
                data: [],
                borderColor: 'rgb(255, 99, 132)',
                backgroundColor: 'rgba(255, 99, 132, 0.1)',
                borderWidth: 2,
                yAxisID: 'y'
            }, {
                label: 'Validation Loss',
                data: [],
                borderColor: 'rgb(255, 159, 64)',
                backgroundColor: 'rgba(255, 159, 64, 0.1)',
                borderWidth: 2,
                yAxisID: 'y'
            }, {
                label: 'Training Accuracy',
                data: [],
                borderColor: 'rgb(54, 162, 235)',
                backgroundColor: 'rgba(54, 162, 235, 0.1)',
                borderWidth: 2,
                yAxisID: 'y1'
            }, {
                label: 'Validation Accuracy',
                data: [],
                borderColor: 'rgb(153, 102, 255)',
                backgroundColor: 'rgba(153, 102, 255, 0.1)',
                borderWidth: 2,
                yAxisID: 'y1'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                title: {
                    display: true,
                    text: 'Training Progress'
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
                        text: 'Epoch'
                    }
                },
                y: {
                    type: 'linear',
                    display: true,
                    position: 'left',
                    title: {
                        display: true,
                        text: 'Loss'
                    }
                },
                y1: {
                    type: 'linear',
                    display: true,
                    position: 'right',
                    title: {
                        display: true,
                        text: 'Accuracy'
                    },
                    grid: {
                        drawOnChartArea: false
                    }
                }
            }
        }
    });
}

/**
 * Initialize model metrics chart
 */
function initializeModelMetricsChart() {
    const ctx = document.getElementById('modelMetricsChart');
    if (!ctx) return;
    
    modelMetricsChart = new Chart(ctx.getContext('2d'), {
        type: 'bar',
        data: {
            labels: ['Precision', 'Recall', 'F1-Score', 'AUC-ROC'],
            datasets: [{
                label: 'Performance Metrics',
                data: [0, 0, 0, 0],
                backgroundColor: [
                    'rgba(255, 99, 132, 0.8)',
                    'rgba(54, 162, 235, 0.8)',
                    'rgba(255, 205, 86, 0.8)',
                    'rgba(75, 192, 192, 0.8)'
                ],
                borderColor: [
                    'rgb(255, 99, 132)',
                    'rgb(54, 162, 235)',
                    'rgb(255, 205, 86)',
                    'rgb(75, 192, 192)'
                ],
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                title: {
                    display: true,
                    text: 'Model Performance Metrics'
                },
                legend: {
                    display: false
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    max: 1.0,
                    title: {
                        display: true,
                        text: 'Score'
                    }
                }
            }
        }
    });
}

/**
 * Initialize loss chart
 */
function initializeLossChart() {
    const ctx = document.getElementById('lossChart');
    if (!ctx) return;
    
    lossChart = new Chart(ctx.getContext('2d'), {
        type: 'line',
        data: {
            labels: [],
            datasets: [{
                label: 'Training Loss',
                data: [],
                borderColor: 'rgb(255, 99, 132)',
                backgroundColor: 'rgba(255, 99, 132, 0.1)',
                borderWidth: 2,
                fill: true
            }, {
                label: 'Validation Loss',
                data: [],
                borderColor: 'rgb(255, 159, 64)',
                backgroundColor: 'rgba(255, 159, 64, 0.1)',
                borderWidth: 2,
                fill: true
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                title: {
                    display: true,
                    text: 'Loss Over Time'
                }
            },
            scales: {
                x: {
                    title: {
                        display: true,
                        text: 'Epoch'
                    }
                },
                y: {
                    title: {
                        display: true,
                        text: 'Loss'
                    },
                    beginAtZero: true
                }
            }
        }
    });
}

/**
 * Initialize accuracy chart
 */
function initializeAccuracyChart() {
    const ctx = document.getElementById('accuracyChart');
    if (!ctx) return;
    
    accuracyChart = new Chart(ctx.getContext('2d'), {
        type: 'line',
        data: {
            labels: [],
            datasets: [{
                label: 'Training Accuracy',
                data: [],
                borderColor: 'rgb(54, 162, 235)',
                backgroundColor: 'rgba(54, 162, 235, 0.1)',
                borderWidth: 2,
                fill: true
            }, {
                label: 'Validation Accuracy',
                data: [],
                borderColor: 'rgb(153, 102, 255)',
                backgroundColor: 'rgba(153, 102, 255, 0.1)',
                borderWidth: 2,
                fill: true
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                title: {
                    display: true,
                    text: 'Accuracy Over Time'
                }
            },
            scales: {
                x: {
                    title: {
                        display: true,
                        text: 'Epoch'
                    }
                },
                y: {
                    title: {
                        display: true,
                        text: 'Accuracy'
                    },
                    beginAtZero: true,
                    max: 1.0
                }
            }
        }
    });
}

/**
 * Setup event listeners
 */
function setupEventListeners() {
    // Training control buttons
    const startTrainingBtn = document.getElementById('startTrainingBtn');
    if (startTrainingBtn) {
        startTrainingBtn.addEventListener('click', startTraining);
    }
    
    const stopTrainingBtn = document.getElementById('stopTrainingBtn');
    if (stopTrainingBtn) {
        stopTrainingBtn.addEventListener('click', stopTraining);
    }
    
    // Dataset management
    const downloadDatasetBtn = document.getElementById('downloadDatasetBtn');
    if (downloadDatasetBtn) {
        downloadDatasetBtn.addEventListener('click', downloadDataset);
    }
    
    const uploadDatasetForm = document.getElementById('uploadDatasetForm');
    if (uploadDatasetForm) {
        uploadDatasetForm.addEventListener('submit', uploadDataset);
    }
    
    // Configuration management
    const saveConfigBtn = document.getElementById('saveConfigBtn');
    if (saveConfigBtn) {
        saveConfigBtn.addEventListener('click', saveConfiguration);
    }
    
    const loadConfigBtn = document.getElementById('loadConfigBtn');
    if (loadConfigBtn) {
        loadConfigBtn.addEventListener('click', loadConfiguration);
    }
    
    const resetConfigBtn = document.getElementById('resetConfigBtn');
    if (resetConfigBtn) {
        resetConfigBtn.addEventListener('click', resetConfiguration);
    }
    
    // Model management
    const saveModelBtn = document.getElementById('saveModelBtn');
    if (saveModelBtn) {
        saveModelBtn.addEventListener('click', saveModel);
    }
    
    const loadModelBtn = document.getElementById('loadModelBtn');
    if (loadModelBtn) {
        loadModelBtn.addEventListener('click', loadModel);
    }
    
    // Logs management
    const clearLogsBtn = document.getElementById('clearLogsBtn');
    if (clearLogsBtn) {
        clearLogsBtn.addEventListener('click', clearLogs);
    }
    
    const exportLogsBtn = document.getElementById('exportLogsBtn');
    if (exportLogsBtn) {
        exportLogsBtn.addEventListener('click', exportLogs);
    }
    
    // Configuration inputs
    setupConfigurationInputs();
}

/**
 * Setup configuration input handlers
 */
function setupConfigurationInputs() {
    const configInputs = [
        'epochs', 'batchSize', 'learningRate', 'validationSplit',
        'sequenceLength', 'featureDim', 'lstmUnits', 'dropoutRate'
    ];
    
    configInputs.forEach(inputId => {
        const input = document.getElementById(inputId);
        if (input) {
            input.addEventListener('change', updateConfiguration);
        }
    });
}

/**
 * Start model training
 */
function startTraining() {
    console.log('Starting model training...');
    
    // Validate configuration
    if (!validateConfiguration()) {
        return;
    }
    
    // Get training configuration
    const config = getCurrentConfiguration();
    
    // Update UI
    updateTrainingUI(true);
    
    // Start training
    fetch('/api/train_model', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(config)
    })
    .then(response => response.json())
    .then(data => {
        if (data.status === 'success') {
            addLog('Training started successfully!', 'success');
            startTrainingStatusUpdates();
        } else {
            addLog('Failed to start training: ' + data.message, 'error');
            updateTrainingUI(false);
        }
    })
    .catch(error => {
        addLog('Error starting training: ' + error.message, 'error');
        updateTrainingUI(false);
    });
}

/**
 * Stop model training
 */
function stopTraining() {
    console.log('Stopping model training...');
    
    fetch('/api/stop_training', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        }
    })
    .then(response => response.json())
    .then(data => {
        if (data.status === 'success') {
            addLog('Training stopped successfully!', 'warning');
            stopTrainingStatusUpdates();
            updateTrainingUI(false);
        } else {
            addLog('Failed to stop training: ' + data.message, 'error');
        }
    })
    .catch(error => {
        addLog('Error stopping training: ' + error.message, 'error');
    });
}

/**
 * Download CERT dataset
 */
function downloadDataset() {
    const button = document.getElementById('downloadDatasetBtn');
    const originalText = button.innerHTML;
    
    button.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Downloading...';
    button.disabled = true;
    
    fetch('/api/download_cert_dataset', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        }
    })
    .then(response => response.json())
    .then(data => {
        if (data.status === 'success') {
            addLog('CERT dataset downloaded successfully!', 'success');
            updateDatasetInfo(data.dataset_info);
        } else {
            addLog('Failed to download dataset: ' + data.message, 'error');
        }
    })
    .catch(error => {
        addLog('Error downloading dataset: ' + error.message, 'error');
    })
    .finally(() => {
        button.innerHTML = originalText;
        button.disabled = false;
    });
}

/**
 * Upload custom dataset
 */
function uploadDataset(event) {
    event.preventDefault();
    
    const fileInput = document.getElementById('datasetFile');
    const file = fileInput.files[0];
    
    if (!file) {
        addLog('Please select a file to upload', 'error');
        return;
    }
    
    const formData = new FormData();
    formData.append('file', file);
    
    const progressBar = document.getElementById('uploadProgress');
    const progressBarFill = progressBar.querySelector('.progress-bar');
    
    progressBar.style.display = 'block';
    progressBarFill.style.width = '0%';
    
    addLog(`Uploading ${file.name}...`, 'info');
    
    fetch('/api/upload_dataset', {
        method: 'POST',
        body: formData
    })
    .then(response => response.json())
    .then(data => {
        if (data.status === 'success') {
            addLog(`Dataset uploaded successfully! Processed ${data.records} records.`, 'success');
            fileInput.value = '';
            updateDatasetInfo(data.dataset_info);
        } else {
            addLog('Upload failed: ' + data.message, 'error');
        }
    })
    .catch(error => {
        addLog('Error uploading dataset: ' + error.message, 'error');
    })
    .finally(() => {
        progressBar.style.display = 'none';
    });
}

/**
 * Start training status updates
 */
function startTrainingStatusUpdates() {
    if (trainingStatusInterval) {
        clearInterval(trainingStatusInterval);
    }
    
    trainingStatusInterval = setInterval(updateTrainingStatus, 5000);
}

/**
 * Stop training status updates
 */
function stopTrainingStatusUpdates() {
    if (trainingStatusInterval) {
        clearInterval(trainingStatusInterval);
        trainingStatusInterval = null;
    }
}

/**
 * Update training status
 */
function updateTrainingStatus() {
    fetch('/api/training_status')
    .then(response => response.json())
    .then(data => {
        updateTrainingProgress(data);
        
        if (data.training_metrics) {
            updateTrainingCharts(data.training_metrics);
        }
        
        if (!data.is_training) {
            stopTrainingStatusUpdates();
            updateTrainingUI(false);
            
            if (data.training_completed) {
                addLog('Training completed successfully!', 'success');
                loadModelMetrics();
            }
        }
    })
    .catch(error => {
        addLog('Error updating training status: ' + error.message, 'error');
    });
}

/**
 * Update training progress
 */
function updateTrainingProgress(status) {
    // Update progress bar
    const progressBar = document.getElementById('trainingProgressBar');
    if (progressBar) {
        progressBar.style.width = `${status.progress}%`;
        progressBar.textContent = `${status.progress}%`;
        
        if (status.is_training) {
            progressBar.classList.add('progress-bar-animated');
        } else {
            progressBar.classList.remove('progress-bar-animated');
        }
    }
    
    // Update status badge
    const statusBadge = document.getElementById('trainingStatusBadge');
    if (statusBadge) {
        statusBadge.textContent = status.status;
        statusBadge.className = `badge bg-${status.is_training ? 'warning' : 'success'}`;
    }
    
    // Update current epoch
    const currentEpoch = document.getElementById('currentEpoch');
    if (currentEpoch && status.current_epoch) {
        currentEpoch.textContent = `${status.current_epoch}/${status.total_epochs}`;
    }
    
    // Update ETA
    const eta = document.getElementById('trainingETA');
    if (eta && status.eta) {
        eta.textContent = status.eta;
    }
}

/**
 * Update training charts
 */
function updateTrainingCharts(metrics) {
    if (!metrics || !metrics.history) return;
    
    const history = metrics.history;
    const epochs = Array.from({ length: history.loss.length }, (_, i) => i + 1);
    
    // Update training history chart
    if (trainingHistoryChart) {
        trainingHistoryChart.data.labels = epochs;
        trainingHistoryChart.data.datasets[0].data = history.loss;
        trainingHistoryChart.data.datasets[1].data = history.val_loss || [];
        trainingHistoryChart.data.datasets[2].data = history.accuracy;
        trainingHistoryChart.data.datasets[3].data = history.val_accuracy || [];
        trainingHistoryChart.update('none');
    }
    
    // Update loss chart
    if (lossChart) {
        lossChart.data.labels = epochs;
        lossChart.data.datasets[0].data = history.loss;
        lossChart.data.datasets[1].data = history.val_loss || [];
        lossChart.update('none');
    }
    
    // Update accuracy chart
    if (accuracyChart) {
        accuracyChart.data.labels = epochs;
        accuracyChart.data.datasets[0].data = history.accuracy;
        accuracyChart.data.datasets[1].data = history.val_accuracy || [];
        accuracyChart.update('none');
    }
}

/**
 * Update training UI
 */
function updateTrainingUI(isTraining) {
    const startBtn = document.getElementById('startTrainingBtn');
    const stopBtn = document.getElementById('stopTrainingBtn');
    const configInputs = document.querySelectorAll('.config-input');
    
    if (startBtn) {
        startBtn.disabled = isTraining;
    }
    
    if (stopBtn) {
        stopBtn.disabled = !isTraining;
    }
    
    configInputs.forEach(input => {
        input.disabled = isTraining;
    });
}

/**
 * Get current configuration
 */
function getCurrentConfiguration() {
    return {
        epochs: parseInt(document.getElementById('epochs').value) || 50,
        batch_size: parseInt(document.getElementById('batchSize').value) || 32,
        learning_rate: parseFloat(document.getElementById('learningRate').value) || 0.001,
        validation_split: parseFloat(document.getElementById('validationSplit').value) || 0.2,
        sequence_length: parseInt(document.getElementById('sequenceLength').value) || 10,
        feature_dim: parseInt(document.getElementById('featureDim').value) || 20,
        lstm_units: parseInt(document.getElementById('lstmUnits').value) || 128,
        dropout_rate: parseFloat(document.getElementById('dropoutRate').value) || 0.3
    };
}

/**
 * Update configuration
 */
function updateConfiguration() {
    currentTrainingConfig = getCurrentConfiguration();
    console.log('Configuration updated:', currentTrainingConfig);
}

/**
 * Validate configuration
 */
function validateConfiguration() {
    const config = getCurrentConfiguration();
    const errors = [];
    
    if (config.epochs < 1 || config.epochs > 1000) {
        errors.push('Epochs must be between 1 and 1000');
    }
    
    if (config.batch_size < 1 || config.batch_size > 1024) {
        errors.push('Batch size must be between 1 and 1024');
    }
    
    if (config.learning_rate <= 0 || config.learning_rate > 1) {
        errors.push('Learning rate must be between 0 and 1');
    }
    
    if (config.validation_split <= 0 || config.validation_split >= 1) {
        errors.push('Validation split must be between 0 and 1');
    }
    
    if (errors.length > 0) {
        addLog('Configuration validation failed: ' + errors.join(', '), 'error');
        return false;
    }
    
    return true;
}

/**
 * Load training configuration
 */
function loadTrainingConfiguration() {
    fetch('/api/training_config')
    .then(response => response.json())
    .then(data => {
        if (data.status === 'success') {
            setConfiguration(data.config);
            addLog('Configuration loaded successfully', 'success');
        }
    })
    .catch(error => {
        console.error('Error loading configuration:', error);
    });
}

/**
 * Set configuration values
 */
function setConfiguration(config) {
    document.getElementById('epochs').value = config.epochs || 50;
    document.getElementById('batchSize').value = config.batch_size || 32;
    document.getElementById('learningRate').value = config.learning_rate || 0.001;
    document.getElementById('validationSplit').value = config.validation_split || 0.2;
    document.getElementById('sequenceLength').value = config.sequence_length || 10;
    document.getElementById('featureDim').value = config.feature_dim || 20;
    document.getElementById('lstmUnits').value = config.lstm_units || 128;
    document.getElementById('dropoutRate').value = config.dropout_rate || 0.3;
    
    currentTrainingConfig = config;
}

/**
 * Save configuration
 */
function saveConfiguration() {
    const config = getCurrentConfiguration();
    
    fetch('/api/save_training_config', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ config: config })
    })
    .then(response => response.json())
    .then(data => {
        if (data.status === 'success') {
            addLog('Configuration saved successfully', 'success');
        } else {
            addLog('Failed to save configuration: ' + data.message, 'error');
        }
    })
    .catch(error => {
        addLog('Error saving configuration: ' + error.message, 'error');
    });
}

/**
 * Reset configuration to defaults
 */
function resetConfiguration() {
    const defaultConfig = {
        epochs: 50,
        batch_size: 32,
        learning_rate: 0.001,
        validation_split: 0.2,
        sequence_length: 10,
        feature_dim: 20,
        lstm_units: 128,
        dropout_rate: 0.3
    };
    
    setConfiguration(defaultConfig);
    addLog('Configuration reset to defaults', 'info');
}

/**
 * Check training status on page load
 */
function checkTrainingStatus() {
    fetch('/api/training_status')
    .then(response => response.json())
    .then(data => {
        if (data.is_training) {
            updateTrainingUI(true);
            startTrainingStatusUpdates();
            addLog('Training in progress...', 'info');
        }
    })
    .catch(error => {
        console.error('Error checking training status:', error);
    });
}

/**
 * Load training history
 */
function loadTrainingHistory() {
    fetch('/api/training_history')
    .then(response => response.json())
    .then(data => {
        if (data.status === 'success' && data.history) {
            trainingHistory = data.history;
            updateTrainingCharts(data.history);
        }
    })
    .catch(error => {
        console.error('Error loading training history:', error);
    });
}

/**
 * Load model metrics
 */
function loadModelMetrics() {
    fetch('/api/model_metrics')
    .then(response => response.json())
    .then(data => {
        if (data.status === 'success' && data.metrics) {
            updateModelMetricsChart(data.metrics);
        }
    })
    .catch(error => {
        console.error('Error loading model metrics:', error);
    });
}

/**
 * Update model metrics chart
 */
function updateModelMetricsChart(metrics) {
    if (!modelMetricsChart) return;
    
    const values = [
        metrics.precision || 0,
        metrics.recall || 0,
        metrics.f1_score || 0,
        metrics.auc_roc || 0
    ];
    
    modelMetricsChart.data.datasets[0].data = values;
    modelMetricsChart.update();
}

/**
 * Update dataset info
 */
function updateDatasetInfo(info) {
    const infoElement = document.getElementById('datasetInfo');
    if (infoElement && info) {
        // Create DOM elements safely to prevent XSS
        const container = document.createElement('div');
        container.className = 'row';
        
        // Left column
        const leftCol = document.createElement('div');
        leftCol.className = 'col-md-6';
        
        const leftTitle = document.createElement('h6');
        leftTitle.textContent = 'Dataset Information';
        leftCol.appendChild(leftTitle);
        
        const recordsP = document.createElement('p');
        recordsP.innerHTML = '<strong>Records:</strong> ';
        recordsP.appendChild(document.createTextNode(info.record_count || 'N/A'));
        leftCol.appendChild(recordsP);
        
        const sizeP = document.createElement('p');
        sizeP.innerHTML = '<strong>Size:</strong> ';
        sizeP.appendChild(document.createTextNode(info.file_size || 'N/A'));
        leftCol.appendChild(sizeP);
        
        const formatP = document.createElement('p');
        formatP.innerHTML = '<strong>Format:</strong> ';
        formatP.appendChild(document.createTextNode(info.format || 'CSV'));
        leftCol.appendChild(formatP);
        
        // Right column
        const rightCol = document.createElement('div');
        rightCol.className = 'col-md-6';
        
        const rightTitle = document.createElement('h6');
        rightTitle.textContent = 'Data Quality';
        rightCol.appendChild(rightTitle);
        
        const missingP = document.createElement('p');
        missingP.innerHTML = '<strong>Missing Values:</strong> ';
        missingP.appendChild(document.createTextNode(info.missing_values || 'N/A'));
        rightCol.appendChild(missingP);
        
        const duplicatesP = document.createElement('p');
        duplicatesP.innerHTML = '<strong>Duplicates:</strong> ';
        duplicatesP.appendChild(document.createTextNode(info.duplicates || 'N/A'));
        rightCol.appendChild(duplicatesP);
        
        const statusP = document.createElement('p');
        statusP.innerHTML = '<strong>Status:</strong> ';
        statusP.appendChild(document.createTextNode(info.status || 'Unknown'));
        rightCol.appendChild(statusP);
        
        container.appendChild(leftCol);
        container.appendChild(rightCol);
        
        // Clear existing content and add new safe content
        infoElement.innerHTML = '';
        infoElement.appendChild(container);
    }
}

/**
 * Add log entry
 */
function addLog(message, type = 'info') {
    const logsContainer = document.getElementById('trainingLogs');
    if (!logsContainer) return;
    
    const timestamp = new Date().toISOString().substring(11, 19);
    const logEntry = document.createElement('div');
    
    const colorClass = {
        'success': 'text-success',
        'error': 'text-danger',
        'warning': 'text-warning',
        'info': 'text-info'
    }[type] || 'text-light';
    
    logEntry.className = colorClass;
    logEntry.textContent = `[${timestamp}] ${message}`;
    
    logsContainer.appendChild(logEntry);
    logsContainer.scrollTop = logsContainer.scrollHeight;
    
    // Keep only last 1000 log entries
    while (logsContainer.children.length > 1000) {
        logsContainer.removeChild(logsContainer.firstChild);
    }
}

/**
 * Clear logs
 */
function clearLogs() {
    const logsContainer = document.getElementById('trainingLogs');
    if (logsContainer) {
        logsContainer.innerHTML = '<div class="text-muted">Training logs will appear here...</div>';
    }
}

/**
 * Export logs
 */
function exportLogs() {
    const logsContainer = document.getElementById('trainingLogs');
    if (!logsContainer) return;
    
    const logs = Array.from(logsContainer.children)
        .map(entry => entry.textContent)
        .join('\n');
    
    const blob = new Blob([logs], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `training_logs_${new Date().toISOString().split('T')[0]}.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    
    addLog('Logs exported successfully', 'success');
}

/**
 * Save model
 */
function saveModel() {
    fetch('/api/save_model', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        }
    })
    .then(response => response.json())
    .then(data => {
        if (data.status === 'success') {
            addLog('Model saved successfully', 'success');
        } else {
            addLog('Failed to save model: ' + data.message, 'error');
        }
    })
    .catch(error => {
        addLog('Error saving model: ' + error.message, 'error');
    });
}

/**
 * Load model
 */
function loadModel() {
    fetch('/api/load_model', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        }
    })
    .then(response => response.json())
    .then(data => {
        if (data.status === 'success') {
            addLog('Model loaded successfully', 'success');
            loadModelMetrics();
        } else {
            addLog('Failed to load model: ' + data.message, 'error');
        }
    })
    .catch(error => {
        addLog('Error loading model: ' + error.message, 'error');
    });
}
