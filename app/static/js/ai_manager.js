document.addEventListener('DOMContentLoaded', function () {
    // --- CHART CONFIGURATION ---
    const chartFontColor = '#94a3b8';
    const gridColor = 'rgba(51, 65, 85, 0.5)';

    // Dummy Data (replace with actual data from backend)
    const dummyModelHistory = [
        { version: 'v1.2.1', date: '2025-10-08', accuracy: '99.1%', active: true },
        { version: 'v1.2.0', date: '2025-09-20', accuracy: '98.8%', active: false },
        { version: 'v1.1.5', date: '2025-08-15', accuracy: '98.2%', active: false },
    ];

    const dummyAIDetections = [
        'AI flagged IP 192.168.1.10 for unusual UDP flood.',
        'Anomaly detected: Port scan signature from 10.0.0.5.',
        'AI blocked 203.0.113.22 for matching C&C server pattern.',
    ];

    // --- DOM ELEMENTS ---
    const trainModelBtn = document.getElementById('train-model-btn');
    const trainingStatusContainer = document.getElementById('training-status-container');
    const trainingProgressBar = document.getElementById('training-progress-bar');
    const trainingTimer = document.getElementById('training-timer'); // PUDHU ELEMENT
    const modelHistoryBody = document.getElementById('model-history-body');
    const aiDetectionsLog = document.getElementById('ai-detections-log');

    // Global timer variable
    let countdownInterval;

    // --- FUNCTION TO INITIALIZE CHARTS ---
    function initCharts() {
        // 1. Training Performance Chart (Line Chart)
        const perfCtx = document.getElementById('training-performance-chart').getContext('2d');
        new Chart(perfCtx, {
            type: 'line',
            data: {
                labels: ['Epoch 1', 'Epoch 2', 'Epoch 3', 'Epoch 4', 'Epoch 5', 'Epoch 6'],
                datasets: [
                    {
                        label: 'Accuracy',
                        data: [85, 88, 92, 94, 96, 99.1],
                        borderColor: 'rgba(22, 181, 117, 1)', // --secondary
                        backgroundColor: 'rgba(22, 181, 117, 0.2)',
                        fill: true,
                        tension: 0.4
                    },
                    {
                        label: 'Loss',
                        data: [0.3, 0.25, 0.2, 0.15, 0.1, 0.08],
                        borderColor: 'rgba(255, 71, 87, 1)', // --danger
                        backgroundColor: 'rgba(255, 71, 87, 0.2)',
                        fill: true,
                        tension: 0.4
                    }
                ]
            },
            options: chartOptions('Training Progress')
        });

        // 2. Confusion Matrix (Doughnut Chart - visual representation)
        const confusionCtx = document.getElementById('confusion-matrix-chart').getContext('2d');
        new Chart(confusionCtx, {
            type: 'doughnut',
            data: {
                labels: ['True Positives', 'True Negatives', 'False Positives', 'False Negatives'],
                datasets: [{
                    label: 'Prediction Analysis',
                    data: [1200, 8500, 50, 25],
                    backgroundColor: ['#16B575', '#5a76e9', '#ff9f43', '#ff4757'],
                    borderWidth: 2,
                    borderColor: '#0f172a'
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: { position: 'top', labels: { color: chartFontColor } },
                    title: { display: true, text: 'Prediction Breakdown', color: chartFontColor, font: { size: 16 } }
                }
            }
        });

        // 3. Feature Importance (Bar Chart)
        const featureCtx = document.getElementById('feature-importance-chart').getContext('2d');
        new Chart(featureCtx, {
            type: 'bar',
            data: {
                labels: ['Packet Size', 'Protocol Type', 'Source Port', 'Time Delta', 'Flag Count'],
                datasets: [{
                    label: 'Importance Score',
                    data: [0.88, 0.75, 0.65, 0.50, 0.42],
                    backgroundColor: 'rgba(120, 104, 230, 0.6)', // --accent
                    borderColor: 'rgba(120, 104, 230, 1)',
                    borderWidth: 1
                }]
            },
            options: chartOptions('Feature Importance', false)
        });
    }

    // --- Generic Chart Options ---
    function chartOptions(title, showX = true) {
        return {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { labels: { color: chartFontColor } },
                title: { display: true, text: title, color: 'white', font: { size: 16 } }
            },
            scales: {
                y: {
                    ticks: { color: chartFontColor },
                    grid: { color: gridColor }
                },
                x: {
                    display: showX,
                    ticks: { color: chartFontColor },
                    grid: { color: gridColor }
                }
            }
        };
    }

    // --- FUNCTION TO POPULATE UI ---
    function populateUI() {
        // Populate Model History Table
        modelHistoryBody.innerHTML = ''; // Clear loader
        dummyModelHistory.forEach(model => {
            const row = `
                <tr>
                    <td>${model.version}</td>
                    <td>${model.date}</td>
                    <td>${model.accuracy}</td>
                    <td>
                        <span class="status-badge ${model.active ? 'status-active' : 'status-archived'}">
                            ${model.active ? 'Active' : 'Archived'}
                        </span>
                    </td>
                    <td>
                        ${!model.active ? '<button class="btn btn-secondary btn-sm">Activate</button>' : '-'}
                    </td>
                </tr>
            `;
            modelHistoryBody.insertAdjacentHTML('beforeend', row);
        });

        // Populate Live AI Detections
        aiDetectionsLog.innerHTML = ''; // Clear placeholder
        dummyAIDetections.forEach(log => {
            const logItem = `
                <li class="log-item">
                    <i class="fas fa-robot log-icon"></i>
                    <span>${log}</span>
                </li>
            `;
            aiDetectionsLog.insertAdjacentHTML('beforeend', logItem);
        });
    }

    // --- FUNCTION TO START THE TIMER ---
    function startTrainingTimer(durationInSeconds) {
        let timer = durationInSeconds;
        let minutes, seconds;

        countdownInterval = setInterval(function () {
            minutes = parseInt(timer / 60, 10);
            seconds = parseInt(timer % 60, 10);

            minutes = minutes < 10 ? "0" + minutes : minutes;
            seconds = seconds < 10 ? "0" + seconds : seconds;

            trainingTimer.innerHTML = `<i class="fas fa-clock"></i> Est. Time: ${minutes}:${seconds}`;

            if (--timer < 0) {
                clearInterval(countdownInterval);
                 trainingTimer.innerHTML = `<i class="fas fa-check-circle"></i> Completed!`;
            }
        }, 1000);
    }

    // --- EVENT LISTENERS ---
    trainModelBtn.addEventListener('click', () => {
        trainingStatusContainer.classList.remove('hidden');
        trainModelBtn.disabled = true;
        trainModelBtn.querySelector('span').textContent = 'Training...';

        // Clear any previous timer
        clearInterval(countdownInterval);

        // Simulate training progress
        let progress = 0;
        const trainingDuration = 90; // 90 seconds for simulation
        startTrainingTimer(trainingDuration); // Start countdown

        const interval = setInterval(() => {
            progress += 1; // Increment progress smoothly
            trainingProgressBar.style.width = `${progress}%`;

            if (progress >= 100) {
                clearInterval(interval);
                trainModelBtn.disabled = false;
                trainModelBtn.querySelector('span').textContent = 'Train New Model';
                // Don't hide the container immediately, let user see "Completed!" message
                setTimeout(() => trainingStatusContainer.classList.add('hidden'), 3000);
            }
        }, (trainingDuration * 1000) / 100); // Calculate interval based on duration
    });

    // --- INITIALIZATION ---
    initCharts();
    populateUI();
});