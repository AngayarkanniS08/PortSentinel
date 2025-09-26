document.addEventListener('DOMContentLoaded', function () {
    // ==========================================================
    // 1. ELEMENT SELECTIONS
    // ==========================================================
    const startStopBtn = document.getElementById('start-stop-btn');
    const packetsTableBody = document.getElementById('packets-table-body');
    const detectionsTableBody = document.querySelector('.recent-detections-card tbody');
    const ipFilter = document.getElementById('ip-filter');
    const protocolFilter = document.getElementById('protocol-filter');
    const statusFilter = document.getElementById('status-filter');
    const threatIntelToggle = document.getElementById('threat-intel-toggle');
    
    // Common elements present on both pages
    const statusIndicatorBox = document.getElementById('status-indicator-box');
    const statusDot = document.getElementById('status-dot');
    const statusText = document.getElementById('status-text');
    const logoutButton = document.getElementById('logout-button');
    const logoutModal = document.getElementById('logout-modal');
    const cancelLogoutBtn = document.getElementById('cancel-logout-btn');
    const confirmLogoutBtn = document.getElementById('confirm-logout-btn');
    
    // Modals
    const ipActionModal = document.getElementById('ip-action-modal');
    const cancelActionBtn = document.getElementById('cancel-action-btn');
    const confirmActionBtn = document.getElementById('confirm-action-btn');

    // ==========================================================
    // 2. STATE & SOCKET.IO SETUP
    // ==========================================================
    const socket = io();
    let isMonitoring = false;
    let currentIpToAction = null;
    let currentAction = null;

    // ==========================================================
    // 3. EVENT LISTENERS (with null checks)
    // ==========================================================

    if (startStopBtn) {
        startStopBtn.addEventListener('click', () => {
            const action = !isMonitoring ? 'start' : 'stop';
            socket.emit('control_monitoring', { 'action': action });
        });
    }
    
    if (threatIntelToggle) {
        threatIntelToggle.addEventListener('change', function() {
            socket.emit('toggle_threat_intel', { 'enabled': this.checked });
        });
    }

    function applyNewFilter() {
        if (packetsTableBody) {
            packetsTableBody.innerHTML = `<tr><td colspan="6" class="text-center p-8 text-slate-400">Listening for packets that match your filter...</td></tr>`;
        }
    }
    if (ipFilter) ipFilter.addEventListener('keyup', applyNewFilter);
    if (protocolFilter) protocolFilter.addEventListener('change', applyNewFilter);
    if (statusFilter) statusFilter.addEventListener('change', applyNewFilter);

    if (logoutButton) logoutButton.addEventListener('click', () => logoutModal.classList.add('active'));
    if (cancelLogoutBtn) cancelLogoutBtn.addEventListener('click', () => logoutModal.classList.remove('active'));
    if (confirmLogoutBtn) confirmLogoutBtn.addEventListener('click', () => { window.location.href = '/logout'; });

    if (detectionsTableBody) {
        detectionsTableBody.addEventListener('click', function(event) {
            const actionButton = event.target.closest('.action-btn');
            if (!actionButton) return;

            currentIpToAction = actionButton.dataset.ip;
            currentAction = actionButton.dataset.action;
            
            const modalTitle = document.getElementById('modal-title');
            const modalBody = document.getElementById('modal-body');

            if (currentAction === 'block') {
                modalTitle.innerText = 'Confirm Block';
                modalBody.innerHTML = `Are you sure you want to block IP: <br><strong>${currentIpToAction}</strong>?`;
            } else {
                modalTitle.innerText = 'Confirm Unblock';
                modalBody.innerHTML = `Are you sure you want to unblock IP: <br><strong>${currentIpToAction}</strong>?`;
            }
            ipActionModal.classList.add('active');
        });
    }

    if (confirmActionBtn) {
        confirmActionBtn.addEventListener('click', () => {
            if (currentIpToAction && currentAction) {
                socket.emit(`${currentAction}_ip_request`, { 'ip': currentIpToAction });
                const buttonInTable = detectionsTableBody.querySelector(`.action-btn[data-ip="${currentIpToAction}"]`);
                if(buttonInTable) {
                    buttonInTable.innerHTML = '<i class="fas fa-spinner fa-spin"></i>';
                    buttonInTable.disabled = true;
                }
            }
            if (ipActionModal) ipActionModal.classList.remove('active');
        });
    }
    
    if (cancelActionBtn) cancelActionBtn.addEventListener('click', () => ipActionModal.classList.remove('active'));

    // ==========================================================
    // 4. SOCKET.IO EVENT HANDLERS
    // ==========================================================
    socket.on('connect', () => console.log('Connected to backend!'));
    
    socket.on('packet_update_batch', (packet_batch) => { 
        if(packetsTableBody) packet_batch.forEach(addPacketToTable); 
    });

    socket.on('new_alert', (alert) => { 
        if(detectionsTableBody) addDetectionToTable(alert);
    });

    socket.on('stats_update', (stats) => { 
        // Dashboard page-la mattum irukura elements-ku oru check
        if(document.getElementById('packets-processed')) {
            updateStats(stats); 
        }
    });

    socket.on('monitor_status_update', (data) => {
        isMonitoring = data.is_running;
        updateMonitorStatusUI(isMonitoring);
    });

    socket.on('threat_intel_status_update', (data) => {
        if (threatIntelToggle) threatIntelToggle.checked = data.is_enabled;
    });
    
    socket.on('ip_action_status', (data) => {
        if (!detectionsTableBody) return;
        const button = detectionsTableBody.querySelector(`button[data-ip="${data.ip}"]`);
        if (!button) return;
        const cell = button.parentElement;
        if (data.success) {
            cell.innerHTML = data.action === 'block' 
                ? `<button class="btn btn-success action-btn" style="padding: 5px 10px; font-size: 12px;" data-ip="${data.ip}" data-action="unblock"><i class="fas fa-check"></i> Unblock</button>`
                : `<button class="btn btn-danger action-btn" style="padding: 5px 10px; font-size: 12px;" data-ip="${data.ip}" data-action="block"><i class="fas fa-ban"></i> Block</button>`;
        } else {
            alert(`Failed to ${data.action} IP: ${data.ip}`);
            button.innerHTML = data.action === 'block' ? '<i class="fas fa-ban"></i> Block' : '<i class="fas fa-check"></i> Unblock';
            button.disabled = false;
        }
    });

    // ==========================================================
    // 5. UI UPDATE FUNCTIONS (Corrected and complete)
    // ==========================================================
    
    function updateMonitorStatusUI(isRunning) {
        const scanAnimationEl = document.querySelector('.scan-animation');

        if (isRunning) {
            if(startStopBtn) {
                startStopBtn.querySelector('i').className = 'fas fa-pause';
                startStopBtn.querySelector('span').innerText = 'Stop Monitor';
                startStopBtn.classList.remove('btn-success');
                startStopBtn.classList.add('btn-danger');
            }
            if(scanAnimationEl) {
                scanAnimationEl.classList.remove('scan-red');
                scanAnimationEl.classList.add('scan-green');
            }
            if(packetsTableBody) applyNewFilter();
            
            statusIndicatorBox.classList.remove('status-idle');
            statusIndicatorBox.classList.add('status-live');
            statusDot.className = 'status-dot bg-green-500';
            statusText.innerText = 'Live Monitor';
            statusText.classList.remove('text-idle');
            statusText.classList.add('text-live');

        } else {
             if(startStopBtn) {
                startStopBtn.querySelector('i').className = 'fas fa-play';
                startStopBtn.querySelector('span').innerText = 'Start Monitor';
                startStopBtn.classList.remove('btn-danger');
                startStopBtn.classList.add('btn-success');
            }
            if(scanAnimationEl) {
                scanAnimationEl.classList.remove('scan-green');
                scanAnimationEl.classList.add('scan-red');
            }
            if(packetsTableBody) packetsTableBody.innerHTML = `<tr><td colspan="6" class="text-center p-8 text-slate-400">Click 'Start Monitor' to see live traffic.</td></tr>`;

            statusIndicatorBox.classList.remove('status-live');
            statusIndicatorBox.classList.add('status-idle');
            statusDot.className = 'status-dot bg-red-500 blinking';
            statusText.innerText = 'Monitor Idle';
            statusText.classList.remove('text-live');
            statusText.classList.add('text-idle');
        }
    }

    function addPacketToTable(packet) {
        if (packetsTableBody.rows.length > 0 && packetsTableBody.rows[0].cells[0].colSpan > 1) {
            packetsTableBody.innerHTML = '';
        }
        // ... (rest of the function from your original file)
        const newRow = packetsTableBody.insertRow(0);
        let statusBadge = '';
        if (packet.status === 'Scan') statusBadge = '<span class="alert-badge alert-warning">Scan</span>';
        else if (packet.status === 'Blocked') statusBadge = '<span class="alert-badge alert-critical">Blocked</span>';
        else statusBadge = '<span class="alert-badge alert-info">Allowed</span>';

        let protoBadge = '';
        switch(packet.proto.toUpperCase()) {
            case 'TCP': protoBadge = '<span class="proto-badge proto-tcp">TCP</span>'; break;
            case 'UDP': protoBadge = '<span class="proto-badge proto-udp">UDP</span>'; break;
            case 'ICMP': protoBadge = '<span class="proto-badge proto-icmp">ICMP</span>'; break;
            default: protoBadge = `<span class="proto-badge proto-unknown">${packet.proto}</span>`;
        }

        newRow.innerHTML = `
            <td>${packet.sno}</td> 
            <td>${packet.time}</td> 
            <td>${protoBadge}</td> 
            <td class="font-mono">${packet.source_ip}</td> 
            <td class="font-mono">${packet.dest_ip}</td> 
            <td>${statusBadge}</td>`;
        
        if (packetsTableBody.rows.length > 200) {
            packetsTableBody.deleteRow(-1); 
        }
    }
    
    function updateStats(stats) {
        document.getElementById('packets-processed').innerText = stats.packets_processed.toLocaleString();
        document.getElementById('alerts-triggered').innerText = stats.alerts_triggered.toLocaleString();
        document.getElementById('detected-ips').innerText = stats.detected_ips_count.toLocaleString();
        document.getElementById('current-traffic').innerText = `${stats.current_traffic_pps}/s`;
        document.getElementById('stats-interface').innerText = stats.interface;
        document.getElementById('stats-uptime').innerText = stats.uptime;
        document.getElementById('stats-accuracy').innerText = `${stats.detection_accuracy}%`;
        document.getElementById('stats-traffic-load-value').innerText = `${stats.traffic_load_percent}%`;
        document.getElementById('stats-traffic-load-bar').style.width = `${stats.traffic_load_percent}%`;
        document.getElementById('packets-progress-bar').style.width = `${stats.packets_bar_percent || 0}%`;
        document.getElementById('alerts-progress-bar').style.width = `${stats.alerts_bar_percent || 0}%`;
        document.getElementById('ips-progress-bar').style.width = `${stats.ips_bar_percent || 0}%`;
        document.getElementById('traffic-progress-bar').style.width = `${stats.traffic_bar_percent || 0}%`;
    }

    // This function for adding detections needs to exist
    function addDetectionToTable(alert) {
        const placeholder = detectionsTableBody.querySelector('td[colspan="5"]');
        if(placeholder) placeholder.parentElement.remove();
        
        const newRow = detectionsTableBody.insertRow(0);
        
        const severityClass = alert.severity.toLowerCase() === 'critical' ? 'text-red-600 font-bold' : 'text-amber-400';

        let intelCellHtml = '<td>N/A</td>';
        if (alert.intel && alert.intel.score !== undefined) {
            let score = alert.intel.score;
            let scoreColor = score > 80 ? 'text-red-500' : score > 50 ? 'text-amber-500' : 'text-green-500';
            intelCellHtml = `<td>
                                <span class="${scoreColor} font-semibold">${score}%</span>
                                <span class="text-xs text-slate-400">(${alert.intel.country})</span>
                             </td>`;
        }

        const actionCellHtml = alert.is_blocked
            ? `<td><button class="btn btn-success action-btn" style="padding: 5px 10px; font-size: 12px;" data-ip="${alert.ip_address}" data-action="unblock"><i class="fas fa-check"></i> Unblock</button></td>`
            : `<td><button class="btn btn-danger action-btn" style="padding: 5px 10px; font-size: 12px;" data-ip="${alert.ip_address}" data-action="block"><i class="fas fa-ban"></i> Block</button></td>`;
        
        newRow.innerHTML = `
            <td class="font-mono">${alert.ip_address}</td> 
            <td>${alert.scan_type}</td> 
            <td><span class="${severityClass}">${alert.severity}</span></td>
            ${intelCellHtml}
            ${actionCellHtml}`;

        if (detectionsTableBody.rows.length > 5) { 
            detectionsTableBody.deleteRow(-1); 
        }
    }
});