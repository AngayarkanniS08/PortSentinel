// file: app/static/js/traffic_monitor.js
document.addEventListener('DOMContentLoaded', function () {
    // ==========================================================
    // 1. ELEMENT SELECTIONS
    // ==========================================================
    const trafficStartStopBtn = document.getElementById('start-stop-btn');
    const packetsTableBody = document.getElementById('packets-table-body');
    const ipFilter = document.getElementById('ip-filter');
    const protocolFilter = document.getElementById('protocol-filter');
    const statusFilter = document.getElementById('status-filter');
    const statusIndicatorBox = document.getElementById('status-indicator-box');
    const statusDot = document.getElementById('status-dot');
    const statusText = document.getElementById('status-text');

    // ==========================================================
    // 2. STATE & SOCKET.IO SETUP
    // ==========================================================
    const socket = io();
    let isMonitoring = false;

    // ==========================================================
    // 3. EVENT LISTENERS
    // ==========================================================

    function handleStartStopClick() {
        const action = !isMonitoring ? 'start' : 'stop';
        socket.emit('control_monitoring', { 'action': action });
    }

    if (trafficStartStopBtn) {
        trafficStartStopBtn.addEventListener('click', handleStartStopClick);
    }

    function applyNewFilter() {
        if (packetsTableBody) {
            packetsTableBody.innerHTML = `<tr><td colspan="6" class="text-center p-8 text-slate-400">Listening for packets that match your filter...</td></tr>`;
        }
    }
    if (ipFilter) ipFilter.addEventListener('keyup', applyNewFilter);
    if (protocolFilter) protocolFilter.addEventListener('change', applyNewFilter);
    if (statusFilter) statusFilter.addEventListener('change', applyNewFilter);

    // ==========================================================
    // 4. SOCKET.IO EVENT HANDLERS
    // ==========================================================
    socket.on('connect', () => console.log('Connected to backend!'));

    socket.on('packet_update_batch', (packet_batch) => {
        if (!packetsTableBody) return;
        
        // Get current filter values
        const ipFilterVal = ipFilter ? ipFilter.value.toLowerCase() : '';
        const protoFilterVal = protocolFilter ? protocolFilter.value : 'ALL';
        const statusFilterVal = statusFilter ? statusFilter.value : 'ALL';

        // Filter the batch based on UI controls
        const filtered_batch = packet_batch.filter(packet => {
            const packet_ip = `${packet.source_ip} ${packet.dest_ip}`.toLowerCase();
            const proto_match = protoFilterVal === 'ALL' || packet.proto.toUpperCase() === protoFilterVal;
            const status_match = statusFilterVal === 'ALL' || packet.status === statusFilterVal;
            const ip_match = ipFilterVal === '' || packet_ip.includes(ipFilterVal);
            return proto_match && status_match && ip_match;
        });

        // *** ITHU THAAN PUTHU FIX ***
        // Add the filtered packets to the table
        filtered_batch.forEach(addPacketToTable);
    });

    socket.on('monitor_status_update', (data) => {
        isMonitoring = data.is_running;
        updateMonitorStatusUI(isMonitoring);
    });

    // ==========================================================
    // 5. UI UPDATE FUNCTIONS
    // ==========================================================

    function updateMonitorStatusUI(isRunning) {
        const scanAnimationEl = document.querySelector('.scan-animation');

        if (isRunning) {
            if (trafficStartStopBtn) {
                trafficStartStopBtn.querySelector('i').className = 'fas fa-pause';
                trafficStartStopBtn.querySelector('span').innerText = 'Stop Monitor';
                trafficStartStopBtn.classList.remove('btn-success');
                trafficStartStopBtn.classList.add('btn-danger');
            }
            if (scanAnimationEl) {
                scanAnimationEl.classList.remove('scan-red');
                scanAnimationEl.classList.add('scan-green');
            }
            if (statusIndicatorBox) {
                statusIndicatorBox.classList.remove('status-idle');
                statusIndicatorBox.classList.add('status-live');
                statusDot.className = 'status-dot bg-green-500';
                statusText.innerText = 'Live Monitor';
                statusText.classList.remove('text-idle');
                statusText.classList.add('text-live');
            }
             if (packetsTableBody && packetsTableBody.rows.length > 0 && packetsTableBody.rows[0].cells[0].colSpan > 1) {
                packetsTableBody.innerHTML = `<tr><td colspan="6" class="text-center p-8 text-slate-400">Listening for packets...</td></tr>`;
            }

        } else {
            if (trafficStartStopBtn) {
                trafficStartStopBtn.querySelector('i').className = 'fas fa-play';
                trafficStartStopBtn.querySelector('span').innerText = 'Start Monitor';
                trafficStartStopBtn.classList.remove('btn-danger');
                trafficStartStopBtn.classList.add('btn-success');
            }
            if (scanAnimationEl) {
                scanAnimationEl.classList.remove('scan-green');
                scanAnimationEl.classList.add('scan-red');
            }
            if (packetsTableBody) packetsTableBody.innerHTML = `<tr><td colspan="6" class="text-center p-8 text-slate-400">Click 'Start Monitor' to see live traffic.</td></tr>`;
            
            if (statusIndicatorBox) {
                statusIndicatorBox.classList.remove('status-live');
                statusIndicatorBox.classList.add('status-idle');
                statusDot.className = 'status-dot bg-red-500 blinking';
                statusText.innerText = 'Monitor Idle';
                statusText.classList.remove('text-live');
                statusText.classList.add('text-idle');
            }
        }
    }

    function addPacketToTable(packet) {
        if (!packetsTableBody) return;
        // Clear placeholder if it exists
        if (packetsTableBody.rows.length > 0 && packetsTableBody.rows[0].cells[0].colSpan > 1) packetsTableBody.innerHTML = '';
        
        const newRow = packetsTableBody.insertRow(0);
        
        let statusBadge = '';
        if (packet.status === 'Scan') statusBadge = '<span class="alert-badge alert-warning">Scan</span>';
        else if (packet.status === 'Blocked') statusBadge = '<span class="alert-badge alert-critical">Blocked</span>';
        else statusBadge = '<span class="alert-badge alert-info">Allowed</span>';
        
        let protoBadge = '';
        switch (packet.proto.toUpperCase()) {
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
            <td>${statusBadge}</td>
        `;
        
        // Limit table rows to 200 for performance
        if (packetsTableBody.rows.length > 200) packetsTableBody.deleteRow(-1);
    }

    // Initial check on load
    socket.emit('get_monitor_status');
});