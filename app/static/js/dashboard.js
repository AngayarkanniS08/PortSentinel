
    document.addEventListener('DOMContentLoaded', function () {
        // ==========================================================
        // 1. ELEMENT SELECTIONS (ELLA ELEMENTS-UM INGA IRUKKU)
        // ==========================================================
        const startStopBtn = document.getElementById('start-stop-btn');
        const startStopBtnIcon = startStopBtn.querySelector('i');
        const startStopBtnText = startStopBtn.querySelector('span');
        const statusDot = document.getElementById('status-dot');
        const statusText = document.getElementById('status-text');
        const packetsTableBody = document.getElementById('packets-table-body');
        const detectionsTableBody = document.getElementById('detections-table-body');
        const packetsProcessedEl = document.getElementById('packets-processed');
        const alertsTriggeredEl = document.getElementById('alerts-triggered');
        const detectedIpsEl = document.getElementById('detected-ips');
        const currentTrafficEl = document.getElementById('current-traffic');
        const statsInterfaceEl = document.getElementById('stats-interface');
        const statsUptimeEl = document.getElementById('stats-uptime');
        const statsAccuracyEl = document.getElementById('stats-accuracy');
        const statsTrafficLoadValueEl = document.getElementById('stats-traffic-load-value');
        const statsTrafficLoadBarEl = document.getElementById('stats-traffic-load-bar');
        const scanAnimationEl = document.querySelector('.scan-animation');
        const ipFilter = document.getElementById('ip-filter');
        const protocolFilter = document.getElementById('protocol-filter');
        const statusFilter = document.getElementById('status-filter');

        // Logout Modal Elements
        const logoutButton = document.getElementById('logout-button');
        const logoutModal = document.getElementById('logout-modal');
        const cancelLogoutBtn = document.getElementById('cancel-logout-btn');
        const confirmLogoutBtn = document.getElementById('confirm-logout-btn');

        // PUTHU IP Action Modal Elements
        const ipActionModal = document.getElementById('ip-action-modal');
        const modalTitle = document.getElementById('modal-title');
        const modalBody = document.getElementById('modal-body');
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
        // 3. EVENT LISTENERS (ELLA BUTTON CLICKS-UM INGA HANDLE AAGUM)
        // ==========================================================

        // Start/Stop Monitor Button
        startStopBtn.addEventListener('click', () => {
            isMonitoring = !isMonitoring;
            socket.emit('control_monitoring', { 'action': isMonitoring ? 'start' : 'stop' });
            updateMonitorStatusUI(isMonitoring);
        });

        // Filter Inputs
        function applyNewFilter() {
            packetsTableBody.innerHTML = `<tr><td colspan="6" class="text-center p-8 text-slate-400">Listening for packets that match your filter...</td></tr>`;
        }
        ipFilter.addEventListener('keyup', applyNewFilter);
        protocolFilter.addEventListener('change', applyNewFilter);
        statusFilter.addEventListener('change', applyNewFilter);

        // Logout Logic
        logoutButton.addEventListener('click', () => { logoutModal.classList.add('active'); });
        cancelLogoutBtn.addEventListener('click', () => { logoutModal.classList.remove('active'); });
        confirmLogoutBtn.addEventListener('click', () => { window.location.href = '/logout'; });
        logoutModal.addEventListener('click', (e) => {
            if (e.target === logoutModal) { logoutModal.classList.remove('active'); }
        });

        // --- PUTHU CONFIRMATION MODAL LOGIC ---
        // 'Block' or 'Unblock' button-ah table-la click panna
        detectionsTableBody.addEventListener('click', function(event) {
            const actionButton = event.target.closest('.action-btn');
            if (!actionButton) return;

            currentIpToAction = actionButton.dataset.ip;
            currentAction = actionButton.dataset.action; // 'block' or 'unblock'

            if (currentAction === 'block') {
                modalTitle.innerText = 'Confirm Block';
                modalBody.innerHTML = `Are you sure you want to block IP: <br><strong>${currentIpToAction}</strong>?`;
                confirmActionBtn.className = 'btn btn-danger';
                confirmActionBtn.innerText = 'Confirm Block';
            } else {
                modalTitle.innerText = 'Confirm Unblock';
                modalBody.innerHTML = `Are you sure you want to unblock IP: <br><strong>${currentIpToAction}</strong>?`;
                confirmActionBtn.className = 'btn btn-success';
                confirmActionBtn.innerText = 'Confirm Unblock';
            }
            ipActionModal.classList.add('active');
        });

        // Modal-la "Confirm" button-ah click panna
        confirmActionBtn.addEventListener('click', () => {
            if (currentIpToAction && currentAction) {
                const eventName = `${currentAction}_ip_request`;
                socket.emit(eventName, { 'ip': currentIpToAction });
                
                const buttonInTable = detectionsTableBody.querySelector(`.action-btn[data-ip="${currentIpToAction}"]`);
                if(buttonInTable) {
                    buttonInTable.innerHTML = '<i class="fas fa-spinner fa-spin"></i>';
                    buttonInTable.disabled = true;
                }
            }
            ipActionModal.classList.remove('active');
        });

        // Modal-la "Cancel" button-ah click panna
        cancelActionBtn.addEventListener('click', () => { ipActionModal.classList.remove('active'); });

        // ==========================================================
        // 4. SOCKET.IO EVENT HANDLERS (BACKEND-LA IRUNDHU VARRA DATA)
        // ==========================================================
        socket.on('connect', () => console.log('Connected to backend!'));
        socket.on('packet_update_batch', (packet_batch) => { if (isMonitoring) { packet_batch.forEach(addPacketToTable); } });
        socket.on('new_alert', (alert) => { if(isMonitoring) { addDetectionToTable(alert); } });
        socket.on('stats_update', (stats) => { if(isMonitoring) { updateStats(stats); } });

        // Block/Unblock action-oda result vandha
        socket.on('ip_action_status', (data) => {
            const button = detectionsTableBody.querySelector(`button[data-ip="${data.ip}"]`);
            const cell = button?.parentElement;
            if (!cell) return;
            
            if (data.success) {
                if (data.action === 'block') {
                    cell.innerHTML = `<button class="btn btn-success action-btn" style="padding: 5px 10px; font-size: 12px;" data-ip="${data.ip}" data-action="unblock"><i class="fas fa-check"></i> Unblock</button>`;
                } else {
                    cell.innerHTML = `<button class="btn btn-danger action-btn" style="padding: 5px 10px; font-size: 12px;" data-ip="${data.ip}" data-action="block"><i class="fas fa-ban"></i> Block</button>`;
                }
            } else {
                alert(`Failed to ${data.action} IP: ${data.ip}`);
                button.innerHTML = data.action === 'block' ? '<i class="fas fa-ban"></i> Block' : '<i class="fas fa-check"></i> Unblock';
                button.disabled = false;
            }
        });

        // ==========================================================
        // 5. UI UPDATE FUNCTIONS (SCREEN-AH UPDATE PANRA LOGIC)
        // ==========================================================

        function addDetectionToTable(alert) {
            const placeholder = detectionsTableBody.querySelector('td[colspan="5"]');
            if(placeholder) placeholder.parentElement.remove();
            
            const newRow = detectionsTableBody.insertRow(0);
            
            const severityClass = alert.severity.toLowerCase() === 'critical' ? 'text-red-600 font-bold' :
                                  alert.severity.toLowerCase() === 'high' ? 'text-red-400' :
                                  alert.severity.toLowerCase() === 'medium' ? 'text-amber-400' : 'text-blue-400';

            let intelCellHtml = '<td>N/A</td>';
            if (alert.intel && alert.intel.score !== undefined) {
                let score = alert.intel.score;
                let scoreColor = score > 80 ? 'text-red-500' : score > 50 ? 'text-amber-500' : 'text-green-500';
                intelCellHtml = `<td>
                                    <span class="${scoreColor} font-semibold">${score}%</span>
                                    <span class="text-xs text-slate-400">(${alert.intel.country})</span>
                                 </td>`;
            }

            let actionCellHtml;
            if (alert.is_blocked) {
                actionCellHtml = `<td><button class="btn btn-success action-btn" style="padding: 5px 10px; font-size: 12px;" data-ip="${alert.ip_address}" data-action="unblock"><i class="fas fa-check"></i> Unblock</button></td>`;
            } else {
                actionCellHtml = `<td><button class="btn btn-danger action-btn" style="padding: 5px 10px; font-size: 12px;" data-ip="${alert.ip_address}" data-action="block"><i class="fas fa-ban"></i> Block</button></td>`;
            }
            
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
        
        function updateMonitorStatusUI(isRunning) {
            const statusIndicatorBox = document.getElementById('status-indicator-box');
            if (isRunning) {
                startStopBtnIcon.className = 'fas fa-pause';
                startStopBtnText.innerText = 'Stop Monitor';
                startStopBtn.classList.remove('btn-success');
                startStopBtn.classList.add('btn-danger');
                statusIndicatorBox.classList.remove('status-idle');
                statusIndicatorBox.classList.add('status-live');
                statusDot.className = 'status-dot bg-green-500';
                statusText.innerText = 'Live Monitor';
                statusText.classList.remove('text-idle');
                statusText.classList.add('text-live');
                scanAnimationEl.classList.remove('scan-red');
                scanAnimationEl.classList.add('scan-green');
                applyNewFilter(); 
                detectionsTableBody.innerHTML = '<tr><td colspan="5" class="text-center p-8 text-slate-400">Monitoring for new detections...</td></tr>';
            } else {
                startStopBtnIcon.className = 'fas fa-play';
                startStopBtnText.innerText = 'Start Monitor';
                startStopBtn.classList.remove('btn-danger');
                startStopBtn.classList.add('btn-success');
                statusIndicatorBox.classList.remove('status-live');
                statusIndicatorBox.classList.add('status-idle');
                statusDot.className = 'status-dot bg-red-500 blinking';
                statusText.innerText = 'Monitor Idle';
                statusText.classList.remove('text-live');
                statusText.classList.add('text-idle');
                scanAnimationEl.classList.remove('scan-green');
                scanAnimationEl.classList.add('scan-red');
            }
        }

        function addPacketToTable(packet) {
            const ipQuery = ipFilter.value.toLowerCase();
            const protoQuery = protocolFilter.value;
            const statusQuery = statusFilter.value;
            const sourceIp = packet.source_ip.toLowerCase();
            const destIp = packet.dest_ip.toLowerCase();
            const ipMatch = ipQuery === "" || sourceIp.includes(ipQuery) || destIp.includes(ipQuery);
            const protoMatch = protoQuery === "" || packet.proto === protoQuery;
            const statusMatch = statusQuery === "" || packet.status === statusQuery;

            if (! (ipMatch && protoMatch && statusMatch) ) return;

            if (packetsTableBody.rows.length > 0 && packetsTableBody.rows[0].cells[0].colSpan > 1) {
                packetsTableBody.innerHTML = '';
            }

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
        
        function updateStats(stats){
            packetsProcessedEl.innerText = stats.packets_processed.toLocaleString();
            alertsTriggeredEl.innerText = stats.alerts_triggered.toLocaleString();
            detectedIpsEl.innerText = stats.detected_ips_count.toLocaleString();
            currentTrafficEl.innerText = `${stats.current_traffic_pps}/s`;
            statsInterfaceEl.innerText = stats.interface;
            statsUptimeEl.innerText = stats.uptime;
            statsAccuracyEl.innerText = `${stats.detection_accuracy}%`;
            statsTrafficLoadValueEl.innerText = `${stats.traffic_load_percent}%`;
            statsTrafficLoadBarEl.style.width = `${stats.traffic_load_percent}%`;
            document.getElementById('packets-progress-bar').style.width = `${stats.packets_bar_percent || 0}%`;
            document.getElementById('alerts-progress-bar').style.width = `${stats.alerts_bar_percent || 0}%`;
            document.getElementById('ips-progress-bar').style.width = `${stats.ips_bar_percent || 0}%`;
            document.getElementById('traffic-progress-bar').style.width = `${stats.traffic_bar_percent || 0}%`;
        }
    });
