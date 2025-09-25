        document.addEventListener('DOMContentLoaded', function () {
            // Select all elements
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

            const logoutButton = document.getElementById('logout-button');
            const logoutModal = document.getElementById('logout-modal');
            const cancelLogoutBtn = document.getElementById('cancel-logout-btn');
            const confirmLogoutBtn = document.getElementById('confirm-logout-btn');

            const socket = io();
            let isMonitoring = false;

            startStopBtn.addEventListener('click', () => {
                isMonitoring = !isMonitoring;
                socket.emit('control_monitoring', { 'action': isMonitoring ? 'start' : 'stop' });
                updateMonitorStatusUI(isMonitoring);
            });
            
            function applyNewFilter() {
                packetsTableBody.innerHTML = `<tr><td colspan="6" class="text-center p-8 text-slate-400">Listening for packets that match your filter...</td></tr>`;
            }
            ipFilter.addEventListener('keyup', applyNewFilter);
            protocolFilter.addEventListener('change', applyNewFilter);
            statusFilter.addEventListener('change', applyNewFilter);

            logoutButton.addEventListener('click', () => {
                logoutModal.classList.add('active');
            });
            cancelLogoutBtn.addEventListener('click', () => {
                logoutModal.classList.remove('active');
            });
            confirmLogoutBtn.addEventListener('click', () => {
                window.location.href = '/logout';
            });
            logoutModal.addEventListener('click', (e) => {
                if (e.target === logoutModal) { // Overlay click panna close aagum
                    logoutModal.classList.remove('active');
                }
            });


            socket.on('connect', () => console.log('Connected to backend!'));
            socket.on('packet_update_batch', (packet_batch) => { if (isMonitoring) { packet_batch.forEach(addPacketToTable); } });
            socket.on('new_alert', (alert) => { if(isMonitoring) { addDetectionToTable(alert); } });
            socket.on('stats_update', (stats) => { if(isMonitoring) { updateStats(stats); } });

        function updateMonitorStatusUI(isRunning) {
            const statusIndicatorBox = document.getElementById('status-indicator-box');

            if (isRunning) {
                // --- Live State ---
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
                detectionsTableBody.innerHTML = '<tr><td colspan="4" class="text-center p-8 text-slate-400">Monitoring for new detections...</td></tr>';
            } else {
                // --- Idle State ---
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

                if (! (ipMatch && protoMatch && statusMatch) ) {
                    return; 
                }

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
            
            // Intha function-ah PUDHUSA REPLACE PANNUNGA
            function addDetectionToTable(alert) {
                const placeholder = detectionsTableBody.querySelector('td[colspan="5"]');
                if(placeholder) placeholder.parentElement.remove();

                const newRow = detectionsTableBody.insertRow(0);
                newRow.id = `detection-${alert.alert_id}`; // Row-ku oru unique ID kudukrom

                const severityClass = alert.severity === 'High' ? 'text-red-400' : 'text-amber-400';
                const isBlocked = alert.is_blocked;
                const statusText = isBlocked ? 'Blocked' : 'Detected';
                const statusClass = isBlocked ? 'alert-critical' : 'alert-warning';
                
                // PUDHU HTML: Toggle switch-oda serthu create panrom
                newRow.innerHTML = `
                    <td class="font-mono">${alert.ip_address}</td>
                    <td>${alert.scan_type}</td>
                    <td><span class="${severityClass}">${alert.severity}</span></td>
                    <td><span class="alert-badge ${statusClass}">${statusText}</span></td>
                    <td>
                        <label class="toggle-switch">
                            <input type="checkbox" class="ip-toggle" data-ip="${alert.ip_address}" ${isBlocked ? 'checked' : ''}>
                            <span class="slider"></span>
                        </label>
                    </td>`;

                if (detectionsTableBody.rows.length > 10) { 
                    detectionsTableBody.deleteRow(-1); 
                }
                
                // Pudhusa create panna switch-ku event listener add panrom
                addToggleListener(newRow.querySelector('.ip-toggle'));
            }

            // ITHA PUDHUSA ADD PANNUNGA
            function addToggleListener(toggleElement) {
                toggleElement.addEventListener('change', function () {
                    const ip = this.dataset.ip;
                    const action = this.checked ? 'block' : 'unblock';
                    
                    console.log(`Manual control: Requesting to ${action} IP ${ip}`);
                    
                    // Backend-ku 'manual_ip_control' event-ah anuprom
                    socket.emit('manual_ip_control', { 'ip_address': ip, 'action': action });
                });
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