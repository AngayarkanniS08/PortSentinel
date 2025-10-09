document.addEventListener('DOMContentLoaded', function () {
    const startStopBtn = document.getElementById('start-stop-btn');
    const packetsTableBody = document.getElementById('packets-table-body');
    const protocolFilter = document.getElementById('protocol-filter');
    const statusFilter = document.getElementById('status-filter');
    const ipFilter = document.getElementById('ip-filter');
    const threatIntelToggle = document.getElementById('threat-intel-toggle');
    const threatIntelModal = document.getElementById('threat-intel-modal');
    const confirmThreatIntelBtn = document.getElementById('confirm-threat-intel-btn');
    const cancelThreatIntelBtn = document.getElementById('cancel-threat-intel-btn');
    const threatIntelModalTitle = document.getElementById('threat-intel-modal-title');
    const threatIntelModalBody = document.getElementById('threat-intel-modal-body');

    let isMonitoring = false;
    let socket;

    function connectSocket() {
        socket = io.connect(location.protocol + '//' + document.domain + ':' + location.port);

        socket.on('connect', () => {
            console.log('Socket connected for traffic monitor.');
        });

        socket.on('disconnect', () => {
            console.log('Socket disconnected from traffic monitor.');
        });

        socket.on('packet_data', function(data) {
            updatePacketsTable(data.packets);
        });
    }

    function toggleMonitoring() {
        isMonitoring = !isMonitoring;
        const icon = startStopBtn.querySelector('i');
        const span = startStopBtn.querySelector('span');

        if (isMonitoring) {
            startStopBtn.classList.replace('btn-success', 'btn-danger');
            icon.classList.replace('fa-play', 'fa-stop');
            span.textContent = 'Stop Monitor';
            packetsTableBody.innerHTML = '<tr><td colspan="6" class="text-center p-8 text-slate-400">Monitoring... Waiting for packets.</td></tr>';
            fetch('/start_capture', { method: 'POST' });
            if (!socket || !socket.connected) {
                connectSocket();
            }
        } else {
            startStopBtn.classList.replace('btn-danger', 'btn-success');
            icon.classList.replace('fa-stop', 'fa-play');
            span.textContent = 'Start Monitor';
            fetch('/stop_capture', { method: 'POST' });
            if (socket) {
                socket.disconnect();
            }
        }
    }

    function updatePacketsTable(packets) {
        if (packets.length === 0 && isMonitoring) {
            packetsTableBody.innerHTML = '<tr><td colspan="6" class="text-center p-8 text-slate-400">No new packets detected. Monitor is active.</td></tr>';
            return;
        }
        if (packets.length > 0) {
             packetsTableBody.innerHTML = '';
        }

        const protocolFilterValue = protocolFilter.value;
        const statusFilterValue = statusFilter.value;
        const ipFilterValue = ipFilter.value.toLowerCase();

        const filteredPackets = packets.filter(packet => {
            const protocolMatch = !protocolFilterValue || packet.protocol === protocolFilterValue;
            const statusMatch = !statusFilterValue || packet.status === statusFilterValue;
            const ipMatch = !ipFilterValue || packet.source_ip.toLowerCase().includes(ipFilterValue) || packet.dest_ip.toLowerCase().includes(ipFilterValue);
            return protocolMatch && statusMatch && ipMatch;
        });

        filteredPackets.forEach((packet, index) => {
            let statusClass = '';
            if (packet.status === 'Blocked') {
                statusClass = 'text-red-400';
            } else if (packet.status === 'Allowed') {
                statusClass = 'text-green-400';
            } else {
                statusClass = 'text-yellow-400';
            }

            const row = `
                <tr>
                    <td>${index + 1}</td>
                    <td>${packet.timestamp}</td>
                    <td><span class="proto-badge proto-${packet.protocol.toLowerCase()}">${packet.protocol}</span></td>
                    <td>${packet.source_ip}</td>
                    <td>${packet.dest_ip}</td>
                    <td class="${statusClass}">${packet.status}</td>
                </tr>`;
            packetsTableBody.insertAdjacentHTML('beforeend', row);
        });
    }

    let threatIntelState = threatIntelToggle.checked;

    threatIntelToggle.addEventListener('change', (e) => {
        const isEnabled = e.target.checked;
        threatIntelModal.classList.add('active');

        if (isEnabled) {
            threatIntelModalTitle.textContent = 'Enable Threat Intelligence';
            threatIntelModalBody.textContent = 'This will actively block IPs from known threat lists. Are you sure?';
            confirmThreatIntelBtn.className = 'btn btn-success';
        } else {
            threatIntelModalTitle.textContent = 'Disable Threat Intelligence';
            threatIntelModalBody.textContent = 'This will stop blocking IPs from threat lists. Existing blocks may remain until cleared.';
            confirmThreatIntelBtn.className = 'btn btn-danger';
        }
    });

    cancelThreatIntelBtn.addEventListener('click', () => {
        threatIntelModal.classList.remove('active');
        threatIntelToggle.checked = threatIntelState; // Revert toggle
    });

    confirmThreatIntelBtn.addEventListener('click', () => {
        threatIntelState = threatIntelToggle.checked;
        fetch('/toggle_threat_intel', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ enabled: threatIntelState })
        });
        threatIntelModal.classList.remove('active');
    });

    startStopBtn.addEventListener('click', toggleMonitoring);
    protocolFilter.addEventListener('change', () => fetch('/get_packets').then(res => res.json()).then(data => updatePacketsTable(data.packets)));
    statusFilter.addEventListener('change', () => fetch('/get_packets').then(res => res.json()).then(data => updatePacketsTable(data.packets)));
    ipFilter.addEventListener('input', () => fetch('/get_packets').then(res => res.json()).then(data => updatePacketsTable(data.packets)));
});