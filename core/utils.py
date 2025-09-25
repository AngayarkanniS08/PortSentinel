import time
import socket
import psutil
import fcntl
import struct

def find_active_interface():
    """
    Finds the first active, non-loopback network interface with an IPv4 address.
    This method is reliable and cross-platform.
    """
    # Get a dictionary of all network interface cards (NICs)
    all_nics = psutil.net_if_addrs()
    
    # Get a dictionary of NIC stats (including if they are up)
    nic_stats = psutil.net_if_stats()

    for interface_name, addresses in all_nics.items():
        # Check if the interface is 'up' and not the loopback interface
        if interface_name in nic_stats and nic_stats[interface_name].isup and interface_name != 'lo':
            # Check if it has an IPv4 address
            for addr in addresses:
                if addr.family == socket.AF_INET:
                    print(f"✅ Found active interface: {interface_name}")
                    return interface_name

    print("⚠️ WARNING: Could not find an active interface. Check network connections.")
    return None


class SystemMonitor:
    """Manages system-related stats like uptime."""
    def __init__(self):
        self.start_time = None

    def start_timer(self):
        """
        Starts the uptime timer when monitoring begins.
        (Intha function illama thaan error vandhuchu, ippo add panniyachu)
        """
        self.start_time = time.time()
        print("Uptime timer started.")

    def get_uptime(self):
        """
        Calculates and formats uptime, showing only relevant units.
        """
        if self.start_time is None:
            return '0m 0s' 

        uptime_seconds = int(time.time() - self.start_time)
        
        days = uptime_seconds // (24 * 3600)
        remainder = uptime_seconds % (24 * 3600)
        hours = remainder // 3600
        remainder %= 3600
        minutes = remainder // 60
        seconds = remainder % 60
        
        # Build the string based on what's available
        if days > 0:
            return f"{days}d {hours}h {minutes}m"
        elif hours > 0:
            return f"{hours}h {minutes}m {seconds}s"
        else:
            return f"{minutes}m {seconds}s"

