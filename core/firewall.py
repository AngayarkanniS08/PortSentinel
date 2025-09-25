import subprocess

class FirewallManager:
    """
    Manages interactions with the system's firewall (iptables).
    NOTE: This requires the script to be run with sudo privileges.
    """
    def block_ip(self, ip_address):
        """Adds a firewall rule to block an IP address."""
        print(f"Attempting to block IP: {ip_address}")
        try:
            # Use '-I INPUT 1' to insert the rule at the top of the chain
            subprocess.run(
                ['iptables', '-I', 'INPUT', '1', '-s', ip_address, '-j', 'DROP'],
                check=True,
                capture_output=True,
                text=True
            )
            print(f"Successfully blocked IP: {ip_address}")
            return True
        except subprocess.CalledProcessError as e:
            print(f"Failed to block IP {ip_address}: {e.stderr}")
            return False

    def unblock_ip(self, ip_address):
        """Removes a firewall rule to unblock an IP address."""
        print(f"Attempting to unblock IP: {ip_address}")
        try:
            subprocess.run(
                ['iptables', '-D', 'INPUT', '-s', ip_address, '-j', 'DROP'],
                check=True,
                capture_output=True,
                text=True
            )
            print(f"Successfully unblocked IP: {ip_address}")
            return True
        except subprocess.CalledProcessError as e:
            print(f"Failed to unblock IP {ip_address}. It might not be blocked: {e.stderr}")
            return False
