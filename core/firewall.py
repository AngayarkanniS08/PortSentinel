import subprocess

class FirewallManager:
    """
    Manages interactions with Layer 3 (iptables) and Layer 2 (arptables).
    NOTE: This requires the script to be run with sudo privileges.
    """
    def block_ip(self, ip_address):
        """
        Blocks an IP at both the IP layer (iptables) and ARP layer (arptables).
        This provides a more robust block against local network scans.
        """
        print(f"Attempting full block (IP & ARP) for: {ip_address}")
        
        iptables_success = False
        arptables_success = False

        # Step 1: Block at Layer 3 (IP level) with iptables
        try:
            subprocess.run(
                ['iptables', '-I', 'INPUT', '1', '-s', ip_address, '-j', 'DROP'],
                check=True, capture_output=True, text=True
            )
            print(f"  [+] iptables rule added for {ip_address}")
            iptables_success = True
        except subprocess.CalledProcessError as e:
            # Rule already exists-nu vandha, adhu success thaan
            if "already exists" in e.stderr:
                print(f"  [!] iptables rule for {ip_address} already exists.")
                iptables_success = True
            else:
                print(f"  [-] Failed to add iptables rule for {ip_address}: {e.stderr}")

        # Step 2: Block at Layer 2 (ARP level) with arptables
        try:
            # Intha command, antha IP address-lerndhu vara ARP requests-ah drop pannidum
            subprocess.run(
                ['arptables', '-I', 'INPUT', '1', '--source-ip', ip_address, '-j', 'DROP'],
                check=True, capture_output=True, text=True
            )
            print(f"  [+] arptables rule added for {ip_address}")
            arptables_success = True
        except subprocess.CalledProcessError as e:
            if "already exists" in e.stderr:
                print(f"  [!] arptables rule for {ip_address} already exists.")
                arptables_success = True
            else:
                print(f"  [-] Failed to add arptables rule for {ip_address}: {e.stderr}")
        
        # Rendume success aana thaan, full-ah success
        if iptables_success and arptables_success:
            print(f"✅ Successfully completed full block for {ip_address}")
            return True
        else:
            return False


    def unblock_ip(self, ip_address):
        """Removes both iptables and arptables rules for an IP address."""
        print(f"Attempting to unblock (IP & ARP) for: {ip_address}")
        
        # Unblock panra bodhum, rendulayum irundhu rule-ah remove pannanum
        try:
            subprocess.run(
                ['iptables', '-D', 'INPUT', '-s', ip_address, '-j', 'DROP'],
                check=True, capture_output=True, text=True
            )
            print(f"  [+] Successfully removed iptables rule for {ip_address}")
        except subprocess.CalledProcessError:
            print(f"  [!] iptables rule for {ip_address} not found or failed to remove.")

        try:
            subprocess.run(
                ['arptables', '-D', 'INPUT', '--source-ip', ip_address, '-j', 'DROP'],
                check=True, capture_output=True, text=True
            )
            print(f"  [+] Successfully removed arptables rule for {ip_address}")
        except subprocess.CalledProcessError:
            print(f"  [!] arptables rule for {ip_address} not found or failed to remove.")
            
        print(f"✅ Unblock process finished for {ip_address}")
        return True