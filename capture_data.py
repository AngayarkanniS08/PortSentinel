import pcapy
import sys
from core.utils import find_active_interface

# --- SETTINGS ---
# Evlo neram data capture pannanum-nu inga sollunga (seconds-la)
# Example: 1 hour = 3600 seconds. 8 hours = 28800 seconds
CAPTURE_DURATION_SECONDS = 300  # Ippo test-ku 5 nimisham vechikalam

# Enga save pannanum
OUTPUT_PCAP_FILE = 'data/normal_traffic.pcap'

def main():
    """
    Normal network traffic-ah capture panni, model training-kaga oru .pcap file-la save pannum.
    """
    # 1. Active network interface-ah thedurom
    interface = find_active_interface()
    if not interface:
        print("❌ Active network interface kandupudika mudiyala. Check pannunga.")
        sys.exit(1)

    print(f"✅'{interface}' interface-la data capture panna poren...")
    print(f"⏳ Capture {CAPTURE_DURATION_SECONDS} seconds-ku nadakum. Please wait...")

    try:
        # 2. Packet capture-ah start panrom
        # 65536 = max packet size, 1 = promiscuous mode, 0 = no timeout
        cap = pcapy.open_live(interface, 65536, 1, 0)
        
        # 3. Save panrathukku oru dumper create panrom
        dumper = cap.dump_open(OUTPUT_PCAP_FILE)

        # 4. Packets-ah capture panni save panrom
        packet_count = 0
        end_time = time.time() + CAPTURE_DURATION_SECONDS
        
        while time.time() < end_time:
            header, packet = cap.next()
            if packet:
                dumper.dump(header, packet)
                packet_count += 1
        
        print(f"\n🎉 Capture mudinjathu!")
        print(f"📊 മൊത്തം {packet_count} packets capture panni, '{OUTPUT_PCAP_FILE}'-la save panniyachu.")
        print("💡 Ippo namma 'trainer.py' script vechi model-ah train pannalam.")

    except pcapy.PcapError as e:
        print(f"\n❌ CRITICAL ERROR: {e}")
        print("sudo vechi run panni parunga: 'sudo python capture_data.py'")
    except Exception as e:
        print(f"\nAn unexpected error occurred: {e}")

if __name__ == '__main__':
    # Namma time module-ah import pannanum
    import time
    main()