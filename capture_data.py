import pcapy
import sys
import time # time module-ah mela import pannikonga

# --- SETTINGS ---
# Hardcoded time-ah remove pannitom
# CAPTURE_DURATION_SECONDS = 300 
OUTPUT_PCAP_FILE = 'data/normal_traffic.pcap'

def main():
    """
    Normal network traffic-ah capture panni, model training-kaga oru .pcap file-la save pannum.
    """
    # --- PUTHU CHANGE: User kudutha time-ah eduthukrom ---
    try:
        # Command-line la irundhu varra neratha eduthukrom (default ah 300 seconds)
        capture_duration = int(sys.argv[1]) if len(sys.argv) > 1 else 300
    except (ValueError, IndexError):
        print("❌ Invalid time kuduthurukeenga. Default ah 5 nimisham eduthukuren.")
        capture_duration = 300
    
    # Active network interface-ah thedurom
    # (From core.utils import find_active_interface)
    # Note: Intha script thaniya run aagurathala, namma core module-ah theda vekkanum
    try:
        from core.utils import find_active_interface
    except ImportError:
        print("❌ Core modules-ah load panna mudiyala. Project root folder-la irundhu run panreengala nu paarunga.")
        sys.exit(1)

    interface = find_active_interface()
    if not interface:
        print("❌ Active network interface kandupudika mudiyala. Check pannunga.")
        sys.exit(1)

    print(f"✅ '{interface}' interface-la data capture panna poren...")
    print(f"⏳ Capture {capture_duration // 60} nimisham {capture_duration % 60} seconds-ku nadakum. Please wait...")

    try:
        cap = pcapy.open_live(interface, 65536, 1, 0)
        dumper = cap.dump_open(OUTPUT_PCAP_FILE)

        packet_count = 0
        end_time = time.time() + capture_duration
        
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
    except (KeyboardInterrupt, SystemExit):
        print("\n⏹️ Capture cancelled by user.")
    except Exception as e:
        print(f"\nAn unexpected error occurred: {e}")

if __name__ == '__main__':
    main()