from scapy.all import rdpcap, IP, TCP, SMB2_Header
import json
from datetime import datetime

def extract_smb_info(pcap_file):
    packets = rdpcap(pcap_file)
    smb_operations = []

    for packet in packets:
        if packet.haslayer(SMB2_Header):
            smb_header = packet[SMB2_Header]
            operation = {
                'timestamp': datetime.fromtimestamp(float(packet.time)).isoformat(),
                'src_ip': packet[IP].src,
                'src_port': packet[TCP].sport,
                'dst_ip': packet[IP].dst,
                'dst_port': packet[TCP].dport,
                'command': smb_header.Command
            }

            # Try to extract filename and file size if available
            try:
                if hasattr(packet, 'FileName'):
                    operation['filename'] = packet.FileName.decode('utf-16-le')
                elif hasattr(packet, 'File_Name'):
                    operation['filename'] = packet.File_Name.decode('utf-16-le')
            except AttributeError:
                pass

            try:
                if hasattr(packet, 'EndofFile'):
                    operation['file_size'] = packet.EndofFile
                elif hasattr(packet, 'End_of_File'):
                    operation['file_size'] = packet.End_of_File
            except AttributeError:
                pass

            smb_operations.append(operation)

    return smb_operations

def main(input_file):
    smb_info = extract_smb_info(input_file)
    
    # Save metadata to JSON file
    with open('smb_metadata.json', 'w') as f:
        json.dump(smb_info, f, indent=2)
    
    print(f"Extraction complete. Metadata saved to 'smb_metadata.json'")
    print(f"Total SMB operations extracted: {len(smb_info)}")

if __name__ == '__main__':
    import sys
    if len(sys.argv) != 2:
        print("Usage: python3 smb_extractor.py <input_file>")
        sys.exit(1)

    input_file = sys.argv[1]
    main(input_file)
