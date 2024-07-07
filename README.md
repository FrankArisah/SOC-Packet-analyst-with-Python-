# SOC-Packet-analyst-with-Python-

Upon writing and further debbuging a script to analyze SMB packets from the PCAP file provided, extract attachments, and gather metadata, I concluded

1. The PCAP file contains SMBv2 traffic. Evidenced by the presence of SMB2_Header and various SMB2 request/response layers.

![SMB2 request response layers](https://github.com/FrankArisah/SOC-Packet-analyst-with-Python-/assets/50199693/ddd2b381-c086-4f33-b74b-a1d906db8828)


2. There are no Raw layers in these packets, numerous attempts to extract file data were unfruitful.

![Untitled design (2)](https://github.com/FrankArisah/SOC-Packet-analyst-with-Python-/assets/50199693/cdbd3a19-2d42-4eab-8273-b41db1d6b7f0)

3. The SMB2 operations I saw included Create, Query Info, Close, and Query Directory requests and responses.

![SMB2 request response layers](https://github.com/FrankArisah/SOC-Packet-analyst-with-Python-/assets/50199693/ddd2b381-c086-4f33-b74b-a1d906db8828)
   
4. The packets contain the SMB protocol information, but the actual file data is not present in the packet captures.


Given this information, I modified my approach. I focused on gathering metadata about the SMB operations. 

To run the script:

Save it as ```smb_extractor.py```

Run it with: ```python3 smb_extractor.py smb.pcap```

This should create a smb_metadata.json file containing information about the SMB operations, including timestamps, IP addresses, ports, and SMB commands. It will attempt to include filenames and file sizes when available, but won't raise an error if these fields are missing.

![Untitled design (3)](https://github.com/FrankArisah/SOC-Packet-analyst-with-Python-/assets/50199693/24c6d73f-6829-4da7-92b2-d8a7b564b10a)
![smbmetadata](https://github.com/FrankArisah/SOC-Packet-analyst-with-Python-/assets/50199693/06f9d00b-d803-4fe0-a952-0dae86d2d2b2)

Regards, 
Frank. 



