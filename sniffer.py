import sys
from scapy.all import sniff, IP, wrpcap, get_if_list

def analyze_frame(frame):
    '''
    analyze ethernet frame, prints src & dst MAC addrs
    if ip layer, print ip version, src, and dst
    print MAC header (14)
    print (part of) payload (28)
    '''
    print(f'Source (MAC): {frame.src}')
    print(f'Destination (MAC): {frame.dst}')
    
    if IP in frame:
        ip_layer = frame[IP]
        print(f'\nIP Version: {ip_layer.version}')
        print(f'Source (IP): {ip_layer.src}')
        print(f'Destination (IP): {ip_layer.dst}')
    
    # prints mac header
    mac_header = bytes(frame)[:14]
    print('\nMAC header')
    for i in range(0, len(mac_header), 8):
        print(' '.join(f'{byte:02x}' for byte in mac_header[i:i+8]))

    # prints payload
    raw_payload = bytes(frame)[14:42]
    print('\nRaw data (28 Bytes)')
    for i in range(0, len(raw_payload), 8):
        print(' '.join(f'{byte:02x}' for byte in raw_payload[i:i+8]))

# must give interface
if len(sys.argv) < 2:
    print('Expected Interface: sniffer.py <iface>')
    sys.exit(1)

# arguments
interface = sys.argv[1]
file_name = sys.argv[2] if len(sys.argv) > 2 else None

# reports invalid interface
if interface not in get_if_list():
    print(f'Invalid interface: {interface}')
    sys.exit(1)

# use Scapy sniffer
capture = sniff(iface=interface, count=15)

# analyze all frames
for frame in capture:
    analyze_frame(frame)
    print('-' * 50)

# if specified, save capture to file
if file_name:
    wrpcap(f'{file_name}.pcap', capture)