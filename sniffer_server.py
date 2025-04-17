import socket
import struct
import threading
import json
import platform
from datetime import datetime
import select

# Server Settings
SERVER_HOST = '0.0.0.0'  # Listen on all available network interfaces
SERVER_PORT = 12345
BUFFER_SIZE = 65536

# Detect OS (to handle raw socket permissions)
IS_WINDOWS = platform.system() == "Windows"

# Helper functions
def format_mac(bytes_addr):
    return ":".join(map("{:02x}".format, bytes_addr)).upper()

def format_ip(addr):
    return ".".join(map(str, addr))

def parse_ethernet_frame(data):
    dest_mac, src_mac, eth_proto = struct.unpack("!6s6sH", data[:14])
    return format_mac(dest_mac), format_mac(src_mac), socket.ntohs(eth_proto), data[14:]

def parse_ipv4_packet(data):
    header_length = (data[0] & 15) * 4
    proto, src_ip, dest_ip = struct.unpack("!9xB2x4s4s", data[:20])
    return format_ip(src_ip), format_ip(dest_ip), proto, header_length, data[header_length:]

def get_default_interface():
    try:
        with open("/proc/net/route") as f:
            for line in f.readlines()[1:]:
                fields = line.strip().split()
                if fields[1] == "00000000":  # Default route
                    return fields[0]
    except FileNotFoundError:
        return "eth0"
    return "wlan0"

# Handling multiple clients
clients = []

def handle_client(client_socket, addr):
    try:
        print(f"Connection established with {addr}")

        # Start sniffing and sending data to the client
        sniffing = True
        interface = get_default_interface()
        conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        conn.bind((interface, 0))
        print(f"🌐 Listening on {interface}...")

        while sniffing:
            raw_data, _ = conn.recvfrom(BUFFER_SIZE)
            dest_mac, src_mac, eth_proto, data = parse_ethernet_frame(raw_data)

            protocol_name = {8: "IPv4", 56710: "IPv6", 1544: "ARP"}.get(eth_proto, f"Other ({eth_proto})")

            # Extract details for IPv4 packets
            src_ip, dest_ip, proto_name = "N/A", "N/A", protocol_name
            if eth_proto == 8:  # IPv4
                src_ip, dest_ip, proto, header_length, payload = parse_ipv4_packet(data)
                proto_name = {6: "TCP", 17: "UDP", 1: "ICMP", 41: "IPv6", 53: "DNS"}.get(proto, "Other")

            packet_info = {
                "timestamp": str(datetime.now()),
                "source_mac": src_mac,
                "destination_mac": dest_mac,
                "source_ip": src_ip,
                "destination_ip": dest_ip,
                "protocol": proto_name,
                "size": len(raw_data),
                "payload": data[:20].hex()
            }

            # Send packet information to client
            client_socket.send(json.dumps(packet_info).encode())

    except Exception as e:
        print(f"Error in client handler: {e}")
    finally:
        client_socket.close()

def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((SERVER_HOST, SERVER_PORT))
    server_socket.listen(5)
    print(f"Server listening on {SERVER_HOST}:{SERVER_PORT}...")

    while True:
        client_socket, addr = server_socket.accept()
        clients.append(client_socket)
        threading.Thread(target=handle_client, args=(client_socket, addr)).start()

# ✅ Corrected line here
if __name__ == "__main__":
    start_server()