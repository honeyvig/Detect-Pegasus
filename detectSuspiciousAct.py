import psutil
import scapy.all as scapy
import time

# List of known suspicious IP addresses (to be updated based on threat intelligence)
SUSPICIOUS_IPS = [
    "192.168.1.100",  # Example of suspicious IP (replace with known malicious IPs)
    "203.0.113.45"
]

# Function to check active network connections
def check_active_connections():
    print("Checking active network connections...")
    # Get all current network connections
    connections = psutil.net_connections(kind='inet')
    
    for conn in connections:
        # If the connection's remote address is suspicious, flag it
        remote_ip = conn.raddr.ip if conn.raddr else None
        if remote_ip and remote_ip in SUSPICIOUS_IPS:
            print(f"Suspicious connection found: {remote_ip} (PID: {conn.pid})")
            try:
                # Get the process info associated with the suspicious connection
                proc = psutil.Process(conn.pid)
                print(f"Process Name: {proc.name()}, Path: {proc.exe()}")
            except psutil.NoSuchProcess:
                continue

# Function to capture packets on the network and identify suspicious patterns
def packet_sniffer():
    print("Starting network packet sniffing...")
    
    # Define the callback function to analyze packets
    def analyze_packet(packet):
        if packet.haslayer(scapy.IP):
            ip_src = packet[scapy.IP].src
            ip_dst = packet[scapy.IP].dst
            if ip_dst in SUSPICIOUS_IPS:
                print(f"Suspicious packet detected: {ip_src} -> {ip_dst}")
                print(packet.summary())
    
    # Start sniffing packets (this will capture packets for a short duration)
    scapy.sniff(prn=analyze_packet, timeout=60)

# Main function to start monitoring for Pegasus-like behavior
def main():
    print("Starting spyware detection...")
    
    # Step 1: Monitor active network connections
    check_active_connections()
    
    # Step 2: Analyze network packets for suspicious traffic
    packet_sniffer()
    
    print("Spyware detection complete!")

if __name__ == "__main__":
    main()
