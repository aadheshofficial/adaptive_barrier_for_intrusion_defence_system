from scapy.all import IP, TCP, UDP, DNS, Raw
from netfilterqueue import NetfilterQueue
import json
import logging
import subprocess
import time
import requests
from collections import defaultdict

# Configure logging
logging.basicConfig(filename='firewall.log', level=logging.INFO, format='%(asctime)s - %(message)s')

# Connection tracking for Stateful Inspection and DDoS Protection
active_connections = {}
request_counts = defaultdict(int)
TIME_WINDOW = 60  # 1-minute time window for rate limiting
MAX_REQUESTS = 200  # Maximum allowed requests per IP in the time window
CONNECTION_TIMEOUT = 300  # 5 minutes timeout

# Load blacklist and rules from JSON
def load_blacklist(file_path='blacklist.json'):
    try:
        with open(file_path, 'r') as file:
            data = json.load(file)
            return set(data.get("blacklist", [])), set(data.get("blocked_countries", []))
    except (FileNotFoundError, json.JSONDecodeError):
        logging.error("Error loading blacklist file.")
        return set(), set()

# Intrusion Detection System (IDS) - Basic pattern detection
def detect_intrusion(pkt):
    if pkt.haslayer(TCP) and pkt[TCP].flags == 'S':  # SYN flag detection for SYN flood attack
        src = pkt.src
        active_connections[src] = active_connections.get(src, 0) + 1
        if active_connections[src] > 100:
            logging.warning(f"Potential SYN flood detected from {src}")
            return True
    return False

# DDoS Protection - Rate Limiting
def detect_ddos(pkt):
    current_time = time.time()
    src_ip = pkt.src
    request_counts[src_ip] += 1
    if request_counts[src_ip] > MAX_REQUESTS:
        logging.warning(f"Potential DDoS attack detected from {src_ip}")
        return True
    return False

# NAT Implementation using iptables
def setup_nat():
    subprocess.run(['iptables', '-t', 'nat', '-A', 'POSTROUTING', '-o', 'eth0', '-j', 'MASQUERADE'], check=True)
    logging.info("NAT setup completed.")

# Geofencing - Blocking specific geographic regions
def is_geo_blocked(ip, blocked_countries):
    try:
        response = requests.get(f"https://ipapi.co/{ip}/country/", timeout=5)
        country_code = response.text.strip()
        if country_code in blocked_countries:
            logging.warning(f"Blocked IP {ip} from restricted region: {country_code}")
            return True
    except requests.RequestException:
        logging.error("Geolocation API error.")
    return False

# Anti-Malware Integration (Sample implementation)
def scan_packet_for_malware(pkt):
    if pkt.haslayer(Raw) and b'virus' in pkt[Raw].load.lower():
        logging.warning(f"Malware signature detected in packet from {pkt.src}")
        return True
    return False

# Packet inspection and filtering
def packet_handler(packet):
    pkt = IP(packet.get_payload())
    blacklist, blocked_countries = load_blacklist()

    # Block blacklisted IP addresses
    if pkt.src in blacklist or pkt.dst in blacklist:
        logging.warning(f"Blocked connection from {pkt.src} to {pkt.dst}")
        packet.drop()
        return

    # Geofencing check
    if is_geo_blocked(pkt.src, blocked_countries):
        packet.drop()
        return

    # Port-based filtering (e.g., block port 23 for Telnet)
    if pkt.haslayer(TCP) and pkt[TCP].dport == 23:
        logging.warning(f"Blocked Telnet traffic from {pkt.src} to {pkt.dst}")
        packet.drop()
        return

    # URL Filtering for DNS traffic
    if pkt.haslayer(DNS) and pkt.haslayer(Raw):
        dns_query = pkt[Raw].load.decode(errors='ignore')
        if "malicious.com" in dns_query:
            logging.warning(f"Blocked DNS request to malicious domain from {pkt.src}")
            packet.drop()
            return

    # IDS/IPS: Detect SYN flood attack
    if detect_intrusion(pkt):
        logging.warning(f"Blocked potential SYN flood from {pkt.src}")
        packet.drop()
        return

    # DDoS Protection
    if detect_ddos(pkt):
        packet.drop()
        return

    # Anti-Malware Check
    if scan_packet_for_malware(pkt):
        packet.drop()
        return

    # Bandwidth Control / Rate Limiting (Example: Limit UDP packets)
    if pkt.haslayer(UDP):
        logging.info(f"UDP packet allowed: {pkt.src} to {pkt.dst}")

    # Default action: Allow traffic
    logging.info(f"Allowed traffic from {pkt.src} to {pkt.dst}")
    packet.accept()

# Main firewall loop
def start_firewall():
    setup_nat()

    nfqueue = NetfilterQueue()
    nfqueue.bind(1, packet_handler)
    logging.info("Firewall started successfully.")
    try:
        nfqueue.run()
    except KeyboardInterrupt:
        logging.info("Firewall stopped.")
        nfqueue.unbind()

if __name__ == "__main__":
    start_firewall()
