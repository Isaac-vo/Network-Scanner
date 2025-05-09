from scapy.all import ARP, Ether, srp, IP, ICMP, sr1
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QPushButton, QTableWidget, QTableWidgetItem, QTextEdit 
from PyQt5.QtCore import QThread, pyqtSignal
import nmap
import os
import platform
import sys
import threading
import requests
import shutil
import scapy.all as scapy
import re

MAX_THREADS = 50 # Limit concurrent threads
SUBNET = "Your LAN Default Gateway IP/24" # This is the subnet that will be scanned (Change it if needed, please only keep the "/24" part)

# Get Nmap path if available
def get_nmap_path():
    # Try detecting Nmap automatilcally
    nmap_path = shutil.which("nmap")

    if nmap_path:
        return nmap_path # If found, return path
    
    # If not found, search in common directories

    common_paths = [
        "C: \\Program Files \\Nmap\\nmap.exe",
        "C: \\Program Files (x86) \\Nmap\\nmap.exe",
    ]

    for path in common_paths:
        if shutil.which(path):
            return path
    
    raise FileNotFoundError("Nmap executable not found. Amke sure it's installed")

# Initialize Nmap scanner with detected path

nm = nmap.PortScanner()
nm.nmap_path = get_nmap_path() # Auto-assing the Nmap path


# Retrieve CVE database from NVD API
def get_vulnerabilities(service_name, version=None):
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    query = f"{service_name}"

    if version:
        query += f" {version}" # Search vulnerabilities related to specific version

    params = {"keyword": query, "resultsPerPage": 10}

    response = requests.get(base_url, params=params)
    if response.status_code == 200:
        data = response.json()
        return [
            {"id": cve["cve"]["CVE_data_meta"]["ID"], "summary": cve["cve"]["description"]["description_data"][0]["value"]}
            for cve in data.get("result", {}).get("CVE_Items", [])
        ]
        
    return []

def generate_ip_range(SUBNET):
    subnet_parts = SUBNET.split('/')
    base_ip = subnet_parts[0].split('.')
    prefix = int(subnet_parts[1])
    total_ips = 2 ** (32 - prefix) # Calculate number of usable IPs in subnet

    ip_list = []
    for i in range(1, total_ips - 1): # Exclude network & broadcast addresses

        ip_list.append(f"{base_ip[0]}.{base_ip[1]}.{base_ip[2]}.{i}")
    
    return ip_list

def get_mac(ip):
    # First attempt via Scapy ARP request
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast/arp_request
    answered_list = scapy.srp(packet, timeout=5, verbose=0)[0]

    if answered_list:
        return answered_list[0][1].hwsrc
    
    # If Scapy fails, try fetching MAC from ARP cache
    try:
        result = os.popen(f"arp -a {ip}").read()
        match = re.search(r'([0-9a-fA-F]{2}-[0-9a-fA-F]{2}-[0-9a-fA-F]{2}-[0-9a-fA-F]{2}-[0-9a-fA-F]{2}-[0-9a-fA-F]{2})', result)
        if match:
            return match.group(0).replace('-', ':') # Convert Widows format to standard MAC notation)
        
    except Exception as e:
        print(f"Error retrienving MAC for {ip}: {e}")

    return "N/A" # Default asnwer if no MAC is found

def scan_network(SUBNET):
    # Using ARP to detect devices on a subnet
    arp = ARP(pdst=SUBNET)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp 

    result = srp(packet, timeout=10, verbose=0)[0]
    devices = [{'ip': recv.psrc, 'mac': recv.hwsrc} for _, recv in result]

    # Re-check missing MAC addresses
    for device in devices:
        if device['mac'] == "N/A":
            device['mac'] = get_mac(device['ip']) # Try resolving MAC again
               
    return devices

# Function to perform ICMP Echo requests (ping)
def ping_device(ip):
    # Ping a device to check if it is on the network

    param = '-n 1' if platform.system().lower() == 'windows' else '-c 1'
    command = f"ping {param} {ip}"
    response = os.system(command)

    return response == 0 # True if the ping was successful

# Function to verify IP responsiveness before ICMP scanning
def verify_ip(ip):
    packet = IP(dst=ip)/ICMP()
    response = sr1(packet, timeout=1, verbose=0)
    return response is not None # True if ICMP response is received
    
# Enhanced discovery process combining ARP and ping
def enhanced_scan(SUBNET):
    detected_devices = scan_network(SUBNET) 
    arp_ips = {device['ip'] for device in detected_devices}

    # Generate all possible IPs in subnet (ensures full scan coverage)
    ip_list = generate_ip_range(SUBNET)

    # Multi-threaded ICMP scanning
    thread_semaphore = threading.Semaphore(MAX_THREADS)
    threads = []
    results = []

    def scan_ip(ip):
        with thread_semaphore:
            try:
                if ip not in arp_ips and verify_ip(ip) and ping_device(ip):
                    results.append({'ip': ip, 'mac': 'N/A'})
            except Exception as e:
                print(f"Error scanning {ip}: {e}")

    for ip in ip_list: # Exclude network and broadcast addresses
        thread = threading.Thread(target=scan_ip, args=(ip,))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    # Retry MAC resolution for missing entries
                
    for device in detected_devices:
        if device['mac'] == "N/A":
            device['mac'] = get_mac(device['ip']) # Final attemmp at resolving MACs

    detected_devices.extend(results) # Merge ICMP results with ARP discovery
       
    return detected_devices
            
# Example usage
devices = enhanced_scan(SUBNET)

if devices:
    for device in devices:
        print(f"IP: {device['ip']}, MAC: {device['mac']}")
else:
    print("Error: No devices found!")

# Function to scan ports on a device
def scan_ports(ip):
    nm = nmap.PortScanner()
    try:
        nm.scan(ip, arguments="--script vuln,smb-vuln-ms10-054,smb-vuln-ms10-061,http-vuln-cve2014-3704") # Using Nmap's vulnerability script

        if ip not in nm.all_hosts():
            print(f"Warning: No data returned for {ip}. Nmap scan might have failed.")

        ports = []
        for proto in nm[ip].all_protocols():
            for port in nm[ip][proto]:
                service_name = nm[ip][proto][port]["name"]
                version = nm[ip][proto][port].get("version", None) # Extract version if available

                # Get vulnerabilities detected by nmap
                vuln_output =nm[ip][proto][port].get("script", {}) # Get vulnerability script results
                vulnerabilities = [
                    {"id": k, "summary": v} for k, v in vuln_output.items() # Convert vuln scrip results to list
                ]

                # Also query NVD API
                vulnerabilities += get_vulnerabilities(service_name, version)

                ports.append({
                    "port": port,
                    "state": nm[ip][proto][port]["state"],
                    "service": service_name,
                    "vulnerabilities": vulnerabilities 
                })

        return ports
    
    except Exception as e:
        print(f"Error scanning {ip}: {e}")
        return [] # Scan an empty list if scan fails

# GUI Class using PyQt5

class PortScanThread(QThread):
    scan_complete = pyqtSignal(str, list) # Signal to return scan results

    def __init__(self, ip):
            super().__init__()
            self.ip = ip
        
    def run(self):
        ports = scan_ports(self.ip)
        self.scan_complete.emit(self.ip, ports) # Send results back to main UI

class NetworkScanThread(QThread):
    scan_complete = pyqtSignal(list)

    def __init__(self, SUBNET):
        super().__init__()
        self.SUBNET = SUBNET
    
    def run(self):
        print("Network scanning in progress...")

        devices = enhanced_scan(self.SUBNET) # Run scan in a background thread

        if devices:
            print(f"Scan competed. {len(devices)} devices found.")
        else:
            print("No devices detected!")

        self.scan_complete.emit(devices)

class NetworkScanner(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()
    
    def initUI(self):
        self.layout = QVBoxLayout()

        # Buttons
        self.scan_network_button = QPushButton("Scan Network")
        self.scan_network_button.clicked.connect(self.scan_network_action)
        self.layout.addWidget(self.scan_network_button)

        self.scan_ports_button = QPushButton("Scan Ports")
        self.scan_ports_button.clicked.connect(self.scan_ports_action)
        self.layout.addWidget(self.scan_ports_button)

        # Device Table
        self.table = QTableWidget(0, 2)
        self.table.setHorizontalHeaderLabels(["IP Address", "MAC Address"])
        self.layout.addWidget(self.table)

        # Results Display
        self.result_text = QTextEdit()
        self.layout.addWidget(self.result_text)

        # Set main window layout
        self.setLayout(self.layout)
        self.setWindowTitle("Network Scanner")
    
    def scan_network_action(self):
        print("Scan Network button clicked")

        self.scan_thread = NetworkScanThread(SUBNET)
        self.scan_thread.scan_complete.connect(self.update_table) # UI updates when scan is done
        self.scan_thread.start()

    def update_table(self, detected_devices):
        print(f"Updating table with {len(detected_devices)} devices...")

        self.detected_devices = detected_devices
        self.table.setRowCount(len(self.detected_devices))

        for device in self.detected_devices:
            if device["mac"] == "N/A" or device["mac"] == "Unknown":
                device["mac"] = get_mac(device["ip"])

        for row, device in enumerate(self.detected_devices):
            print(f"Adding to table: IP {device['ip']}, MAC {device['mac']}") # Debbuging print

            ip_item = QTableWidgetItem(device["ip"])
            mac_item =QTableWidgetItem(device["mac"] if device["mac"] != "N/A" else "Unknown") # Always show de IP

            self.table.setItem(row, 0, ip_item)
            self.table.setItem(row, 1, mac_item)

        self.table.repaint()


    def scan_ports_action(self):
        selected_row = self.table.currentRow()
        if selected_row != -1:
            ip = self.table.item(selected_row, 0).text()
            self.result_text.clear()
            self.result_text.append(f"Scanning {ip} ... \n")

            # Start background thread for scanning ports
            self.scan_thread = PortScanThread(ip)
            self.scan_thread.scan_complete.connect(self.display_scan_results) # Update UI when done
            self.scan_thread.start()
        else:
            print("No device selected for port scan.")
    
    def display_scan_results(self, ip, ports):
            self.result_text.clear()
            self.result_text.append(f"Scan complete for {ip}\n")
            if ports:
                for port in ports:
                    self.result_text.append(f"Port {port['port']} - {port['state']} ({port['service']})")

                    if port["vulnerabilities"]:
                        self.result_text.append("  ⚠️Known Vulnerabilities:")
                        for vuln in port["vulnerabilities"]:
                            self.result_text.append(f"   - {vuln['id']}: {vuln['summary']}")
                    else:
                        self.result_text.append("  ✅ No known vulnerabilities found.")
            else:
                self.result_text.append("No open ports found or scan failed.")

# Run the app

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = NetworkScanner()
    window.show()
    sys.exit(app.exec_())

