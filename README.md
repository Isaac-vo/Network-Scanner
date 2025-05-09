# Network Scanner App

## About the developer
Hello everyone, my name is Isaac Venerucci de Oliveira, I am a cybersecurity student and a passionate enthusiast for securing networks. Welcome to my third project out of nine that I have committed to developing this year, ranging from the simplest to the most challenging. Stay tuned for innovative cybersecurity projects, and let's dive into the details of this *Network Scanner App*.

### Level
Beginner

## Description
The Network Scanner App is a PyQt5-based GUI application that allows users to **DETECT DEVICES, SCAN PORTS, and ASSESS VULNERABILITIES** in their local network. It combines **ARP and ICMP** scanning for enhanced device discovery and uses **Nmap** alongside the **NVD API** to check for known vulnerabilities affecting detected services.
The tool is designed for network security assessments, enabling users to retrieve IP and MAC addresses, identify open ports, and analyze potential risks efficiently.

## How Does It Work?

### 1. Network Discovery

- Uses **ARP requests** to detect devices connected to the subnet.
- Implements **ICMP Echo requests** to verify responsiveness.
- Retrieves IP and MAC addresses, even for devices that don’t respond to ARP scans.


>PS: If you are interested in figuring out the vendor name of a device based on its MAC, you can check the website below for more details:

- https://maclookup.app/

### 2. Port Scanning & Vulnerability Detection

- Performs **Nmap scans** to identify open ports on detected devices.
- Uses Nmap’s vulnerability detection scripts and **NVD API** to cross-check known CVEs.

---
### Extra features

#### Graphical Interface

- PyQt5-based GUI with an interactive table displaying detected devices.
- Users can select a device and trigger a detailed port scan.
- Results are displayed with vulnerabilities clearly marked.

#### Multi-Threading for Efficiency

- Uses background threads to perform scans without freezing the UI.
- Ensures faster and smoother scanning operations.
---

## Installation

### 1. Clone the Repository

- git clone <https://github.com/Isaac-vo/Network-Scanner.git>

### 2. Install Dependencies

- pip install -r requirements.txt

### 3. Configure the Subnet

Before running the scanner, update the **SUBNET variable** in the script to match your LAN default gateway subnet.
- Find your Default Gateway:
    - Open **CMD** on Windows and type: **ipconfig** (look for - "Default Gateway")
- Modify the global variable in the script:
    - SUBNET = "**Your LAN Default Gateway IP**/24" # This is the subnet that will be scanned (Change it if needed, please only keep the "/24" part)

### 4. Run the Application

- Running **CMD** or **PowerShell** as administrador, type:
    - python .\network-scanner.py

## How to Use It?

- Click **"Scan Network"** to detect devices.
- Select a detected device and click **"Scan Ports"** to identify open ports and vulnerabilities.
- Review results in the interactive table and the text output panel.

## Support

If you have any questions about the app that were not addressed in this introduction, feel free to reach out to me through Github or by email at (veneruci@gmail.com).

Thank you so much for reading until here, and I hope I have helped you improve your security against potencial threats on the internet.

Thank you! 05/09/2025!
