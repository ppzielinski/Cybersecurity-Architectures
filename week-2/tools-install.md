### Prerequisites
- **System**: A Debian-based Linux server (e.g., Ubuntu 22.04 LTS or Debian 12).
- **Access**: Root or sudo privileges.
- **Network**: Internet connectivity for package downloads.
- **Initial Setup**: Update and upgrade the system first:

  ```bash
  sudo apt update && sudo apt upgrade -y
  ```

---

### Tools by Slide and Installation Commands

#### Slide 2: Introduction to Network Security Architecture
- **Tool**: `iproute2` (for `ip link show`)
  - **Purpose**: View network interfaces.
  - **Installation**: Pre-installed on most Debian systems, but ensure it’s available:
    ```bash
    sudo apt install iproute2 -y
    ```
  - **Verify**: `ip -V`

#### Slide 3: OSI Model Overview
- **Tool**: `tcpdump`
  - **Purpose**: Capture network traffic.
  - **Installation**:
    ```bash
    sudo apt install tcpdump -y
    ```
  - **Verify**: `tcpdump --version`

#### Slide 4: Physical Layer Security
- **Tool**: AWS CLI (for `aws ec2 describe-instances`)
  - **Purpose**: Manage AWS resources.
  - **Installation**:
    ```bash
    sudo apt install awscli -y
    ```
    - Configure with `aws configure` (requires AWS credentials).
  - **Verify**: `aws --version`

#### Slide 5: Data Link Layer Security
- **Tool**: `docker`
  - **Purpose**: Simulate VLANs with container networks.
  - **Installation**:
    ```bash
    sudo apt install docker.io -y
    sudo systemctl enable docker
    sudo systemctl start docker
    ```
    - Add user to docker group (optional): `sudo usermod -aG docker $USER`
  - **Verify**: `docker --version`

#### Slide 6: Network Layer Security
- **Tool**: `iptables`
  - **Purpose**: Configure firewall rules.
  - **Installation**: Pre-installed on most Debian systems, but ensure it’s available:
    ```bash
    sudo apt install iptables -y
    ```
  - **Verify**: `iptables -V`

#### Slide 7: Transport Layer Security
- **Tool**: `certbot`
  - **Purpose**: Obtain SSL/TLS certificates.
  - **Installation**:
    ```bash
    sudo apt install certbot -y
    ```
  - **Verify**: `certbot --version`

#### Slide 8: Session Layer Security
- **Tool**: AWS CLI (already installed for Slide 4)
  - **Purpose**: Manage MFA on AWS.
  - **Notes**: No additional install needed; use `aws iam create-virtual-mfa-device`.

#### Slide 9: Presentation Layer Security
- **Tool**: `openssl`
  - **Purpose**: Verify SSL connections.
  - **Installation**: Pre-installed on most systems, but ensure it’s available:
    ```bash
    sudo apt install openssl -y
    ```
  - **Verify**: `openssl version`

#### Slide 10: Application Layer Security
- **Tool**: AWS CLI (already installed)
  - **Purpose**: Deploy WAF on AWS.
  - **Notes**: No additional install; use `aws wafv2 create-web-acl`.

#### Slide 14: XDR
- **Tool**: `crowdstrike-falcon-sensor` (example)
  - **Purpose**: Endpoint detection and response.
  - **Installation**: Not in default repos; requires CrowdStrike subscription:
    - Download from CrowdStrike portal (e.g., `falcon-sensor.deb`).
    - Install:
      ```bash
      sudo dpkg -i falcon-sensor.deb
      sudo apt-get install -f -y  # Fix dependencies if needed
      ```
    - Configure with customer ID from CrowdStrike.
  - **Verify**: `/opt/CrowdStrike/falconctl -g --cid`
  - **Note**: This is proprietary; replace with open-source like `osquery` if needed:
    ```bash
    sudo apt install osquery -y
    ```

#### Slide 15: SOAR
- **Tool**: `ufw`
  - **Purpose**: Simple firewall for automation simulation.
  - **Installation**:
    ```bash
    sudo apt install ufw -y
    ```
  - **Verify**: `ufw --version`

#### Slide 16: AI/ML in Security
- **Tool**: `python3` and `scikit-learn`
  - **Purpose**: Anomaly detection.
  - **Installation**:
    ```bash
    sudo apt install python3 python3-pip -y
    pip3 install scikit-learn
    ```
  - **Verify**: `python3 -c "import sklearn; print(sklearn.__version__)"`

#### Slide 17: MITRE ATT&CK Framework
- **Tool**: `grep` (for log analysis)
  - **Purpose**: Search logs for attack patterns.
  - **Installation**: Pre-installed, but ensure:
    ```bash
    sudo apt install grep -y
    ```
  - **Verify**: `grep --version`

#### Slide 25: Hands-on Firewall Setup
- **Tool**: `ufw` (already installed for Slide 15)
  - **Notes**: No additional install needed.

#### Slide 26: Hands-on VLAN Setup
- **Tool**: `docker` (already installed for Slide 5)
  - **Notes**: No additional install needed.

#### Slide 27: Hands-on SSL/TLS Setup
- **Tool**: `certbot` and `python3-certbot-nginx`
  - **Purpose**: Automate SSL with Nginx.
  - **Installation**:
    ```bash
    sudo apt install nginx python3-certbot-nginx -y
    ```
  - **Verify**: `nginx -v`

#### Slide 28: Hands-on Security Assessment
- **Tool**: `lynis`
  - **Purpose**: Audit system security.
  - **Installation**:
    ```bash
    sudo apt install lynis -y
    ```
  - **Verify**: `lynis --version`

#### Slide 30: Introduction to TCP/IP
- **Tool**: `net-tools` (for `netstat`)
  - **Purpose**: View TCP/IP connections.
  - **Installation**:
    ```bash
    sudo apt install net-tools -y
    ```
  - **Verify**: `netstat --version`

#### Slide 31: Link Layer in TCP/IP
- **Tool**: `arp` (part of `net-tools`, already installed)
  - **Notes**: No additional install needed.

#### Slide 32: Internet Layer in TCP/IP
- **Tool**: `ping` (part of `iputils-ping`)
  - **Purpose**: Test connectivity.
  - **Installation**: Pre-installed, but ensure:
    ```bash
    sudo apt install iputils-ping -y
    ```
  - **Verify**: `ping -V`

#### Slide 33: Transport Layer in TCP/IP
- **Tool**: `ss` (part of `iproute2`, already installed)
  - **Notes**: No additional install needed.

#### Slide 34: Application Layer in TCP/IP
- **Tool**: `dnsutils` (for `dig`)
  - **Purpose**: DNS queries.
  - **Installation**:
    ```bash
    sudo apt install dnsutils -y
    ```
  - **Verify**: `dig -v`

#### Slide 35: TCP/IP Security Challenges
- **Tool**: `tcpdump` (already installed for Slide 3)
  - **Notes**: No additional install needed.

#### Slide 36: Securing TCP/IP with IPsec
- **Tool**: `strongswan`
  - **Purpose**: IPsec VPN.
  - **Installation**:
    ```bash
    sudo apt install strongswan -y
    ```
  - **Verify**: `ipsec version`

#### Slide 37: TCP Handshake Security
- **Tool**: `netcat` (for `nc`)
  - **Purpose**: Simulate TCP connections.
  - **Installation**:
    ```bash
    sudo apt install netcat -y
    ```
  - **Verify**: `nc -h`

#### Slide 38: Hands-on TCP Traffic Analysis
- **Tool**: `wireshark`
  - **Purpose**: Packet analysis.
  - **Installation**:
    ```bash
    sudo apt install wireshark -y
    ```
    - During install, allow non-root users to capture packets (optional).
  - **Verify**: `wireshark --version`

#### Slide 39: TCP/IP in Modern Architecture
- **Tool**: AWS CLI (already installed)
  - **Notes**: No additional install needed.

---

### Consolidated Installation Script
To install all tools at once, save this script as `install_tools.sh`, make it executable (`chmod +x install_tools.sh`), and run it with `sudo ./install_tools.sh`:

```bash
#!/bin/bash
apt update && apt upgrade -y
apt install -y iproute2 tcpdump awscli docker.io iptables certbot openssl ufw python3 python3-pip net-tools iputils-ping dnsutils strongswan netcat wireshark nginx python3-certbot-nginx lynis osquery
systemctl enable docker
systemctl start docker
pip3 install scikit-learn
# CrowdStrike Falcon requires manual download; skipping here
echo "Please download CrowdStrike Falcon sensor from their portal and install with 'dpkg -i falcon-sensor.deb'"
```

---

### Troubleshooting Tips
1. **Permission Denied**: Ensure you use `sudo` or run as root.
2. **Package Not Found**: Add repositories if needed:
   - For older Ubuntu/Debian: `sudo add-apt-repository universe`
   - Update with `sudo apt update`.
3. **AWS CLI Errors**: Run `aws configure` with valid credentials (Access Key, Secret Key, Region).
4. **Docker Not Starting**: Check status with `systemctl status docker` and logs with `journalctl -u docker`.
5. **Wireshark GUI**: Requires X11 forwarding (`ssh -X`) or a desktop environment; use `tshark` for CLI:
   ```bash
   sudo apt install tshark -y
   ```
6. **Certbot Fails**: Ensure port 80 is open and no web server conflicts (stop Nginx temporarily if needed).

---

### Verification
After installation, test each tool:
- `tcpdump -i lo` (loopback capture, Ctrl+C to stop)
- `docker run hello-world`
- `iptables -L`
- `certbot --version`
- `wireshark &` (or `tshark -i eth0`)

---

### Notes
- **CrowdStrike Falcon**: Requires a subscription; replace with `osquery` for an open-source alternative if desired.
- **Dependencies**: Some tools (e.g., `python3-pip`) may pull additional packages; `-f` fixes broken installs.
- **Environment**: Tested on Ubuntu 22.04; slight variations may occur on other Debian versions.

