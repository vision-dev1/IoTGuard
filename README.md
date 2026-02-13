# IoTGuard

**IoTGuard** is a defensive IoT security assessment tool designed to help security professionals identify and mitigate vulnerabilities in IoT devices across enterprise networks.

![IoTGuard Interface](https://img.shields.io/badge/Framework-Flask-blue) ![Python](https://img.shields.io/badge/Python-3.8+-green) ![License](https://img.shields.io/badge/License-MIT-yellow)

## Features

- 🔍 **Network Discovery**: Safely scan your network to identify all connected IoT devices
- 🛡️ **Risk Assessment**: Automatically identify security vulnerabilities and risks
- 📋 **Mitigation Guide**: Get practical recommendations to secure your devices
- 📊 **Reporting**: Export comprehensive security reports for analysis
- 🎨 **Modern UI**: Clean, responsive interface with dark mode support
- 🔒 **Defensive Focus**: Designed strictly for authorized security assessments

## Technology Stack

- **Backend**: Flask (Python)
- **Frontend**: HTML, TailwindCSS, Material Symbols Icons
- **Scanner**: Nmap integration
- **Data Format**: JSON

## Installation

### Prerequisites

- Python 3.8 or higher
- Nmap installed on your system
- Linux/Unix environment (recommended)

### Setup Instructions

1. **Clone the repository**
   ```bash
   git clone https://github.com/vision-dev1/IoTGuard.git
   cd IoTGuard
   ```

2. **Install Python dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Install Nmap** (if not already installed)
   ```bash
   # Ubuntu/Debian
   sudo apt-get install nmap
   
   # Fedora/RHEL
   sudo dnf install nmap
   
   # macOS
   brew install nmap
   ```

4. **Run the application**
   ```bash
   python3 app.py
   ```

5. **Access the interface**
   - Open your browser and navigate to: `http://localhost:5000`
   - Or access from network: `http://<your-ip>:5000`

## Usage

### 1. Configure Scan
- Enter the target subnet in CIDR notation (e.g., `192.168.1.0/24`)
- Select port range:
  - **Common Ports (1-1000)**: Quick scan of standard services
  - **All Ports (1-65535)**: Comprehensive scan (slower)
  - **IoT Specific Ports**: Targeted scan for IoT devices

### 2. Review Results
- View summary statistics (Total devices, High/Medium/Low risk)
- Browse discovered devices in the interactive table
- Filter and sort devices by risk level

### 3. Inspect Devices
- Click "Inspect" on any device to view detailed information
- Review identified risks and vulnerabilities
- Follow mitigation recommendations

### 4. Export Reports
- Click "Export Report" to download scan results as JSON
- Share reports with your security team
- Track improvements over time

## Project Structure

```
IoTGuard/
├── app.py                      # Flask application entry point
├── requirements.txt            # Python dependencies
├── scanner/                    # Core scanning modules
│   ├── __init__.py
│   ├── nmap_scanner.py        # Nmap integration
│   ├── device_fingerprinting.py  # Device identification
│   └── risk_rules.py          # Risk assessment engine
├── templates/                  # HTML templates
│   ├── index.html             # Scan configuration page
│   ├── results.html           # Results dashboard
│   └── device.html            # Device detail page
├── static/                     # Static assets
│   └── style.css              # Additional styles
├── mitigations/               # Mitigation database
│   └── mitigations.json       # Risk mitigation strategies
└── reports/                    # Scan reports directory
```

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Scan configuration page |
| `/scan` | POST | Start network scan |
| `/results` | GET | View scan results |
| `/device/<ip>` | GET | Device detail page |
| `/export` | GET | Export results as JSON |
| `/api/devices` | GET | Get devices list (API) |

## Configuration

### Scan Parameters
- **Subnet**: Network range in CIDR notation
- **Port Range**: Customize which ports to scan
- **Timeout**: Adjust scan timeout (default: auto)

### Security Considerations
- Always obtain proper authorization before scanning
- Use on your own networks only
- Respect privacy and legal boundaries
- Follow responsible disclosure practices

## Risk Levels

IoTGuard categorizes devices into three risk levels:

- 🔴 **HIGH**: Critical vulnerabilities requiring immediate attention
- 🟡 **MEDIUM**: Moderate risks that should be addressed
- 🟢 **LOW**: Minor issues or informational findings

## Mitigation Database

The tool includes a comprehensive mitigation database covering:
- Default credentials
- Insecure protocols (Telnet, FTP, etc.)
- Outdated firmware
- Open management interfaces
- Weak encryption
- And more...

## Development

### Running in Debug Mode
```bash
python3 app.py
```
Debug mode is enabled by default in `app.py`.

### Adding New Risk Rules
Edit `scanner/risk_rules.py` to add custom risk detection rules.

### Customizing Mitigations
Update `mitigations/mitigations.json` with your organization's specific mitigation strategies.

## Troubleshooting

### Nmap Permission Issues
If you encounter permission errors, run with sudo or configure Nmap capabilities:
```bash
sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip $(which nmap)
```

### Port Already in Use
Change the port in `app.py`:
```python
app.run(debug=True, host='0.0.0.0', port=5001)
```

### No Devices Found
- Verify network connectivity
- Check subnet notation is correct
- Ensure Nmap is properly installed
- Try a smaller subnet range first

## Ethical Use Notice

**⚠️ IMPORTANT: This tool is designed for defensive security assessment only.**

- ✅ Use on networks you own or have explicit permission to scan
- ✅ Obtain proper authorization before scanning
- ✅ Follow responsible disclosure practices
- ❌ Do not use against systems without permission
- ❌ Do not use for malicious purposes
- ❌ Respect privacy and legal boundaries

Unauthorized network scanning may be illegal in your jurisdiction. Always ensure you have proper authorization.

## Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Author

**Vision KC**

[Github](https://github.com/vision-dev1)
[Website](https://visionkc.com.np)

---
