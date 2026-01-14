import os
import json
import logging
from flask import Flask, render_template, request, jsonify, redirect, url_for
from scanner.nmap_scanner import NmapScanner
from scanner.device_fingerprinting import DeviceFingerprinter
from scanner.risk_rules import RiskRulesEngine


logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)


nmap_scanner = NmapScanner()
fingerprinter = DeviceFingerprinter()
risk_engine = RiskRulesEngine()


REPORTS_DIR = 'reports'
os.makedirs(REPORTS_DIR, exist_ok=True)
REPORT_FILE = os.path.join(REPORTS_DIR, 'scan_results.json')

@app.route('/')
def index():
    
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def start_scan():
    
    try:
        subnet = request.form.get('subnet', '').strip()
        port_range = request.form.get('port_range', '1-1000')
        
        if not subnet:
            return "Subnet is required", 400
            
        
        if not nmap_scanner.validate_subnet(subnet):
            return "Invalid subnet format. Please use CIDR notation (e.g., 192.168.1.0/24)", 400
        
        
        logger.info(f"Starting scan for subnet {subnet} with port range {port_range}")
        raw_devices = nmap_scanner.safe_network_scan(subnet, port_range)
        
        
        processed_devices = []
        for device in raw_devices:
            
            fingerprint = fingerprinter.fingerprint_device(device)
            
            
            risks = risk_engine.assess_device_risks(fingerprint)
            
            
            overall_risk, _ = risk_engine.calculate_overall_risk_score(risks)
            
            
            processed_device = {
                'fingerprint': fingerprint,
                'risks': risks,
                'overall_risk': overall_risk
            }
            processed_devices.append(processed_device)
        
        
        risk_report = risk_engine.generate_risk_report(processed_devices)
        
        
        with open(REPORT_FILE, 'w') as f:
            json.dump(risk_report, f, indent=2)
        
        logger.info(f"Scan completed successfully. Found {len(processed_devices)} devices.")
        
        
        
        return redirect(url_for('results'))
        
    except ValueError as ve:
        logger.error(f"Validation error during scan: {ve}")
        return str(ve), 400
    except Exception as e:
        logger.error(f"Error during scan: {e}")
        return f"Scan failed: {str(e)}", 500

@app.route('/results')
def results():
    
    try:
        if not os.path.exists(REPORT_FILE):
            return "No scan results available. Please run a scan first.", 404
            
        with open(REPORT_FILE, 'r') as f:
            report = json.load(f)
        
        
        summary = report.get('scan_summary', {})
        devices = report.get('devices', [])
        
        return render_template('results.html', summary=summary, devices=devices)
        
    except json.JSONDecodeError:
        return "Error reading scan results. Invalid JSON format.", 500
    except Exception as e:
        logger.error(f"Error displaying results: {e}")
        return "Error displaying results", 500

@app.route('/device/<ip>')
def device_detail(ip):
    
    try:
        if not os.path.exists(REPORT_FILE):
            return "No scan results available. Please run a scan first.", 404
            
        with open(REPORT_FILE, 'r') as f:
            report = json.load(f)
        
        
        devices = report.get('devices', [])
        device = None
        
        for d in devices:
            if d['fingerprint']['basic_info']['ip_address'] == ip:
                device = d
                break
        
        if not device:
            return f"Device with IP {ip} not found in scan results.", 404
        
        return render_template('device.html', device=device)
        
    except json.JSONDecodeError:
        return "Error reading scan results. Invalid JSON format.", 500
    except Exception as e:
        logger.error(f"Error displaying device detail: {e}")
        return "Error displaying device details", 500

@app.route('/export')
def export_results():
    
    try:
        if not os.path.exists(REPORT_FILE):
            return "No scan results available to export.", 404
            
        with open(REPORT_FILE, 'r') as f:
            report = json.load(f)
        
        
        response = app.response_class(
            response=json.dumps(report, indent=2),
            mimetype='application/json',
            headers={'Content-Disposition': 'attachment; filename=iotguard_scan_results.json'}
        )
        return response
        
    except Exception as e:
        logger.error(f"Error exporting results: {e}")
        return "Error exporting results", 500

@app.route('/api/devices')
def api_devices():
    
    try:
        if not os.path.exists(REPORT_FILE):
            return jsonify({'error': 'No scan results available'}), 404
            
        with open(REPORT_FILE, 'r') as f:
            report = json.load(f)
        
        devices = report.get('devices', [])
        device_list = []
        
        for device in devices:
            basic_info = device['fingerprint']['basic_info']
            device_list.append({
                'ip': basic_info['ip_address'],
                'hostname': basic_info['hostname'],
                'vendor': device['fingerprint']['identification']['vendor'],
                'device_type': device['fingerprint']['identification']['device_type'],
                'overall_risk': device['overall_risk']
            })
        
        return jsonify({'devices': device_list})
        
    except Exception as e:
        logger.error(f"Error in API devices endpoint: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.errorhandler(404)
def not_found(error):
    return "Page not found", 404

@app.errorhandler(500)
def internal_error(error):
    return "Internal server error", 500

if __name__ == '__main__':
    logger.info("Starting IoTGuard application...")
    app.run(debug=True, host='0.0.0.0', port=5000)