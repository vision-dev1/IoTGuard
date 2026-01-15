import nmap
import json
import logging
from typing import Dict, List, Optional
import ipaddress
import socket
import time

logger = logging.getLogger(__name__)

class NmapScanner:
    
    def __init__(self):
        self.scanner = nmap.PortScanner()
        self.scan_timeout = 300
    
    def validate_subnet(self, subnet: str) -> bool:
        try:
            ipaddress.ip_network(subnet, strict=False)
            return True
        except ValueError:
            return False
    
    def discover_hosts(self, subnet: str) -> List[Dict]:
        if not self.validate_subnet(subnet):
            raise ValueError(f"Invalid subnet format: {subnet}")
        
        logger.info(f"Starting host discovery on {subnet}")
        hosts = []
        
        try:
            self.scanner.scan(hosts=subnet, arguments='-sn', timeout=self.scan_timeout)
            
            for host in self.scanner.all_hosts():
                if self.scanner[host].state() == 'up':
                    host_info = {
                        'ip': host,
                        'hostname': self.scanner[host].hostname() or 'Unknown',
                        'status': 'up'
                    }
                    hosts.append(host_info)
                    logger.debug(f"Found live host: {host}")
                    
        except Exception as e:
            logger.error(f"Host discovery failed: {str(e)}")
            raise
        
        logger.info(f"Discovered {len(hosts)} live hosts")
        return hosts
    
    def scan_ports_and_services(self, target_ip: str, port_range: str = '1-1000') -> Dict:
        logger.info(f"Scanning ports {port_range} on {target_ip}")
        
        scan_result = {
            'open_ports': [],
            'services': [],
            'os_guess': 'Unknown'
        }
        
        try:
            scan_args = f'-sV --version-intensity 3 -p {port_range}'
            self.scanner.scan(hosts=target_ip, arguments=scan_args, timeout=self.scan_timeout)
            
            if target_ip in self.scanner.all_hosts():
                host_data = self.scanner[target_ip]
                
                if 'tcp' in host_data:
                    for port in host_data['tcp']:
                        port_info = host_data['tcp'][port]
                        if port_info['state'] == 'open':
                            service_info = {
                                'port': port,
                                'protocol': 'tcp',
                                'service': port_info.get('name', 'unknown'),
                                'version': port_info.get('version', ''),
                                'product': port_info.get('product', ''),
                                'banner': port_info.get('extrainfo', '')
                            }
                            scan_result['open_ports'].append(port)
                            scan_result['services'].append(service_info)
                
                if 'osmatch' in host_data and host_data['osmatch']:
                    os_matches = sorted(host_data['osmatch'], key=lambda x: x.get('accuracy', 0), reverse=True)
                    if os_matches:
                        scan_result['os_guess'] = os_matches[0].get('name', 'Unknown')
                        
        except Exception as e:
            logger.error(f"Port scanning failed for {target_ip}: {str(e)}")
            
        return scan_result
    
    def get_mac_address(self, target_ip: str) -> Optional[str]:
        try:
            return None
        except Exception as e:
            logger.debug(f"Could not retrieve MAC for {target_ip}: {str(e)}")
            return None

    def safe_network_scan(self, subnet: str, port_range: str = '1-1000') -> List[Dict]:
        logger.info(f"Starting comprehensive scan of {subnet}")
        start_time = time.time()
        
        live_hosts = self.discover_hosts(subnet)
        
        scanned_devices = []
        for host_info in live_hosts:
            try:
                port_scan = self.scan_ports_and_services(host_info['ip'], port_range)
                
                device_profile = {
                    **host_info,
                    **port_scan,
                    'mac_address': self.get_mac_address(host_info['ip']),
                    'scan_timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
                }
                
                scanned_devices.append(device_profile)
                logger.info(f"Completed scan for {host_info['ip']}")
                
            except Exception as e:
                logger.error(f"Failed to scan {host_info['ip']}: {str(e)}")
                
        scan_duration = time.time() - start_time
        logger.info(f"Scan completed in {scan_duration:.2f} seconds")
        logger.info(f"Analyzed {len(scanned_devices)} devices")
        
        return scanned_devices