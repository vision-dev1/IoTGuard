import re
import json
import logging
from typing import Dict, List, Tuple
from collections import defaultdict

logger = logging.getLogger(__name__)

class DeviceFingerprinter:
    
    def __init__(self):
        self.mac_vendors = self._load_mac_vendors()
        
        self.service_patterns = {
            'camera': ['rtsp', 'onvif', 'axis', 'hikvision', 'dahua'],
            'router': ['http', 'ssh', 'telnet', 'snmp', 'upnp'],
            'printer': ['ipp', 'lpd', 'jetdirect'],
            'smart_home': ['mqtt', 'zigbee', 'zwave', 'homekit'],
            'nas': ['nfs', 'smb', 'afp', 'ftp'],
            'iot_gateway': ['coap', 'lwm2m', 'opcua']
        }
    
    def _load_mac_vendors(self) -> Dict[str, str]:
        vendors = {
            '00:1E:C0': 'Raspberry Pi Foundation',
            'B8:27:EB': 'Raspberry Pi Foundation',
            'DC:A6:32': 'Raspberry Pi Trading Ltd',
            '28:CD:C1': 'HUAWEI TECHNOLOGIES CO.,LTD',
            '00:1A:2B': 'Ayecom Technology Co., Ltd.',
            '00:1D:BA': 'Intelicis Corporation',
            '00:1E:58': 'Sony Mobile Communications AB',
            '00:1F:3B': 'NETGEAR',
            '00:22:61': 'Frontier Silicon Ltd',
            '00:23:6C': 'Apple, Inc.',
            '00:24:E8': 'Samsung Electronics Co.,Ltd',
            '00:26:75': 'Aztech Electronics Pte Ltd',
            '00:27:0E': 'Ubiquiti Networks Inc.',
            '00:50:56': 'VMware, Inc.',
            '00:AA:00': 'Intel Corporation',
            '00:DD:01': 'Ungermann-Bass Inc.',
            '08:00:20': 'Sun Microsystems Inc.',
            '08:00:27': 'PCS Systemtechnik GmbH',
            '52:54:00': 'QEMU virtual NIC',
            '54:52:00': 'VirtualBox virtual NIC'
        }
        return vendors
    
    def identify_vendor_from_mac(self, mac_address: str) -> str:
        if not mac_address:
            return 'Unknown'
            
        normalized_mac = mac_address.upper().replace('-', ':')
        if ':' in normalized_mac:
            vendor_prefix = ':'.join(normalized_mac.split(':')[:3])
            return self.mac_vendors.get(vendor_prefix, 'Unknown Vendor')
        return 'Unknown'
    
    def classify_device_type(self, services: List[Dict], hostname: str = '') -> str:
        service_names = [service.get('service', '').lower() for service in services]
        hostname_lower = hostname.lower()
        
        scores = defaultdict(int)
        for device_type, patterns in self.service_patterns.items():
            for pattern in patterns:
                for service_name in service_names:
                    if pattern in service_name:
                        scores[device_type] += 2
                if pattern in hostname_lower:
                    scores[device_type] += 1
        
        if any('camera' in s or 'rtsp' in s for s in service_names):
            scores['camera'] += 3
            
        if any('printer' in s or 'ipp' in s for s in service_names):
            scores['printer'] += 3
            
        if any('mqtt' in s for s in service_names):
            scores['smart_home'] += 2
            
        if scores:
            device_type = max(scores.items(), key=lambda x: x[1])[0]
            if scores[device_type] >= 2:
                return device_type.title()
        
        return 'Generic IoT Device'
    
    def extract_device_metadata(self, device_data: Dict) -> Dict:
        metadata = {
            'vendor': self.identify_vendor_from_mac(device_data.get('mac_address', '')),
            'device_type': self.classify_device_type(
                device_data.get('services', []), 
                device_data.get('hostname', '')
            ),
            'open_port_count': len(device_data.get('open_ports', [])),
            'services_detected': len(device_data.get('services', []))
        }
        
        banners = []
        for service in device_data.get('services', []):
            if service.get('banner'):
                banners.append(service['banner'])
            if service.get('product'):
                banners.append(service['product'])
            if service.get('version'):
                banners.append(service['version'])
        
        metadata['banners'] = '; '.join(banners)[:200]
        return metadata
    
    def fingerprint_device(self, device_data: Dict) -> Dict:
        fingerprint = {
            'basic_info': {
                'ip_address': device_data.get('ip'),
                'hostname': device_data.get('hostname'),
                'mac_address': device_data.get('mac_address'),
                'status': device_data.get('status')
            },
            'network_info': {
                'open_ports': device_data.get('open_ports', []),
                'services': device_data.get('services', [])
            },
            'identification': self.extract_device_metadata(device_data),
            'scan_details': {
                'timestamp': device_data.get('scan_timestamp'),
                'os_guess': device_data.get('os_guess', 'Unknown')
            }
        }
        
        logger.debug(f"Fingerprinted device: {fingerprint['basic_info']['ip_address']} "
                    f"as {fingerprint['identification']['device_type']}")
        
        return fingerprint