import json
import logging
from typing import Dict, List, Tuple
from enum import Enum

logger = logging.getLogger(__name__)

class RiskLevel(Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM" 
    HIGH = "HIGH"

class RiskRulesEngine:
    
    def __init__(self, mitigations_file: str = 'mitigations/mitigations.json'):
        self.mitigations = self._load_mitigations(mitigations_file)
        self.risk_rules = self._define_risk_rules()
    
    def _load_mitigations(self, file_path: str) -> Dict:
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
                return data.get('mitigations', {})
        except FileNotFoundError:
            logger.warning(f"Mitigations file not found: {file_path}")
            return {}
        except json.JSONDecodeError as e:
            logger.error(f"Error parsing mitigations file: {e}")
            return {}
    
    def _define_risk_rules(self) -> Dict:
        return {
            'TELNET_EXPOSED': {
                'condition': lambda services: any(s.get('service') == 'telnet' for s in services),
                'risk_level': RiskLevel.HIGH,
                'mitigation_key': 'TELNET_EXPOSED'
            },
            'HTTP_INSECURE': {
                'condition': lambda services: (
                    any(s.get('service') == 'http' for s in services) and
                    not any(s.get('service') == 'https' for s in services)
                ),
                'risk_level': RiskLevel.MEDIUM,
                'mitigation_key': 'HTTP_INSECURE'
            },
            'CAMERA_RTSP_OPEN': {
                'condition': lambda services: any(
                    'rtsp' in s.get('service', '') or 
                    'onvif' in s.get('service', '') 
                    for s in services
                ),
                'risk_level': RiskLevel.HIGH,
                'mitigation_key': 'CAMERA_RTSP_OPEN'
            },
            'MQTT_NO_AUTH': {
                'condition': lambda services: any('mqtt' in s.get('service', '') for s in services),
                'risk_level': RiskLevel.HIGH,
                'mitigation_key': 'MQTT_NO_AUTH'
            },
            'UPNP_ENABLED': {
                'condition': lambda services: any('upnp' in s.get('service', '') for s in services),
                'risk_level': RiskLevel.MEDIUM,
                'mitigation_key': 'UPNP_ENABLED'
            },
            'WEAK_SSH_CONFIG': {
                'condition': lambda services: (
                    any(s.get('service') == 'ssh' for s in services) and
                    any(s.get('port') == 22 for s in services)
                ),
                'risk_level': RiskLevel.MEDIUM,
                'mitigation_key': 'WEAK_SSH_CONFIG'
            },
            'DEFAULT_CREDENTIALS': {
                'condition': lambda services: any(
                    s.get('banner', '').lower() in ['admin', 'root', 'default', 'password'] or
                    s.get('product', '').lower() in ['router', 'camera', 'printer']
                    for s in services
                ),
                'risk_level': RiskLevel.HIGH,
                'mitigation_key': 'DEFAULT_CREDENTIALS'
            }
        }
    
    def assess_device_risks(self, device_fingerprint: Dict) -> List[Dict]:
        services = device_fingerprint.get('network_info', {}).get('services', [])
        risks = []
        
        for rule_name, rule in self.risk_rules.items():
            try:
                if rule['condition'](services):
                    risk_assessment = {
                        'risk_id': rule_name,
                        'risk_level': rule['risk_level'].value,
                        'detected_service': self._find_triggering_service(services, rule['condition']),
                        'mitigation': self._get_mitigation(rule['mitigation_key'])
                    }
                    risks.append(risk_assessment)
                    logger.debug(f"Risk detected for {device_fingerprint['basic_info']['ip_address']}: {rule_name}")
            except Exception as e:
                logger.error(f"Error applying risk rule {rule_name}: {str(e)}")
        
        return risks
    
    def _find_triggering_service(self, services: List[Dict], condition_func) -> str:
        for service in services:
            temp_services = [service]
            if condition_func(temp_services):
                return f"{service.get('service')}:{service.get('port')}"
        return "Unknown service"
    
    def _get_mitigation(self, mitigation_key: str) -> Dict:
        mitigation = self.mitigations.get(mitigation_key, {})
        return {
            'title': mitigation.get('title', 'Unknown Risk'),
            'description': mitigation.get('description', ''),
            'danger': mitigation.get('danger', ''),
            'mitigation_steps': mitigation.get('mitigation_steps', []),
            'references': mitigation.get('references', [])
        }
    
    def calculate_overall_risk_score(self, risks: List[Dict]) -> Tuple[str, int]:
        if not risks:
            return RiskLevel.LOW.value, 0
            
        risk_scores = {
            RiskLevel.LOW.value: 1,
            RiskLevel.MEDIUM.value: 2, 
            RiskLevel.HIGH.value: 3
        }
        
        total_score = sum(risk_scores.get(risk['risk_level'], 0) for risk in risks)
        max_possible = len(risks) * risk_scores[RiskLevel.HIGH.value]
        
        if total_score == 0:
            return RiskLevel.LOW.value, 0
        elif total_score <= max_possible * 0.33:
            return RiskLevel.LOW.value, total_score
        elif total_score <= max_possible * 0.66:
            return RiskLevel.MEDIUM.value, total_score
        else:
            return RiskLevel.HIGH.value, total_score
    
    def generate_risk_report(self, devices_with_risks: List[Dict]) -> Dict:
        total_devices = len(devices_with_risks)
        risk_summary = {
            'LOW': 0,
            'MEDIUM': 0,
            'HIGH': 0
        }
        
        for device in devices_with_risks:
            overall_risk = device.get('overall_risk', 'LOW')
            risk_summary[overall_risk] += 1
        
        report = {
            'scan_summary': {
                'total_devices_scanned': total_devices,
                'devices_by_risk_level': risk_summary,
                'high_risk_devices': risk_summary['HIGH'],
                'timestamp': self._get_current_timestamp()
            },
            'devices': devices_with_risks
        }
        
        logger.info(f"Risk assessment complete: {total_devices} devices, "
                   f"{risk_summary['HIGH']} high risk, {risk_summary['MEDIUM']} medium risk")
        
        return report
    
    def _get_current_timestamp(self) -> str:
        import time
        return time.strftime('%Y-%m-%d %H:%M:%S')