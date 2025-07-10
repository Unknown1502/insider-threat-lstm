#!/usr/bin/env python3
"""
Splunk Backend Integration
Handles communication with Splunk instance and MLTK
"""

import os
import json
import logging
from datetime import datetime, timedelta
import requests
import urllib3
import defusedxml.ElementTree as ET

logger = logging.getLogger(__name__)

class SplunkBackend:
    """Splunk backend integration for insider threat detection"""
    
    def __init__(self):
        self.splunk_host = os.getenv('SPLUNK_HOST', 'localhost')
        self.splunk_port = os.getenv('SPLUNK_PORT', '8089')
        self.splunk_username = os.getenv('SPLUNK_USERNAME', 'admin')
        self.splunk_password = os.getenv('SPLUNK_PASSWORD', 'changeme')
        self.splunk_app = os.getenv('SPLUNK_APP', 'insider_threat_detection')
        
        self.base_url = f"https://{self.splunk_host}:{self.splunk_port}"
        self.session_key = None
        self.splunk_enabled = os.getenv('SPLUNK_ENABLED', 'false').lower() == 'true'
        
        # SSL certificate verification settings
        # Allow disabling SSL verification only for development environments
        self.verify_ssl = os.getenv('SPLUNK_VERIFY_SSL', 'true').lower() == 'true'
        self.ca_cert_path = os.getenv('SPLUNK_CA_CERT_PATH', None)
        
        # Disable SSL warnings only when verification is explicitly disabled
        if not self.verify_ssl:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
        # Only initialize connection if Splunk is enabled
        if self.splunk_enabled:
            self._authenticate()
        else:
            logger.info("Splunk integration disabled (SPLUNK_ENABLED=false)")
    
    def _get_ssl_verify(self):
        """Get SSL verification setting - returns True/False or path to CA cert"""
        if self.ca_cert_path and os.path.exists(self.ca_cert_path):
            return self.ca_cert_path
        return self.verify_ssl
    
    def _authenticate(self):
        """Authenticate with Splunk instance"""
        if not self.splunk_enabled:
            return
            
        try:
            auth_url = f"{self.base_url}/services/auth/login"
            auth_data = {
                'username': self.splunk_username,
                'password': self.splunk_password
            }
            
            response = requests.post(auth_url, data=auth_data, verify=self._get_ssl_verify(), timeout=5)
            
            if response.status_code == 200:
                # Extract session key from XML response
                root = ET.fromstring(response.content)
                session_key = root.find('.//sessionKey')
                if session_key is not None:
                    self.session_key = session_key.text
                    logger.info("Successfully authenticated with Splunk")
                else:
                    logger.error("Failed to extract session key from Splunk response")
            else:
                logger.error(f"Splunk authentication failed: {response.status_code}")
                
        except Exception as e:
            logger.debug(f"Splunk not available: {str(e)}")
    
    def _get_headers(self):
        """Get headers for Splunk API requests"""
        return {
            'Authorization': f'Splunk {self.session_key}',
            'Content-Type': 'application/json'
        }
    
    def execute_search(self, search_query, earliest_time='-1h', latest_time='now'):
        """Execute SPL search query"""
        if not self.splunk_enabled:
            return None
            
        try:
            search_url = f"{self.base_url}/services/search/jobs"
            
            search_data = {
                'search': search_query,
                'earliest_time': earliest_time,
                'latest_time': latest_time,
                'output_mode': 'json'
            }
            
            # Start search job
            response = requests.post(
                search_url,
                data=search_data,
                headers=self._get_headers(),
                verify=self._get_ssl_verify(),
                timeout=10
            )
            
            if response.status_code == 201:
                root = ET.fromstring(response.content)
                sid = root.find('.//sid')
                if sid is not None:
                    return self._wait_for_search_completion(sid.text)
            else:
                logger.error(f"Failed to start search job: {response.status_code}")
                return None
                
        except Exception as e:
            logger.debug(f"Splunk search not available: {str(e)}")
            return None
    
    def _wait_for_search_completion(self, search_id):
        """Wait for search job completion and return results"""
        try:
            status_url = f"{self.base_url}/services/search/jobs/{search_id}"
            results_url = f"{self.base_url}/services/search/jobs/{search_id}/results"
            
            # Wait for completion
            import time
            max_wait = 300  # 5 minutes
            waited = 0
            
            while waited < max_wait:
                response = requests.get(
                    status_url,
                    headers=self._get_headers(),
                    verify=self._get_ssl_verify()
                )
                
                if response.status_code == 200:
                    import xml.etree.ElementTree as ET
                    root = ET.fromstring(response.content)
                    
                    # Check if search is done
                    is_done = root.find('.//s:key[@name="isDone"]', {'s': 'http://dev.splunk.com/ns/rest'})
                    if is_done is not None and is_done.text == '1':
                        break
                
                time.sleep(5)
                waited += 5
            
            # Get results
            response = requests.get(
                results_url,
                headers=self._get_headers(),
                params={'output_mode': 'json'},
                verify=self._get_ssl_verify()
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                logger.error(f"Failed to get search results: {response.status_code}")
                return None
                
        except Exception as e:
            logger.error(f"Error waiting for search completion: {str(e)}")
            return None
    
    def fetch_new_data(self):
        """Fetch new data from Splunk for threat detection"""
        if not self.splunk_enabled:
            return []
            
        try:
            # SPL query to get recent email and authentication events
            search_query = '''
            search index=main earliest=-5m latest=now
            | eval event_type=case(
                match(sourcetype, "email"), "email",
                match(sourcetype, "auth"), "authentication",
                match(sourcetype, "web"), "web",
                1=1, "other"
            )
            | where event_type IN ("email", "authentication", "web")
            | eval timestamp=_time
            | eval user=coalesce(user, src_user, from, sender)
            | eval src_ip=coalesce(src_ip, src, client_ip)
            | eval dest_ip=coalesce(dest_ip, dest, server_ip)
            | eval action=coalesce(action, verb, command)
            | eval size=coalesce(size, bytes_out, bytes_in)
            | fields timestamp, user, src_ip, dest_ip, action, size, event_type, _raw
            '''
            
            results = self.execute_search(search_query)
            
            if results and 'results' in results:
                return results['results']
            else:
                return []
                
        except Exception as e:
            logger.debug(f"Splunk data fetch not available: {str(e)}")
            return []
    
    def get_email_events(self, time_range='-24h'):
        """Get email events for analysis"""
        try:
            search_query = f'''
            search index=main sourcetype=email earliest={time_range} latest=now
            | eval timestamp=_time
            | eval sender=coalesce(sender, from)
            | eval recipient=coalesce(recipient, to)
            | eval subject=coalesce(subject, email_subject)
            | eval size=coalesce(size, message_size)
            | eval attachment_count=coalesce(attachment_count, attachments)
            | fields timestamp, sender, recipient, subject, size, attachment_count, _raw
            '''
            
            results = self.execute_search(search_query)
            return results.get('results', []) if results else []
            
        except Exception as e:
            logger.error(f"Error getting email events: {str(e)}")
            return []
    
    def get_authentication_events(self, time_range='-24h'):
        """Get authentication events for analysis"""
        try:
            search_query = f'''
            search index=main sourcetype=auth earliest={time_range} latest=now
            | eval timestamp=_time
            | eval user=coalesce(user, src_user, username)
            | eval src_ip=coalesce(src_ip, src, client_ip)
            | eval dest_ip=coalesce(dest_ip, dest, server_ip)
            | eval action=coalesce(action, auth_action, result)
            | eval success=case(
                match(action, "success|Success|LOGIN"), 1,
                match(action, "failure|Failure|FAILED"), 0,
                1=1, null()
            )
            | fields timestamp, user, src_ip, dest_ip, action, success, _raw
            '''
            
            results = self.execute_search(search_query)
            return results.get('results', []) if results else []
            
        except Exception as e:
            logger.error(f"Error getting authentication events: {str(e)}")
            return []
    
    def send_alert_to_splunk(self, alert_data):
        """Send alert back to Splunk"""
        try:
            # Create alert event in Splunk
            alert_event = {
                'timestamp': alert_data['timestamp'],
                'alert_type': 'insider_threat',
                'threat_score': alert_data['threat_score'],
                'user': alert_data.get('user', 'unknown'),
                'src_ip': alert_data.get('src_ip', 'unknown'),
                'event_data': json.dumps(alert_data['event_data']),
                'severity': 'high' if alert_data['threat_score'] > 0.8 else 'medium'
            }
            
            # Send to Splunk HTTP Event Collector (HEC)
            hec_url = f"{self.base_url}/services/collector/event"
            hec_token = os.getenv('SPLUNK_HEC_TOKEN', '')
            
            if hec_token:
                hec_headers = {
                    'Authorization': f'Splunk {hec_token}',
                    'Content-Type': 'application/json'
                }
                
                hec_data = {
                    'event': alert_event,
                    'sourcetype': 'insider_threat_alert',
                    'index': 'main'
                }
                
                response = requests.post(
                    hec_url,
                    json=hec_data,
                    headers=hec_headers,
                    verify=self._get_ssl_verify()
                )
                
                if response.status_code == 200:
                    logger.info("Alert sent to Splunk successfully")
                    return True
                else:
                    logger.error(f"Failed to send alert to Splunk: {response.status_code}")
            else:
                logger.warning("No HEC token configured for sending alerts")
                
        except Exception as e:
            logger.error(f"Error sending alert to Splunk: {str(e)}")
        
        return False
    
    def create_saved_search(self, name, search_query, cron_schedule="0 */1 * * *"):
        """Create a saved search for automated threat detection"""
        try:
            saved_search_url = f"{self.base_url}/services/saved/searches"
            
            search_data = {
                'name': name,
                'search': search_query,
                'cron_schedule': cron_schedule,
                'is_scheduled': '1',
                'actions': 'script',
                'action.script.filename': 'insider_threat_detection.py'
            }
            
            response = requests.post(
                saved_search_url,
                data=search_data,
                headers=self._get_headers(),
                verify=self._get_ssl_verify()
            )
            
            if response.status_code == 201:
                logger.info(f"Created saved search: {name}")
                return True
            else:
                logger.error(f"Failed to create saved search: {response.status_code}")
                return False
                
        except Exception as e:
            logger.error(f"Error creating saved search: {str(e)}")
            return False
    
    def get_model_data_for_training(self, days_back=30):
        """Get historical data for model training"""
        try:
            search_query = f'''
            search index=main earliest=-{days_back}d latest=now
            | eval event_type=case(
                match(sourcetype, "email"), "email",
                match(sourcetype, "auth"), "authentication",
                match(sourcetype, "web"), "web",
                1=1, "other"
            )
            | where event_type IN ("email", "authentication", "web")
            | eval timestamp=_time
            | eval user=coalesce(user, src_user, from, sender)
            | eval src_ip=coalesce(src_ip, src, client_ip)
            | eval dest_ip=coalesce(dest_ip, dest, server_ip)
            | eval action=coalesce(action, verb, command)
            | eval size=coalesce(size, bytes_out, bytes_in)
            | eval hour=strftime(_time, "%H")
            | eval day_of_week=strftime(_time, "%w")
            | stats count, avg(size) as avg_size, dc(dest_ip) as unique_destinations, 
                    dc(action) as unique_actions by user, hour, day_of_week, event_type
            | eval behavior_score=case(
                count > 100, 0.8,
                count > 50, 0.6,
                count > 20, 0.4,
                1=1, 0.2
            )
            '''
            
            results = self.execute_search(search_query)
            return results.get('results', []) if results else []
            
        except Exception as e:
            logger.error(f"Error getting model training data: {str(e)}")
            return []
