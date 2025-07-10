#!/usr/bin/env python3
"""
Common Information Model (CIM) Transformer
Transforms data to CIM-compliant format for Splunk
"""

import os
import json
import logging
from datetime import datetime
import pandas as pd
import re

logger = logging.getLogger(__name__)

class CIMTransformer:
    """Transforms data to CIM-compliant format"""
    
    def __init__(self):
        self.email_mapping = {
            'message_id': 'message_id',
            'from': 'src_user',
            'to': 'dest_user',
            'cc': 'cc',
            'bcc': 'bcc',
            'subject': 'subject',
            'size': 'size',
            'attachments': 'attachment_count',
            'timestamp': 'timestamp',
            'date': 'timestamp'
        }
        
        self.auth_mapping = {
            'user': 'user',
            'src_ip': 'src_ip',
            'dest_ip': 'dest_ip',
            'action': 'action',
            'result': 'result',
            'timestamp': 'timestamp'
        }
        
        self.web_mapping = {
            'user': 'user',
            'src_ip': 'src_ip',
            'dest_ip': 'dest_ip',
            'url': 'url',
            'method': 'http_method',
            'status': 'status',
            'bytes': 'bytes',
            'timestamp': 'timestamp'
        }
    
    def transform_to_cim(self, raw_data):
        """Transform raw data to CIM format"""
        try:
            if isinstance(raw_data, dict):
                return self._transform_single_event(raw_data)
            elif isinstance(raw_data, list):
                return [self._transform_single_event(event) for event in raw_data]
            else:
                logger.error("Invalid data format for CIM transformation")
                return None
                
        except Exception as e:
            logger.error(f"Error transforming to CIM: {str(e)}")
            return None
    
    def _transform_single_event(self, event):
        """Transform a single event to CIM format"""
        try:
            # Detect event type
            event_type = self._detect_event_type(event)
            
            # Transform based on event type
            if event_type == 'email':
                return self._transform_email_event(event)
            elif event_type == 'authentication':
                return self._transform_auth_event(event)
            elif event_type == 'web':
                return self._transform_web_event(event)
            else:
                return self._transform_generic_event(event)
                
        except Exception as e:
            logger.error(f"Error transforming single event: {str(e)}")
            return event
    
    def _detect_event_type(self, event):
        """Detect the type of event"""
        try:
            # Check for email indicators
            email_fields = ['from', 'to', 'subject', 'size', 'attachments', 'message_id']
            if any(field in event for field in email_fields):
                return 'email'
            
            # Check for authentication indicators
            auth_fields = ['user', 'action', 'result', 'login', 'auth']
            if any(field in event for field in auth_fields):
                return 'authentication'
            
            # Check for web indicators
            web_fields = ['url', 'method', 'status', 'http_method', 'referer']
            if any(field in event for field in web_fields):
                return 'web'
            
            # Check for explicit event type
            if 'event_type' in event:
                return event['event_type']
            
            return 'generic'
            
        except Exception as e:
            logger.error(f"Error detecting event type: {str(e)}")
            return 'generic'
    
    def _transform_email_event(self, event):
        """Transform email event to CIM format"""
        try:
            cim_event = {
                'event_type': 'email',
                'timestamp': self._normalize_timestamp(event.get('timestamp', event.get('date'))),
                'sourcetype': 'email',
                'source': 'insider_threat_detection'
            }
            
            # Map email fields
            for raw_field, cim_field in self.email_mapping.items():
                if raw_field in event:
                    cim_event[cim_field] = event[raw_field]
            
            # Additional CIM fields for email
            cim_event['message_id'] = event.get('id', event.get('message_id', 'unknown'))
            cim_event['sender'] = event.get('from', event.get('sender', 'unknown'))
            cim_event['recipient'] = event.get('to', event.get('recipient', 'unknown'))
            cim_event['message_size'] = self._normalize_size(event.get('size', 0))
            cim_event['attachment_count'] = int(event.get('attachments', event.get('attachment_count', 0)))
            
            # Extract domain information
            sender_domain = self._extract_domain(cim_event['sender'])
            recipient_domain = self._extract_domain(cim_event['recipient'])
            
            cim_event['sender_domain'] = sender_domain
            cim_event['recipient_domain'] = recipient_domain
            cim_event['is_external'] = 1 if sender_domain != recipient_domain else 0
            
            # Risk scoring
            cim_event['risk_score'] = self._calculate_email_risk(cim_event)
            
            return cim_event
            
        except Exception as e:
            logger.error(f"Error transforming email event: {str(e)}")
            return event
    
    def _transform_auth_event(self, event):
        """Transform authentication event to CIM format"""
        try:
            cim_event = {
                'event_type': 'authentication',
                'timestamp': self._normalize_timestamp(event.get('timestamp')),
                'sourcetype': 'auth',
                'source': 'insider_threat_detection'
            }
            
            # Map authentication fields
            for raw_field, cim_field in self.auth_mapping.items():
                if raw_field in event:
                    cim_event[cim_field] = event[raw_field]
            
            # Additional CIM fields for authentication
            cim_event['user'] = event.get('user', event.get('username', 'unknown'))
            cim_event['src_ip'] = event.get('src_ip', event.get('source_ip', 'unknown'))
            cim_event['dest_ip'] = event.get('dest_ip', event.get('destination_ip', 'unknown'))
            cim_event['action'] = event.get('action', event.get('auth_action', 'unknown'))
            cim_event['result'] = event.get('result', event.get('auth_result', 'unknown'))
            
            # Normalize result
            cim_event['success'] = self._normalize_auth_result(cim_event['result'])
            
            # Risk scoring
            cim_event['risk_score'] = self._calculate_auth_risk(cim_event)
            
            return cim_event
            
        except Exception as e:
            logger.error(f"Error transforming auth event: {str(e)}")
            return event
    
    def _transform_web_event(self, event):
        """Transform web event to CIM format"""
        try:
            cim_event = {
                'event_type': 'web',
                'timestamp': self._normalize_timestamp(event.get('timestamp')),
                'sourcetype': 'web',
                'source': 'insider_threat_detection'
            }
            
            # Map web fields
            for raw_field, cim_field in self.web_mapping.items():
                if raw_field in event:
                    cim_event[cim_field] = event[raw_field]
            
            # Additional CIM fields for web
            cim_event['user'] = event.get('user', event.get('username', 'unknown'))
            cim_event['src_ip'] = event.get('src_ip', event.get('client_ip', 'unknown'))
            cim_event['dest_ip'] = event.get('dest_ip', event.get('server_ip', 'unknown'))
            cim_event['url'] = event.get('url', event.get('uri', 'unknown'))
            cim_event['http_method'] = event.get('method', event.get('http_method', 'GET'))
            cim_event['status'] = int(event.get('status', event.get('http_status', 200)))
            cim_event['bytes'] = int(event.get('bytes', event.get('bytes_out', 0)))
            
            # Extract URL components
            cim_event['domain'] = self._extract_domain_from_url(cim_event['url'])
            cim_event['is_external'] = 1 if self._is_external_domain(cim_event['domain']) else 0
            
            # Risk scoring
            cim_event['risk_score'] = self._calculate_web_risk(cim_event)
            
            return cim_event
            
        except Exception as e:
            logger.error(f"Error transforming web event: {str(e)}")
            return event
    
    def _transform_generic_event(self, event):
        """Transform generic event to CIM format"""
        try:
            cim_event = {
                'event_type': 'generic',
                'timestamp': self._normalize_timestamp(event.get('timestamp')),
                'sourcetype': 'generic',
                'source': 'insider_threat_detection'
            }
            
            # Copy all fields
            for key, value in event.items():
                if key not in cim_event:
                    cim_event[key] = value
            
            # Add basic risk score
            cim_event['risk_score'] = 0.1
            
            return cim_event
            
        except Exception as e:
            logger.error(f"Error transforming generic event: {str(e)}")
            return event
    
    def _normalize_timestamp(self, timestamp):
        """Normalize timestamp to ISO format"""
        try:
            if timestamp is None:
                return datetime.now().isoformat()
            
            if isinstance(timestamp, str):
                # Try different timestamp formats
                formats = [
                    '%Y-%m-%d %H:%M:%S',
                    '%m/%d/%Y %H:%M:%S',
                    '%Y-%m-%dT%H:%M:%S',
                    '%Y-%m-%dT%H:%M:%SZ',
                    '%Y-%m-%dT%H:%M:%S.%f'
                ]
                
                for fmt in formats:
                    try:
                        dt = datetime.strptime(timestamp, fmt)
                        return dt.isoformat()
                    except ValueError:
                        continue
                
                # If no format matches, return as is
                return timestamp
            
            elif isinstance(timestamp, (int, float)):
                # Unix timestamp
                dt = datetime.fromtimestamp(timestamp)
                return dt.isoformat()
            
            else:
                return str(timestamp)
                
        except Exception as e:
            logger.error(f"Error normalizing timestamp: {str(e)}")
            return datetime.now().isoformat()
    
    def _normalize_size(self, size):
        """Normalize size to integer"""
        try:
            if isinstance(size, str):
                # Remove non-numeric characters
                size = re.sub(r'[^\d.]', '', size)
                return int(float(size)) if size else 0
            else:
                return int(size)
        except (ValueError, TypeError):
            return 0
    
    def _normalize_auth_result(self, result):
        """Normalize authentication result to boolean"""
        try:
            if isinstance(result, str):
                result_lower = result.lower()
                if any(success_term in result_lower for success_term in ['success', 'pass', 'ok', 'true', 'login']):
                    return 1
                elif any(fail_term in result_lower for fail_term in ['fail', 'error', 'false', 'deny', 'reject']):
                    return 0
                else:
                    return 0
            else:
                return 1 if result else 0
        except Exception:
            return 0
    
    def _extract_domain(self, email):
        """Extract domain from email address"""
        try:
            if '@' in str(email):
                return str(email).split('@')[1]
            else:
                return 'unknown'
        except Exception:
            return 'unknown'
    
    def _extract_domain_from_url(self, url):
        """Extract domain from URL"""
        try:
            if '://' in str(url):
                domain = str(url).split('://')[1].split('/')[0]
                return domain
            else:
                return str(url).split('/')[0]
        except Exception:
            return 'unknown'
    
    def _is_external_domain(self, domain):
        """Check if domain is external"""
        try:
            internal_domains = ['dtaa.com', 'company.com', 'localhost', '127.0.0.1']
            return domain.lower() not in [d.lower() for d in internal_domains]
        except Exception:
            return True
    
    def _calculate_email_risk(self, event):
        """Calculate risk score for email event"""
        try:
            risk_score = 0.0
            
            # Size-based risk
            size = event.get('message_size', 0)
            if size > 50000000:  # 50MB
                risk_score += 0.4
            elif size > 10000000:  # 10MB
                risk_score += 0.2
            
            # Attachment risk
            attachment_count = event.get('attachment_count', 0)
            if attachment_count > 10:
                risk_score += 0.3
            elif attachment_count > 5:
                risk_score += 0.2
            
            # External communication risk
            if event.get('is_external', 0):
                risk_score += 0.3
            
            # Time-based risk
            timestamp = event.get('timestamp', '')
            if timestamp:
                try:
                    dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                    hour = dt.hour
                    if hour < 6 or hour > 22:  # After hours
                        risk_score += 0.2
                except Exception:
                    pass
            
            return min(risk_score, 1.0)
            
        except Exception as e:
            logger.error(f"Error calculating email risk: {str(e)}")
            return 0.1
    
    def _calculate_auth_risk(self, event):
        """Calculate risk score for authentication event"""
        try:
            risk_score = 0.0
            
            # Failed authentication risk
            if not event.get('success', 1):
                risk_score += 0.5
            
            # Admin user risk
            user = event.get('user', '').lower()
            if 'admin' in user or 'root' in user:
                risk_score += 0.3
            
            # External IP risk
            src_ip = event.get('src_ip', '')
            if not src_ip.startswith('10.') and not src_ip.startswith('192.168.'):
                risk_score += 0.4
            
            # Time-based risk
            timestamp = event.get('timestamp', '')
            if timestamp:
                try:
                    dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                    hour = dt.hour
                    if hour < 6 or hour > 22:  # After hours
                        risk_score += 0.2
                except Exception:
                    pass
            
            return min(risk_score, 1.0)
            
        except Exception as e:
            logger.error(f"Error calculating auth risk: {str(e)}")
            return 0.1
    
    def _calculate_web_risk(self, event):
        """Calculate risk score for web event"""
        try:
            risk_score = 0.0
            
            # Status code risk
            status = event.get('status', 200)
            if status >= 400:
                risk_score += 0.3
            
            # External domain risk
            if event.get('is_external', 0):
                risk_score += 0.2
            
            # Large transfer risk
            bytes_transferred = event.get('bytes', 0)
            if bytes_transferred > 100000000:  # 100MB
                risk_score += 0.4
            
            # Suspicious methods
            method = event.get('http_method', 'GET').upper()
            if method in ['DELETE', 'PUT', 'PATCH']:
                risk_score += 0.2
            
            return min(risk_score, 1.0)
            
        except Exception as e:
            logger.error(f"Error calculating web risk: {str(e)}")
            return 0.1
    
    def transform_splunk_data(self, splunk_results):
        """Transform Splunk search results to CIM format"""
        try:
            if not splunk_results:
                return []
            
            # Handle different Splunk result formats
            if isinstance(splunk_results, dict):
                if 'results' in splunk_results:
                    events = splunk_results['results']
                else:
                    events = [splunk_results]
            elif isinstance(splunk_results, list):
                events = splunk_results
            else:
                logger.error("Invalid Splunk results format")
                return []
            
            cim_events = []
            for event in events:
                cim_event = self._transform_single_event(event)
                if cim_event:
                    cim_events.append(cim_event)
            
            return cim_events
            
        except Exception as e:
            logger.error(f"Error transforming Splunk data: {str(e)}")
            return []
    
    def validate_cim_compliance(self, event):
        """Validate CIM compliance of an event"""
        try:
            required_fields = ['timestamp', 'sourcetype', 'source', 'event_type']
            
            validation_result = {
                'is_compliant': True,
                'missing_fields': [],
                'warnings': []
            }
            
            # Check required fields
            for field in required_fields:
                if field not in event:
                    validation_result['missing_fields'].append(field)
                    validation_result['is_compliant'] = False
            
            # Check timestamp format
            if 'timestamp' in event:
                try:
                    datetime.fromisoformat(event['timestamp'].replace('Z', '+00:00'))
                except Exception:
                    validation_result['warnings'].append('Invalid timestamp format')
            
            # Check event type specific fields
            event_type = event.get('event_type', 'generic')
            if event_type == 'email':
                email_fields = ['sender', 'recipient', 'message_size']
                for field in email_fields:
                    if field not in event:
                        validation_result['warnings'].append(f'Missing recommended email field: {field}')
            
            return validation_result
            
        except Exception as e:
            logger.error(f"Error validating CIM compliance: {str(e)}")
            return {'is_compliant': False, 'error': str(e)}
