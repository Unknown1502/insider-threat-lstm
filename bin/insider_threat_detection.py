#!/usr/bin/env python3
"""
Insider Threat Detection Search Command
Splunk custom search command for LSTM-based insider threat detection
"""

import os
import sys
import json
import logging
from datetime import datetime, timedelta

# Add the app directory to Python path
app_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, app_dir)

try:
    from splunklib.searchcommands import dispatch, StreamingCommand, Configuration, Option, validators
    from splunklib.searchcommands.decorators import ConfigurationSetting
except ImportError as e:
    print(f"Error importing Splunk libraries: {e}")
    sys.exit(1)

# Import our custom modules
try:
    from lstm_model import InsiderThreatLSTM
    from cim_transformer import CIMTransformer
    from data_processor import DataProcessor
    from alert_manager import AlertManager
except ImportError as e:
    print(f"Error importing custom modules: {e}")
    sys.exit(1)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(app_dir, 'logs', 'insider_threat_detection.log')),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)

@Configuration()
class InsiderThreatDetectionCommand(StreamingCommand):
    """
    Insider Threat Detection Search Command
    
    Usage:
    | insiderthreat [threshold=0.7] [model=lstm] [output=threat_score]
    """
    
    threshold = Option(
        doc='Threat score threshold (default: 0.7)',
        require=False,
        default=0.7,
        validate=validators.Float(0.0, 1.0)
    )
    
    model = Option(
        doc='Model type to use (default: lstm)',
        require=False,
        default='lstm',
        validate=validators.Set('lstm', 'ensemble')
    )
    
    output = Option(
        doc='Output field name (default: threat_score)',
        require=False,
        default='threat_score',
        validate=validators.Fieldname()
    )
    
    def __init__(self):
        super(InsiderThreatDetectionCommand, self).__init__()
        self.lstm_model = None
        self.cim_transformer = None
        self.data_processor = None
        self.alert_manager = None
        
    def prepare(self):
        """Prepare the command execution"""
        try:
            # Initialize components
            self.lstm_model = InsiderThreatLSTM()
            self.cim_transformer = CIMTransformer()
            self.data_processor = DataProcessor()
            self.alert_manager = AlertManager()
            
            logger.info("Insider Threat Detection command initialized successfully")
            
        except Exception as e:
            logger.error(f"Error initializing command: {str(e)}")
            raise
    
    def stream(self, records):
        """Process input records and return threat scores"""
        try:
            self.prepare()
            
            for record in records:
                try:
                    # Transform record to CIM format
                    cim_record = self.cim_transformer.transform_to_cim(record)
                    
                    # Calculate threat score
                    threat_score = self.lstm_model.predict_threat(cim_record)
                    
                    # Add threat score to output
                    record[self.output] = threat_score
                    
                    # Add additional threat analysis fields
                    record['threat_level'] = self._get_threat_level(threat_score)
                    record['is_threat'] = 1 if threat_score >= self.threshold else 0
                    record['analysis_timestamp'] = datetime.now().isoformat()
                    
                    # Generate alert if threshold exceeded
                    if threat_score >= self.threshold:
                        self._generate_alert(record, threat_score)
                    
                    # Add behavioral analysis
                    anomalies = self.data_processor.detect_anomalies(cim_record)
                    record['anomaly_count'] = len(anomalies)
                    record['anomaly_types'] = ','.join([a['type'] for a in anomalies])
                    
                    # Add risk factors
                    risk_factors = self._calculate_risk_factors(cim_record)
                    record['risk_factors'] = ','.join(risk_factors)
                    record['risk_factor_count'] = len(risk_factors)
                    
                    yield record
                    
                except Exception as e:
                    logger.error(f"Error processing record: {str(e)}")
                    # Return record with error information
                    record[self.output] = 0.0
                    record['error'] = str(e)
                    yield record
                    
        except Exception as e:
            logger.error(f"Error in stream processing: {str(e)}")
            raise
    
    def _get_threat_level(self, threat_score):
        """Get threat level based on score"""
        if threat_score >= 0.9:
            return 'critical'
        elif threat_score >= 0.7:
            return 'high'
        elif threat_score >= 0.5:
            return 'medium'
        else:
            return 'low'
    
    def _generate_alert(self, record, threat_score):
        """Generate alert for high threat score"""
        try:
            alert_data = {
                'timestamp': datetime.now().isoformat(),
                'threat_score': threat_score,
                'user': record.get('user', record.get('src_user', 'unknown')),
                'src_ip': record.get('src_ip', 'unknown'),
                'dest_ip': record.get('dest_ip', 'unknown'),
                'event_type': record.get('event_type', 'unknown'),
                'alert_type': 'insider_threat',
                'event_data': record
            }
            
            self.alert_manager.create_alert(alert_data)
            logger.info(f"Alert generated for user {alert_data['user']} with threat score {threat_score}")
            
        except Exception as e:
            logger.error(f"Error generating alert: {str(e)}")
    
    def _calculate_risk_factors(self, record):
        """Calculate risk factors for the event"""
        risk_factors = []
        
        try:
            # Time-based risk factors
            timestamp = record.get('timestamp', '')
            if timestamp:
                try:
                    dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                    hour = dt.hour
                    day_of_week = dt.weekday()
                    
                    if hour < 6 or hour > 22:
                        risk_factors.append('after_hours')
                    
                    if day_of_week >= 5:
                        risk_factors.append('weekend_activity')
                        
                except Exception:
                    pass
            
            # Email-specific risk factors
            if record.get('event_type') == 'email':
                size = record.get('message_size', 0)
                attachments = record.get('attachment_count', 0)
                
                if size > 50000000:  # 50MB
                    risk_factors.append('large_email')
                elif size > 10000000:  # 10MB
                    risk_factors.append('medium_email')
                
                if attachments > 10:
                    risk_factors.append('many_attachments')
                elif attachments > 5:
                    risk_factors.append('multiple_attachments')
                
                if record.get('is_external', 0):
                    risk_factors.append('external_communication')
            
            # Authentication-specific risk factors
            elif record.get('event_type') == 'authentication':
                if not record.get('success', 1):
                    risk_factors.append('failed_authentication')
                
                user = record.get('user', '').lower()
                if 'admin' in user or 'root' in user:
                    risk_factors.append('privileged_account')
                
                src_ip = record.get('src_ip', '')
                if src_ip and not src_ip.startswith(('10.', '192.168.', '172.')):
                    risk_factors.append('external_ip')
            
            # Web-specific risk factors
            elif record.get('event_type') == 'web':
                status = record.get('status', 200)
                if status >= 400:
                    risk_factors.append('http_error')
                
                method = record.get('http_method', 'GET').upper()
                if method in ['DELETE', 'PUT', 'PATCH']:
                    risk_factors.append('suspicious_method')
                
                bytes_transferred = record.get('bytes', 0)
                if bytes_transferred > 100000000:  # 100MB
                    risk_factors.append('large_transfer')
            
            # General risk factors
            user = record.get('user', record.get('src_user', '')).lower()
            if any(term in user for term in ['admin', 'root', 'system', 'service']):
                risk_factors.append('system_account')
            
            # Data exfiltration indicators
            if record.get('is_external', 0) and record.get('message_size', 0) > 1000000:
                risk_factors.append('potential_exfiltration')
            
            return risk_factors
            
        except Exception as e:
            logger.error(f"Error calculating risk factors: {str(e)}")
            return []

# Custom search command for model training
@Configuration()
class InsiderThreatTrainCommand(StreamingCommand):
    """
    Insider Threat Model Training Command
    
    Usage:
    | insiderthreat_train [epochs=50] [batch_size=32] [model_name=default]
    """
    
    epochs = Option(
        doc='Number of training epochs (default: 50)',
        require=False,
        default=50,
        validate=validators.Integer(1, 1000)
    )
    
    batch_size = Option(
        doc='Training batch size (default: 32)',
        require=False,
        default=32,
        validate=validators.Integer(1, 1024)
    )
    
    model_name = Option(
        doc='Model name for saving (default: default)',
        require=False,
        default='default',
        validate=validators.Fieldname()
    )
    
    def stream(self, records):
        """Train the model with input data"""
        try:
            # Collect all records for training
            training_data = []
            for record in records:
                training_data.append(record)
                yield record
            
            # Start training in background
            self._start_training(training_data)
            
        except Exception as e:
            logger.error(f"Error in training command: {str(e)}")
            raise
    
    def _start_training(self, training_data):
        """Start model training with collected data"""
        try:
            import threading
            
            def train_model():
                try:
                    lstm_model = InsiderThreatLSTM()
                    data_processor = DataProcessor()
                    
                    # Preprocess training data
                    processed_data = data_processor.preprocess_cert_data(training_data)
                    
                    # Train model
                    training_result = lstm_model.train(processed_data)
                    
                    # Save model
                    lstm_model.save_model()
                    
                    logger.info(f"Model training completed successfully: {training_result}")
                    
                except Exception as e:
                    logger.error(f"Error in model training: {str(e)}")
            
            # Start training in background thread
            training_thread = threading.Thread(target=train_model)
            training_thread.daemon = True
            training_thread.start()
            
            logger.info("Model training started in background")
            
        except Exception as e:
            logger.error(f"Error starting training: {str(e)}")

# Custom search command for threat analysis
@Configuration()
class InsiderThreatAnalyzeCommand(StreamingCommand):
    """
    Insider Threat Analysis Command
    
    Usage:
    | insiderthreat_analyze [user=*] [timerange=24h] [detailed=true]
    """
    
    user = Option(
        doc='User to analyze (default: all users)',
        require=False,
        default='*'
    )
    
    timerange = Option(
        doc='Time range for analysis (default: 24h)',
        require=False,
        default='24h'
    )
    
    detailed = Option(
        doc='Include detailed analysis (default: true)',
        require=False,
        default=True,
        validate=validators.Boolean()
    )
    
    def stream(self, records):
        """Perform threat analysis on input records"""
        try:
            lstm_model = InsiderThreatLSTM()
            data_processor = DataProcessor()
            cim_transformer = CIMTransformer()
            
            user_stats = {}
            
            for record in records:
                try:
                    # Transform to CIM format
                    cim_record = cim_transformer.transform_to_cim(record)
                    
                    # Get user
                    user = cim_record.get('user', cim_record.get('src_user', 'unknown'))
                    
                    # Skip if user filter specified and doesn't match
                    if self.user != '*' and user != self.user:
                        continue
                    
                    # Initialize user stats
                    if user not in user_stats:
                        user_stats[user] = {
                            'total_events': 0,
                            'threat_scores': [],
                            'anomalies': [],
                            'risk_factors': set(),
                            'event_types': set()
                        }
                    
                    # Calculate threat score
                    threat_score = lstm_model.predict_threat(cim_record)
                    
                    # Detect anomalies
                    anomalies = data_processor.detect_anomalies(cim_record)
                    
                    # Update user stats
                    user_stats[user]['total_events'] += 1
                    user_stats[user]['threat_scores'].append(threat_score)
                    user_stats[user]['anomalies'].extend(anomalies)
                    user_stats[user]['event_types'].add(cim_record.get('event_type', 'unknown'))
                    
                    # Add to original record
                    record['threat_score'] = threat_score
                    record['anomaly_count'] = len(anomalies)
                    
                    yield record
                    
                except Exception as e:
                    logger.error(f"Error analyzing record: {str(e)}")
                    record['analysis_error'] = str(e)
                    yield record
            
            # Generate user analysis summary
            for user, stats in user_stats.items():
                if stats['total_events'] > 0:
                    avg_threat_score = sum(stats['threat_scores']) / len(stats['threat_scores'])
                    max_threat_score = max(stats['threat_scores'])
                    
                    summary_record = {
                        'user': user,
                        'analysis_type': 'user_summary',
                        'total_events': stats['total_events'],
                        'avg_threat_score': avg_threat_score,
                        'max_threat_score': max_threat_score,
                        'total_anomalies': len(stats['anomalies']),
                        'event_types': ','.join(stats['event_types']),
                        'risk_level': self._get_risk_level(avg_threat_score),
                        'analysis_timestamp': datetime.now().isoformat()
                    }
                    
                    if self.detailed:
                        summary_record['threat_scores'] = stats['threat_scores']
                        summary_record['anomaly_types'] = ','.join(set(a['type'] for a in stats['anomalies']))
                    
                    yield summary_record
                    
        except Exception as e:
            logger.error(f"Error in analysis command: {str(e)}")
            raise
    
    def _get_risk_level(self, avg_threat_score):
        """Get risk level based on average threat score"""
        if avg_threat_score >= 0.8:
            return 'high'
        elif avg_threat_score >= 0.5:
            return 'medium'
        else:
            return 'low'

# Register the search commands
dispatch(InsiderThreatDetectionCommand, sys.argv, sys.stdin, sys.stdout, __name__)
dispatch(InsiderThreatTrainCommand, sys.argv, sys.stdin, sys.stdout, __name__)
dispatch(InsiderThreatAnalyzeCommand, sys.argv, sys.stdin, sys.stdout, __name__)
