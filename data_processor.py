#!/usr/bin/env python3
"""
Data Processing Module for CERT Dataset and Real-time Data
Handles data preprocessing, feature engineering, and transformation
"""

import os
import json
import logging
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from collections import defaultdict
import hashlib

logger = logging.getLogger(__name__)

class DataProcessor:
    """Data processor for insider threat detection"""
    
    def __init__(self):
        self.user_profiles = {}
        self.baseline_stats = {}
        self.processed_data_cache = {}
    
    def preprocess_cert_data(self, cert_data):
        """Preprocess CERT dataset for LSTM training"""
        try:
            logger.info("Starting CERT data preprocessing")
            
            # Convert to DataFrame if not already
            if not isinstance(cert_data, pd.DataFrame):
                df = pd.DataFrame(cert_data)
            else:
                df = cert_data.copy()
            
            # Clean and standardize data
            df = self._clean_cert_data(df)
            
            # Generate user behavior profiles
            self._generate_user_profiles(df)
            
            # Extract behavioral features
            processed_records = self._extract_behavioral_features(df)
            
            logger.info(f"Preprocessed {len(processed_records)} records")
            return processed_records
            
        except Exception as e:
            logger.error(f"Error preprocessing CERT data: {str(e)}")
            raise
    
    def _clean_cert_data(self, df):
        """Clean and standardize CERT dataset"""
        try:
            # Standardize column names
            column_mapping = {
                'date': 'timestamp',
                'user': 'user',
                'pc': 'pc',
                'to': 'recipient',
                'cc': 'cc',
                'bcc': 'bcc',
                'from': 'sender',
                'size': 'size',
                'attachments': 'attachment_count'
            }
            
            for old_col, new_col in column_mapping.items():
                if old_col in df.columns:
                    df[new_col] = df[old_col]
            
            # Convert timestamps
            if 'timestamp' in df.columns:
                df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
            
            # Handle missing values
            df['size'] = pd.to_numeric(df['size'], errors='coerce').fillna(0)
            df['attachment_count'] = pd.to_numeric(df['attachment_count'], errors='coerce').fillna(0)
            
            # Fill missing string values
            string_columns = ['user', 'sender', 'recipient', 'pc']
            for col in string_columns:
                if col in df.columns:
                    df[col] = df[col].fillna('unknown')
            
            # Remove invalid records
            df = df.dropna(subset=['timestamp'])
            
            logger.info(f"Cleaned dataset shape: {df.shape}")
            return df
            
        except Exception as e:
            logger.error(f"Error cleaning CERT data: {str(e)}")
            raise
    
    def _generate_user_profiles(self, df):
        """Generate behavioral profiles for users"""
        try:
            logger.info("Generating user behavioral profiles")
            
            user_stats = df.groupby('user').agg({
                'size': ['mean', 'std', 'max', 'count'],
                'attachment_count': ['mean', 'std', 'max'],
                'timestamp': ['min', 'max']
            }).reset_index()
            
            # Flatten column names
            user_stats.columns = ['user', 'avg_size', 'std_size', 'max_size', 'email_count',
                                'avg_attachments', 'std_attachments', 'max_attachments',
                                'first_seen', 'last_seen']
            
            # Calculate additional behavioral metrics
            for _, row in user_stats.iterrows():
                user = row['user']
                user_data = df[df['user'] == user].copy()  # Fix pandas warning by making explicit copy
                
                # Time-based patterns
                user_data.loc[:, 'hour'] = user_data['timestamp'].dt.hour
                user_data.loc[:, 'day_of_week'] = user_data['timestamp'].dt.dayofweek
                
                # Calculate hourly and daily patterns
                hourly_pattern = user_data['hour'].value_counts().to_dict()
                daily_pattern = user_data['day_of_week'].value_counts().to_dict()
                
                # Recipient patterns
                recipient_diversity = user_data['recipient'].nunique()
                external_emails = user_data[user_data['recipient'].str.contains('@', na=False)]['recipient'].nunique()
                
                # Store profile
                self.user_profiles[user] = {
                    'avg_size': row['avg_size'],
                    'std_size': row['std_size'],
                    'max_size': row['max_size'],
                    'email_count': row['email_count'],
                    'avg_attachments': row['avg_attachments'],
                    'std_attachments': row['std_attachments'],
                    'max_attachments': row['max_attachments'],
                    'first_seen': row['first_seen'],
                    'last_seen': row['last_seen'],
                    'hourly_pattern': hourly_pattern,
                    'daily_pattern': daily_pattern,
                    'recipient_diversity': recipient_diversity,
                    'external_emails': external_emails
                }
            
            logger.info(f"Generated profiles for {len(self.user_profiles)} users")
            
        except Exception as e:
            logger.error(f"Error generating user profiles: {str(e)}")
            raise
    
    def _extract_behavioral_features(self, df):
        """Extract behavioral features from email data"""
        try:
            processed_records = []
            
            for _, row in df.iterrows():
                user = row['user']
                timestamp = row['timestamp']
                
                # Basic features
                features = {
                    'timestamp': timestamp.isoformat() if pd.notna(timestamp) else datetime.now().isoformat(),
                    'user': user,
                    'size': float(row.get('size', 0)),
                    'attachment_count': int(row.get('attachment_count', 0)),
                    'recipient': row.get('recipient', ''),
                    'sender': row.get('sender', ''),
                    'pc': row.get('pc', ''),
                    'event_type': 'email'
                }
                
                # Time-based features
                if pd.notna(timestamp):
                    features['hour'] = timestamp.hour
                    features['day_of_week'] = timestamp.dayofweek
                    features['is_weekend'] = 1 if timestamp.dayofweek >= 5 else 0
                    features['is_after_hours'] = 1 if timestamp.hour < 7 or timestamp.hour > 19 else 0
                
                # User behavior deviation features
                if user in self.user_profiles:
                    profile = self.user_profiles[user]
                    
                    # Size deviation
                    if profile['std_size'] > 0:
                        features['size_zscore'] = (features['size'] - profile['avg_size']) / profile['std_size']
                    else:
                        features['size_zscore'] = 0
                    
                    # Attachment deviation
                    if profile['std_attachments'] > 0:
                        features['attachment_zscore'] = (features['attachment_count'] - profile['avg_attachments']) / profile['std_attachments']
                    else:
                        features['attachment_zscore'] = 0
                    
                    # Time pattern deviation
                    hour_normal_count = profile['hourly_pattern'].get(features.get('hour', 0), 0)
                    features['hour_frequency'] = hour_normal_count / profile['email_count']
                    
                    day_normal_count = profile['daily_pattern'].get(features.get('day_of_week', 0), 0)
                    features['day_frequency'] = day_normal_count / profile['email_count']
                
                # Recipient analysis
                recipient = features['recipient']
                if recipient:
                    features['is_external'] = 1 if '@' in recipient and not recipient.endswith('@dtaa.com') else 0
                    features['recipient_hash'] = self._hash_string(recipient)
                else:
                    features['is_external'] = 0
                    features['recipient_hash'] = 0
                
                # Sender analysis
                sender = features['sender']
                if sender:
                    features['sender_hash'] = self._hash_string(sender)
                    features['is_sender_external'] = 1 if '@' in sender and not sender.endswith('@dtaa.com') else 0
                else:
                    features['sender_hash'] = 0
                    features['is_sender_external'] = 0
                
                # PC/source analysis
                pc = features['pc']
                if pc:
                    features['pc_hash'] = self._hash_string(pc)
                else:
                    features['pc_hash'] = 0
                
                # Anomaly indicators
                features['large_email'] = 1 if features['size'] > 10000000 else 0  # 10MB
                features['many_attachments'] = 1 if features['attachment_count'] > 5 else 0
                features['unusual_time'] = 1 if features.get('is_after_hours', 0) or features.get('is_weekend', 0) else 0
                
                processed_records.append(features)
            
            return processed_records
            
        except Exception as e:
            logger.error(f"Error extracting behavioral features: {str(e)}")
            raise
    
    def _hash_string(self, string):
        """Create hash of string for anonymization"""
        return int(hashlib.md5(str(string).encode()).hexdigest(), 16) % 10000
    
    def process_custom_dataset(self, file_path):
        """Process custom uploaded dataset"""
        try:
            logger.info(f"Processing custom dataset: {file_path}")
            
            # Read CSV file
            df = pd.read_csv(file_path)
            
            # Detect dataset format and adapt
            if 'email' in file_path.lower() or any(col in df.columns for col in ['to', 'from', 'subject']):
                # Email dataset
                return self.preprocess_cert_data(df)
            elif any(col in df.columns for col in ['user', 'action', 'result']):
                # Authentication dataset
                return self._process_auth_data(df)
            else:
                # Generic dataset
                return self._process_generic_data(df)
                
        except Exception as e:
            logger.error(f"Error processing custom dataset: {str(e)}")
            raise
    
    def _process_auth_data(self, df):
        """Process authentication data"""
        try:
            processed_records = []
            
            for _, row in df.iterrows():
                features = {
                    'timestamp': row.get('timestamp', datetime.now().isoformat()),
                    'user': row.get('user', 'unknown'),
                    'action': row.get('action', 'unknown'),
                    'result': row.get('result', 'unknown'),
                    'src_ip': row.get('src_ip', 'unknown'),
                    'dest_ip': row.get('dest_ip', 'unknown'),
                    'event_type': 'authentication'
                }
                
                # Add temporal features
                timestamp = pd.to_datetime(features['timestamp'])
                features['hour'] = timestamp.hour
                features['day_of_week'] = timestamp.dayofweek
                features['is_weekend'] = 1 if timestamp.dayofweek >= 5 else 0
                features['is_after_hours'] = 1 if timestamp.hour < 7 or timestamp.hour > 19 else 0
                
                # Add behavioral features
                features['is_failure'] = 1 if 'fail' in features['result'].lower() else 0
                features['is_admin'] = 1 if 'admin' in features['user'].lower() else 0
                features['src_ip_hash'] = self._hash_string(features['src_ip'])
                features['dest_ip_hash'] = self._hash_string(features['dest_ip'])
                
                processed_records.append(features)
            
            return processed_records
            
        except Exception as e:
            logger.error(f"Error processing auth data: {str(e)}")
            raise
    
    def _process_generic_data(self, df):
        """Process generic dataset"""
        try:
            processed_records = []
            
            for _, row in df.iterrows():
                features = {
                    'timestamp': row.get('timestamp', datetime.now().isoformat()),
                    'event_type': 'generic'
                }
                
                # Add all columns as features
                for col in df.columns:
                    if col != 'timestamp':
                        features[col] = row[col] if pd.notna(row[col]) else 0
                
                # Add temporal features
                timestamp = pd.to_datetime(features['timestamp'])
                features['hour'] = timestamp.hour
                features['day_of_week'] = timestamp.dayofweek
                features['is_weekend'] = 1 if timestamp.dayofweek >= 5 else 0
                features['is_after_hours'] = 1 if timestamp.hour < 7 or timestamp.hour > 19 else 0
                
                processed_records.append(features)
            
            return processed_records
            
        except Exception as e:
            logger.error(f"Error processing generic data: {str(e)}")
            raise
    
    def calculate_baseline_stats(self, data):
        """Calculate baseline statistics for anomaly detection"""
        try:
            logger.info("Calculating baseline statistics")
            
            df = pd.DataFrame(data)
            
            # Calculate statistics by user
            user_stats = df.groupby('user').agg({
                'size': ['mean', 'std', 'count'],
                'attachment_count': ['mean', 'std'],
                'hour': lambda x: x.mode().iloc[0] if not x.empty else 12,
                'day_of_week': lambda x: x.mode().iloc[0] if not x.empty else 1
            }).reset_index()
            
            # Store baseline stats
            self.baseline_stats = {
                'user_stats': user_stats.to_dict('records'),
                'global_stats': {
                    'avg_size': df['size'].mean(),
                    'std_size': df['size'].std(),
                    'avg_attachments': df['attachment_count'].mean(),
                    'std_attachments': df['attachment_count'].std(),
                    'total_events': len(df)
                }
            }
            
            logger.info("Baseline statistics calculated")
            
        except Exception as e:
            logger.error(f"Error calculating baseline stats: {str(e)}")
            raise
    
    def get_user_baseline(self, user):
        """Get baseline statistics for a specific user"""
        if user in self.user_profiles:
            return self.user_profiles[user]
        else:
            return self.baseline_stats.get('global_stats', {})
    
    def detect_anomalies(self, event_data):
        """Detect anomalies in event data"""
        try:
            anomalies = []
            
            user = event_data.get('user', 'unknown')
            baseline = self.get_user_baseline(user)
            
            # Size anomaly
            event_size = event_data.get('size', 0)
            if baseline.get('std_size', 0) > 0:
                size_zscore = (event_size - baseline.get('avg_size', 0)) / baseline.get('std_size', 1)
                if abs(size_zscore) > 2:
                    anomalies.append({
                        'type': 'size_anomaly',
                        'severity': min(abs(size_zscore) / 2, 1.0),
                        'description': f'Email size significantly different from user baseline'
                    })
            
            # Time anomaly
            hour = event_data.get('hour', 12)
            if hour < 6 or hour > 22:
                anomalies.append({
                    'type': 'time_anomaly',
                    'severity': 0.6,
                    'description': 'Activity during unusual hours'
                })
            
            # Attachment anomaly
            attachment_count = event_data.get('attachment_count', 0)
            if attachment_count > 5:
                anomalies.append({
                    'type': 'attachment_anomaly',
                    'severity': min(attachment_count / 10, 1.0),
                    'description': 'Unusually high number of attachments'
                })
            
            # External communication anomaly
            if event_data.get('is_external', 0):
                anomalies.append({
                    'type': 'external_communication',
                    'severity': 0.4,
                    'description': 'Communication with external entities'
                })
            
            return anomalies
            
        except Exception as e:
            logger.error(f"Error detecting anomalies: {str(e)}")
            return []
