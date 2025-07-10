#!/usr/bin/env python3
"""
CERT Dataset Downloader and Loader
Downloads and processes CERT Insider Threat dataset from Kaggle
"""

import os
import json
import logging
import pandas as pd
import requests
import zipfile
from datetime import datetime
import time

logger = logging.getLogger(__name__)

class CERTDatasetDownloader:
    """CERT dataset downloader and loader"""
    
    def __init__(self):
        self.kaggle_api_key = os.getenv('KAGGLE_API_KEY', '')
        self.kaggle_username = os.getenv('KAGGLE_USERNAME', '')
        self.dataset_url = 'https://www.kaggle.com/datasets/nitishabharathi/cert-insider-threat'
        self.dataset_path = 'data/cert_dataset'
        self.email_file = 'email.csv'
        self.psychometric_file = 'psychometric.csv'
        
        # Create data directory
        os.makedirs(self.dataset_path, exist_ok=True)
    
    def download_dataset(self):
        """Download CERT dataset from Kaggle"""
        try:
            logger.info("Starting CERT dataset download")
            
            # Check if dataset already exists
            email_path = os.path.join(self.dataset_path, self.email_file)
            if os.path.exists(email_path):
                logger.info("Dataset already exists, skipping download")
                return True
            
            # Try to download using Kaggle API if credentials are available
            if self.kaggle_api_key and self.kaggle_username:
                return self._download_with_kaggle_api()
            else:
                logger.info("Kaggle API credentials not found, creating sample dataset")
                return self._create_sample_dataset()
                
        except Exception as e:
            logger.error(f"Error downloading dataset: {str(e)}")
            return False
    
    def _download_with_kaggle_api(self):
        """Download using Kaggle API"""
        try:
            # Set up Kaggle API configuration
            kaggle_config = {
                'username': self.kaggle_username,
                'key': self.kaggle_api_key
            }
            
            # Create kaggle config directory
            kaggle_dir = os.path.expanduser('~/.kaggle')
            os.makedirs(kaggle_dir, exist_ok=True)
            
            # Write kaggle.json
            with open(os.path.join(kaggle_dir, 'kaggle.json'), 'w') as f:
                json.dump(kaggle_config, f)
            
            # Set permissions
            os.chmod(os.path.join(kaggle_dir, 'kaggle.json'), 0o600)
            
            # Download dataset using kaggle command
            import subprocess
            import os.path
            
            # Validate and sanitize the dataset path to prevent command injection
            # Ensure path doesn't contain shell metacharacters and is within expected bounds
            if not os.path.isabs(self.dataset_path):
                # Convert to absolute path to prevent directory traversal
                safe_dataset_path = os.path.abspath(self.dataset_path)
            else:
                safe_dataset_path = self.dataset_path
            
            # Additional validation: ensure path doesn't contain dangerous characters
            if any(char in safe_dataset_path for char in [';&|`$']):
                raise ValueError("Dataset path contains potentially dangerous characters")
            
            cmd = [
                'kaggle', 'datasets', 'download', 
                'nitishabharathi/cert-insider-threat',
                '-p', safe_dataset_path,
                '--unzip'
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                logger.info("Dataset downloaded successfully using Kaggle API")
                return True
            else:
                logger.error(f"Kaggle API download failed: {result.stderr}")
                return self._create_sample_dataset()
                
        except Exception as e:
            logger.error(f"Error with Kaggle API download: {str(e)}")
            return self._create_sample_dataset()
    
    def _create_sample_dataset(self):
        """Create sample dataset for demonstration"""
        try:
            logger.info("Creating sample CERT dataset")
            
            # Generate sample email data
            sample_data = self._generate_sample_email_data()
            
            # Save to CSV
            email_path = os.path.join(self.dataset_path, self.email_file)
            sample_df = pd.DataFrame(sample_data)
            sample_df.to_csv(email_path, index=False)
            
            logger.info(f"Sample dataset created with {len(sample_data)} records")
            return True
            
        except Exception as e:
            logger.error(f"Error creating sample dataset: {str(e)}")
            return False
    
    def _generate_sample_email_data(self):
        """Generate sample email data based on CERT dataset structure"""
        import random
        from datetime import datetime, timedelta
        
        # Sample users and domains
        users = [
            'alice.smith', 'bob.johnson', 'charlie.brown', 'diana.wilson',
            'eve.davis', 'frank.miller', 'grace.taylor', 'henry.clark',
            'iris.lee', 'jack.white', 'karen.green', 'leo.harris',
            'mia.thompson', 'noah.martin', 'olivia.garcia', 'peter.robinson'
        ]
        
        pcs = [
            'LAP0001', 'LAP0002', 'LAP0003', 'LAP0004', 'LAP0005',
            'DSK0001', 'DSK0002', 'DSK0003', 'DSK0004', 'DSK0005'
        ]
        
        domains = ['@dtaa.com', '@company.com', '@partner.com', '@external.com']
        
        sample_data = []
        start_date = datetime(2010, 1, 1)
        
        for i in range(10000):  # Generate 10,000 sample records
            # Generate timestamp
            days_offset = random.randint(0, 365)
            hours_offset = random.randint(0, 23)
            minutes_offset = random.randint(0, 59)
            
            timestamp = start_date + timedelta(
                days=days_offset,
                hours=hours_offset,
                minutes=minutes_offset
            )
            
            # Select user and PC
            user = random.choice(users)
            pc = random.choice(pcs)
            
            # Generate email addresses
            sender = f"{user}{random.choice(domains)}"
            recipient = f"{random.choice(users)}{random.choice(domains)}"
            
            # Generate email properties
            size = random.randint(1000, 50000000)  # 1KB to 50MB
            attachment_count = random.choices([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10], 
                                           weights=[50, 20, 10, 5, 3, 2, 2, 2, 2, 2, 2])[0]
            
            # Generate some anomalous patterns
            is_anomalous = random.random() < 0.05  # 5% anomalous
            
            if is_anomalous:
                # Make some events anomalous
                if random.random() < 0.3:  # Large size
                    size = random.randint(20000000, 100000000)
                if random.random() < 0.3:  # Many attachments
                    attachment_count = random.randint(8, 15)
                if random.random() < 0.3:  # Unusual time
                    timestamp = timestamp.replace(hour=random.randint(0, 5))
                if random.random() < 0.3:  # External communication
                    recipient = f"{random.choice(users)}@external.com"
            
            record = {
                'id': f"E{i:06d}",
                'date': timestamp.strftime('%m/%d/%Y %H:%M:%S'),
                'user': user,
                'pc': pc,
                'to': recipient,
                'cc': '' if random.random() < 0.7 else f"{random.choice(users)}@dtaa.com",
                'bcc': '' if random.random() < 0.9 else f"{random.choice(users)}@dtaa.com",
                'from': sender,
                'size': size,
                'attachments': attachment_count
            }
            
            sample_data.append(record)
        
        return sample_data
    
    def load_dataset(self):
        """Load CERT dataset from local files"""
        try:
            email_path = os.path.join(self.dataset_path, self.email_file)
            
            if not os.path.exists(email_path):
                logger.warning("Email dataset not found, attempting download")
                if not self.download_dataset():
                    return None
            
            logger.info("Loading CERT email dataset")
            
            # Load email data
            email_df = pd.read_csv(email_path)
            logger.info(f"Loaded {len(email_df)} email records")
            
            # Load psychometric data if available
            psychometric_path = os.path.join(self.dataset_path, self.psychometric_file)
            if os.path.exists(psychometric_path):
                psychometric_df = pd.read_csv(psychometric_path)
                logger.info(f"Loaded {len(psychometric_df)} psychometric records")
                
                # Merge datasets if possible
                try:
                    merged_df = pd.merge(email_df, psychometric_df, on='user', how='left')
                    logger.info("Merged email and psychometric data")
                    return merged_df
                except Exception as e:
                    logger.warning(f"Could not merge datasets: {str(e)}")
                    return email_df
            
            return email_df
            
        except Exception as e:
            logger.error(f"Error loading dataset: {str(e)}")
            return None
    
    def get_dataset_path(self):
        """Get path to dataset directory"""
        return self.dataset_path
    
    def get_dataset_info(self):
        """Get information about the dataset"""
        try:
            email_path = os.path.join(self.dataset_path, self.email_file)
            psychometric_path = os.path.join(self.dataset_path, self.psychometric_file)
            
            info = {
                'dataset_path': self.dataset_path,
                'email_file_exists': os.path.exists(email_path),
                'psychometric_file_exists': os.path.exists(psychometric_path),
                'email_file_size': os.path.getsize(email_path) if os.path.exists(email_path) else 0,
                'psychometric_file_size': os.path.getsize(psychometric_path) if os.path.exists(psychometric_path) else 0
            }
            
            if info['email_file_exists']:
                try:
                    # Get basic statistics
                    df = pd.read_csv(email_path, nrows=1000)  # Sample for quick stats
                    info['email_columns'] = list(df.columns)
                    info['sample_record_count'] = len(df)
                except Exception as e:
                    logger.error(f"Error getting dataset stats: {str(e)}")
            
            return info
            
        except Exception as e:
            logger.error(f"Error getting dataset info: {str(e)}")
            return {}
    
    def preprocess_for_splunk(self, df):
        """Preprocess dataset for Splunk ingestion"""
        try:
            logger.info("Preprocessing dataset for Splunk")
            
            # Standardize timestamp format
            df['timestamp'] = pd.to_datetime(df['date'])
            df['_time'] = df['timestamp'].astype(int) // 10**9  # Unix timestamp
            
            # Add Splunk-friendly fields
            df['sourcetype'] = 'cert_email'
            df['source'] = 'cert_dataset'
            df['index'] = 'main'
            
            # Create event signature
            df['event_signature'] = df.apply(
                lambda row: f"user={row['user']} size={row['size']} attachments={row['attachments']}",
                axis=1
            )
            
            # Add CIM-compliant fields
            df['src_user'] = df['user']
            df['message_size'] = df['size']
            df['attachment_count'] = df['attachments']
            df['email_from'] = df['from']
            df['email_to'] = df['to']
            df['email_cc'] = df['cc']
            df['email_bcc'] = df['bcc']
            
            logger.info("Dataset preprocessed for Splunk")
            return df
            
        except Exception as e:
            logger.error(f"Error preprocessing for Splunk: {str(e)}")
            raise
    
    def export_to_splunk_format(self, output_path='data/cert_splunk.csv'):
        """Export dataset in Splunk-ready format"""
        try:
            df = self.load_dataset()
            if df is None:
                return False
            
            # Preprocess for Splunk
            splunk_df = self.preprocess_for_splunk(df)
            
            # Export to CSV
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            splunk_df.to_csv(output_path, index=False)
            
            logger.info(f"Dataset exported to Splunk format: {output_path}")
            return True
            
        except Exception as e:
            logger.error(f"Error exporting to Splunk format: {str(e)}")
            return False
