#!/usr/bin/env python3
"""
LSTM Model for Insider Threat Detection
Implements deep learning model using TensorFlow/Keras
"""

import os
import json
import logging
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
import joblib

# TensorFlow imports
import tensorflow as tf
from tensorflow.keras.models import Sequential, load_model
from tensorflow.keras.layers import LSTM, Dense, Dropout, BatchNormalization, Conv1D, MaxPooling1D, Flatten, Embedding, Reshape
from tensorflow.keras.optimizers import Adam
from tensorflow.keras.callbacks import EarlyStopping, ReduceLROnPlateau
from tensorflow.keras.utils import to_categorical

logger = logging.getLogger(__name__)

class InsiderThreatLSTM:
    """LSTM-CNN hybrid model for insider threat detection (based on research paper)"""
    
    def __init__(self, sequence_length=150, feature_dim=32):
        # Research paper parameters
        self.sequence_length = sequence_length  # 150 activities per day
        self.feature_dim = feature_dim  # 32 action types
        self.lstm_units = 40  # Hidden units from paper
        self.lstm_dropout = 0.2  # Dropout rate
        self.lstm_batch_size = 20  # LSTM batch size
        self.lstm_epochs = 10  # LSTM epochs
        self.cnn_filters_1 = 32  # Conv1 filters
        self.cnn_filters_2 = 64  # Conv2 filters
        self.cnn_batch_size = 512  # CNN batch size
        self.cnn_epochs = 70  # CNN epochs
        
        self.model = None
        self.scaler = StandardScaler()
        self.label_encoder = LabelEncoder()
        self.model_path = 'models/insider_threat_lstm_cnn.h5'
        self.scaler_path = 'models/scaler.pkl'
        self.encoder_path = 'models/label_encoder.pkl'
        
        # Create models directory
        os.makedirs('models', exist_ok=True)
        
        # Try to load existing model
        self.load_model()
    
    def _create_model(self):
        """Create LSTM model architecture for insider threat detection"""
        model = Sequential([
            # Input layer - accepts sequences of action indices
            LSTM(self.lstm_units, return_sequences=True, dropout=self.lstm_dropout, 
                 recurrent_dropout=self.lstm_dropout, input_shape=(self.sequence_length, 1)),
            
            # Additional LSTM layers for temporal feature extraction
            LSTM(self.lstm_units, return_sequences=True, dropout=self.lstm_dropout, 
                 recurrent_dropout=self.lstm_dropout),
            
            LSTM(self.lstm_units, return_sequences=False, dropout=self.lstm_dropout, 
                 recurrent_dropout=self.lstm_dropout),
            
            # Dense layers for classification
            Dense(64, activation='relu'),
            Dropout(0.3),
            Dense(32, activation='relu'),
            Dropout(0.2),
            
            # Output layer (binary classification: normal/anomaly)
            Dense(1, activation='sigmoid')
        ])
        
        # Compile model with ADAM optimizer
        model.compile(
            optimizer=Adam(learning_rate=0.001),
            loss='binary_crossentropy',
            metrics=['accuracy', 'precision', 'recall']
        )
        
        return model
    
    def _prepare_features(self, data):
        """Prepare features from user activity data (32 actions as per research paper)"""
        # Define 32 action types as per research paper
        action_types = {
            # Email actions (internal/external)
            'email_internal': 0, 'email_external': 1, 'email_large': 2, 'email_attachments': 3,
            # File actions
            'file_read': 4, 'file_write': 5, 'file_delete': 6, 'file_copy': 7, 'file_move': 8,
            # Device actions
            'device_connect': 9, 'device_disconnect': 10, 'usb_connect': 11, 'usb_disconnect': 12,
            # HTTP actions
            'http_neutral': 13, 'http_hacktivist': 14, 'http_jobsearch': 15, 'http_cloud': 16,
            # Authentication actions
            'logon_success': 17, 'logon_failed': 18, 'logoff': 19, 'privilege_escalation': 20,
            # Time-based actions
            'after_hours': 21, 'weekend': 22, 'unusual_time': 23,
            # Data transfer actions
            'large_upload': 24, 'large_download': 25, 'bulk_transfer': 26,
            # System actions
            'system_access': 27, 'admin_access': 28, 'config_change': 29,
            # Behavioral actions
            'anomaly_pattern': 30, 'unknown_action': 31
        }
        
        # Convert each record to action type (single integer value)
        action_sequence = []
        for record in data:
            action_type = self._classify_action(record, action_types)
            action_sequence.append(action_type)
        
        return np.array(action_sequence)
    
    def _classify_action(self, record, action_types):
        """Classify user action into one of 32 action types (as per research paper)"""
        # Extract relevant fields from record
        event_type = record.get('event_type', 'unknown')
        action = record.get('action', '')
        size = record.get('size', 0)
        timestamp = pd.to_datetime(record.get('timestamp', datetime.now()))
        
        # Time-based classification
        hour = timestamp.hour
        day_of_week = timestamp.weekday()
        
        # Email classification
        if event_type == 'email':
            if record.get('is_external', False):
                return action_types['email_external']
            elif int(size) > 10000000:  # Large email > 10MB
                return action_types['email_large']
            elif int(record.get('attachment_count', 0)) > 5:
                return action_types['email_attachments']
            else:
                return action_types['email_internal']
        
        # File classification
        elif event_type == 'file':
            if 'read' in action.lower():
                return action_types['file_read']
            elif 'write' in action.lower() or 'create' in action.lower():
                return action_types['file_write']
            elif 'delete' in action.lower():
                return action_types['file_delete']
            elif 'copy' in action.lower():
                return action_types['file_copy']
            elif 'move' in action.lower():
                return action_types['file_move']
        
        # Device classification
        elif event_type == 'device':
            if 'connect' in action.lower():
                if 'usb' in action.lower():
                    return action_types['usb_connect']
                else:
                    return action_types['device_connect']
            elif 'disconnect' in action.lower():
                if 'usb' in action.lower():
                    return action_types['usb_disconnect']
                else:
                    return action_types['device_disconnect']
        
        # HTTP classification
        elif event_type == 'http':
            url = record.get('url', '').lower()
            if any(keyword in url for keyword in ['hack', 'exploit', 'malware']):
                return action_types['http_hacktivist']
            elif any(keyword in url for keyword in ['job', 'career', 'resume']):
                return action_types['http_jobsearch']
            elif any(keyword in url for keyword in ['cloud', 'drive', 'storage']):
                return action_types['http_cloud']
            else:
                return action_types['http_neutral']
        
        # Authentication classification
        elif event_type == 'authentication':
            if record.get('success', True):
                return action_types['logon_success']
            else:
                return action_types['logon_failed']
        
        # Time-based anomalies
        if hour < 6 or hour > 22:
            return action_types['after_hours']
        elif day_of_week >= 5:  # Weekend
            return action_types['weekend']
        
        # Data transfer classification
        if int(size) > 100000000:  # Large transfer > 100MB
            return action_types['large_upload']
        
        # Default to unknown action
        return action_types['unknown_action']
    
    def _create_sequences(self, features, labels=None):
        """Create sequences for LSTM input"""
        sequences = []
        sequence_labels = []
        
        for i in range(len(features) - self.sequence_length + 1):
            sequence = features[i:i + self.sequence_length]
            sequences.append(sequence)
            
            if labels is not None:
                # Use the label of the last event in the sequence
                sequence_labels.append(labels[i + self.sequence_length - 1])
        
        sequences = np.array(sequences)
        
        # Ensure sequences have the right shape for LSTM: (batch_size, sequence_length, 1)
        if sequences.ndim == 2:
            sequences = sequences.reshape(sequences.shape[0], sequences.shape[1], 1)
        
        if labels is not None:
            sequence_labels = np.array(sequence_labels)
            return sequences, sequence_labels
        
        return sequences
    
    def _generate_labels(self, data):
        """Generate labels for training data (simulated insider threats)"""
        labels = []
        
        for record in data:
            # Simple heuristic to identify potential insider threats
            threat_score = 0.0
            
            # Time-based anomalies
            timestamp = pd.to_datetime(record.get('timestamp', datetime.now()))
            hour = timestamp.hour
            day_of_week = timestamp.weekday()
            
            if hour < 6 or hour > 22:  # After hours
                threat_score += 0.3
            
            if day_of_week >= 5:  # Weekend
                threat_score += 0.2
            
            # Size-based anomalies
            email_size = float(record.get('size', 0))
            if email_size > 10000000:  # Large emails
                threat_score += 0.4
            
            # Attachment anomalies
            attachment_count = int(record.get('attachment_count', 0))
            if attachment_count > 5:
                threat_score += 0.3
            
            # User behavior anomalies
            user = record.get('user', '').lower()
            if 'admin' in user or 'root' in user:
                threat_score += 0.2
            
            # External communication
            dest_ip = record.get('dest_ip', '')
            if 'external' in dest_ip or dest_ip.startswith('10.') == False:
                threat_score += 0.2
            
            # Convert threat score to binary label
            is_threat = 1 if threat_score > 0.5 else 0
            labels.append(is_threat)
        
        return np.array(labels)
    
    def train(self, training_data):
        """Train the LSTM model"""
        try:
            logger.info("Starting LSTM model training")
            
            # Prepare features
            features = self._prepare_features(training_data)
            logger.info(f"Prepared features shape: {features.shape}")
            
            # Generate labels (in real scenario, these would be from known threats)
            labels = self._generate_labels(training_data)
            logger.info(f"Generated labels shape: {labels.shape}")
            
            # Normalize features manually (action indices are already in 0-31 range)
            features_normalized = features / 31.0  # Normalize to 0-1 range
            
            # Create sequences
            X, y = self._create_sequences(features_normalized, labels)
            logger.info(f"Created sequences - X shape: {X.shape}, y shape: {y.shape}")
            
            # Manual train-test split to avoid sklearn issues
            split_idx = int(0.8 * len(X))
            X_train, X_test = X[:split_idx], X[split_idx:]
            y_train, y_test = y[:split_idx], y[split_idx:]
            
            # Create and train model
            self.model = self._create_model()
            
            # Callbacks
            early_stopping = EarlyStopping(
                monitor='val_loss',
                patience=10,
                restore_best_weights=True
            )
            
            reduce_lr = ReduceLROnPlateau(
                monitor='val_loss',
                factor=0.5,
                patience=5,
                min_lr=0.0001
            )
            
            # Train model
            history = self.model.fit(
                X_train, y_train,
                epochs=50,
                batch_size=32,
                validation_data=(X_test, y_test),
                callbacks=[early_stopping, reduce_lr],
                verbose=1
            )
            
            # Evaluate model
            y_pred = (self.model.predict(X_test) > 0.5).astype(int)
            
            # Calculate metrics
            accuracy = np.mean(y_pred.flatten() == y_test)
            final_loss = history.history['val_loss'][-1]
            
            logger.info(f"Model training completed - Accuracy: {accuracy:.4f}, Loss: {final_loss:.4f}")
            
            # Print classification report
            print("\nClassification Report:")
            print(classification_report(y_test, y_pred))
            
            return {
                'accuracy': accuracy,
                'loss': final_loss,
                'history': history.history
            }
            
        except Exception as e:
            logger.error(f"Error training LSTM model: {str(e)}")
            raise
    
    def predict_threat(self, event_data):
        """Predict threat score for a single event"""
        try:
            if self.model is None:
                logger.warning("Model not loaded, returning default score")
                return 0.1
            
            # Prepare features for single event
            features = self._prepare_features([event_data])
            
            # Scale features
            features_scaled = self.scaler.transform(features)
            
            # For single prediction, we need to create a sequence
            # Use padding or repeat the event to create sequence
            sequence = np.tile(features_scaled, (self.sequence_length, 1))
            sequence = sequence.reshape(1, self.sequence_length, self.feature_dim)
            
            # Predict
            prediction = self.model.predict(sequence, verbose=0)
            threat_score = float(prediction[0][0])
            
            return threat_score
            
        except Exception as e:
            logger.error(f"Error predicting threat: {str(e)}")
            return 0.1
    
    def predict_batch(self, events_data):
        """Predict threat scores for multiple events"""
        try:
            if self.model is None:
                logger.warning("Model not loaded, returning default scores")
                return [0.1] * len(events_data)
            
            # Prepare features
            features = self._prepare_features(events_data)
            features_scaled = self.scaler.transform(features)
            
            # Create sequences
            sequences = self._create_sequences(features_scaled)
            
            if len(sequences) == 0:
                return [0.1] * len(events_data)
            
            # Predict
            predictions = self.model.predict(sequences, verbose=0)
            threat_scores = [float(pred[0]) for pred in predictions]
            
            # Pad scores to match input length
            while len(threat_scores) < len(events_data):
                threat_scores.insert(0, 0.1)
            
            return threat_scores
            
        except Exception as e:
            logger.error(f"Error predicting batch threats: {str(e)}")
            return [0.1] * len(events_data)
    
    def save_model(self):
        """Save trained model and preprocessors"""
        try:
            if self.model is not None:
                self.model.save(self.model_path)
                logger.info(f"Model saved to {self.model_path}")
            
            joblib.dump(self.scaler, self.scaler_path)
            logger.info(f"Scaler saved to {self.scaler_path}")
            
        except Exception as e:
            logger.error(f"Error saving model: {str(e)}")
    
    def load_model(self):
        """Load trained model and preprocessors"""
        try:
            if os.path.exists(self.model_path):
                self.model = load_model(self.model_path)
                logger.info(f"Model loaded from {self.model_path}")
            
            if os.path.exists(self.scaler_path):
                self.scaler = joblib.load(self.scaler_path)
                logger.info(f"Scaler loaded from {self.scaler_path}")
            
        except Exception as e:
            logger.error(f"Error loading model: {str(e)}")
    
    def get_model_metrics(self):
        """Get current model performance metrics"""
        try:
            if self.model is None:
                return {
                    'status': 'No model loaded',
                    'accuracy': 0.0,
                    'loss': 0.0
                }
            
            # Return basic model information
            return {
                'status': 'Model loaded',
                'layers': len(self.model.layers),
                'parameters': self.model.count_params(),
                'input_shape': str(self.model.input_shape),
                'output_shape': str(self.model.output_shape)
            }
            
        except Exception as e:
            logger.error(f"Error getting model metrics: {str(e)}")
            return {
                'status': f'Error: {str(e)}',
                'accuracy': 0.0,
                'loss': 0.0
            }
    
    def retrain_with_new_data(self, new_data):
        """Retrain model with new data"""
        try:
            logger.info("Starting model retraining with new data")
            
            # Combine with existing model or retrain from scratch
            return self.train(new_data)
            
        except Exception as e:
            logger.error(f"Error retraining model: {str(e)}")
            raise
