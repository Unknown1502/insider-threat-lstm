#!/usr/bin/env python3
"""
Database Models for Insider Threat Detection
PostgreSQL models using SQLAlchemy
"""

import os
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy import Column, Integer, String, Float, DateTime, Boolean, Text, JSON

class Base(DeclarativeBase):
    pass

db = SQLAlchemy(model_class=Base)

class ThreatEvent(db.Model):
    """Model for storing threat detection events"""
    __tablename__ = 'threat_events'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(String(255), nullable=False, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    event_type = Column(String(100), nullable=False)  # email, file, device, http, auth
    action_type = Column(Integer, nullable=False)  # 0-31 action classification
    threat_score = Column(Float, nullable=False, index=True)
    threat_level = Column(String(20), nullable=False)  # low, medium, high, critical
    is_anomaly = Column(Boolean, default=False, nullable=False)
    
    # Event details
    source_ip = Column(String(45))  # IPv4/IPv6
    destination_ip = Column(String(45))
    file_size = Column(Integer)
    attachment_count = Column(Integer)
    url = Column(Text)
    email_subject = Column(Text)
    file_path = Column(Text)
    
    # Risk factors
    risk_factors = Column(JSON)  # Store as JSON array
    anomaly_types = Column(JSON)  # Store anomaly details
    
    # Metadata
    model_version = Column(String(50))
    processing_time = Column(Float)  # Processing time in seconds
    created_at = Column(DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<ThreatEvent {self.id}: {self.user_id} - {self.threat_level}>'

class UserProfile(db.Model):
    """Model for storing user behavioral profiles"""
    __tablename__ = 'user_profiles'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(String(255), unique=True, nullable=False, index=True)
    
    # Baseline statistics
    avg_daily_emails = Column(Float, default=0.0)
    avg_email_size = Column(Float, default=0.0)
    avg_attachments = Column(Float, default=0.0)
    avg_logon_time = Column(Float, default=0.0)  # Hour of day
    avg_session_duration = Column(Float, default=0.0)  # Minutes
    
    # Behavioral patterns
    weekend_activity_ratio = Column(Float, default=0.0)
    after_hours_ratio = Column(Float, default=0.0)
    external_email_ratio = Column(Float, default=0.0)
    large_file_ratio = Column(Float, default=0.0)
    
    # Risk metrics
    total_events = Column(Integer, default=0)
    threat_events = Column(Integer, default=0)
    avg_threat_score = Column(Float, default=0.0)
    max_threat_score = Column(Float, default=0.0)
    last_threat_date = Column(DateTime)
    
    # Profile metadata
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_updated = Column(DateTime, default=datetime.utcnow)
    profile_version = Column(String(50))
    
    def __repr__(self):
        return f'<UserProfile {self.user_id}: {self.total_events} events>'

class Alert(db.Model):
    """Model for storing security alerts"""
    __tablename__ = 'alerts'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    alert_id = Column(String(100), unique=True, nullable=False, index=True)
    
    # Alert details
    user_id = Column(String(255), nullable=False, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    severity = Column(String(20), nullable=False, index=True)  # low, medium, high, critical
    alert_type = Column(String(50), nullable=False)  # insider_threat, anomaly, etc.
    
    # Threat information
    threat_score = Column(Float, nullable=False)
    event_count = Column(Integer, default=1)
    description = Column(Text, nullable=False)
    
    # Event context
    source_events = Column(JSON)  # Related threat events
    risk_indicators = Column(JSON)  # Risk factors that triggered alert
    
    # Alert status
    status = Column(String(20), default='active', index=True)  # active, acknowledged, resolved, false_positive
    acknowledged_by = Column(String(255))
    acknowledged_at = Column(DateTime)
    resolution_notes = Column(Text)
    
    # Metadata
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<Alert {self.alert_id}: {self.user_id} - {self.severity}>'

class ModelMetrics(db.Model):
    """Model for storing ML model performance metrics"""
    __tablename__ = 'model_metrics'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    model_version = Column(String(50), nullable=False, index=True)
    model_type = Column(String(50), nullable=False)  # lstm_cnn, ensemble, etc.
    
    # Training metrics
    training_accuracy = Column(Float)
    validation_accuracy = Column(Float)
    test_accuracy = Column(Float)
    precision = Column(Float)
    recall = Column(Float)
    f1_score = Column(Float)
    roc_auc = Column(Float)
    
    # Training parameters
    epochs = Column(Integer)
    batch_size = Column(Integer)
    learning_rate = Column(Float)
    dropout_rate = Column(Float)
    
    # Dataset information
    training_samples = Column(Integer)
    validation_samples = Column(Integer)
    test_samples = Column(Integer)
    
    # Performance metrics
    inference_time_ms = Column(Float)  # Average inference time
    throughput_events_per_sec = Column(Float)
    
    # Metadata
    trained_at = Column(DateTime, default=datetime.utcnow)
    dataset_version = Column(String(50))
    notes = Column(Text)
    
    def __repr__(self):
        return f'<ModelMetrics {self.model_version}: {self.test_accuracy:.3f} accuracy>'

class DatasetInfo(db.Model):
    """Model for storing dataset information"""
    __tablename__ = 'dataset_info'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    dataset_name = Column(String(100), nullable=False)
    dataset_version = Column(String(50), nullable=False)
    
    # Dataset statistics
    total_records = Column(Integer, nullable=False)
    malicious_records = Column(Integer, default=0)
    normal_records = Column(Integer, default=0)
    users_count = Column(Integer, default=0)
    
    # Time range
    start_date = Column(DateTime)
    end_date = Column(DateTime)
    duration_days = Column(Integer)
    
    # Processing information
    processed_records = Column(Integer, default=0)
    processing_time_seconds = Column(Float)
    file_size_bytes = Column(Integer)
    
    # Metadata
    source_path = Column(String(500))
    description = Column(Text)
    uploaded_at = Column(DateTime, default=datetime.utcnow)
    processed_at = Column(DateTime)
    
    def __repr__(self):
        return f'<DatasetInfo {self.dataset_name} v{self.dataset_version}: {self.total_records} records>'