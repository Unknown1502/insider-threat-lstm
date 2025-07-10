#!/usr/bin/env python3
"""
Alert Manager for Insider Threat Detection
Manages alerts, notifications, and threat tracking
"""

import os
import json
import logging
from datetime import datetime, timedelta
import sqlite3
import threading
from typing import List, Dict, Optional

logger = logging.getLogger(__name__)

class AlertManager:
    """Manages alerts and notifications for insider threat detection"""
    
    def __init__(self, db_path='data/alerts.db'):
        self.db_path = db_path
        self.lock = threading.Lock()
        
        # Create data directory
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        
        # Initialize database
        self._init_database()
    
    def _init_database(self):
        """Initialize SQLite database for alerts"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Create alerts table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS alerts (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT NOT NULL,
                        alert_type TEXT NOT NULL,
                        severity TEXT NOT NULL,
                        threat_score REAL NOT NULL,
                        user TEXT,
                        src_ip TEXT,
                        dest_ip TEXT,
                        event_type TEXT,
                        description TEXT,
                        event_data TEXT,
                        status TEXT DEFAULT 'active',
                        acknowledged_at TEXT,
                        acknowledged_by TEXT,
                        created_at TEXT DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                # Create threat_history table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS threat_history (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT NOT NULL,
                        user TEXT NOT NULL,
                        threat_score REAL NOT NULL,
                        event_type TEXT,
                        risk_factors TEXT,
                        created_at TEXT DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                # Create user_profiles table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS user_profiles (
                        user TEXT PRIMARY KEY,
                        total_events INTEGER DEFAULT 0,
                        threat_events INTEGER DEFAULT 0,
                        last_activity TEXT,
                        risk_score REAL DEFAULT 0.0,
                        profile_data TEXT,
                        updated_at TEXT DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                conn.commit()
                logger.info("Alert database initialized successfully")
                
        except Exception as e:
            logger.error(f"Error initializing alert database: {str(e)}")
            raise
    
    def create_alert(self, alert_data: Dict) -> int:
        """Create a new alert"""
        try:
            with self.lock:
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.cursor()
                    
                    # Determine severity based on threat score
                    threat_score = float(alert_data.get('threat_score', 0))
                    severity = self._determine_severity(threat_score)
                    
                    # Extract event data
                    event_data = alert_data.get('event_data', {})
                    user = event_data.get('user', alert_data.get('user', 'unknown'))
                    src_ip = event_data.get('src_ip', alert_data.get('src_ip', 'unknown'))
                    dest_ip = event_data.get('dest_ip', alert_data.get('dest_ip', 'unknown'))
                    event_type = event_data.get('event_type', alert_data.get('event_type', 'unknown'))
                    
                    # Generate description
                    description = self._generate_alert_description(alert_data)
                    
                    # Insert alert
                    cursor.execute('''
                        INSERT INTO alerts (
                            timestamp, alert_type, severity, threat_score, user, src_ip, dest_ip,
                            event_type, description, event_data
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        alert_data.get('timestamp', datetime.now().isoformat()),
                        alert_data.get('alert_type', 'insider_threat'),
                        severity,
                        threat_score,
                        user,
                        src_ip,
                        dest_ip,
                        event_type,
                        description,
                        json.dumps(event_data)
                    ))
                    
                    alert_id = cursor.lastrowid
                    conn.commit()
                    
                    # Update user profile
                    self._update_user_profile(user, threat_score, event_type)
                    
                    # Log threat history
                    self._log_threat_history(alert_data)
                    
                    logger.info(f"Created alert {alert_id} for user {user} with threat score {threat_score}")
                    
                    # Send notifications for high-severity alerts
                    if severity in ['high', 'critical']:
                        self._send_notification(alert_id, alert_data)
                    
                    return alert_id
                    
        except Exception as e:
            logger.error(f"Error creating alert: {str(e)}")
            raise
    
    def _determine_severity(self, threat_score: float) -> str:
        """Determine alert severity based on threat score"""
        if threat_score >= 0.9:
            return 'critical'
        elif threat_score >= 0.7:
            return 'high'
        elif threat_score >= 0.5:
            return 'medium'
        else:
            return 'low'
    
    def _generate_alert_description(self, alert_data: Dict) -> str:
        """Generate human-readable alert description"""
        try:
            threat_score = alert_data.get('threat_score', 0)
            event_data = alert_data.get('event_data', {})
            user = event_data.get('user', 'unknown')
            event_type = event_data.get('event_type', 'unknown')
            
            descriptions = []
            
            # Base description
            descriptions.append(f"Insider threat detected for user {user}")
            descriptions.append(f"Threat score: {threat_score:.2f}")
            
            # Event-specific descriptions
            if event_type == 'email':
                size = event_data.get('message_size', 0)
                attachments = event_data.get('attachment_count', 0)
                is_external = event_data.get('is_external', 0)
                
                if size > 50000000:
                    descriptions.append(f"Large email size: {size:,} bytes")
                if attachments > 5:
                    descriptions.append(f"High attachment count: {attachments}")
                if is_external:
                    descriptions.append("External communication detected")
            
            elif event_type == 'authentication':
                success = event_data.get('success', 1)
                src_ip = event_data.get('src_ip', 'unknown')
                
                if not success:
                    descriptions.append("Failed authentication attempt")
                if not src_ip.startswith('10.'):
                    descriptions.append(f"External IP access: {src_ip}")
            
            # Time-based anomalies
            timestamp = event_data.get('timestamp', '')
            if timestamp:
                try:
                    dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                    hour = dt.hour
                    if hour < 6 or hour > 22:
                        descriptions.append("Activity during off-hours")
                    if dt.weekday() >= 5:
                        descriptions.append("Weekend activity")
                except Exception:
                    pass
            
            return "; ".join(descriptions)
            
        except Exception as e:
            logger.error(f"Error generating alert description: {str(e)}")
            return f"Insider threat detected with score {alert_data.get('threat_score', 0):.2f}"
    
    def _update_user_profile(self, user: str, threat_score: float, event_type: str):
        """Update user profile with new threat data"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Get existing profile
                cursor.execute('SELECT * FROM user_profiles WHERE user = ?', (user,))
                existing = cursor.fetchone()
                
                if existing:
                    # Update existing profile
                    total_events = existing[1] + 1
                    threat_events = existing[2] + (1 if threat_score > 0.5 else 0)
                    new_risk_score = (existing[4] * 0.8) + (threat_score * 0.2)  # Weighted average
                    
                    cursor.execute('''
                        UPDATE user_profiles 
                        SET total_events = ?, threat_events = ?, last_activity = ?, 
                            risk_score = ?, updated_at = CURRENT_TIMESTAMP
                        WHERE user = ?
                    ''', (total_events, threat_events, datetime.now().isoformat(), 
                          new_risk_score, user))
                else:
                    # Create new profile
                    cursor.execute('''
                        INSERT INTO user_profiles (user, total_events, threat_events, 
                                                 last_activity, risk_score)
                        VALUES (?, ?, ?, ?, ?)
                    ''', (user, 1, 1 if threat_score > 0.5 else 0, 
                          datetime.now().isoformat(), threat_score))
                
                conn.commit()
                
        except Exception as e:
            logger.error(f"Error updating user profile: {str(e)}")
    
    def _log_threat_history(self, alert_data: Dict):
        """Log threat event to history"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                event_data = alert_data.get('event_data', {})
                user = event_data.get('user', 'unknown')
                threat_score = alert_data.get('threat_score', 0)
                event_type = event_data.get('event_type', 'unknown')
                
                # Extract risk factors
                risk_factors = []
                if event_data.get('is_external', 0):
                    risk_factors.append('external_communication')
                if event_data.get('large_email', 0):
                    risk_factors.append('large_email')
                if event_data.get('many_attachments', 0):
                    risk_factors.append('many_attachments')
                if event_data.get('unusual_time', 0):
                    risk_factors.append('unusual_time')
                
                cursor.execute('''
                    INSERT INTO threat_history (timestamp, user, threat_score, event_type, risk_factors)
                    VALUES (?, ?, ?, ?, ?)
                ''', (
                    alert_data.get('timestamp', datetime.now().isoformat()),
                    user,
                    threat_score,
                    event_type,
                    json.dumps(risk_factors)
                ))
                
                conn.commit()
                
        except Exception as e:
            logger.error(f"Error logging threat history: {str(e)}")
    
    def _send_notification(self, alert_id: int, alert_data: Dict):
        """Send notification for high-severity alerts"""
        try:
            # In a real implementation, this would send emails, SMS, or push notifications
            # For now, we'll just log the notification
            logger.warning(f"HIGH SEVERITY ALERT {alert_id}: {alert_data.get('threat_score', 0):.2f} threat score")
            
            # Could integrate with external notification services here
            # Examples: email, Slack, PagerDuty, etc.
            
        except Exception as e:
            logger.error(f"Error sending notification: {str(e)}")
    
    def get_recent_threats(self, limit: int = 10) -> List[Dict]:
        """Get recent threat detections"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    SELECT id, timestamp, alert_type, severity, threat_score, user, 
                           src_ip, event_type, description, status
                    FROM alerts 
                    ORDER BY timestamp DESC 
                    LIMIT ?
                ''', (limit,))
                
                rows = cursor.fetchall()
                
                alerts = []
                for row in rows:
                    alerts.append({
                        'id': row[0],
                        'timestamp': row[1],
                        'alert_type': row[2],
                        'severity': row[3],
                        'threat_score': row[4],
                        'user': row[5],
                        'src_ip': row[6],
                        'event_type': row[7],
                        'description': row[8],
                        'status': row[9]
                    })
                
                return alerts
                
        except Exception as e:
            logger.error(f"Error getting recent threats: {str(e)}")
            return []
    
    def get_threat_summary(self) -> Dict:
        """Get threat summary statistics"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Get counts by severity
                cursor.execute('''
                    SELECT severity, COUNT(*) 
                    FROM alerts 
                    WHERE DATE(timestamp) = DATE('now')
                    GROUP BY severity
                ''')
                
                severity_counts = dict(cursor.fetchall())
                
                # Get total alerts today
                cursor.execute('''
                    SELECT COUNT(*) 
                    FROM alerts 
                    WHERE DATE(timestamp) = DATE('now')
                ''')
                
                total_today = cursor.fetchone()[0]
                
                # Get active alerts
                cursor.execute('''
                    SELECT COUNT(*) 
                    FROM alerts 
                    WHERE status = 'active'
                ''')
                
                active_alerts = cursor.fetchone()[0]
                
                # Get top threatened users
                cursor.execute('''
                    SELECT user, COUNT(*) as alert_count, MAX(threat_score) as max_score
                    FROM alerts 
                    WHERE DATE(timestamp) >= DATE('now', '-7 days')
                    GROUP BY user
                    ORDER BY alert_count DESC, max_score DESC
                    LIMIT 5
                ''')
                
                top_users = []
                for row in cursor.fetchall():
                    top_users.append({
                        'user': row[0],
                        'alert_count': row[1],
                        'max_threat_score': row[2]
                    })
                
                # Get threat trend (last 7 days)
                cursor.execute('''
                    SELECT DATE(timestamp), COUNT(*) 
                    FROM alerts 
                    WHERE DATE(timestamp) >= DATE('now', '-7 days')
                    GROUP BY DATE(timestamp)
                    ORDER BY DATE(timestamp)
                ''')
                
                trend_data = []
                for row in cursor.fetchall():
                    trend_data.append({
                        'date': row[0],
                        'count': row[1]
                    })
                
                return {
                    'total_today': total_today,
                    'active_alerts': active_alerts,
                    'severity_counts': severity_counts,
                    'top_users': top_users,
                    'trend_data': trend_data
                }
                
        except Exception as e:
            logger.error(f"Error getting threat summary: {str(e)}")
            return {}
    
    def get_all_alerts(self, limit: int = 100) -> List[Dict]:
        """Get all alerts with pagination"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    SELECT id, timestamp, alert_type, severity, threat_score, user, 
                           src_ip, event_type, description, status, acknowledged_at, acknowledged_by
                    FROM alerts 
                    ORDER BY timestamp DESC 
                    LIMIT ?
                ''', (limit,))
                
                rows = cursor.fetchall()
                
                alerts = []
                for row in rows:
                    alerts.append({
                        'id': row[0],
                        'timestamp': row[1],
                        'alert_type': row[2],
                        'severity': row[3],
                        'threat_score': row[4],
                        'user': row[5],
                        'src_ip': row[6],
                        'event_type': row[7],
                        'description': row[8],
                        'status': row[9],
                        'acknowledged_at': row[10],
                        'acknowledged_by': row[11]
                    })
                
                return alerts
                
        except Exception as e:
            logger.error(f"Error getting all alerts: {str(e)}")
            return []
    
    def acknowledge_alert(self, alert_id: int, acknowledged_by: str = 'system'):
        """Acknowledge an alert"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    UPDATE alerts 
                    SET status = 'acknowledged', acknowledged_at = ?, acknowledged_by = ?
                    WHERE id = ?
                ''', (datetime.now().isoformat(), acknowledged_by, alert_id))
                
                conn.commit()
                
                if cursor.rowcount > 0:
                    logger.info(f"Alert {alert_id} acknowledged by {acknowledged_by}")
                    return True
                else:
                    logger.warning(f"Alert {alert_id} not found for acknowledgment")
                    return False
                    
        except Exception as e:
            logger.error(f"Error acknowledging alert: {str(e)}")
            return False
    
    def get_user_threat_history(self, user: str, days: int = 30) -> List[Dict]:
        """Get threat history for a specific user"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    SELECT timestamp, threat_score, event_type, risk_factors
                    FROM threat_history 
                    WHERE user = ? AND DATE(timestamp) >= DATE('now', '-' || ? || ' days')
                    ORDER BY timestamp DESC
                ''', (user, days))
                
                rows = cursor.fetchall()
                
                history = []
                for row in rows:
                    history.append({
                        'timestamp': row[0],
                        'threat_score': row[1],
                        'event_type': row[2],
                        'risk_factors': json.loads(row[3]) if row[3] else []
                    })
                
                return history
                
        except Exception as e:
            logger.error(f"Error getting user threat history: {str(e)}")
            return []
    
    def cleanup_old_alerts(self, days: int = 90):
        """Clean up old alerts to prevent database bloat"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Delete old alerts
                cursor.execute('''
                    DELETE FROM alerts 
                    WHERE DATE(timestamp) < DATE('now', '-' || ? || ' days')
                ''', (days,))
                
                deleted_alerts = cursor.rowcount
                
                # Delete old threat history
                cursor.execute('''
                    DELETE FROM threat_history 
                    WHERE DATE(timestamp) < DATE('now', '-' || ? || ' days')
                ''', (days,))
                
                deleted_history = cursor.rowcount
                
                conn.commit()
                
                logger.info(f"Cleaned up {deleted_alerts} old alerts and {deleted_history} old threat history records")
                
        except Exception as e:
            logger.error(f"Error cleaning up old alerts: {str(e)}")
