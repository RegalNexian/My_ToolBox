# database.py - Database management system for tool configurations and results storage
import sqlite3
import json
import os
from datetime import datetime
from typing import Dict, List, Any, Optional
import threading

class DatabaseManager:
    """SQLite database manager for tool configurations and results storage"""
    
    def __init__(self, db_path="toolbox_data.db"):
        self.db_path = db_path
        self.lock = threading.Lock()
        self.init_database()
    
    def init_database(self):
        """Initialize database with required tables"""
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Tool configurations table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS tool_configs (
                    tool_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    category TEXT,
                    config_data TEXT,
                    last_used TIMESTAMP,
                    user_preferences TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Analysis results table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS analysis_results (
                    analysis_id TEXT PRIMARY KEY,
                    tool_id TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    input_data TEXT,
                    results_summary TEXT,
                    detailed_findings TEXT,
                    recommendations TEXT,
                    metrics TEXT,
                    export_formats TEXT,
                    FOREIGN KEY (tool_id) REFERENCES tool_configs (tool_id)
                )
            ''')
            
            # Tool states and history table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS tool_states (
                    state_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    tool_id TEXT,
                    state_name TEXT,
                    state_data TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (tool_id) REFERENCES tool_configs (tool_id)
                )
            ''')
            
            # User preferences table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS user_preferences (
                    pref_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    category TEXT,
                    preference_key TEXT,
                    preference_value TEXT,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(category, preference_key)
                )
            ''')
            
            conn.commit()
            conn.close()
    
    def save_tool_config(self, tool_id: str, name: str, category: str = None, 
                        config_data: Dict = None, user_preferences: Dict = None):
        """Save or update tool configuration"""
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            config_json = json.dumps(config_data) if config_data else None
            prefs_json = json.dumps(user_preferences) if user_preferences else None
            
            cursor.execute('''
                INSERT OR REPLACE INTO tool_configs 
                (tool_id, name, category, config_data, last_used, user_preferences, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (tool_id, name, category, config_json, datetime.now(), prefs_json, datetime.now()))
            
            conn.commit()
            conn.close()
    
    def get_tool_config(self, tool_id: str) -> Optional[Dict]:
        """Retrieve tool configuration"""
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT tool_id, name, category, config_data, last_used, user_preferences, 
                       created_at, updated_at
                FROM tool_configs WHERE tool_id = ?
            ''', (tool_id,))
            
            row = cursor.fetchone()
            conn.close()
            
            if row:
                return {
                    'tool_id': row[0],
                    'name': row[1],
                    'category': row[2],
                    'config_data': json.loads(row[3]) if row[3] else {},
                    'last_used': row[4],
                    'user_preferences': json.loads(row[5]) if row[5] else {},
                    'created_at': row[6],
                    'updated_at': row[7]
                }
            return None
    
    def save_analysis_result(self, analysis_id: str, tool_id: str, input_data: Dict,
                           results_summary: Dict, detailed_findings: List = None,
                           recommendations: List = None, metrics: Dict = None,
                           export_formats: List = None):
        """Save analysis results"""
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT OR REPLACE INTO analysis_results 
                (analysis_id, tool_id, input_data, results_summary, detailed_findings,
                 recommendations, metrics, export_formats)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                analysis_id, tool_id,
                json.dumps(input_data),
                json.dumps(results_summary),
                json.dumps(detailed_findings) if detailed_findings else None,
                json.dumps(recommendations) if recommendations else None,
                json.dumps(metrics) if metrics else None,
                json.dumps(export_formats) if export_formats else None
            ))
            
            conn.commit()
            conn.close()
    
    def get_analysis_results(self, tool_id: str = None, limit: int = 100) -> List[Dict]:
        """Retrieve analysis results"""
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            if tool_id:
                cursor.execute('''
                    SELECT analysis_id, tool_id, timestamp, input_data, results_summary,
                           detailed_findings, recommendations, metrics, export_formats
                    FROM analysis_results WHERE tool_id = ?
                    ORDER BY timestamp DESC LIMIT ?
                ''', (tool_id, limit))
            else:
                cursor.execute('''
                    SELECT analysis_id, tool_id, timestamp, input_data, results_summary,
                           detailed_findings, recommendations, metrics, export_formats
                    FROM analysis_results
                    ORDER BY timestamp DESC LIMIT ?
                ''', (limit,))
            
            rows = cursor.fetchall()
            conn.close()
            
            results = []
            for row in rows:
                results.append({
                    'analysis_id': row[0],
                    'tool_id': row[1],
                    'timestamp': row[2],
                    'input_data': json.loads(row[3]) if row[3] else {},
                    'results_summary': json.loads(row[4]) if row[4] else {},
                    'detailed_findings': json.loads(row[5]) if row[5] else [],
                    'recommendations': json.loads(row[6]) if row[6] else [],
                    'metrics': json.loads(row[7]) if row[7] else {},
                    'export_formats': json.loads(row[8]) if row[8] else []
                })
            
            return results
    
    def save_tool_state(self, tool_id: str, state_name: str, state_data: Dict):
        """Save tool state for history tracking"""
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO tool_states (tool_id, state_name, state_data)
                VALUES (?, ?, ?)
            ''', (tool_id, state_name, json.dumps(state_data)))
            
            conn.commit()
            conn.close()
    
    def get_tool_states(self, tool_id: str, limit: int = 50) -> List[Dict]:
        """Retrieve tool state history"""
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT state_id, tool_id, state_name, state_data, timestamp
                FROM tool_states WHERE tool_id = ?
                ORDER BY timestamp DESC LIMIT ?
            ''', (tool_id, limit))
            
            rows = cursor.fetchall()
            conn.close()
            
            states = []
            for row in rows:
                states.append({
                    'state_id': row[0],
                    'tool_id': row[1],
                    'state_name': row[2],
                    'state_data': json.loads(row[3]) if row[3] else {},
                    'timestamp': row[4]
                })
            
            return states
    
    def save_user_preference(self, category: str, preference_key: str, preference_value: Any):
        """Save user preference"""
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT OR REPLACE INTO user_preferences 
                (category, preference_key, preference_value, updated_at)
                VALUES (?, ?, ?, ?)
            ''', (category, preference_key, json.dumps(preference_value), datetime.now()))
            
            conn.commit()
            conn.close()
    
    def get_user_preference(self, category: str, preference_key: str) -> Any:
        """Retrieve user preference"""
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT preference_value FROM user_preferences 
                WHERE category = ? AND preference_key = ?
            ''', (category, preference_key))
            
            row = cursor.fetchone()
            conn.close()
            
            if row:
                return json.loads(row[0])
            return None
    
    def get_all_user_preferences(self, category: str = None) -> Dict:
        """Retrieve all user preferences for a category or all categories"""
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            if category:
                cursor.execute('''
                    SELECT preference_key, preference_value FROM user_preferences 
                    WHERE category = ?
                ''', (category,))
            else:
                cursor.execute('''
                    SELECT category, preference_key, preference_value FROM user_preferences
                ''')
            
            rows = cursor.fetchall()
            conn.close()
            
            preferences = {}
            if category:
                for row in rows:
                    preferences[row[0]] = json.loads(row[1])
            else:
                for row in rows:
                    if row[0] not in preferences:
                        preferences[row[0]] = {}
                    preferences[row[0]][row[1]] = json.loads(row[2])
            
            return preferences
    
    def cleanup_old_data(self, days_old: int = 30):
        """Clean up old analysis results and tool states"""
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cutoff_date = datetime.now().replace(day=datetime.now().day - days_old)
            
            # Clean old analysis results
            cursor.execute('''
                DELETE FROM analysis_results 
                WHERE timestamp < ?
            ''', (cutoff_date,))
            
            # Clean old tool states
            cursor.execute('''
                DELETE FROM tool_states 
                WHERE timestamp < ?
            ''', (cutoff_date,))
            
            conn.commit()
            conn.close()
    
    def get_database_stats(self) -> Dict:
        """Get database statistics"""
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            stats = {}
            
            # Count records in each table
            tables = ['tool_configs', 'analysis_results', 'tool_states', 'user_preferences']
            for table in tables:
                cursor.execute(f'SELECT COUNT(*) FROM {table}')
                stats[f'{table}_count'] = cursor.fetchone()[0]
            
            # Database file size
            if os.path.exists(self.db_path):
                stats['db_size_bytes'] = os.path.getsize(self.db_path)
            
            conn.close()
            return stats


# Singleton instance for global access
db_manager = DatabaseManager()