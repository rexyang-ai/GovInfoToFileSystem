import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), 'data.db')

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    c = conn.cursor()
    
    # Create Users table
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    ''')
    
    # Create CrawledData table
    c.execute('''
        CREATE TABLE IF NOT EXISTS crawled_data (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT,
            url TEXT,
            summary TEXT,
            cover_url TEXT,
            search_keyword TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Create CrawlingRules table
    c.execute('''
        CREATE TABLE IF NOT EXISTS crawling_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            rule_name TEXT,
            domain TEXT,
            url_pattern TEXT,
            title_xpath TEXT,
            content_xpath TEXT,
            request_headers TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Create ContentDetails table
    c.execute('''
        CREATE TABLE IF NOT EXISTS content_details (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_url TEXT UNIQUE,
            title TEXT,
            content TEXT,
            html_content TEXT,
            rule_id INTEGER,
            crawled_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(rule_id) REFERENCES crawling_rules(id)
        )
    ''')
    
    # Create AI Models table
    c.execute('''
        CREATE TABLE IF NOT EXISTS ai_models (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            provider TEXT,
            api_base TEXT,
            api_key TEXT,
            model_name TEXT,
            is_active BOOLEAN DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Create Token Consumption table
    c.execute('''
        CREATE TABLE IF NOT EXISTS token_consumption (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            model_id INTEGER,
            tokens_used INTEGER,
            request_type TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(model_id) REFERENCES ai_models(id)
        )
    ''')
    
    # Check if admin exists
    c.execute('SELECT * FROM users WHERE username = ?', ('admin',))
    if not c.fetchone():
        c.execute('INSERT INTO users (username, password) VALUES (?, ?)', ('admin', 'admin888'))
        print("Admin user created.")
        
    conn.commit()
    conn.close()
    print("Database initialized.")

if __name__ == '__main__':
    init_db()
