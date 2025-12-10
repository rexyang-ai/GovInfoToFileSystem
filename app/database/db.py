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
    
    # 创建用户表
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    ''')
    
    # 创建爬取数据表
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
    
    # 创建爬取规则表
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
    
    # 创建内容详情表
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

    # 创建爬取源表 (新)
    c.execute('''
        CREATE TABLE IF NOT EXISTS crawl_sources (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            url TEXT NOT NULL,
            headers TEXT,
            method TEXT DEFAULT 'GET',
            list_selector TEXT,
            title_selector TEXT,
            link_selector TEXT,
            date_selector TEXT,
            is_enabled BOOLEAN DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # 创建 AI 模型表
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

    # 创建 Token 消耗表
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
    
    # 创建 AI 对话表
    c.execute('''
        CREATE TABLE IF NOT EXISTS ai_conversations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            title TEXT,
            model_id INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id),
            FOREIGN KEY(model_id) REFERENCES ai_models(id)
        )
    ''')

    # 创建 AI 消息表
    c.execute('''
        CREATE TABLE IF NOT EXISTS ai_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            conversation_id INTEGER,
            role TEXT,
            content TEXT,
            meta_info TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(conversation_id) REFERENCES ai_conversations(id) ON DELETE CASCADE
        )
    ''')
    
    # 检查管理员是否存在
    c.execute('SELECT * FROM users WHERE username = ?', ('admin',))
    if not c.fetchone():
        c.execute('INSERT INTO users (username, password) VALUES (?, ?)', ('admin', 'admin888'))
        print("管理员用户已创建。")
        
    conn.commit()
    conn.close()
    print("数据库已初始化。")

if __name__ == '__main__':
    init_db()
