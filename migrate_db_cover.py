import sqlite3
import os

def migrate_db():
    db_path = os.path.join('app', 'database', 'data.db')
    conn = sqlite3.connect(db_path)
    
    try:
        # Check if column exists
        cursor = conn.execute("PRAGMA table_info(crawl_sources)")
        columns = [row[1] for row in cursor.fetchall()]
        
        if 'cover_selector' not in columns:
            print("Adding cover_selector column...")
            conn.execute("ALTER TABLE crawl_sources ADD COLUMN cover_selector TEXT")
            print("Column added.")
        else:
            print("cover_selector column already exists.")
            
        conn.commit()
        
    except Exception as e:
        print(f"Error migrating database: {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    migrate_db()
