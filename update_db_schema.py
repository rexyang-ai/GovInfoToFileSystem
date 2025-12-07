import sqlite3
import os

DB_PATH = os.path.join('app', 'database', 'data.db')

def update_db():
    if not os.path.exists(DB_PATH):
        print(f"Database not found at {DB_PATH}")
        return

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    try:
        # Check if columns exist
        cursor = c.execute("SELECT * FROM crawl_sources LIMIT 1")
        columns = [description[0] for description in cursor.description]
        
        if 'pagination_param' not in columns:
            print("Adding pagination_param column...")
            c.execute("ALTER TABLE crawl_sources ADD COLUMN pagination_param TEXT")
            
        if 'pagination_step' not in columns:
            print("Adding pagination_step column...")
            c.execute("ALTER TABLE crawl_sources ADD COLUMN pagination_step INTEGER DEFAULT 0")
            
        if 'start_value' not in columns:
            print("Adding start_value column...")
            c.execute("ALTER TABLE crawl_sources ADD COLUMN start_value INTEGER DEFAULT 0")
            
        conn.commit()
        print("Database updated successfully.")
        
    except Exception as e:
        print(f"Error updating database: {e}")
        conn.rollback()
    finally:
        conn.close()

if __name__ == '__main__':
    update_db()
