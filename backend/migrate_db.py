import sqlite3
import os

DB_PATH = 'scanner.db'

def run_migration():
    if not os.path.exists(DB_PATH):
        print(f"Database {DB_PATH} not found.")
        return
        
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    try:
        # Check if column exists
        cursor.execute("PRAGMA table_info(jobs)")
        columns = [info[1] for info in cursor.fetchall()]
        
        if 'scan_mode' not in columns:
            print("Adding scan_mode column to jobs table...")
            cursor.execute("ALTER TABLE jobs ADD COLUMN scan_mode VARCHAR DEFAULT 'fast'")
            conn.commit()
            print("Migration successful: added scan_mode")
        else:
            print("Column scan_mode already exists.")
            
    except Exception as e:
        print(f"Migration error: {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    run_migration()
