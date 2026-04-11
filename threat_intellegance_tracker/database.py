import sqlite3

def init_db():
    # Connect to the SQLite database (creates the file if it doesn't exist)
    conn = sqlite3.connect('threat_intel.db')
    
    # Create a cursor object to execute SQL commands
    cursor = conn.cursor()
    
    # Create the Threats table with specific columns
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS Threats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT UNIQUE,
            abuse_score INTEGER,
            country TEXT,
            isp TEXT,
            record_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Save (commit) the changes and close the connection
    conn.commit()
    conn.close()
    print("Database (threat_intel.db) and tables successfully initialized.")

def get_recent_threats(limit=5):
    # 1. Connect to the database
    conn = sqlite3.connect('threat_intel.db')
    cursor = conn.cursor()
    
    try:
        # 2. SQL SELECT Command (Fetch the latest records, ordered by ID descending)
        cursor.execute('''
            SELECT ip_address, abuse_score, country, record_date 
            FROM Threats 
            ORDER BY id DESC 
            LIMIT ?
        ''', (limit,))
        
        # 3. Fetch all matching rows
        records = cursor.fetchall()
        return records
        
    except Exception as e:
        print(f" Error fetching data: {e}")
        return []
        
    finally:
        conn.close()


def insert_threat_data(ip, score, country, isp):
    # 1. Connect to the database
    conn = sqlite3.connect('threat_intel.db')
    cursor = conn.cursor()
    
    try:
        # 2. SQL INSERT Command (Insert data into corresponding columns)
        # Question marks (?) act as a security shield to prevent SQL Injection.
        cursor.execute('''
            INSERT INTO Threats (ip_address, abuse_score, country, isp)
            VALUES (?, ?, ?, ?)
        ''', (ip, score, country, isp))
        
        # 3. Commit and save the changes
        conn.commit()
        print(f"{ip} successfully saved to the database.")
        
    except sqlite3.IntegrityError:
        # If the ip_address already exists (due to our UNIQUE rule), prevent a crash and warn gently.
        print(f"{ip} already exists in the database. Not added again.")
        
    except Exception as e:
        print(f"Unknown error occurred during insertion: {e}")
        
    finally:
        # 4. Close the connection when done
        conn.close()
if __name__ == '__main__':
    init_db()