import pymysql
import sys

db_config = {
    'host': 'localhost',
    'user': 'root',
    'password': 'Shyam@2005',
    'database': 'scam_detector'
}

try:
    print("Connecting to database with PyMySQL...")
    conn = pymysql.connect(**db_config)
    print("Connected!")
    cursor = conn.cursor()
    
    print("Checking tables...")
    cursor.execute("SHOW TABLES")
    tables = cursor.fetchall()
    print("Tables:", tables)
    
    cursor.close()
    conn.close()

except Exception as e:
    print(f"Connection failed: {e}")
    sys.exit(1)
