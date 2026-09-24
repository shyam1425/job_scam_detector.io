import os
import sys

import pymysql


db_config = {
    "host": os.getenv("DB_HOST", "localhost"),
    "user": os.getenv("DB_USER", "scam_detector"),
    "password": os.getenv("DB_PASSWORD", ""),
    "database": os.getenv("DB_NAME", "scam_detector"),
}

if not db_config["password"]:
    raise SystemExit("Set DB_PASSWORD before running the database diagnostic")

try:
    print("Connecting to database with PyMySQL...")
    conn = pymysql.connect(**db_config)
    print("Connected!")
    with conn.cursor() as cursor:
        cursor.execute("SHOW TABLES")
        print("Tables:", cursor.fetchall())
    conn.close()
except Exception as exc:
    print(f"Connection failed: {exc}", file=sys.stderr)
    sys.exit(1)
