import sqlite3
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "egovdb.db")

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

db = get_db()

print("\n=== PANCHAYAT USERS ===")
users = db.execute("SELECT id, name, email, role, is_active FROM users WHERE role='panchayat'").fetchall()
for u in users:
    print(f"ID: {u['id']}, Name: {u['name']}, Email: {u['email']}, Active: {u['is_active']}")

print("\n=== COMPLAINTS ===")
complaints = db.execute("SELECT id, title, status, panchayat_id FROM complaints").fetchall()
for c in complaints:
    print(f"ID: {c['id']}, Title: {c['title']}, Status: {c['status']}, Panchayat_ID: {c['panchayat_id']}")

db.close()
