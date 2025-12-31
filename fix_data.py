import sqlite3
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "egovdb.db")

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

db = get_db()

# 1. Find a valid Panchayat
panchayat = db.execute("SELECT id, name FROM users WHERE role='panchayat' AND is_active=1 LIMIT 1").fetchone()

if not panchayat:
    print("Cannot fix data: No active Panchayat found!")
else:
    pid = panchayat["id"]
    print(f"Found Panchayat: {panchayat['name']} (ID: {pid})")
    
    # 2. Assign orphaned complaints to this Panchayat
    cursor = db.execute("UPDATE complaints SET panchayat_id=? WHERE panchayat_id IS NULL", (pid,))
    db.commit()
    print(f"Fixed {cursor.rowcount} complaints (Assigned to Panchayat ID {pid})")

# 3. Check Inspector Data (User mentioned this)
# If complaints are assigned to an inspector but have no panchayat, that would be weird, but let's check.
# Actually, let's see if we should auto-assign an inspector for testing purposes if requested, 
# but for now we won't force it unless the user explicitly asks for "auto-assign inspector".
# However, we can check if there are any inspectors.
inspector = db.execute("SELECT id, name FROM users WHERE role='inspector' AND is_active=1 LIMIT 1").fetchone()
if inspector:
    print(f"Found Inspector: {inspector['name']} (ID: {inspector['id']})")
else:
    print("No active Inspector found.")

db.close()
