from werkzeug.security import generate_password_hash
from app import get_db   # make sure app.py name is correct

db = get_db()

db.execute("""
    INSERT INTO users (name, email, password, role, is_active)
    VALUES (?, ?, ?, 'collector', 1)
""", (
    "District Collector",
    "collector@egov.com",
    generate_password_hash("ABCD123ABCD@")
))

db.commit()
db.close()

print("Collector account created successfully")
