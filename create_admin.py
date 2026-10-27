import os
from getpass import getpass
from sqlalchemy import select
from app.main import SessionLocal, Account, pwd

username = input("Admin username [admin]: ").strip() or "admin"
password = getpass("New admin password (12+ characters): ")
if len(password) < 12:
    raise SystemExit("Password must be at least 12 characters.")
with SessionLocal() as db:
    if db.scalar(select(Account).where(Account.username == username)):
        raise SystemExit("That username already exists.")
    db.add(Account(username=username, password_hash=pwd.hash(password), role="superadmin", active=True))
    db.commit()
print("Admin created. Save the password securely.")
