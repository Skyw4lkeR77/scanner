"""Seed script — create initial admin user."""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.database import init_db, SessionLocal
from app.models import User, UserRole
from app.auth import hash_password


def seed():
    """Create initial admin user if not exists."""
    init_db()
    db = SessionLocal()

    try:
        existing = db.query(User).filter(User.username == "admin").first()
        if existing:
            print(f"Admin user already exists (id={existing.id})")
            return

        admin = User(
            username="admin",
            email="admin@scanner.local",
            password_hash=hash_password("Admin@123"),
            role=UserRole.ADMIN,
            is_active=True,
        )
        db.add(admin)
        db.commit()
        print("=" * 50)
        print("  Admin user created successfully!")
        print("=" * 50)
        print(f"  Username: admin")
        print(f"  Password: Admin@123")
        print(f"  Email:    admin@scanner.local")
        print("=" * 50)
        print("  ⚠  CHANGE THIS PASSWORD IMMEDIATELY!")
        print("=" * 50)
    finally:
        db.close()


if __name__ == "__main__":
    seed()
