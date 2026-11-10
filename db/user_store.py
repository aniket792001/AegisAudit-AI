"""
User Storage and Persistence Layer for AegisAudit AI.
Handles user registration, authentication lookups, and default admin seeding.
"""

import sqlite3
import uuid
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Any
from core.config import settings
from core.logger import logger
from core.security import PasswordHasher
from models.user_schema import UserRole, UserResponse

class UserDatabase:
    def __init__(self, db_path: Path = None):
        self.db_path = db_path or (settings.DB_DIR / "aegisaudit.db")
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()
        self._seed_default_admin()

    def _get_connection(self) -> sqlite3.Connection:
        """Returns hardened SQLite connection with WAL mode and concurrency resilience."""
        conn = sqlite3.connect(str(self.db_path), timeout=30.0)
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA busy_timeout=5000;")
        return conn

    def _init_db(self):
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id TEXT PRIMARY KEY,
                    email TEXT UNIQUE NOT NULL,
                    full_name TEXT NOT NULL,
                    hashed_password TEXT NOT NULL,
                    role TEXT NOT NULL,
                    is_active INTEGER DEFAULT 1,
                    created_at TEXT NOT NULL
                )
            """)
            conn.commit()

    def _seed_default_admin(self):
        """Seeds default admin if no users exist."""
        admin = self.get_user_by_email("admin@aegisaudit.com")
        if not admin:
            logger.info("UserDatabase: Seeding default admin account (admin@aegisaudit.com)...")
            self.create_user(
                email="admin@aegisaudit.com",
                password="AdminPass123!",
                full_name="Lead Security Admin",
                role=UserRole.ADMIN
            )

    def create_user(
        self,
        email: str,
        password: str,
        full_name: str,
        role: UserRole = UserRole.AUDITOR
    ) -> UserResponse:
        """Creates a new user record with hashed password."""
        user_id = f"USR-{uuid.uuid4().hex[:8].upper()}"
        hashed_pw = PasswordHasher.hash_password(password)
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO users (id, email, full_name, hashed_password, role, is_active, created_at)
                VALUES (?, ?, ?, ?, ?, 1, ?)
            """, (user_id, email.lower().strip(), full_name.strip(), hashed_pw, role.value, now_str))
            conn.commit()

        logger.info(f"UserDatabase: Created user {email} with role {role.value}")
        return UserResponse(
            id=user_id,
            email=email.lower().strip(),
            full_name=full_name.strip(),
            role=role,
            is_active=True,
            created_at=now_str
        )

    def get_user_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        """Retrieves raw user record including hashed password."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, email, full_name, hashed_password, role, is_active, created_at
                FROM users WHERE email = ?
            """, (email.lower().strip(),))
            row = cursor.fetchone()
            if row:
                return {
                    "id": row[0],
                    "email": row[1],
                    "full_name": row[2],
                    "hashed_password": row[3],
                    "role": UserRole(row[4]),
                    "is_active": bool(row[5]),
                    "created_at": row[6]
                }
        return None

    def get_user_by_id(self, user_id: str) -> Optional[UserResponse]:
        """Retrieves sanitized user response model by user ID."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, email, full_name, role, is_active, created_at
                FROM users WHERE id = ?
            """, (user_id,))
            row = cursor.fetchone()
            if row:
                return UserResponse(
                    id=row[0],
                    email=row[1],
                    full_name=row[2],
                    role=UserRole(row[3]),
                    is_active=bool(row[4]),
                    created_at=row[5]
                )
        return None

    def list_users(self) -> List[UserResponse]:
        """Lists all registered users."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, email, full_name, role, is_active, created_at
                FROM users ORDER BY created_at DESC
            """)
            rows = cursor.fetchall()
            return [
                UserResponse(
                    id=r[0],
                    email=r[1],
                    full_name=r[2],
                    role=UserRole(r[3]),
                    is_active=bool(r[4]),
                    created_at=r[5]
                )
                for r in rows
            ]
