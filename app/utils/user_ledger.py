import os
import json
from datetime import datetime, timezone

LEDGER_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data', 'users_ledger.json')

def save_user_to_ledger(user):
    """
    Saves a user record to the persistent JSON ledger file.
    """
    try:
        os.makedirs(os.path.dirname(LEDGER_PATH), exist_ok=True)
        ledger_data = []

        if os.path.exists(LEDGER_PATH):
            try:
                with open(LEDGER_PATH, 'r') as f:
                    ledger_data = json.load(f)
            except Exception:
                ledger_data = []

        # Check if user already in ledger
        existing_idx = -1
        for idx, u_data in enumerate(ledger_data):
            if u_data.get('username') == user.username:
                existing_idx = idx
                break

        user_entry = {
            'username': user.username,
            'email': user.email,
            'password_hash': user.password_hash,
            'role': user.role,
            'is_active': user.is_active,
            'created_at': user.created_at.strftime('%Y-%m-%d %H:%M:%S UTC') if hasattr(user, 'created_at') and user.created_at else datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
        }

        if existing_idx >= 0:
            ledger_data[existing_idx] = user_entry
        else:
            ledger_data.append(user_entry)

        with open(LEDGER_PATH, 'w') as f:
            json.dump(ledger_data, f, indent=2)

        print(f"User '{user.username}' saved to persistent ledger.")
    except Exception as e:
        print(f"Ledger save error: {e}")

def sync_users_from_ledger(db_session, user_model):
    """
    Syncs user accounts from the persistent JSON ledger into SQLite DB on startup.
    """
    try:
        if not os.path.exists(LEDGER_PATH):
            return

        with open(LEDGER_PATH, 'r') as f:
            ledger_data = json.load(f)

        synced_count = 0
        for u_data in ledger_data:
            existing = user_model.query.filter_by(username=u_data['username']).first()
            if not existing:
                new_u = user_model(
                    username=u_data['username'],
                    email=u_data['email'],
                    password_hash=u_data['password_hash'],
                    role=u_data.get('role', 'user'),
                    is_active=u_data.get('is_active', True)
                )
                db_session.add(new_u)
                synced_count += 1
            else:
                existing.role = u_data.get('role', existing.role)
                existing.is_active = u_data.get('is_active', existing.is_active)

        if synced_count > 0:
            db_session.commit()
            print(f"Synced {synced_count} registered user(s) from persistent ledger into SQLite.")
    except Exception as e:
        print(f"Ledger sync error: {e}")
