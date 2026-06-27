"""
Migration: adds tracking columns and phishing_submissions table.
Run ONCE from your project root: python migrate_tracking.py
"""
import sqlite3, os

DB_PATH = os.path.join(os.path.dirname(__file__), 'database', 'phishguard.db')

def migrate():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # 1. Add missing columns to campaign_targets
    c.execute("PRAGMA table_info(campaign_targets)")
    existing = [row[1] for row in c.fetchall()]

    new_cols = {
        'email_sent_at': 'DATETIME',
        'credentials_submitted_at': 'DATETIME',
        'reported_at': 'DATETIME',
    }
    for col, coltype in new_cols.items():
        if col not in existing:
            c.execute(f"ALTER TABLE campaign_targets ADD COLUMN {col} {coltype}")
            print(f"  + Added campaign_targets.{col}")

    # 2. Create phishing_submissions table
    c.execute("""
        CREATE TABLE IF NOT EXISTS phishing_submissions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            campaign_target_id INTEGER NOT NULL REFERENCES campaign_targets(id),
            submitted_email VARCHAR(120),
            ip_address VARCHAR(45),
            user_agent VARCHAR(255),
            submitted_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    print("  + phishing_submissions table ready")

    conn.commit()
    conn.close()
    print("✅ Migration complete! Restart Flask.")

if __name__ == '__main__':
    migrate()
