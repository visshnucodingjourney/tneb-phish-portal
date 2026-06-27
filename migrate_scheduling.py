"""
migrate_scheduling.py
───────────────────────
One-time migration: adds the new scheduling/attachment columns to an
existing phishguard.db without touching any existing data.

Run once from the project root:
    python migrate_scheduling.py
"""

import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), 'database', 'phishguard.db')


def column_exists(cur, table, column):
    cur.execute(f'PRAGMA table_info({table})')
    return any(row[1] == column for row in cur.fetchall())


def add_column_if_missing(cur, table, column, coltype):
    if not column_exists(cur, table, column):
        print(f'Adding {table}.{column} ({coltype})')
        cur.execute(f'ALTER TABLE {table} ADD COLUMN {column} {coltype}')
    else:
        print(f'  {table}.{column} already exists, skipping')


def main():
    if not os.path.exists(DB_PATH):
        print(f'No database found at {DB_PATH} — nothing to migrate (a fresh one will be created on next run).')
        return

    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()

    add_column_if_missing(cur, 'campaigns', 'scheduled_at', 'DATETIME')
    add_column_if_missing(cur, 'campaigns', 'sent_at', 'DATETIME')

    add_column_if_missing(cur, 'email_templates', 'attachment_filename', 'VARCHAR(255)')
    add_column_if_missing(cur, 'email_templates', 'attachment_original_name', 'VARCHAR(255)')
    add_column_if_missing(cur, 'email_templates', 'attachment_mimetype', 'VARCHAR(100)')

    con.commit()
    con.close()
    print('Migration complete.')


if __name__ == '__main__':
    main()