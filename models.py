import sqlite3

def init_db():
    conn = sqlite3.connect('ghost_sentinel.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            module TEXT,
            target TEXT,
            result TEXT,
            risk_score INTEGER
        )
    ''')
    conn.commit()
    conn.close()

def log_audit(timestamp, module, target, result, risk_score=0):
    conn = sqlite3.connect('ghost_sentinel.db')
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO audit_logs (timestamp, module, target, result, risk_score)
        VALUES (?, ?, ?, ?, ?)
    ''', (timestamp, module, target, result, risk_score))
    conn.commit()
    conn.close()

# Initialize on boot
init_db()