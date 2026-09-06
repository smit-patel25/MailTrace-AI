import sqlite3
import json
import os
import uuid
from datetime import datetime, timezone

def initialize_database(db_path):
    os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS cases (
            case_id TEXT PRIMARY KEY,
            created_at TEXT,
            filename TEXT,
            email_hash TEXT UNIQUE,
            subject TEXT,
            sender_address TEXT,
            sender_domain TEXT,
            reply_to_domain TEXT,
            probable_origin_ip TEXT,
            extracted_urls TEXT,
            fraud_score INTEGER,
            risk_level TEXT,
            verdict TEXT,
            confidence TEXT,
            analyzer_results TEXT,
            campaign_id TEXT
        )
    ''')

    cursor.execute("PRAGMA table_info(cases)")
    columns = [info[1] for info in cursor.fetchall()]
    if 'campaign_id' not in columns:
        cursor.execute("ALTER TABLE cases ADD COLUMN campaign_id TEXT")

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS campaigns (
            campaign_id TEXT PRIMARY KEY,
            created_at TEXT,
            matched_indicators TEXT,
            correlation_confidence TEXT
        )
    ''')

    conn.commit()
    conn.close()

def save_case(db_path, case_data) -> str:
    email_hash = case_data.get('email_hash')
    if not email_hash:
        raise ValueError("email_hash is required to save a case")

    os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)

    # Auto-initialize if not exists
    if not os.path.exists(db_path):
        initialize_database(db_path)

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Check if exists
    try:
        cursor.execute("SELECT case_id FROM cases WHERE email_hash = ?", (email_hash,))
        row = cursor.fetchone()
        if row:
            conn.close()
            return row[0]
    except sqlite3.OperationalError:
        initialize_database(db_path)

    # Generate new ID
    case_id = datetime.now(timezone.utc).strftime("CASE-%Y%m%d-") + uuid.uuid4().hex[:4].upper()
    created_at = datetime.now(timezone.utc).isoformat()

    extracted_urls = case_data.get('extracted_urls', [])
    urls_json = json.dumps(extracted_urls) if extracted_urls else "[]"

    analyzer_results = case_data.get('analyzer_results', {})
    results_json = json.dumps(analyzer_results) if analyzer_results else "{}"

    cursor.execute('''
        INSERT INTO cases (
            case_id, created_at, filename, email_hash, subject, sender_address,
            sender_domain, reply_to_domain, probable_origin_ip, extracted_urls,
            fraud_score, risk_level, verdict, confidence, analyzer_results
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        case_id,
        created_at,
        case_data.get('filename'),
        email_hash,
        case_data.get('subject'),
        case_data.get('sender_address'),
        case_data.get('sender_domain'),
        case_data.get('reply_to_domain'),
        case_data.get('probable_origin_ip'),
        urls_json,
        case_data.get('fraud_score'),
        case_data.get('risk_level'),
        case_data.get('verdict'),
        case_data.get('confidence'),
        results_json
    ))

    conn.commit()
    conn.close()
    return case_id

def get_case(db_path, case_id) -> dict:
    if not os.path.exists(db_path):
        return None

    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM cases WHERE case_id = ?", (case_id,))
        row = cursor.fetchone()
        conn.close()

        if row:
            case = dict(row)
            try:
                case['extracted_urls'] = json.loads(case['extracted_urls'])
            except Exception:
                case['extracted_urls'] = []
            try:
                case['analyzer_results'] = json.loads(case['analyzer_results'])
            except Exception:
                case['analyzer_results'] = {}
            return case
        return None
    except sqlite3.Error:
        return None

def list_cases(db_path, search=None, risk_level=None) -> list:
    if not os.path.exists(db_path):
        return []

    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        query = "SELECT * FROM cases WHERE 1=1"
        params = []

        if risk_level:
            query += " AND risk_level = ?"
            params.append(risk_level)

        if search:
            search_pattern = f"%{search}%"
            query += " AND (subject LIKE ? OR sender_address LIKE ? OR case_id LIKE ? OR filename LIKE ?)"
            params.extend([search_pattern, search_pattern, search_pattern, search_pattern])

        query += " ORDER BY created_at DESC"

        cursor.execute(query, params)
        rows = cursor.fetchall()
        conn.close()

        cases = []
        for row in rows:
            case = dict(row)
            try:
                case['extracted_urls'] = json.loads(case['extracted_urls'])
            except Exception:
                case['extracted_urls'] = []
            try:
                case['analyzer_results'] = json.loads(case['analyzer_results'])
            except Exception:
                case['analyzer_results'] = {}
            cases.append(case)

        return cases
    except sqlite3.Error:
        return []
