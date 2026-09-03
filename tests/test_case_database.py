import os
import pytest
import sqlite3
import tempfile
from modules.case_database import initialize_database, save_case, get_case, list_cases

@pytest.fixture
def temp_db():
    fd, path = tempfile.mkstemp(suffix='.sqlite3')
    os.close(fd)
    yield path
    os.unlink(path)

def test_database_creation(temp_db):
    if os.path.exists(temp_db):
        os.unlink(temp_db)
    initialize_database(temp_db)
    assert os.path.exists(temp_db)
    
    conn = sqlite3.connect(temp_db)
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='cases'")
    assert cursor.fetchone() is not None
    conn.close()

def test_case_saving_and_retrieval(temp_db):
    initialize_database(temp_db)
    case_data = {
        'filename': 'test.eml',
        'email_hash': 'abcdef123456',
        'subject': 'Test Subject',
        'sender_address': 'test@example.com',
        'fraud_score': 85,
        'risk_level': 'Critical',
        'extracted_urls': ['example.com'],
        'analyzer_results': {'header': {'test': True}}
    }
    case_id = save_case(temp_db, case_data)
    assert case_id.startswith('CASE-')
    
    retrieved = get_case(temp_db, case_id)
    assert retrieved is not None
    assert retrieved['case_id'] == case_id
    assert retrieved['filename'] == 'test.eml'
    assert retrieved['email_hash'] == 'abcdef123456'
    assert retrieved['fraud_score'] == 85
    assert retrieved['extracted_urls'] == ['example.com']
    assert retrieved['analyzer_results'] == {'header': {'test': True}}

def test_duplicate_prevention(temp_db):
    initialize_database(temp_db)
    case_data = {
        'email_hash': 'hash1',
        'subject': 'S1'
    }
    id1 = save_case(temp_db, case_data)
    
    case_data_2 = {
        'email_hash': 'hash1',
        'subject': 'S2'
    }
    id2 = save_case(temp_db, case_data_2)
    assert id1 == id2
    
    ret = get_case(temp_db, id1)
    assert ret['subject'] == 'S1'

def test_missing_case(temp_db):
    initialize_database(temp_db)
    assert get_case(temp_db, 'CASE-NONEXISTENT') is None

def test_missing_db():
    assert get_case('nonexistent_folder/db.sqlite', 'CASE-1') is None
    assert list_cases('nonexistent_folder/db.sqlite') == []

def test_listing_and_filtering(temp_db):
    initialize_database(temp_db)
    save_case(temp_db, {'email_hash': '1', 'subject': 'Apple invoice', 'risk_level': 'Low'})
    save_case(temp_db, {'email_hash': '2', 'subject': 'Urgent Apple payment', 'risk_level': 'High'})
    save_case(temp_db, {'email_hash': '3', 'subject': 'Banana receipt', 'risk_level': 'Low'})
    
    all_cases = list_cases(temp_db)
    assert len(all_cases) == 3
    
    low_cases = list_cases(temp_db, risk_level='Low')
    assert len(low_cases) == 2
    
    apple_cases = list_cases(temp_db, search='Apple')
    assert len(apple_cases) == 2
    
    urgent_apple_low = list_cases(temp_db, search='Apple', risk_level='Low')
    assert len(urgent_apple_low) == 1
    
    malformed = list_cases(temp_db, search='%_!')
    assert type(malformed) == list
