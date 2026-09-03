# MailTrace AI Quality Gate Report

**Run Date:** 2026-09-03 23:13:43Z

## Pytest Status: ✅ PASSED

`	ext
============================= test session starts =============================
platform win32 -- Python 3.14.6, pytest-9.1.1, pluggy-1.6.0
rootdir: E:\MailTrace-AI
plugins: anyio-4.14.2
collected 105 items

tests\system\test_app_workflows.py .....                                 [  4%]
tests\test_app_gemini_flow.py ...                                        [  7%]
tests\test_campaign_correlator.py .......                                [ 14%]
tests\test_case_database.py ......                                       [ 20%]
tests\test_content_analyzer.py .....................                     [ 40%]
tests\test_domain_intelligence.py ....                                   [ 43%]
tests\test_email_parser.py ............                                  [ 55%]
tests\test_gemini_analyzer.py ....                                       [ 59%]
tests\test_geolocation.py ........                                       [ 66%]
tests\test_header_analyzer.py ....                                       [ 70%]
tests\test_relay_analyzer.py ......                                      [ 76%]
tests\test_report_generator.py ....                                      [ 80%]
tests\test_risk_scoring.py .....................                         [100%]

============================== warnings summary ===============================
.venv\Lib\site-packages\google\genai\types.py:42
  E:\MailTrace-AI\.venv\Lib\site-packages\google\genai\types.py:42: DeprecationWarning: '_UnionGenericAlias' is deprecated and slated for removal in Python 3.17
    VersionedUnionType = Union[builtin_types.UnionType, _UnionGenericAlias]

-- Docs: https://docs.pytest.org/en/stable/how-to/capture-warnings.html
======================= 105 passed, 1 warning in 15.96s =======================
``n
## Security Status: ✅ PASSED

## Summary
All quality gate checks passed successfully.
