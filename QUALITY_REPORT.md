# MailTrace AI Quality Gate Report

**Run Date:** 2026-09-03 18:00:17Z

## Pytest Status: ✅ PASSED

`	ext
============================= test session starts =============================
platform win32 -- Python 3.14.6, pytest-9.1.1, pluggy-1.6.0
rootdir: E:\MailTrace-AI
plugins: anyio-4.14.2
collected 100 items

tests\system\test_app_workflows.py .....                                 [  5%]
tests\test_app_gemini_flow.py ...                                        [  8%]
tests\test_campaign_correlator.py .......                                [ 15%]
tests\test_case_database.py ......                                       [ 21%]
tests\test_content_analyzer.py .....................                     [ 42%]
tests\test_domain_intelligence.py ....                                   [ 46%]
tests\test_email_parser.py ............                                  [ 58%]
tests\test_gemini_analyzer.py ....                                       [ 62%]
tests\test_geolocation.py ........                                       [ 70%]
tests\test_header_analyzer.py ....                                       [ 74%]
tests\test_relay_analyzer.py ......                                      [ 80%]
tests\test_report_generator.py ....                                      [ 84%]
tests\test_risk_scoring.py ................                              [100%]

============================== warnings summary ===============================
.venv\Lib\site-packages\google\genai\types.py:42
  E:\MailTrace-AI\.venv\Lib\site-packages\google\genai\types.py:42: DeprecationWarning: '_UnionGenericAlias' is deprecated and slated for removal in Python 3.17
    VersionedUnionType = Union[builtin_types.UnionType, _UnionGenericAlias]

-- Docs: https://docs.pytest.org/en/stable/how-to/capture-warnings.html
======================= 100 passed, 1 warning in 15.09s =======================
``n
## Security Status: ✅ PASSED

## Summary
All quality gate checks passed successfully.
