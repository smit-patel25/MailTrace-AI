"""
Central safe-analysis limits for MailTrace AI.

All limits are defined here as module-level constants so they are:
- testable in isolation
- never read from user-controlled input
- easily audited in one place

Do NOT import Streamlit or any email-parsing library here.
"""
from dataclasses import dataclass


@dataclass(frozen=True)
class AnalysisLimits:
    """Immutable configuration of safe email-analysis bounds."""

    # Raw input
    MAX_RAW_BYTES: int = 2 * 1024 * 1024          # 2 MiB

    # MIME structure
    MAX_MIME_PARTS: int = 250
    MAX_MIME_NESTING_DEPTH: int = 30
    MAX_TOTAL_HEADERS: int = 2_000
    MAX_HEADERS_PER_PART: int = 200
    MAX_RAW_HEADER_LINE_BYTES: int = 32 * 1024     # 32 KiB

    # Attachments
    MAX_ATTACHMENTS: int = 50
    MAX_ATTACHMENT_BYTES: int = 2 * 1024 * 1024    # 2 MiB per attachment
    MAX_CUMULATIVE_ATTACHMENT_BYTES: int = 4 * 1024 * 1024  # 4 MiB total

    # Content analysis
    MAX_ANALYSIS_TEXT_CHARS: int = 500_000

    # URL / domain
    MAX_UNIQUE_URLS: int = 200
    MAX_URL_LENGTH: int = 2_048
    MAX_UNIQUE_DOMAINS: int = 200

    # Display
    MAX_DISPLAY_FILENAME_BYTES: int = 255


# Singleton used by all modules — import this object, not the class.
LIMITS = AnalysisLimits()
