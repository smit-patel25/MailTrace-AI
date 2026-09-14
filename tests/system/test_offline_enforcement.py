import pytest
import socket
import urllib.request
import urllib.error
import subprocess
import sys
import os
from unittest.mock import Mock, patch
from pytest_socket import SocketBlockedError

def test_direct_socket_blocked():
    """Verify that direct TCP connections are blocked (IPv4)."""
    with pytest.raises(SocketBlockedError):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("192.0.2.1", 80))  # Documentation IP

def test_direct_socket_v6_blocked():
    """Verify that direct TCP connections are blocked (IPv6)."""
    with pytest.raises(SocketBlockedError):
        s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        s.connect(("2001:db8::1", 80))  # Documentation IP

def test_dns_resolution_blocked():
    """Verify that DNS resolution is blocked."""
    with pytest.raises(SocketBlockedError):
        socket.getaddrinfo("example.invalid", 80)

    with pytest.raises(SocketBlockedError):
        socket.gethostbyname("example.invalid")

def test_http_request_blocked():
    """Verify that standard HTTP requests are blocked, checking the underlying cause."""
    try:
        urllib.request.urlopen("http://example.invalid")
    except SocketBlockedError:
        pass  # Blocked directly
    except urllib.error.URLError as e:
        # If wrapped, ensure the underlying reason is SocketBlockedError
        assert isinstance(e.reason, SocketBlockedError)
    except Exception as e:
        pytest.fail(f"Expected SocketBlockedError or URLError, got {type(e).__name__}: {e}")
    else:
        pytest.fail("urllib.request.urlopen unexpectedly succeeded")

def test_mocked_network_allowed():
    """Verify that mocked external services work normally without SocketBlockedError."""
    with patch("urllib.request.urlopen") as mock_urlopen:
        mock_response = Mock()
        mock_response.read.return_value = b"mocked content"
        mock_urlopen.return_value = mock_response

        response = urllib.request.urlopen("http://example.invalid")
        assert response.read() == b"mocked content"
        mock_urlopen.assert_called_once_with("http://example.invalid")

def test_collection_time_protection(tmp_path):
    """Verify that protection is active before test modules are imported, including pytest --collect-only."""
    import runpy

    root_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    root_conftest = os.path.join(root_dir, "conftest.py")
    pyproject_toml = os.path.join(root_dir, "pyproject.toml")

    # Write a temporary conftest that loads the repository's actual root conftest.py
    conftest_file = tmp_path / "conftest.py"
    conftest_file.write_text(
        f"import runpy\n"
        f"runpy.run_path(r'{root_conftest}')\n",
        encoding="utf-8"
    )

    dummy_test_file = tmp_path / "test_dummy_collection.py"
    dummy_test_file.write_text(
        "import socket\n"
        "s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
        "def test_dummy(): pass\n",
        encoding="utf-8"
    )

    env = os.environ.copy()
    env["PYTHONPATH"] = str(tmp_path)

    # Run the child pytest process with the repository's real pytest configuration
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", str(tmp_path), "-c", pyproject_toml],
        capture_output=True,
        text=True,
        env=env,
        timeout=30
    )

    assert result.returncode != 0
    assert "SocketBlockedError" in result.stderr or "SocketBlockedError" in result.stdout
