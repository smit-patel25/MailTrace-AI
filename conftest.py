import pytest_socket

# Enforce socket blocking as early as possible during collection.
# This ensures that even module-level network calls in tests are blocked.
pytest_socket.disable_socket()
