import sys
import pytest
from models import User

# Fixture `live_server` is provided by our conftest.py

# We will use the `app` fixture from conftest.py directly for most tests
# and modify it if needed for specific production config tests.


def test_database_connectivity(app):
    """
    Testuje, czy aplikacja może połączyć się z bazą danych i wykonać prostą operację.
    Uses the `app` fixture from conftest.py which sets up an in-memory DB.
    """
    with app.app_context():
        # Try to query for users, this will fail if DB connection is bad
        users = User.query.all()
        assert isinstance(users, list)


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="LiveServer tests have multiprocessing issues on Windows",
)
def test_login_page_reachable_and_content(live_server, client):
    """
    Testuje, czy strona logowania jest dostępna i zawiera oczekiwane elementy HTML.
    """
    response = client.get(f"{live_server}/login")
    assert response.status_code == 200
    assert b"<title>Logowanie - Podmieniacz Danych HTML</title>" in response.data
    assert b'<form id="loginForm">' in response.data  # Check for login form


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="LiveServer tests have multiprocessing issues on Windows",
)
def test_register_page_reachable_and_content(live_server, client):
    """
    Testuje, czy strona rejestracji jest dostępna i zawiera oczekiwane elementy HTML.
    """
    response = client.get(f"{live_server}/register")
    assert response.status_code == 200
    assert b"<title>Rejestracja - Podmieniacz Danych HTML</title>" in response.data
    assert b'<form id="registerForm">' in response.data  # Check for registration form


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="LiveServer tests have multiprocessing issues on Windows",
)
def test_static_files_served(live_server, client):
    """
    Testuje, czy pliki statyczne są poprawnie serwowane.
    """
    response = client.get(f"{live_server}/static/main.css")
    assert response.status_code == 200
    assert response.mimetype == "text/css"
    assert b"body" in response.data  # Check for some content in the CSS file


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="LiveServer tests have multiprocessing issues on Windows",
)
def test_404_error_handling(live_server, client):
    """
    Testuje, czy aplikacja poprawnie obsługuje błędy 404 Not Found.
    """
    response = client.get(f"{live_server}/nonexistent_page_12345")
    assert response.status_code == 404
    assert b"Resource not found." in response.data  # Check for custom 404 message
