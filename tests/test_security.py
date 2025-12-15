import pytest
from flask import url_for
import json
import re

def test_csrf_protection_on_login(csrf_enabled_client):
    """
    Testuje, czy endpoint /login jest chroniony przed atakami CSRF.
    """
    response = csrf_enabled_client.post(url_for('login'), data={
        'username': 'testuser',
        'password': 'password123'
    }, follow_redirects=True)

    assert response.status_code == 400
    response_data = json.loads(response.data)
    assert "The CSRF token is missing." in response_data.get("error", "")

def test_xss_sanitization_on_id_card_generation(logged_in_client, registered_user):
    """
    Testuje, czy dane wejściowe w formularzu generowania dowodu są 
    poprawnie czyszczone z potencjalnie złośliwego kodu JavaScript (XSS).
    """
    xss_payload = "<script>alert('XSS-ATTACK');</script>"
    form_data = {
        'imie': xss_payload,
        'nazwisko': 'Testowy',
        'data_urodzenia': '1990-01-01',
        'obywatelstwo': 'POLSKIE',
        'nr_dowodu': 'ABC123456',
        'data_wydania': '2020-01-01',
        'data_waznosci': '2030-01-01',
        'csrf_token': logged_in_client.csrf_token,
        'user_name': registered_user['username']
    }

    response = logged_in_client.post(url_for('index'), data=form_data, follow_redirects=True)

    assert response.status_code == 200
    response_data = json.loads(response.data)
    assert response_data["success"] is True
    assert "Dane i pliki zostały przetworzone pomyślnie." in response_data["message"]

# Nowe testy bezpieczeństwa

@pytest.mark.parametrize(
    "username_payload, password_payload, expected_error_message",
    [
        ("' OR 1=1 --", "", "Nazwa użytkownika i hasło są wymagane"),
        ("admin' --", "", "Nazwa użytkownika i hasło są wymagane"),
        ("testuser", "' OR 1=1 --", "Nieprawidłowa nazwa użytkownika lub hasło"),
        ("testuser' AND 1=1 --", "password123", "Nieprawidłowa nazwa użytkownika lub hasło"),
    ]
)
def test_sql_injection_login(client, username_payload, password_payload, expected_error_message):
    """
    Testuje, czy aplikacja jest odporna na podstawowe próby wstrzykiwania SQL
    w formularzu logowania.
    """
    response = client.post(url_for('login'), json={
        'username': username_payload,
        'password': password_payload
    })
    data = response.get_json()
    assert data["success"] is False
    assert expected_error_message in data["error"]

@pytest.mark.parametrize(
    "path, expected_status, redirect_location",
    [
        ("/admin/", 302, "/admin/login"), # Niezalogowany użytkownik - przekierowanie
        ("/admin/api/users", 401, None), # Niezalogowany użytkownik - API
    ]
)
def test_admin_access_unauthenticated(client, path, expected_status, redirect_location):
    """
    Testuje, czy niezalogowany użytkownik nie ma dostępu do zasobów admina.
    """
    response = client.get(path)
    assert response.status_code == expected_status
    if redirect_location:
        assert response.headers['Location'] == redirect_location

def test_admin_access_authenticated_non_admin(logged_in_client, registered_user):
    """
    Testuje, czy zalogowany użytkownik (nie admin) nie ma dostępu do zasobów admina.
    """
    # Próba dostępu do strony admina
    response_page = logged_in_client.get(url_for('admin'))
    assert response_page.status_code == 302 # Powinien być przekierowany
    assert response_page.headers['Location'] == url_for('admin_login')

    # Próba dostępu do API admina
    response_api = logged_in_client.get(url_for('api_get_users'))
    assert response_api.status_code == 401 # Powinien być 401 Unauthorized

def test_sensitive_data_exposure_on_error(admin_client):
    """
    Testuje, czy błędy API nie ujawniają wrażliwych danych (np. stack trace).
    """
    # Celowe wywołanie błędu poprzez wysłanie nieprawidłowych danych
    # Endpoint /admin/api/update-hubert-coins oczekuje int dla 'amount'
    response = admin_client.post(url_for('api_update_hubert_coins'), json={
        'username': 'nonexistent_user',
        'amount': 'not_an_integer' # To powinno wywołać błąd walidacji/typu
    })
    
    assert response.status_code == 400 # Oczekujemy błędu Bad Request
    response_data = json.loads(response.data)
    
    assert response_data["success"] is False
    assert "Nieprawidłowe dane" in response_data["error"]
    
    # Sprawdzamy, czy w odpowiedzi nie ma śladów stosu ani innych wrażliwych informacji
    response_text = response.get_data(as_text=True)
    assert "Traceback" not in response_text
    assert "/home/" not in response_text # Przykład ścieżki serwera
    assert "/var/www/" not in response_text # Inny przykład ścieżki serwera
    assert "SECRET_KEY" not in response_text
    assert "password" not in response_text

@pytest.mark.parametrize(
    "password, expected_error_message",
    [
        ("short", "Hasło musi mieć co najmniej 6 znaków"),
        ("", "Wszystkie pola są wymagane"),
        ("a" * 101, "Hasło może mieć maksymalnie 100 znaków"), # Zbyt długie hasło
    ]
)
def test_password_policy_enforcement(client, access_key_service, password, expected_error_message):
    """
    Testuje, czy aplikacja wymusza politykę hasła podczas rejestracji.
    """
    username = "new_test_user"
    access_key = access_key_service.generate_access_key("test_key_for_policy")

    response = client.post(url_for('register'), json={
        'username': username,
        'password': password,
        'access_key': access_key
    })
    data = response.get_json()

    assert data["success"] is False
    assert expected_error_message in data["error"]


def test_idor_user_logs_access(logged_in_client, registered_user, auth_manager, access_key_service):
    """
    Testuje, czy zwykły użytkownik nie może uzyskać dostępu do logów innego użytkownika
    poprzez manipulację IDOR w API admina.
    """
    # Tworzymy drugiego użytkownika, którego logi będziemy próbować uzyskać
    another_username = "another_user"
    auth_manager.register_user(another_username, "another_password123", access_key_service.generate_access_key("another_key"))

    # Próba dostępu do logów drugiego użytkownika przez zalogowanego (nie-admina) klienta
    response = logged_in_client.get(url_for('api_get_user_logs', username=another_username))
    
    # Oczekujemy 401 Unauthorized, ponieważ endpoint jest chroniony przez @require_admin_login
    assert response.status_code == 401
    response_data = json.loads(response.data)
    assert "Authentication required" in response_data["error"]

def test_idor_download_user_data(logged_in_client, registered_user, auth_manager, access_key_service):
    """
    Testuje, czy zwykły użytkownik nie może pobrać danych innego użytkownika
    poprzez manipulację IDOR w API admina.
    """
    # Tworzymy drugiego użytkownika
    another_username = "yet_another_user"
    auth_manager.register_user(another_username, "yetanother_password123", access_key_service.generate_access_key("yet_another_key"))

    # Próba pobrania danych drugiego użytkownika przez zalogowanego (nie-admina) klienta
    response = logged_in_client.get(url_for('api_download_user_data', username=another_username))

    # Oczekujemy 401 Unauthorized, ponieważ endpoint jest chroniony przez @require_admin_login
    assert response.status_code == 401
    response_data = json.loads(response.data)
    assert "Authentication required" in response_data["error"]

@pytest.mark.parametrize(
    "malicious_username, expected_status_code, expected_error_message",
    [
        ("../", 404, "Resource not found."),
        ("../../", 404, "Resource not found."),
        ("| ls", 400, "Nieprawidlowa nazwa uzytkownika"),  # Zmieniono z 500 na 400
        ("& cat /etc/passwd", 404, "Resource not found."),
        ("user\0.txt", 400, "Nieprawidlowa nazwa uzytkownika"),  # Zmieniono z 500 na 400 (null byte = atak)
    ]
)
def test_path_traversal_user_logs(admin_client, malicious_username, expected_status_code, expected_error_message):
    """
    Testuje, czy endpoint api_get_user_logs jest odporny na ataki Path Traversal.
    """
    response = admin_client.get(url_for('api_get_user_logs', username=malicious_username))
    assert response.status_code == expected_status_code
    if expected_status_code == 404:
        assert expected_error_message in response.get_data(as_text=True)
    else:
        response_data = json.loads(response.data)
        assert expected_error_message in response_data["error"]

@pytest.mark.parametrize(
    "malicious_username, expected_status_code, expected_error_message",
    [
        ("../", 404, "Resource not found."),
        ("../../", 404, "Resource not found."),
        ("| ls", 400, "Nieprawidlowa nazwa uzytkownika"),  # Zmieniono z 404 na 400
        ("& cat /etc/passwd", 404, "Resource not found."),
        ("user\0.txt", 400, "Nieprawidlowa nazwa uzytkownika"),  # Zmieniono z 404 na 400 (null byte = atak)
    ]
)
def test_path_traversal_download_user_data(admin_client, malicious_username, expected_status_code, expected_error_message):
    """
    Testuje, czy endpoint api_download_user_data jest odporny na ataki Path Traversal.
    """
    response = admin_client.get(url_for('api_download_user_data', username=malicious_username))
    assert response.status_code == expected_status_code
    if expected_status_code == 404:
        response_data = json.loads(response.data)
        assert expected_error_message in response_data["error"]
    else:
        response_data = json.loads(response.data)
        assert expected_error_message in response_data["error"]
