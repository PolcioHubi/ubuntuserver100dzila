import pytest
import io
from models import User


@pytest.mark.parametrize(
    "username_payload, password_payload",
    [
        ("' OR 1=1 --", "any_password"),
        ("admin'--", "any_password"),
        ("' OR 'a'='a", "any_password"),
        ("any_user", "' OR 1=1 --"),
        ("any_user", "' OR 'a'='a"),
    ],
)
def test_sql_injection_login(client, username_payload, password_payload):
    """
    Testuje odporność na SQL Injection na endpointach logowania.
    Oczekujemy, że logowanie nie powiedzie się, a aplikacja nie zwróci błędu serwera.
    """
    response = client.post(
        "/login",
        json={
            "username": username_payload,
            "password": password_payload,
        },
    )
    # Oczekujemy, że logowanie nie powiedzie się (401 Unauthorized) lub zwróci błąd 400 Bad Request
    # Ważne: nie oczekujemy 500 Internal Server Error
    assert response.status_code in [400, 401]
    data = response.get_json()
    assert data["success"] is False
    assert (
        "Nieprawidłowa nazwa użytkownika lub hasło" in data["error"]
        or "Wszystkie pola są wymagane" in data["error"]
    )


def test_file_upload_path_traversal_prevention(logged_in_client):
    """
    Testuje, czy aplikacja zapobiega atakom Path Traversal podczas przesyłania plików.
    """
    malicious_filename = "../../../../../../../../tmp/malicious.jpg"
    image_data = (io.BytesIO(b"malicious_content"), malicious_filename)

    response = logged_in_client.post(
        "/",
        data={
            "user_name": "testuser",
            "imie": "JAN",
            "nazwisko": "KOWALSKI",
            "pesel": "90010112345",
            "image_upload": image_data,
        },
        content_type="multipart/form-data",
        headers={"X-CSRFToken": logged_in_client.csrf_token},
    )

    # Oczekujemy, że aplikacja zwróci błąd lub w inny sposób zablokuje zapis
    # pliku w niepożądanym miejscu. W tym przypadku, walidacja jest po stronie
    # serwera Flask w funkcji user_files, która jest wywoływana przy próbie
    # dostępu do pliku. Przy uploadzie, Flask domyślnie zapisuje w bezpiecznym miejscu.
    # Sprawdzamy, czy aplikacja zwróciła błąd walidacji nazwy pliku.
    assert response.status_code == 400
    data = response.get_json()
    assert "Nazwa pliku zawiera niedozwolone znaki (np. ścieżki)." in data["error"]


def test_external_dependency_failure_handling(auth_manager, mocker, db_session):
    """
    Testuje, czy aplikacja poprawnie obsługuje błędy w zależnościach zewnętrznych
    (np. gdy usługa kluczy dostępu zawiedzie).
    """
    # Arrange: Zasymuluj błąd w access_key_service.generate_access_key
    mocker.patch(
        "services.AccessKeyService.validate_access_key",
        return_value=(False, "Simulated AccessKeyService error"),
    )

    # Act: Spróbuj zarejestrować użytkownika
    username = "error_test_user"
    password = "password123"
    access_key = "any_key"

    success, message, _ = auth_manager.register_user(username, password, access_key)

    # Assert: Sprawdź, czy rejestracja zakończyła się niepowodzeniem
    assert success is False
    assert "Simulated AccessKeyService error" in message

    # Sprawdź, czy użytkownik nie został utworzony w bazie danych
    user = db_session.get(User, username)
    assert user is None

    # Sprawdź, czy transakcja została wycofana (rollback)
    # To jest trudne do bezpośredniego sprawdzenia bez mockowania db.session.rollback
    # Ale brak użytkownika w bazie jest wystarczającym dowodem.
