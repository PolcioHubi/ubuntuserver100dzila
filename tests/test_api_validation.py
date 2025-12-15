# Testy walidacji dla API rejestracji
def test_register_username_too_short(client, access_key_service):
    """Testuje próbę rejestracji z nazwą użytkownika krótszą niż 3 znaki."""
    key = access_key_service.generate_access_key("short_username_test")
    response = client.post(
        "/register",
        json={"username": "ab", "password": "password123", "access_key": key},
    )
    assert response.status_code == 400
    data = response.get_json()
    assert data["error"] == "Nazwa użytkownika musi mieć co najmniej 3 znaki"


def test_register_password_too_short(client, access_key_service):
    """Testuje próbę rejestracji z hasłem krótszym niż 6 znaków."""
    key = access_key_service.generate_access_key("short_password_test")
    response = client.post(
        "/register",
        json={"username": "testuser123", "password": "123", "access_key": key},
    )
    assert response.status_code == 400
    data = response.get_json()
    assert data["error"] == "Hasło musi mieć co najmniej 6 znaków"


def test_register_missing_access_key(client):
    """Testuje próbę rejestracji bez klucza dostępu."""
    response = client.post(
        "/register",
        json={"username": "testuser456", "password": "password123", "access_key": ""},
    )
    assert response.status_code == 400
    data = response.get_json()
    assert data["error"] == "Wszystkie pola są wymagane"


def test_register_duplicate_username(client, registered_user, access_key_service):
    """Testuje próbę rejestracji z już istniejącą nazwą użytkownika."""
    key = access_key_service.generate_access_key("duplicate_user_test")
    response = client.post(
        "/register",
        json={
            "username": registered_user["username"],
            "password": "anotherpassword",
            "access_key": key,
        },
    )
    assert response.status_code == 400
    data = response.get_json()
    assert data["error"] == "Użytkownik o tej nazwie już istnieje"


# Testy walidacji dla API logowania
def test_login_wrong_username(client):
    """Testuje próbę logowania z nieprawidłową nazwą użytkownika."""
    response = client.post(
        "/login", json={"username": "nonexistentuser", "password": "password123"}
    )
    assert response.status_code == 401
    data = response.get_json()
    assert data["error"] == "Nieprawidłowa nazwa użytkownika lub hasło"


def test_login_wrong_password(client, registered_user):
    """Testuje próbę logowania z nieprawidłowym hasłem."""
    response = client.post(
        "/login",
        json={"username": registered_user["username"], "password": "wrongpassword"},
    )
    assert response.status_code == 401
    data = response.get_json()
    assert data["error"] == "Nieprawidłowa nazwa użytkownika lub hasło"


# Testy walidacji dla API panelu admina
def test_admin_reset_password_too_short(admin_client, registered_user):
    """Testuje próbę zresetowania hasła użytkownika na zbyt krótkie przez admina."""
    response = admin_client.post(
        "/admin/api/reset-password",
        json={"username": registered_user["username"], "new_password": "123"},
    )
    assert response.status_code == 400
    data = response.get_json()
    assert data["error"] == "Hasło musi mieć od 6 do 100 znaków"


def test_register_with_self_referral(client, access_key_service, auth_manager):
    """Testuje, czy użytkownik nie otrzymuje monet za polecenie samego siebie."""
    key = access_key_service.generate_access_key("self_referral_test")
    username = "selfreferrer"
    password = "password123"

    response = client.post(
        "/register",
        json={
            "username": username,
            "password": password,
            "access_key": key,
            "referral_code": username,  # Użycie własnej nazwy jako kodu polecającego
        },
    )

    assert response.status_code == 200
    assert response.get_json()["success"] is True

    # Sprawdzenie bezpośrednio w bazie danych
    user = auth_manager.get_user_by_id(username)
    assert user is not None
    assert user.hubert_coins == 0
