import datetime


def test_registration_with_edge_case_data(auth_manager, access_key_service):
    """
    Testuje rejestrację użytkownika z różnymi przypadkami brzegowymi danych.
    """
    test_cases = [
        # Valid cases
        (
            "user_with_special_chars!@#",
            "password123",
            True,
            "Użytkownik zarejestrowany pomyślnie",
        ),
        ("min_len_user", "123456", True, "Użytkownik zarejestrowany pomyślnie"),
        (
            "max_len_user" * 4,
            "long_password" * 5,
            True,
            "Użytkownik zarejestrowany pomyślnie",
        ),  # username 48 chars, password 65 chars
        # Invalid cases
        (
            "a",
            "password123",
            False,
            "Nazwa użytkownika musi mieć co najmniej 3 znaki",
        ),  # Too short username
        (
            "toolongusername" * 5,
            "password123",
            False,
            "Nazwa użytkownika może mieć maksymalnie 50 znaków",
        ),  # Too long username
        (
            "valid_user",
            "12345",
            False,
            "Hasło musi mieć co najmniej 6 znaków",
        ),  # Too short password
    ]

    for username, password, expected_success, expected_message in test_cases:
        access_key = access_key_service.generate_access_key(f"key_{username}")
        success, message, _ = auth_manager.register_user(username, password, access_key)

        assert expected_message in message, (
            f"Test failed for username: {username}, password: {password}. Expected message: '{expected_message}', got: '{message}'"
        )


def test_password_reset_token_expiration(auth_manager, registered_user, mocker):
    """
    Testuje, czy token resetowania hasła wygasa po określonym czasie.
    """
    username = registered_user["username"]
    new_password = "new_password_after_reset"

    # 1. Wygeneruj token resetowania hasła
    token = auth_manager.generate_password_reset_token(username)
    assert token is not None

    # 2. Zasymuluj upływ czasu (np. 2 godziny, token wygasa po 1 godzinie)
    future_time = datetime.datetime.now() + datetime.timedelta(hours=2)
    mock_datetime = mocker.patch("datetime.datetime", mocker.MagicMock(wraps=datetime.datetime))
    mock_datetime.now.return_value = future_time

    # 3. Spróbuj zresetować hasło, używając wygasłego tokenu
    success, message = auth_manager.reset_user_password_with_token(token, new_password)

    # 4. Sprawdź, czy resetowanie hasła zakończyło się niepowodzeniem z powodu wygaśnięcia tokenu
    assert success is False
    assert "Token wygasł" in message

    # 5. Upewnij się, że stare hasło nadal działa (hasło nie zostało zmienione)
    auth_success, _, _ = auth_manager.authenticate_user(
        username, registered_user["password"]
    )
    assert auth_success is True
