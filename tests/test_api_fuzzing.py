import pytest
import secrets
import string
import random

# Funkcja pomocnicza do generowania losowych stringów
def generate_random_string(length):
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(characters) for i in range(length))

# Dane do fuzzingu
fuzz_data = [
    # Puste pola
    ("", "", ""),
    ("test_user", "", ""),
    ("", "password", ""),
    ("", "", "access_key"),

    # Zbyt krótkie/długie dane
    ("a", "12345", "invalid_key"), # Za krótkie
    (generate_random_string(51), generate_random_string(101), generate_random_string(100)), # Za długie

    # Dane ze znakami specjalnymi / próbami iniekcji
    ("admin'--", "password", "key"),
    ("user@example.com", "' OR 1=1 --", "key"),
    ("user", "password", "' OR 1=1 --"),
    ("user", "password", "<script>alert(1)</script>"),
    ("user", "password", "../../etc/passwd"),

    # Dane z nieoczekiwanymi typami (jeśli API przyjmuje JSON)
    # (None, None, None), # Python requests automatycznie konwertuje None na 'null'
    # (123, 456, 789), # Liczby zamiast stringów

    # Kombinacje losowych danych
    (generate_random_string(random.randint(1, 100)), generate_random_string(random.randint(1, 100)), generate_random_string(random.randint(1, 100))),
    (generate_random_string(random.randint(1, 100)), generate_random_string(random.randint(1, 100)), generate_random_string(random.randint(1, 100))),
    (generate_random_string(random.randint(1, 100)), generate_random_string(random.randint(1, 100)), generate_random_string(random.randint(1, 100))),
    (generate_random_string(random.randint(1, 100)), generate_random_string(random.randint(1, 100)), generate_random_string(random.randint(1, 100))),
    (generate_random_string(random.randint(1, 100)), generate_random_string(random.randint(1, 100)), generate_random_string(random.randint(1, 100))),
]

@pytest.mark.parametrize("username, password, access_key", fuzz_data)
def test_register_fuzzing(client, username, password, access_key):
    """
    Wykonuje test fuzzingowy na endpointcie /register.
    Sprawdza, czy aplikacja nie zwraca błędu 500 i zawsze zwraca sensowną odpowiedź.
    """
    response = client.post(
        "/register",
        json={
            "username": username,
            "password": password,
            "access_key": access_key
        }
    )

    # Asercje
    # 1. Nie powinien być to błąd serwera (500 Internal Server Error)
    assert response.status_code != 500, f"Otrzymano błąd 500 dla danych: username={username}, password={password}, access_key={access_key}"

    # 2. Odpowiedź powinna być JSONem
    assert response.headers["Content-Type"] == "application/json"

    # 3. Odpowiedź JSON powinna zawierać klucz 'success' i 'error'
    data = response.get_json()
    assert "success" in data
    assert "error" in data

    # 4. Oczekujemy, że większość (lub wszystkie) z tych przypadków zakończy się niepowodzeniem
    # (chyba że losowo wygenerujemy poprawne dane, co jest mało prawdopodobne)
    assert data["success"] is False
