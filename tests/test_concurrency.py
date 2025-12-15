import pytest
import threading
import secrets
from models import User, AccessKey, db

# Ten plik zawiera testy sprawdzające zachowanie aplikacji w warunkach wielowątkowych.

def test_race_condition_on_access_key_usage(app, auth_manager, access_key_service):
    """
    Testuje warunki wyścigu podczas próby jednoczesnej rejestracji wielu użytkowników
    przy użyciu tego samego klucza dostępu.

    Oczekiwany rezultat: Tylko jeden użytkownik powinien zostać pomyślnie zarejestrowany,
    a klucz dostępu powinien zostać poprawnie zdezaktywowany i oznaczony jako użyty raz.
    """
    # --- Faza 1: Przygotowanie ---
    # Używamy kontekstu aplikacji, aby mieć dostęp do bazy danych w wątkach
    with app.app_context():
        # Stwórz jeden, współdzielony klucz dostępu
        shared_access_key = access_key_service.generate_access_key("race_condition_test_key")
        db.session.commit()

        results = {"success": 0, "failure": 0}
        threads = []

        # --- Faza 2: Definicja zadania dla wątku ---
        def registration_task():
            # Każdy wątek potrzebuje własnego kontekstu aplikacji
            with app.app_context():
                # Każdy wątek próbuje zarejestrować unikalnego użytkownika
                username = f"race_user_{secrets.token_hex(8)}"
                password = "password123"
                
                success, message, token = auth_manager.register_user(
                    username, password, shared_access_key
                )
                
                if success:
                    results["success"] += 1
                else:
                    results["failure"] += 1

        # --- Faza 3: Uruchomienie wątków ---
        for _ in range(10): # Uruchom 10 wątków próbujących się zarejestrować
            thread = threading.Thread(target=registration_task)
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join() # Poczekaj, aż wszystkie wątki zakończą pracę

        # --- Faza 4: Weryfikacja wyników ---
        # Sprawdź, czy dokładnie jedna rejestracja zakończyła się sukcesem
        assert results["success"] == 1, f"Oczekiwano 1 udanej rejestracji, a było {results['success']}"
        assert results["failure"] == 9, f"Oczekiwano 9 nieudanych rejestracji, a było {results['failure']}"

        # Sprawdź stan klucza dostępu w bazie danych
        key_in_db = db.session.get(AccessKey, shared_access_key)
        assert key_in_db is not None
        assert key_in_db.is_active is False, "Klucz dostępu powinien być nieaktywny"
        assert key_in_db.used_count == 1, "Licznik użyć klucza powinien wynosić 1"

        # Sprawdź, czy w bazie danych jest tylko jeden nowy użytkownik z tej puli
        registered_users = User.query.filter(User.username.like("race_user_%")).all()  # type: ignore[union-attr]
        assert len(registered_users) == 1, f"Oczekiwano 1 zarejestrowanego użytkownika, a znaleziono {len(registered_users)}"
