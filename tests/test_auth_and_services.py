import pytest
from models import User, AccessKey, Announcement, db, File, Notification
from services import AnnouncementService, StatisticsService, NotificationService, AccessKeyService # Dodano AccessKeyService
import datetime # Dodano import datetime
from sqlalchemy.exc import IntegrityError # Dodano import IntegrityError


def test_password_hashing(auth_manager):
    """
    Testuje, czy hashowanie i sprawdzanie haseł działa poprawnie.
    Używa fixture `auth_manager`.
    """
    password = "mysecretpassword"
    hashed_password = auth_manager._hash_password(password)

    assert hashed_password != password
    assert auth_manager._check_password(hashed_password, password)
    assert not auth_manager._check_password(hashed_password, "wrongpassword")


def test_user_registration(auth_manager, access_key_service):
    """
    Testuje pomyślny proces rejestracji użytkownika.
    Sprawdza, czy użytkownik jest tworzony w bazie danych, a użyty klucz dostępu
    jest poprawnie dezaktywowany po rejestracji.
    """
    # 1. Stwórz ważny klucz dostępu
    access_key = access_key_service.generate_access_key("test key")

    # 2. Zarejestruj nowego użytkownika
    success, message, token = auth_manager.register_user(
        "testuser", "password123", access_key
    )

    assert success
    assert "Użytkownik zarejestrowany pomyślnie" in message
    assert token is not None

    # 3. Sprawdź, czy użytkownik istnieje w bazie danych
    user = User.query.filter_by(username="testuser").first()
    assert user is not None
    assert user.username == "testuser"

    # 4. Sprawdź, czy klucz dostępu został zużyty (dezaktywowany)
    key_obj = AccessKey.query.filter_by(key=access_key).first()
    assert key_obj is not None, "Access key should exist"
    assert key_obj.is_active is False
    assert key_obj.used_count == 1


def test_duplicate_user_registration(auth_manager, access_key_service):
    """
    Testuje, czy próba rejestracji użytkownika z już istniejącą nazwą
    zakończy się niepowodzeniem i zwróci odpowiedni komunikat.
    """
    key1 = access_key_service.generate_access_key("key1")
    key2 = access_key_service.generate_access_key("key2")

    # Zarejestruj pierwszego użytkownika
    auth_manager.register_user("duplicateuser", "password123", key1)

    # Spróbuj zarejestrować drugiego użytkownika o tej samej nazwie
    success, message, token = auth_manager.register_user(
        "duplicateuser", "anotherpassword", key2
    )

    assert not success
    assert message == "Użytkownik o tej nazwie już istnieje"
    assert token is None


def test_register_user_with_invalid_access_key(auth_manager):
    """
    Testuje, czy rejestracja z nieprawidłowym lub pustym kluczem dostępu
    zakończy się niepowodzeniem.
    """
    success, message, _ = auth_manager.register_user(
        "testuser", "password123", "invalid-key"
    )
    assert not success
    assert message == "Nieprawidłowy klucz dostępu"


def test_register_user_with_short_password(auth_manager, access_key_service):
    """
    Testuje, czy walidacja długości hasła działa i rejestracja ze zbyt
    krótkim hasłem (poniżej 6 znaków) jest niemożliwa.
    """
    key = access_key_service.generate_access_key("short_pass_key")
    success, message, _ = auth_manager.register_user("testuser", "12345", key)
    assert not success
    assert message == "Hasło musi mieć co najmniej 6 znaków"


def test_user_authentication(auth_manager, registered_user):
    """
    Testuje proces uwierzytelniania użytkownika.
    Sprawdza logowanie z poprawnym i niepoprawnym hasłem, a także
    próbę logowania dla nieistniejącego użytkownika.
    """
    # Test pomyślnego uwierzytelnienia
    success, message, user = auth_manager.authenticate_user(
        registered_user["username"], registered_user["password"]
    )
    assert success
    assert user is not None
    assert user.username == registered_user["username"]

    # Test uwierzytelnienia z błędnym hasłem
    success, message, user = auth_manager.authenticate_user(
        registered_user["username"], "wrongpassword"
    )
    assert not success
    assert user is None
    assert message == "Nieprawidłowa nazwa użytkownika lub hasło"

    # Test uwierzytelnienia dla nieistniejącego użytkownika
    success, message, user = auth_manager.authenticate_user(
        "nonexistent", "password123"
    )
    assert not success
    assert user is None


def test_authenticate_inactive_user(auth_manager, registered_user):
    """
    Testuje, czy próba zalogowania się przez użytkownika, którego konto
    zostało dezaktywowane, zakończy się niepowodzeniem.
    """
    # Dezaktywuj użytkownika
    user = User.query.filter_by(username=registered_user["username"]).first()
    assert user is not None, "User should exist"
    user.is_active = False
    db.session.commit()

    success, message, user_obj = auth_manager.authenticate_user(
        registered_user["username"], registered_user["password"]
    )
    assert not success
    assert user_obj is None
    assert message == "Konto użytkownika zostało dezaktywowane"


def test_reset_password_with_invalid_token(auth_manager):
    """
    Testuje, czy próba zresetowania hasła przy użyciu nieprawidłowego
    lub pustego tokenu zakończy się niepowodzeniem.
    """
    success, message = auth_manager.reset_user_password_with_token(
        "invalid-token", "newpassword"
    )
    assert not success
    assert message == "Nieprawidłowy token"


def test_announcement_service(db_session):
    """
    Testuje podstawowe funkcje serwisu ogłoszeń.
    Sprawdza tworzenie, pobieranie aktywnych ogłoszeń i dezaktywację.
    """
    announcement_service = AnnouncementService()

    # Stwórz ogłoszenie
    created = announcement_service.create_announcement(
        "Test Title", "Test Message", "info", None
    )
    assert created

    # Sprawdź, czy jest w bazie danych
    announcements = Announcement.query.all()
    assert len(announcements) == 1
    assert announcements[0].title == "Test Title"

    # Sprawdź, czy jest zwracane przez get_active_announcements
    active_announcements = announcement_service.get_active_announcements()
    assert len(active_announcements) == 1
    assert active_announcements[0].title == "Test Title"

    # Dezaktywuj ogłoszenie
    deactivated = announcement_service.deactivate_announcement(announcements[0].id)
    assert deactivated

    # Sprawdź, czy nie jest już aktywne
    active_announcements = announcement_service.get_active_announcements()
    assert len(active_announcements) == 0


class TestStatisticsService:
    @pytest.fixture(scope="class")
    def statistics_service(self):
        return StatisticsService()

    def test_add_and_get_user_files(
        self, db_session, statistics_service, registered_user
    ):
        """
        Testuje dodawanie i pobieranie plików użytkownika.
        """
        username = registered_user["username"]

        # Dodaj dwa pliki
        statistics_service.add_or_update_file(
            username, "file1.txt", "/path/to/file1.txt", 100, "hash1"
        )
        statistics_service.add_or_update_file(
            username, "file2.txt", "/path/to/file2.txt", 200, "hash2"
        )

        # Pobierz pliki i sprawdź
        files = statistics_service.get_user_files(username)
        assert len(files) == 2
        assert (
            files[0].filename == "file2.txt"
        )  # Domyślnie sortowane po dacie modyfikacji (malejąco)
        assert files[1].filename == "file1.txt"

    def test_update_file(self, db_session, statistics_service, registered_user):
        """
        Testuje aktualizację istniejącego pliku.
        """
        username = registered_user["username"]
        filepath = "/path/to/file.txt"

        # Dodaj plik
        statistics_service.add_or_update_file(
            username, "file.txt", filepath, 100, "hash1"
        )

        # Zaktualizuj plik
        statistics_service.add_or_update_file(
            username, "file.txt", filepath, 150, "hash_updated"
        )

        # Sprawdź, czy został zaktualizowany
        file_record = File.query.filter_by(filepath=filepath).first()
        assert file_record is not None
        assert file_record.size == 150
        assert file_record.file_hash == "hash_updated"

    def test_delete_file(self, db_session, statistics_service, registered_user):
        """
        Testuje usuwanie pliku.
        """
        username = registered_user["username"]
        filepath = "/path/to/file.txt"

        statistics_service.add_or_update_file(
            username, "file.txt", filepath, 100, "hash1"
        )

        # Usuń plik
        statistics_service.delete_file(filepath)

        # Sprawdź, czy został usunięty
        file_record = File.query.filter_by(filepath=filepath).first()
        assert file_record is None

    def test_get_overall_stats(self, db_session, statistics_service, registered_user):
        """
        Testuje pobieranie ogólnych statystyk.
        """
        # Statystyki początkowe (jeden zarejestrowany użytkownik z fixture)
        stats = statistics_service.get_overall_stats()
        assert stats["total_users"] == 1
        assert stats["total_files"] == 0
        assert stats["total_size"] == 0

        # Dodaj pliki
        statistics_service.add_or_update_file(
            registered_user["username"], "f1.txt", "/p/f1", 100, "h1"
        )
        statistics_service.add_or_update_file(
            registered_user["username"], "f2.txt", "/p/f2", 250, "h2"
        )

        # Sprawdź zaktualizowane statystyki
        stats = statistics_service.get_overall_stats()
        assert stats["total_users"] == 1
        assert stats["total_files"] == 2
        assert stats["total_size"] == 350

    def test_get_all_users_with_stats(
        self,
        db_session,
        statistics_service,
        registered_user,
        auth_manager,
        access_key_service,
    ):
        """
        Testuje pobieranie statystyk dla wszystkich użytkowników.
        """
        # Użytkownik 1 (z fixture)
        user1_name = registered_user["username"]
        statistics_service.add_or_update_file(user1_name, "f1.txt", "/p/f1", 100, "h1")

        # Użytkownik 2 (nowy)
        key = access_key_service.generate_access_key("user2_key")
        auth_manager.register_user("user2", "password", key)
        statistics_service.add_or_update_file("user2", "f2.txt", "/p/f2", 200, "h2")
        statistics_service.add_or_update_file("user2", "f3.txt", "/p/f3", 300, "h3")

        # Użytkownik 3 (bez plików)
        key3 = access_key_service.generate_access_key("user3_key")
        auth_manager.register_user("user3", "password", key3)

        # Pobierz statystyki
        users_with_stats = statistics_service.get_all_users_with_stats()["users"]

        assert len(users_with_stats) == 3

        # Konwertuj listę na słownik dla łatwiejszego dostępu
        stats_dict = {user["name"]: user for user in users_with_stats}

        # Sprawdź statystyki dla każdego użytkownika
        assert stats_dict[user1_name]["file_count"] == 1
        assert stats_dict[user1_name]["total_size"] == 100

        assert stats_dict["user2"]["file_count"] == 2
        assert stats_dict["user2"]["total_size"] == 500

        assert stats_dict["user3"]["file_count"] == 0
        assert stats_dict["user3"]["total_size"] == 0


def test_reset_password_with_valid_recovery_token(auth_manager, access_key_service):
    """
    Testuje pomyślny reset hasła przy użyciu tokenu odzyskiwania.
    """
    username = "recovery_user"
    old_password = "old_password"
    new_password = "new_strong_password"
    access_key = access_key_service.generate_access_key("recovery_key")

    # 1. Zarejestruj użytkownika i uzyskaj token odzyskiwania
    _, _, recovery_token = auth_manager.register_user(
        username, old_password, access_key
    )
    assert recovery_token is not None

    # 2. Zresetuj hasło przy użyciu tokenu
    success, message = auth_manager.reset_password_with_recovery_token(
        username, recovery_token, new_password
    )
    assert success is True
    assert message == "Hasło zostało pomyślnie zresetowane"

    # 3. Sprawdź, czy stare hasło już nie działa
    success, _, _ = auth_manager.authenticate_user(username, old_password)
    assert not success

    # 4. Sprawdź, czy nowe hasło działa
    success, _, user = auth_manager.authenticate_user(username, new_password)
    assert success is True
    assert user is not None


def test_deactivate_nonexistent_access_key(access_key_service):
    """
    Testuje dezaktywację nieistniejącego klucza dostępu.
    """
    success = access_key_service.deactivate_access_key("nonexistent_key")
    assert success is False


def test_delete_nonexistent_access_key(access_key_service):
    """
    Testuje usuwanie nieistniejącego klucza dostępu.
    """
    success = access_key_service.delete_access_key("nonexistent_key")
    assert success is False


def test_update_hubert_coins_insufficient_funds(auth_manager, access_key_service):
    """
    Testuje próbę odjęcia Hubert Coinów, gdy saldo jest niewystarczające.
    """
    username = "low_balance_user"
    password = "password123"
    access_key = access_key_service.generate_access_key("low_balance_key")
    auth_manager.register_user(username, password, access_key)

    # Upewnij się, że początkowe saldo wynosi 0
    user = User.query.filter_by(username=username).first()
    assert user is not None, "User should exist"
    assert user.hubert_coins == 0

    # Spróbuj odjąć monety
    success, message = auth_manager.update_hubert_coins(username, -5)
    assert success is False
    assert "Niewystarczająca ilość Hubert Coins" in message

    # Sprawdź, czy saldo pozostało 0
    user = User.query.filter_by(username=username).first()
    assert user is not None, "User should exist"
    assert user.hubert_coins == 0


def test_create_announcement_db_error(db_session, mocker):
    """
    Testuje obsługę błędu bazy danych podczas tworzenia ogłoszenia.
    """
    announcement_service = AnnouncementService()

    # Zasymuluj błąd podczas dodawania do sesji
    mock_db_session_add = mocker.patch('models.db.session.add', side_effect=Exception("Simulated DB error"))
    mock_db_session_rollback = mocker.patch('models.db.session.rollback')

    created = announcement_service.create_announcement(
        "Error Title", "Error Message", "info", None
    )
    assert created is False
    mock_db_session_rollback.assert_called_once()  # Sprawdź, czy rollback został wywołany


def test_get_user_by_id(auth_manager, registered_user):
    """
    Testuje pobieranie użytkownika po ID.
    """
    user = auth_manager.get_user_by_id(registered_user["username"])
    assert user is not None
    assert user.username == registered_user["username"]


def test_get_user_by_id_nonexistent(auth_manager):
    """
    Testuje pobieranie nieistniejącego użytkownika po ID.
    """
    user = auth_manager.get_user_by_id("nonexistent_user")
    assert user is None


def test_get_all_users(auth_manager, registered_user):
    """
    Testuje pobieranie wszystkich użytkowników.
    """
    users = auth_manager.get_all_users()
    assert len(users) >= 1
    assert any(u.username == registered_user["username"] for u in users)


def test_toggle_user_status(auth_manager, registered_user):
    """
    Testuje przełączanie statusu użytkownika.
    """
    username = registered_user["username"]

    # Sprawdź początkowy status (aktywny)
    user = User.query.filter_by(username=username).first()
    assert user is not None, "User should exist"
    assert user.is_active is True

    # Dezaktywuj
    auth_manager.toggle_user_status(username)
    user = User.query.filter_by(username=username).first()
    assert user is not None, "User should exist"
    assert user.is_active is False

    # Aktywuj ponownie
    auth_manager.toggle_user_status(username)
    user = User.query.filter_by(username=username).first()
    assert user is not None, "User should exist"
    assert user.is_active is True


def test_delete_user(auth_manager, registered_user):
    """
    Testuje usuwanie użytkownika.
    """
    username = registered_user["username"]

    # Usuń użytkownika
    deleted = auth_manager.delete_user(username)
    assert deleted is True

    # Sprawdź, czy użytkownik został usunięty
    user = User.query.filter_by(username=username).first()
    assert user is None


def test_delete_nonexistent_user(auth_manager):
    """
    Testuje usuwanie nieistniejącego użytkownika.
    """
    deleted = auth_manager.delete_user("nonexistent_user")
    assert deleted is False


def test_update_hubert_coins(auth_manager, registered_user):
    """
    Testuje aktualizację Hubert Coinów.
    """
    username = registered_user["username"]

    # Dodaj monety
    auth_manager.update_hubert_coins(username, 10)
    user = User.query.filter_by(username=username).first()
    assert user is not None, "User should exist"
    assert user.hubert_coins == 10

    # Odejmij monety
    auth_manager.update_hubert_coins(username, -5)
    user = User.query.filter_by(username=username).first()
    assert user is not None, "User should exist"
    assert user.hubert_coins == 5


def test_reset_user_password(auth_manager, registered_user):
    """
    Testuje resetowanie hasła użytkownika.
    """
    username = registered_user["username"]
    new_password = "new_password"

    # Zresetuj hasło
    auth_manager.reset_user_password(username, new_password)

    # Sprawdź, czy nowe hasło działa
    success, _, user = auth_manager.authenticate_user(username, new_password)
    assert success is True
    assert user is not None


def test_generate_password_reset_token(auth_manager, registered_user):
    """
    Testuje generowanie tokenu do resetowania hasła.
    """
    username = registered_user["username"]
    token = auth_manager.generate_password_reset_token(username)
    assert token is not None

    user = User.query.filter_by(username=username).first()
    assert user is not None, "User should exist"
    assert user.password_reset_token == token
    assert user.password_reset_expires is not None


def test_reset_user_password_with_token(auth_manager, registered_user):
    """
    Testuje resetowanie hasła przy użyciu tokenu.
    """
    username = registered_user["username"]
    new_password = "new_password_token"

    # Wygeneruj token
    token = auth_manager.generate_password_reset_token(username)

    # Zresetuj hasło
    success, message = auth_manager.reset_user_password_with_token(token, new_password)
    assert success is True
    assert message == "Hasło zostało pomyślnie zresetowane"

    # Sprawdź, czy nowe hasło działa
    success, _, user = auth_manager.authenticate_user(username, new_password)
    assert success is True
    assert user is not None


def test_get_user_info(auth_manager, registered_user):
    """
    Testuje pobieranie informacji o użytkowniku.
    """
    username = registered_user["username"]
    user_info = auth_manager.get_user_info(username)
    assert user_info is not None
    assert user_info["username"] == username
    assert "hubert_coins" in user_info
    assert "referral_code" in user_info


def test_get_user_info_nonexistent(auth_manager):
    """
    Testuje pobieranie informacji o nieistniejącym użytkowniku.
    """
    user_info = auth_manager.get_user_info("nonexistent_user")
    assert user_info is None


def test_user_registration_and_login_flow(auth_manager, access_key_service):
    """
    Testuje pełny, podstawowy przepływ: rejestrację i natychmiastowe logowanie.
    """
    # Arrange: Przygotuj dane dla nowego użytkownika
    new_username = "flow_user"
    new_password = "flow_password"
    access_key = access_key_service.generate_access_key("flow_test_key")

    # Act 1: Zarejestruj użytkownika
    reg_success, _, _ = auth_manager.register_user(
        new_username, new_password, access_key
    )

    # Assert 1: Sprawdź, czy rejestracja się powiodła
    assert reg_success is True

    # Act 2: Zaloguj się jako nowy użytkownik
    auth_success, _, user_obj = auth_manager.authenticate_user(
        new_username, new_password
    )

    # Assert 2: Sprawdź, czy logowanie się powiodło i zwróciło obiekt użytkownika
    assert auth_success is True
    assert user_obj is not None
    assert user_obj.username == new_username


def test_delete_user_cascades_data(auth_manager, access_key_service, db_session):
    """
    Testuje, czy usunięcie użytkownika powoduje kaskadowe usunięcie
    wszystkich jego powiązanych danych (plików, powiadomień) z bazy danych.
    """
    statistics_service = StatisticsService()  # Dodana linia
    # 1. Zarejestruj nowego użytkownika
    username = "user_to_delete_with_data"
    password = "password123"
    access_key = access_key_service.generate_access_key("cascade_test_key")
    auth_manager.register_user(username, password, access_key)

    # 2. Dodaj pliki i powiadomienia dla tego użytkownika
    statistics_service.add_or_update_file(
        username, "doc1.html", "/path/to/doc1.html", 500, "hash_doc1"
    )
    statistics_service.add_or_update_file(
        username, "img1.png", "/path/to/img1.png", 100, "hash_img1"
    )
    statistics_service.add_or_update_file(
        username, "doc2.html", "/path/to/doc2.html", 700, "hash_doc2"
    )

    db_session.commit()  # Upewnij się, że zmiany są zapisane

    notification_service = NotificationService()
    notification_service.create_notification(username, "Powiadomienie 1")
    notification_service.create_notification(username, "Powiadomienie 2")

    db_session.commit()  # Upewnij się, że zmiany są zapisane

    # 3. Sprawdź, czy dane istnieją przed usunięciem
    user_before_delete = User.query.filter_by(username=username).first()
    assert user_before_delete is not None
    assert len(user_before_delete.files) == 3
    assert len(user_before_delete.notifications) == 3  # 1 powitalne + 2 testowe

    # 4. Usuń użytkownika
    deleted = auth_manager.delete_user(username)
    assert deleted is True

    # 5. Sprawdź, czy użytkownik i jego dane zostały usunięte
    user_after_delete = User.query.filter_by(username=username).first()
    assert user_after_delete is None

    # Sprawdź, czy pliki zostały usunięte
    files_after_delete = File.query.filter_by(user_username=username).all()
    assert len(files_after_delete) == 0

    # Sprawdź, czy powiadomienia zostały usunięte
    notifications_after_delete = Notification.query.filter_by(user_id=username).all()
    assert len(notifications_after_delete) == 0

# Nowe testy jednostkowe dla services.py i user_auth.py

# Testy dla AccessKeyService
def test_generate_access_key_db_error(mocker):
    """
    Testuje obsługę błędu bazy danych podczas generowania klucza dostępu."""
    mock_db_session_add = mocker.patch('models.db.session.add', side_effect=Exception("Simulated DB error"))
    mock_db_session_rollback = mocker.patch('models.db.session.rollback')
    service = AccessKeyService()
    with pytest.raises(Exception, match="Simulated DB error"):
        service.generate_access_key("error_key")
    mock_db_session_rollback.assert_called_once()
    mocker.stopall()

def test_validate_access_key_deactivation_db_error(mocker, access_key_service):
    """
    Testuje obsługę błędu bazy danych podczas dezaktywacji wygasłego klucza dostępu.
    """
    # Stwórz klucz, który zaraz wygaśnie
    key_val = access_key_service.generate_access_key("expiring_key", expires_days=0)
    # Ustaw expires_at na przeszłość, aby był wygasły
    expired_time = datetime.datetime.now() - datetime.timedelta(days=1)
    key_obj = AccessKey.query.filter_by(key=key_val).first()
    assert key_obj is not None, "Access key should exist"
    key_obj.expires_at = expired_time
    db.session.commit()

    mock_db_session_commit = mocker.patch('models.db.session.commit', side_effect=Exception("Simulated DB error"))
    mock_db_session_rollback = mocker.patch('models.db.session.rollback')
    service = AccessKeyService()
    success, message = service.validate_access_key(key_val)
    assert not success
    assert "Klucz dostępu wygasł" in message
    mock_db_session_rollback.assert_called_once()
    mocker.stopall()

def test_use_access_key_db_error(mocker, access_key_service):
    """
    Testuje obsługę błędu bazy danych podczas używania klucza dostępu.
    """
    key_val = access_key_service.generate_access_key("use_error_key")
    mock_db_session_commit = mocker.patch('models.db.session.commit', side_effect=Exception("Simulated DB error"))
    mock_db_session_rollback = mocker.patch('models.db.session.rollback')
    service = AccessKeyService()
    with pytest.raises(Exception, match="Simulated DB error"):
        service.use_access_key(key_val)
    mock_db_session_rollback.assert_called_once()
    mocker.stopall()

def test_deactivate_access_key_db_error(mocker, access_key_service):
    """
    Testuje obsługę błędu bazy danych podczas dezaktywacji klucza dostępu.
    """
    key_val = access_key_service.generate_access_key("deactivate_error_key")
    mock_db_session_commit = mocker.patch('models.db.session.commit', side_effect=Exception("Simulated DB error"))
    mock_db_session_rollback = mocker.patch('models.db.session.rollback')
    service = AccessKeyService()
    success = service.deactivate_access_key(key_val)
    assert not success
    mock_db_session_rollback.assert_called_once()
    mocker.stopall()

def test_delete_access_key_db_error(mocker, access_key_service):
    """
    Testuje obsługę błędu bazy danych podczas usuwania klucza dostępu.
    """
    key_val = access_key_service.generate_access_key("delete_error_key")
    mock_db_session_commit = mocker.patch('models.db.session.commit', side_effect=Exception("Simulated DB error"))
    mock_db_session_rollback = mocker.patch('models.db.session.rollback')
    service = AccessKeyService()
    success = service.delete_access_key(key_val)
    assert not success
    mock_db_session_rollback.assert_called_once()
    mocker.stopall()

# Testy dla AnnouncementService
def test_create_announcement_invalid_expires_at(mocker):
    """
    Testuje obsługę nieprawidłowego formatu daty wygaśnięcia podczas tworzenia ogłoszenia.
    """
    service = AnnouncementService()
    created = service.create_announcement("Title", "Message", "info", "invalid-date-string")  # type: ignore[arg-type]
    assert created is False

def test_deactivate_announcement_nonexistent(mocker):
    """
    Testuje dezaktywację nieistniejącego ogłoszenia.
    """
    service = AnnouncementService()
    deactivated = service.deactivate_announcement(9999) # ID, które na pewno nie istnieje
    assert deactivated is False

def test_deactivate_announcement_db_error(mocker, db_session):
    """
    Testuje obsługę błędu bazy danych podczas dezaktywacji ogłoszenia.
    """
    service = AnnouncementService()
    announcement = Announcement(title="Test", message="Test", type="info", is_active=True)
    db_session.add(announcement)
    db.session.commit()
    announcement_id = announcement.id

    mock_db_session_commit = mocker.patch('models.db.session.commit', side_effect=Exception("Simulated DB error"))
    mock_db_session_rollback = mocker.patch('models.db.session.rollback')
    deactivated = service.deactivate_announcement(announcement_id)
    assert deactivated is False
    mock_db_session_rollback.assert_called_once()
    mocker.stopall()

# Testy dla StatisticsService
class TestStatisticsServiceExtended:
    @pytest.fixture(scope="class")
    def statistics_service(self):
        return StatisticsService()

    def test_add_or_update_file_db_error(self, db_session, mocker, statistics_service, registered_user):
        """
        Testuje obsługę błędu bazy danych podczas dodawania/aktualizowania pliku.
        """
        mock_db_session_commit = mocker.patch('models.db.session.commit', side_effect=Exception("Simulated DB error"))
        mock_db_session_rollback = mocker.patch('models.db.session.rollback')
        with pytest.raises(Exception, match="Simulated DB error"):
            statistics_service.add_or_update_file(registered_user["username"], "file.txt", "/path/to/file.txt", 100, "hash")
        mock_db_session_rollback.assert_called_once()
        mocker.stopall()

    def test_delete_file_nonexistent(self, statistics_service):
        """
        Testuje usuwanie nieistniejącego pliku.
        """
        # Metoda delete_file nie zwraca wartości, więc sprawdzamy, czy nie rzuca wyjątku
        try:
            statistics_service.delete_file("/path/to/nonexistent_file.txt")
        except Exception as e:
            pytest.fail(f"delete_file raised an unexpected exception: {e}")

    def test_delete_file_db_error(self, db_session, mocker, statistics_service, registered_user):
        """
        Testuje obsługę błędu bazy danych podczas usuwania pliku.
        """
        statistics_service.add_or_update_file(registered_user["username"], "file.txt", "/path/to/file.txt", 100, "hash")
        mock_db_session_commit = mocker.patch('models.db.session.commit', side_effect=Exception("Simulated DB error"))
        mock_db_session_rollback = mocker.patch('models.db.session.rollback')
        with pytest.raises(Exception, match="Simulated DB error"):
            statistics_service.delete_file("/path/to/file.txt")
        mock_db_session_rollback.assert_called_once()
        mocker.stopall()

# Testy dla NotificationService
def test_create_notification_db_error(mocker):
    """
    Testuje obsługę błędu bazy danych podczas tworzenia powiadomienia.
    """
    mock_db_session_add = mocker.patch('models.db.session.add', side_effect=Exception("Simulated DB error"))
    mock_db_session_rollback = mocker.patch('models.db.session.rollback')
    service = NotificationService()
    with pytest.raises(Exception, match="Simulated DB error"):
        service.create_notification("user1", "Test message")
    mock_db_session_rollback.assert_called_once()
    mocker.stopall()

def test_mark_notification_as_read_nonexistent(mocker):
    """
    Testuje oznaczenie nieistniejącego powiadomienia jako przeczytanego.
    """
    service = NotificationService()
    # Metoda nie zwraca wartości, więc sprawdzamy, czy nie rzuca wyjątku
    try:
        service.mark_notification_as_read(9999) # ID, które na pewno nie istnieje
    except Exception as e:
        pytest.fail(f"mark_notification_as_read raised an unexpected exception: {e}")

def test_mark_notification_as_read_db_error(mocker, db_session):
    """
    Testuje obsługę błędu bazy danych podczas oznaczania powiadomienia jako przeczytanego.
    """
    service = NotificationService()
    notification = Notification(user_id="testuser", message="Test message", is_read=False)
    db_session.add(notification)
    db.session.commit()
    notification_id = notification.id

    mock_db_session_commit = mocker.patch('models.db.session.commit', side_effect=Exception("Simulated DB error"))
    mock_db_session_rollback = mocker.patch('models.db.session.rollback')
    with pytest.raises(Exception, match="Simulated DB error"):
        service.mark_notification_as_read(notification_id)
    mock_db_session_rollback.assert_called_once()
    mocker.stopall()

# Testy dla UserAuthManager
def test_validate_referral_code_success(auth_manager, access_key_service):
    """
    Testuje pomyślną walidację istniejącego i aktywnego kodu referencyjnego.
    """
    username = "referrer_user"
    access_key = access_key_service.generate_access_key("referrer_key")
    auth_manager.register_user(username, "password123", access_key)
    
    assert auth_manager.validate_referral_code(username) is True

def test_validate_referral_code_nonexistent(auth_manager):
    """
    Testuje walidację nieistniejącego kodu referencyjnego.
    """
    assert auth_manager.validate_referral_code("nonexistent_referrer") is False

def test_validate_referral_code_inactive(auth_manager, access_key_service):
    """
    Testuje walidację nieaktywnego kodu referencyjnego.
    """
    username = "inactive_referrer"
    access_key = access_key_service.generate_access_key("inactive_key")
    auth_manager.register_user(username, "password123", access_key)
    
    user = User.query.filter_by(username=username).first()
    assert user is not None, "User should exist"
    user.is_active = False
    db.session.commit()

    assert auth_manager.validate_referral_code(username) is False

def test_register_user_integrity_error(auth_manager, access_key_service, mocker):
    """
    Testuje obsługę błędu IntegrityError podczas rejestracji użytkownika.
    """
    key = access_key_service.generate_access_key("integrity_error_key")
    mock_db_session_add = mocker.patch('models.db.session.add', side_effect=IntegrityError(None, None, Exception("Simulated")))  # type: ignore[arg-type]
    mock_db_session_rollback = mocker.patch('models.db.session.rollback')

    success, message, _ = auth_manager.register_user("integrity_user", "password123", key)
    assert not success
    assert "Ten klucz dostępu został już wykorzystany lub nazwa użytkownika jest zajęta." in message
    mock_db_session_rollback.assert_called_once()
    mocker.stopall()

def test_register_user_general_exception(auth_manager, access_key_service, mocker):
    """
    Testuje obsługę ogólnego wyjątku podczas rejestracji użytkownika.
    """
    key = access_key_service.generate_access_key("general_error_key")
    mock_db_session_add = mocker.patch('models.db.session.add', side_effect=Exception("General error"))
    mock_db_session_rollback = mocker.patch('models.db.session.rollback')

    success, message, _ = auth_manager.register_user("general_exception_user", "password123", key)
    assert not success
    assert "Wystąpił wewnętrzny błąd serwera podczas rejestracji." in message
    mock_db_session_rollback.assert_called_once()
    

def test_reset_user_password_short_password(auth_manager):
    """
    Testuje resetowanie hasła użytkownika ze zbyt krótkim nowym hasłem.
    """
    success, message = auth_manager.reset_user_password("any_user", "short")
    assert not success
    assert "Hasło musi mieć od 6 do 100 znaków" in message

def test_reset_user_password_nonexistent_user(auth_manager):
    """
    Testuje resetowanie hasła dla nieistniejącego użytkownika.
    """
    success, message = auth_manager.reset_user_password("nonexistent_user", "new_valid_password")
    assert not success
    assert "Użytkownik nie został znaleziony" in message

def test_reset_user_password_success(auth_manager, registered_user):
    """
    Testuje pomyślne zresetowanie hasła użytkownika.
    """
    username = registered_user["username"]
    new_password = "super_new_password"
    success, message = auth_manager.reset_user_password(username, new_password)
    assert success
    assert "Hasło zostało zresetowane" in message
    
    # Sprawdź, czy nowe hasło działa
    auth_success, _, _ = auth_manager.authenticate_user(username, new_password)
    assert auth_success