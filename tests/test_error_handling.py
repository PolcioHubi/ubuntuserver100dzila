import pytest
from unittest.mock import patch, MagicMock
from sqlalchemy.exc import IntegrityError
import logging

# Testy obsługi błędów dla UserAuthManager
def test_register_user_database_error(auth_manager, access_key_service, mocker):
    """
    Testuje, czy UserAuthManager poprawnie obsługuje błąd bazy danych (np. IntegrityError)
    podczas próby rejestracji użytkownika.
    """
    # Arrange: Przygotuj dane i zamockuj metodę, która rzuci błędem
    username = "db_error_user"
    password = "password123"
    access_key = access_key_service.generate_access_key("db_error_key")

    # Mock db.session.add to raise an IntegrityError
    mocker.patch('models.db.session.add', side_effect=IntegrityError("Simulated DB Integrity Error", [], Exception("orig")))  # type: ignore[arg-type]
    mock_rollback = mocker.patch('models.db.session.rollback')

    # Act: Spróbuj zarejestrować użytkownika
    success, message, token = auth_manager.register_user(username, password, access_key)

    # Assert: Sprawdź, czy operacja się nie powiodła i czy zwrócono odpowiedni komunikat
    assert success is False
    assert token is None
    assert "Ten klucz dostępu został już wykorzystany lub nazwa użytkownika jest zajęta." in message

    # Assert: Sprawdź, czy transakcja została wycofana
    mock_rollback.assert_called_once()

def test_register_user_general_exception(auth_manager, access_key_service, mocker):
    """
    Testuje, czy UserAuthManager poprawnie obsługuje ogólny wyjątek podczas
    rejestracji użytkownika.
    """
    # Arrange
    username = "general_exception_user"
    password = "password123"
    access_key = access_key_service.generate_access_key("general_exception_key")

    # Mock db.session.add to raise a generic Exception
    mocker.patch('models.db.session.add', side_effect=Exception("Simulated general error"))
    mock_rollback = mocker.patch('models.db.session.rollback')

    # Act
    success, message, token = auth_manager.register_user(username, password, access_key)

    # Assert
    assert success is False
    assert token is None
    assert "Wystąpił wewnętrzny błąd serwera podczas rejestracji." in message
    mock_rollback.assert_called_once()


# Testy obsługi błędów dla AnnouncementService
def test_create_announcement_database_error(announcement_service, mocker):
    """
    Testuje, czy AnnouncementService poprawnie obsługuje błąd bazy danych podczas
    tworzenia ogłoszenia.
    """
    # Arrange
    mocker.patch('models.db.session.add', side_effect=Exception("Simulated DB error"))
    mock_rollback = mocker.patch('models.db.session.rollback')

    # Act
    success = announcement_service.create_announcement("Test Title", "Test Message", "info", None)

    # Assert
    assert success is False
    mock_rollback.assert_called_once()

# Testy obsługi błędów dla AccessKeyService
def test_generate_access_key_database_error(access_key_service, mocker):
    """
    Testuje, czy AccessKeyService poprawnie obsługuje błąd bazy danych podczas
    generowania klucza dostępu.
    """
    # Arrange
    mocker.patch('models.db.session.add', side_effect=Exception("Simulated DB error"))
    mock_rollback = mocker.patch('models.db.session.rollback')

    # Act & Assert
    with pytest.raises(Exception, match="Simulated DB error"):
        access_key_service.generate_access_key("some_key")
    
    mock_rollback.assert_called_once()

def test_use_access_key_database_error(access_key_service, mocker):
    """
    Testuje, czy AccessKeyService poprawnie obsługuje błąd bazy danych podczas
    używania (dezaktywacji) klucza dostępu.
    """
    # Arrange
    key = access_key_service.generate_access_key("key_to_use")
    mocker.patch('models.db.session.commit', side_effect=Exception("Simulated DB error"))
    mock_rollback = mocker.patch('models.db.session.rollback')

    # Act & Assert
    with pytest.raises(Exception, match="Simulated DB error"):
        access_key_service.use_access_key(key)
    
    mock_rollback.assert_called_once()

def test_deactivate_access_key_database_error(access_key_service, mocker):
    """
    Testuje, czy AccessKeyService poprawnie obsługuje błąd bazy danych podczas
    dezaktywacji klucza dostępu.
    """
    # Arrange
    key = access_key_service.generate_access_key("key_to_deactivate")
    mocker.patch('models.db.session.commit', side_effect=Exception("Simulated DB error"))
    mock_rollback = mocker.patch('models.db.session.rollback')

    # Act
    success = access_key_service.deactivate_access_key(key)

    # Assert
    assert success is False
    mock_rollback.assert_called_once()

def test_delete_access_key_database_error(access_key_service, mocker):
    """
    Testuje, czy AccessKeyService poprawnie obsługuje błąd bazy danych podczas
    usuwania klucza dostępu.
    """
    # Arrange
    key = access_key_service.generate_access_key("key_to_delete")
    mocker.patch('models.db.session.commit', side_effect=Exception("Simulated DB error"))
    mock_rollback = mocker.patch('models.db.session.rollback')

    # Act
    success = access_key_service.delete_access_key(key)

    # Assert
    assert success is False
    mock_rollback.assert_called_once()

# Testy obsługi błędów dla NotificationService
def test_create_notification_database_error(notification_service, mocker):
    """
    Testuje, czy NotificationService poprawnie obsługuje błąd bazy danych podczas
    tworzenia powiadomienia.
    """
    # Arrange
    mocker.patch('models.db.session.add', side_effect=Exception("Simulated DB error"))
    mock_rollback = mocker.patch('models.db.session.rollback')

    # Act & Assert
    with pytest.raises(Exception, match="Simulated DB error"):
        notification_service.create_notification("testuser", "Test message")
    
    mock_rollback.assert_called_once()

def test_mark_notification_as_read_database_error(notification_service, mocker):
    """
    Testuje, czy NotificationService poprawnie obsługuje błąd bazy danych podczas
    oznaczania powiadomienia jako przeczytanego.
    """
    # Arrange
    # Mock get to return a mock object so the commit is attempted
    mock_notification = MagicMock()
    mocker.patch('models.db.session.get', return_value=mock_notification)
    mocker.patch('models.db.session.commit', side_effect=Exception("Simulated DB error"))
    mock_rollback = mocker.patch('models.db.session.rollback')

    # Act & Assert
    with pytest.raises(Exception, match="Simulated DB error"):
        notification_service.mark_notification_as_read(1)
    
    mock_rollback.assert_called_once()

# Testy obsługi błędów dla StatisticsService
def test_add_or_update_file_database_error(statistics_service, mocker):
    """
    Testuje, czy StatisticsService poprawnie obsługuje błąd bazy danych podczas
    dodawania lub aktualizacji pliku.
    """
    # Arrange
    mocker.patch('models.db.session.commit', side_effect=Exception("Simulated DB error"))
    mock_rollback = mocker.patch('models.db.session.rollback')

    # Act & Assert
    with pytest.raises(Exception, match="Simulated DB error"):
        statistics_service.add_or_update_file("testuser", "test.txt", "/path/to/test.txt", 100, "hash")
    
    mock_rollback.assert_called_once()

def test_delete_file_database_error(statistics_service, mocker, registered_user):
    """
    Testuje, czy StatisticsService poprawnie obsługuje błąd bazy danych podczas
    usuwania pliku.
    """
    # Arrange: First, add a file to have something to delete
    filepath = "/path/to/delete_test.txt"
    statistics_service.add_or_update_file(registered_user['username'], "delete_test.txt", filepath, 100, "hash_to_delete")
    
    # Now, mock the commit to fail during the deletion
    mocker.patch('models.db.session.commit', side_effect=Exception("Simulated DB error"))
    mock_rollback = mocker.patch('models.db.session.rollback')

    # Act & Assert
    with pytest.raises(Exception, match="Simulated DB error"):
        statistics_service.delete_file(filepath)
    
    mock_rollback.assert_called_once()

# Testy obsługi błędów dla app.py
def test_manage_log_directory_size_io_error(mocker, app):
    """
    Testuje, czy manage_log_directory_size poprawnie obsługuje błąd I/O podczas
    odczytu pliku .last_log_check.
    """
    with app.test_request_context():
        # Symulujemy, że próba otwarcia pliku do odczytu rzuca błędem IOError,
        # a kolejne wywołania (do zapisu) działają normalnie.
        mock_open = mocker.patch('builtins.open', side_effect=[
            IOError("Simulated I/O error"), 
            mocker.mock_open().return_value
        ])
        # Mockujemy os.walk, aby nie przechodził do sprawdzania rozmiaru plików
        mocker.patch('os.walk', return_value=iter([]))
        # Mockujemy logger, aby sprawdzić, czy ostrzeżenie zostało zapisane
        mock_logger_warning = mocker.patch('app.app.logger.warning')

        # Importujemy i wywołujemy funkcję w kontekście aplikacji
        from app import manage_log_directory_size
        manage_log_directory_size()

        # Sprawdzamy, czy logger został wywołany z oczekiwanym komunikatem
        mock_logger_warning.assert_called_once()
        assert "Could not read or parse .last_log_check file" in mock_logger_warning.call_args[0][0]

def test_calculate_file_hash_exception(mocker, caplog):
    """
    Testuje, czy calculate_file_hash poprawnie loguje błąd, gdy odczyt pliku się nie powiedzie.
    """
    # Ustawiamy poziom logowania dla caplog, aby przechwytywał błędy
    caplog.set_level(logging.ERROR)

    from app import calculate_file_hash

    # Mockujemy os.path.exists, aby funkcja próbowała otworzyć plik
    mocker.patch("os.path.exists", return_value=True)
    # Symulujemy, że open rzuca wyjątkiem
    mocker.patch("builtins.open", side_effect=Exception("Simulated file read error"))

    # Wywołujemy funkcję
    result = calculate_file_hash("any/fake/path.txt")

    # Sprawdzamy, czy funkcja zwróciła None i czy błąd został zalogowany
    assert result is None
    assert "Error calculating hash for any/fake/path.txt" in caplog.text
    assert "Simulated file read error" in caplog.text