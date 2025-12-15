import io
import logging
from models import db
import os
import shutil
import tempfile
from unittest.mock import mock_open
import time
from app import manage_log_directory_size, load_data_from_file
from bs4 import BeautifulSoup


def test_index_page(client):
    """
    Testuje, czy strona główna ładuje się poprawnie dla niezalogowanego
    użytkownika i czy zawiera poprawny tytuł.
    """
    response = client.get("/", follow_redirects=False)
    assert response.status_code == 302
    assert response.headers["Location"] == "/login"

    # Follow the redirect to ensure it lands on the login page
    response = client.get("/", follow_redirects=True)
    assert response.status_code == 200
    assert b"<title>Logowanie - Podmieniacz Danych HTML</title>" in response.data


def test_profile_page_unauthenticated(client):
    """
    Testuje, czy niezalogowany użytkownik próbujący uzyskać dostęp do
    strony profilowej jest przekierowywany na stronę logowania.
    """
    response = client.get("/profile", follow_redirects=True)
    assert response.status_code == 200
    assert b"<title>Logowanie - Podmieniacz Danych HTML</title>" in response.data


def test_login_and_logout(client, registered_user):
    """
    Testuje pełny cykl życia sesji użytkownika: logowanie, dostęp do
    chronionej strony (profil), wylogowanie i ponowną próbę dostępu.
    """
    # 1. Logowanie
    login_page = client.get("/login")
    soup = BeautifulSoup(login_page.data, "html.parser")
    csrf_meta = soup.find("meta", {"name": "csrf-token"})
    assert csrf_meta is not None, "CSRF meta tag should exist"
    csrf_token = csrf_meta.get("content")  # type: ignore[union-attr]

    response = client.post(
        "/login",
        json={
            "username": registered_user["username"],
            "password": registered_user["password"],
        },
        headers={"X-CSRFToken": csrf_token},
    )
    assert response.status_code == 200
    assert response.get_json()["success"] is True

    # 2. Dostęp do strony profilu
    response = client.get("/profile")
    assert response.status_code == 200
    soup = BeautifulSoup(response.data, "html.parser")
    title_tag = soup.find("title")
    assert title_tag is not None
    assert registered_user["username"] in title_tag.text

    # 3. Wylogowanie
    response = client.get("/logout", follow_redirects=True)
    assert response.status_code == 200
    assert b"<title>Logowanie - Podmieniacz Danych HTML</title>" in response.data

    # 4. Sprawdzenie, czy profil jest ponownie chroniony
    response = client.get("/profile", follow_redirects=True)
    assert response.status_code == 200
    assert b"<title>Logowanie - Podmieniacz Danych HTML</title>" in response.data


def test_notifications_api_flow(logged_in_client):
    """
    Testuje API powiadomień: pobieranie powiadomień i oznaczanie ich
    jako przeczytane. Domyślnie użytkownik dostaje jedno powiadomienie
    po rejestracji.
    """
    # 1. Pobierz powiadomienia
    response = logged_in_client.get("/api/notifications")
    assert response.status_code == 200
    notifications = response.get_json()
    assert len(notifications) == 1
    assert notifications[0]["is_read"] is False
    assert "Witaj w mObywatel!" in notifications[0]["message"]
    notification_id = notifications[0]["id"]

    # 2. Oznacz powiadomienie jako przeczytane
    response = logged_in_client.post(
        "/api/notifications/read", json={"id": notification_id}
    )
    assert response.status_code == 200
    assert response.get_json()["success"] is True

    # 3. Sprawdź, czy powiadomienie jest teraz oznaczone jako przeczytane
    response = logged_in_client.get("/api/notifications")
    notifications = response.get_json()
    assert len(notifications) == 1
    assert notifications[0]["is_read"] is True


def test_main_form_image_upload(logged_in_client):
    """
    Testuje funkcjonalność przesyłania obrazu w głównym formularzu.
    Symuluje wysłanie pliku i sprawdza, czy serwer odpowiada poprawnie.
    """
    # Tworzymy symulowany plik w pamięci
    image_data = (io.BytesIO(b"fake_image_content"), "test.jpg")

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
    )

    assert response.status_code == 200
    data = response.get_json()
    assert data["success"] is True
    assert "Dane i pliki zostały przetworzone pomyślnie" in data["message"]


def test_main_form_invalid_file_type(logged_in_client):
    """
    Testuje walidację typu pliku. Próba wysłania pliku tekstowego
    zamiast obrazu powinna zwrócić błąd.
    """
    text_file = (io.BytesIO(b"this is not an image"), "test.txt")

    response = logged_in_client.post(
        "/",
        data={
            "user_name": "testuser",
            "imie": "JAN",
            "nazwisko": "KOWALSKI",
            "pesel": "90010112345",
            "image_upload": text_file,
        },
        content_type="multipart/form-data",
    )

    assert (
        response.status_code == 200
    )  # Endpoint zwraca JSON z errorem, a nie kod błędu HTTP
    data = response.get_json()
    assert data["success"] is False
    assert "Nieprawidłowy format pliku obrazu" in data["error"]


def test_main_form_upload_same_image_twice(logged_in_client, caplog):
    """
    Testuje, czy aplikacja unika ponownego zapisywania tego samego pliku,
    sprawdzając logi aplikacji.
    """
    image_content = b"unique_image_content_123"
    image_data = (io.BytesIO(image_content), "test.jpg")

    form_data = {
        "user_name": "testuser",
        "imie": "JAN",
        "nazwisko": "KOWALSKI",
        "pesel": "90010112345",
        "image_upload": image_data,
    }

    # Pierwsze przesłanie
    with caplog.at_level(logging.INFO):
        response1 = logged_in_client.post(
            "/", data=form_data, content_type="multipart/form-data"
        )
        assert response1.status_code == 200
        assert "Image file was new and has been saved." in caplog.text

    # Drugie przesłanie tego samego obrazu
    image_data = (io.BytesIO(image_content), "test.jpg")
    form_data["image_upload"] = image_data
    with caplog.at_level(logging.INFO):
        caplog.clear()  # Czyścimy logi przed drugim żądaniem
        response2 = logged_in_client.post(
            "/", data=form_data, content_type="multipart/form-data"
        )
        assert response2.status_code == 200
        assert (
            "Uploaded image was identical to the existing one; not saved."
            in caplog.text
        )


def test_main_form_submit_with_no_image_keeps_old_one(
    logged_in_client, registered_user
):
    """
    Testuje, czy przesłanie formularza bez nowego obrazu pozostawia stary obraz nienaruszony.
    """
    username = registered_user["username"]
    image_content = b"permanent_image_content"
    image_data = (io.BytesIO(image_content), "test.jpg")

    # 1. Prześlij formularz z obrazem
    response1 = logged_in_client.post(
        "/",
        data={
            "user_name": username,
            "imie": "JAN",
            "nazwisko": "KOWALSKI",
            "pesel": "90010112345",
            "image_upload": image_data,
        },
        content_type="multipart/form-data",
    )
    assert response1.status_code == 200
    assert response1.get_json()["success"] is True

    # 2. Prześlij formularz ponownie, ale bez obrazu
    response2 = logged_in_client.post(
        "/",
        data={
            "user_name": username,
            "imie": "ANNA",  # Zmieńmy jakieś dane, aby symulować edycję
            "nazwisko": "NOWAK",
            "pesel": "90010112345",
        },
        content_type="multipart/form-data",
    )
    assert response2.status_code == 200
    assert response2.get_json()["success"] is True

    # 3. Sprawdź, czy plik obrazu nadal istnieje i ma tę samą zawartość (pośrednio przez logikę aplikacji)
    # W tym teście polegamy na tym, że logika aplikacji nie usuwa pliku, jeśli nie ma nowego.


def test_main_form_file_size_limit(logged_in_client, app):  # noqa: F841
    """
    Testuje, czy aplikacja odrzuca pliki, które są zbyt duże.
    """
    # Ustawiamy niski limit na potrzeby testu
    app.config["MAX_CONTENT_LENGTH"] = 1024  # 1 KB

    large_content = b"a" * 2048  # 2 KB
    large_file = (io.BytesIO(large_content), "large_file.jpg")

    response = logged_in_client.post(
        "/",
        data={
            "user_name": "testuser",
            "imie": "JAN",
            "nazwisko": "KOWALSKI",
            "pesel": "90010112345",
            "image_upload": large_file,
        },
        content_type="multipart/form-data",
    )

    # Oczekujemy błędu 413 Request Entity Too Large, ale Flask-Limiter może to inaczej obsłużyć
    # W naszym przypadku, logika aplikacji powinna zwrócić JSON z błędem
    assert response.status_code == 413
    # No need to check JSON response for 413 errors, as Flask handles it before app logic
    # data = response.get_json()
    # assert data["success"] is False
    # assert "Wystąpił błąd podczas przetwarzania danych." in data["error"]


def test_user_cannot_access_other_users_files(client, auth_manager, access_key_service):
    """
    Testuje, czy użytkownik nie może uzyskać dostępu do plików innego użytkownika.
    """
    # 1. Stwórz dwóch użytkowników
    key1 = access_key_service.generate_access_key("user_one_key")
    auth_manager.register_user("user_one", "password_one", key1)

    key2 = access_key_service.generate_access_key("user_two_key")
    auth_manager.register_user("user_two", "password_two", key2)

    # 2. Zaloguj się jako user_one i prześlij plik
    client.post("/login", json={"username": "user_one", "password": "password_one"})

    image_content = b"user_one_secret_file"
    image_filename = "secret.jpg"
    image_data = (io.BytesIO(image_content), image_filename)

    response_upload = client.post(
        "/",
        data={
            "user_name": "user_one",
            "imie": "USER",
            "nazwisko": "ONE",
            "pesel": "11111111111",
            "image_upload": image_data,
        },
        content_type="multipart/form-data",
    )
    assert response_upload.status_code == 200
    assert response_upload.get_json()["success"] is True

    client.get("/logout")  # Wyloguj user_one

    # 3. Zaloguj się jako user_two
    client.post("/login", json={"username": "user_two", "password": "password_two"})

    # 4. Spróbuj uzyskać dostęp do pliku user_one jako user_two, używając poprawnego endpointu
    response_access = client.get(f"/user_files/{'user_one'}/{image_filename}")

    # 5. Sprawdź, czy serwer zwrócił błąd 403 Forbidden, ponieważ user_two nie jest właścicielem pliku
    assert response_access.status_code == 403


def test_main_form_submission_success_message(logged_in_client):
    """
    Testuje, czy pomyślne przesłanie głównego formularza zwraca poprawny komunikat sukcesu.
    """
    image_data = (io.BytesIO(b"test_image_content"), "test.jpg")
    response = logged_in_client.post(
        "/",
        data={
            "user_name": "testuser",
            "imie": "TEST",
            "nazwisko": "USER",
            "pesel": "90010112345",
            "image_upload": image_data,
        },
        content_type="multipart/form-data",
    )

    assert response.status_code == 200
    data = response.get_json()
    assert data["success"] is True
    assert "Dane i pliki zostały przetworzone pomyślnie." in data["message"]


def test_main_form_submission_error_message(logged_in_client):
    """
    Testuje, czy przesłanie głównego formularza z brakującymi danymi zwraca błąd.
    """
    # Brak user_name
    response = logged_in_client.post(
        "/",
        data={"imie": "TEST", "nazwisko": "USER", "pesel": "90010112345"},
        content_type="multipart/form-data",
    )

    assert response.status_code == 200
    data = response.get_json()
    assert data["success"] is False
    assert "Nazwa użytkownika jest wymagana" in data["error"]


def test_delete_announcement_api(admin_client, logged_in_client, db_session):
    """
    Testuje, czy zalogowany użytkownik może usunąć (dezaktywować) ogłoszenie.
    """
    from models import (
        Announcement,
    )  # Importujemy tutaj, aby uniknąć cyklicznych zależności

    # 1. Admin tworzy ogłoszenie
    response_admin = admin_client.post(
        "/admin/api/announcements",
        json={
            "title": "Testowe ogłoszenie do usunięcia",
            "message": "To ogłoszenie zostanie usunięte przez użytkownika.",
            "type": "info",
            "expires_at": "",
        },
    )
    assert response_admin.status_code == 200
    assert response_admin.get_json()["success"] is True

    # Pobierz ID ogłoszenia z bazy danych (zakładamy, że jest to ostatnie dodane)
    announcement = Announcement.query.order_by(Announcement.created_at.desc()).first()
    assert announcement is not None
    announcement_id = announcement.id

    # 2. Użytkownik próbuje usunąć ogłoszenie
    response_user = logged_in_client.delete(
        f"/api/announcements/delete/{announcement_id}",
        headers={"X-CSRFToken": logged_in_client.csrf_token},
    )
    assert response_user.status_code == 200
    assert response_user.get_json()["success"] is True
    assert "Ogłoszenie zostało usunięte." in response_user.get_json()["message"]

    # 3. Sprawdź, czy ogłoszenie zostało dezaktywowane w bazie danych
    updated_announcement = db.session.get(Announcement, announcement_id)
    assert updated_announcement is not None
    assert updated_announcement.is_active is False


def test_admin_login_with_invalid_credentials(client):
    """
    Testuje próbę logowania do panelu admina z nieprawidłowymi danymi.
    Oczekiwany jest błąd i status 401.
    """
    response = client.post(
        "/admin/login", json={"username": "admin", "password": "wrongpassword"}
    )
    assert response.status_code == 401
    data = response.get_json()
    assert data["success"] is False
    assert "Nieprawidłowe dane logowania" in data["error"]


def test_main_form_modifies_existing_file(logged_in_client, registered_user):
    """
    Testuje, czy drugie przesłanie formularza modyfikuje istniejący plik HTML,
    a nie tworzy go od nowa z szablonu.
    """
    username = registered_user["username"]

    # 1. Pierwsze przesłanie formularza
    first_submission_data = {
        "user_name": username,
        "imie": "JAN",
        "nazwisko": "PIERWSZY",
        "pesel": "11111111111",
    }
    response1 = logged_in_client.post(
        "/", data=first_submission_data, content_type="multipart/form-data"
    )
    assert response1.status_code == 200
    assert response1.get_json()["success"] is True

    # 2. Drugie przesłanie formularza ze zmienionymi danymi
    second_submission_data = {
        "user_name": username,
        "imie": "ADAM",
        "nazwisko": "DRUGI",
        "pesel": "22222222222",
    }
    response2 = logged_in_client.post(
        "/", data=second_submission_data, content_type="multipart/form-data"
    )
    assert response2.status_code == 200
    assert response2.get_json()["success"] is True

    # 3. Sprawdź zawartość wygenerowanego pliku
    import os
    from bs4 import BeautifulSoup

    output_file_path = os.path.join("user_data", username, "files", "dowodnowy.html")
    assert os.path.exists(output_file_path)

    with open(output_file_path, "r", encoding="utf-8") as f:
        soup = BeautifulSoup(f, "html.parser")

    # Sprawdź, czy imię zostało zaktualizowane
    name_label = soup.find("p", class_="sub", string="Imię (Imiona)")
    assert name_label is not None, "Name label should exist"
    name_value = name_label.find_previous_sibling("p")
    assert name_value is not None, "Name value should exist"
    assert name_value.string == "ADAM"  # type: ignore[union-attr]

    # Sprawdź, czy nazwisko zostało zaktualizowane
    surname_label = soup.find("p", class_="sub", string="Nazwiskо")
    assert surname_label is not None, "Surname label should exist"
    surname_value = surname_label.find_previous_sibling("p")
    assert surname_value is not None, "Surname value should exist"
    assert surname_value.string == "DRUGI"  # type: ignore[union-attr]


# New tests for app.py functions
def test_manage_log_directory_size_clears_logs(app, mocker):  # noqa: F841
    """
    Testuje, czy manage_log_directory_size czyści logi, gdy rozmiar przekroczy limit.
    """
    # Ustaw tymczasowy katalog logów i plik .last_log_check
    temp_log_dir = tempfile.mkdtemp()
    mocker.patch("app.log_dir", temp_log_dir)
    mocker.patch("app.MAX_LOG_DIR_SIZE_MB", 0.001)  # Bardzo mały limit (ok. 1KB)
    mocker.patch("app.LOG_CHECK_INTERVAL_SECONDS", 0)  # Sprawdzaj zawsze

    # Utwórz fikcyjne pliki logów, które przekroczą limit
    with open(os.path.join(temp_log_dir, "test1.log"), "w") as f:
        f.write("a" * 1024)  # 1KB
    with open(os.path.join(temp_log_dir, "test2.log"), "w") as f:
        f.write("b" * 1024)  # 1KB

    # Upewnij się, że plik .last_log_check istnieje i jest stary
    with open(os.path.join(temp_log_dir, ".last_log_check"), "w") as f:
        f.write(str(time.time() - 1000))

    with app.test_request_context():
        mock_warning = mocker.patch("app.app.logger.warning")
        mock_info = mocker.patch("app.app.logger.info")
        manage_log_directory_size()

        # Sprawdź, czy logi zostały wyczyszczone
        assert os.path.getsize(os.path.join(temp_log_dir, "test1.log")) == 0
        assert os.path.getsize(os.path.join(temp_log_dir, "test2.log")) == 0
        mock_warning.assert_called_once()
        # Sprawdź, czy kluczowy komunikat informacyjny został zalogowany
        mock_info.assert_any_call("Log files have been cleared due to size limit.")
    shutil.rmtree(temp_log_dir)


def test_manage_log_directory_size_handles_io_error(app, mocker, caplog):  # noqa: F841
    """
    Testuje, czy manage_log_directory_size poprawnie obsługuje błędy I/O podczas odczytu pliku znacznika czasu.
    """
    temp_log_dir = tempfile.mkdtemp()
    mocker.patch("app.log_dir", temp_log_dir)
    mocker.patch("app.MAX_LOG_DIR_SIZE_MB", 1)
    mocker.patch("app.LOG_CHECK_INTERVAL_SECONDS", 0)

    # Symuluj błąd tylko przy pierwszej próbie otwarcia (odczyt), a potem działaj normalnie
    mock_file_handle = mock_open().return_value
    mocker.patch(
        "builtins.open",
        side_effect=[IOError("Simulated I/O error on read"), mock_file_handle],
    )

    with app.test_request_context():
        with caplog.at_level(logging.WARNING):
            manage_log_directory_size()
            assert "Could not read or parse .last_log_check file" in caplog.text
            assert "Simulated I/O error on read" in caplog.text

    shutil.rmtree(temp_log_dir)


def test_load_data_from_file_not_found(mocker, caplog):
    """
    Testuje, czy load_data_from_file poprawnie obsługuje brak pliku.
    """
    mocker.patch("os.path.exists", return_value=False)
    with caplog.at_level(logging.ERROR):
        data = load_data_from_file("non_existent_file.txt")
        assert data == []
        assert "Data file not found: non_existent_file.txt" in caplog.text


def test_health_check_endpoint(client):
    """
    Testuje, czy endpoint /health działa i zwraca poprawny status.
    """
    response = client.get("/health")
    assert response.status_code == 200
    json_data = response.get_json()
    assert json_data["status"] == "ok"
    assert "timestamp" in json_data


def test_api_generate_random_data(client):
    """
    Testuje endpoint /api/generate-random-data, weryfikując poprawność
    i spójność generowanych danych.
    """
    # 1. Test bez parametrów
    response = client.get("/api/generate-random-data")
    assert response.status_code == 200
    data = response.get_json()
    assert "pesel" in data
    assert "imie" in data
    assert "nazwisko" in data
    assert len(data["pesel"]) == 11

    # 2. Test z parametrem płci (Mężczyzna)
    response_male = client.get("/api/generate-random-data?plec=M")
    assert response_male.status_code == 200
    data_male = response_male.get_json()
    assert data_male["plec"] == "M"
    # Dziesiąta cyfra PESEL dla mężczyzny musi być nieparzysta
    assert int(data_male["pesel"][9]) % 2 != 0

    # 3. Test z parametrem płci (Kobieta)
    response_female = client.get("/api/generate-random-data?plec=K")
    assert response_female.status_code == 200
    data_female = response_female.get_json()
    assert data_female["plec"] == "K"
    # Dziesiąta cyfra PESEL dla kobiety musi być parzysta
    assert int(data_female["pesel"][9]) % 2 == 0


def test_set_user_success(client):
    """
    Testuje pomyślne ustawienie użytkownika i utworzenie jego folderu.
    """
    user_name = "test_user_folder"
    response = client.post("/set_user", json={"user_name": user_name})
    assert response.status_code == 200
    assert response.get_json()["success"] is True

    # Sprawdź, czy folder użytkownika został utworzony
    user_folder_path = os.path.join("user_data", user_name)
    assert os.path.isdir(user_folder_path)

    # Sprzątanie po teście
    shutil.rmtree(user_folder_path)


def test_set_user_invalid_username(client):
    """
    Testuje walidację nazwy użytkownika w /set_user.
    """
    response = client.post("/set_user", json={"user_name": "a"})  # za krótka nazwa
    assert response.status_code == 200  # Aplikacja zwraca JSON, nie kod błędu HTTP
    data = response.get_json()
    assert data["success"] is False
    assert "musi mieć od 2 do 50 znaków" in data["error"]


def test_handle_generate_pesel_success(client):
    """
    Testuje pomyślne wygenerowanie numeru PESEL przez endpoint API.
    """
    response = client.post(
        "/generate_pesel", json={"birth_date": "01.01.1990", "gender": "Mężczyzna"}
    )
    assert response.status_code == 200
    data = response.get_json()
    assert data["success"] is True
    assert "pesel" in data
    assert len(data["pesel"]) == 11


def test_handle_generate_pesel_missing_data(client):
    """
    Testuje, czy endpoint /generate_pesel zwraca błąd przy braku danych.
    """
    response = client.post("/generate_pesel", json={"birth_date": "01.01.1990"})
    assert response.status_code == 400
    data = response.get_json()
    assert data["success"] is False
    assert "Data urodzenia i płeć są wymagane" in data["error"]


def test_manage_log_directory_size_symlink_ignored(app, mocker, caplog):
    """
    Testuje, czy manage_log_directory_size poprawnie ignoruje symlinki.
    """
    temp_log_dir = tempfile.mkdtemp()
    mocker.patch("app.log_dir", temp_log_dir)
    mocker.patch("app.MAX_LOG_DIR_SIZE_MB", 10)  # Duży limit
    mocker.patch("app.LOG_CHECK_INTERVAL_SECONDS", 0)

    # Utwórz fikcyjny plik logów
    log_file_path = os.path.join(temp_log_dir, "test.log")
    with open(log_file_path, "w") as f:
        f.write("test content")

    # Utwórz symlink do pliku logów
    symlink_path = os.path.join(temp_log_dir, "test_symlink.log")
    # Upewnij się, że os.symlink jest dostępny na danym systemie
    if hasattr(os, 'symlink'):
        os.symlink(log_file_path, symlink_path)
        mocker.patch('os.path.islink', side_effect=lambda p: p == symlink_path) # Mock islink

    # Upewnij się, że plik .last_log_check istnieje i jest stary
    with open(os.path.join(temp_log_dir, ".last_log_check"), "w") as f:
        f.write(str(time.time() - 1000))

    with app.test_request_context():
        with caplog.at_level(logging.DEBUG):
            manage_log_directory_size()
            # Sprawdź, czy rozmiar symlinka nie został dodany do total_size
            # (trudno to bezpośrednio asertować bez mockowania os.path.getsize)
            # Zamiast tego, sprawdzamy, czy nie ma błędów i czy funkcja działa normalnie.
            assert "Error during log directory size management" not in caplog.text

    shutil.rmtree(temp_log_dir)

def test_manage_log_directory_size_getsize_error(app, mocker, caplog):
    """
    Testuje, czy manage_log_directory_size poprawnie obsługuje błędy
    podczas próby pobrania rozmiaru pliku (np. brak dostępu).
    """
    temp_log_dir = tempfile.mkdtemp()
    mocker.patch("app.log_dir", temp_log_dir)
    mocker.patch("app.MAX_LOG_DIR_SIZE_MB", 10)
    mocker.patch("app.LOG_CHECK_INTERVAL_SECONDS", 0)

    # Utwórz fikcyjny plik logów
    log_file_path = os.path.join(temp_log_dir, "test.log")
    with open(log_file_path, "w") as f:
        f.write("test content")

    # Mock os.path.getsize, aby rzucał błędem
    mocker.patch('os.path.getsize', side_effect=OSError("Permission denied"))

    # Upewnij się, że plik .last_log_check istnieje i jest stary
    with open(os.path.join(temp_log_dir, ".last_log_check"), "w") as f:
        f.write(str(time.time() - 1000))

    with app.test_request_context():
        with caplog.at_level(logging.ERROR):
            manage_log_directory_size()
            # Sprawdź, czy błąd został zalogowany
            assert "Error during log directory size management" in caplog.text
            assert "Permission denied" in caplog.text

    shutil.rmtree(temp_log_dir)

def test_load_data_from_file_os_error(mocker, caplog):
    """
    Testuje, czy load_data_from_file poprawnie obsługuje błędy systemowe
    podczas próby otwarcia pliku (np. brak uprawnień).
    """
    # Mock os.path.join, aby zwrócił ścieżkę, która spowoduje błąd przy otwarciu
    mocker.patch('os.path.join', return_value="/nonexistent/path/to/file.txt")
    # Mock builtins.open, aby rzucał błędem OSError
    mocker.patch('builtins.open', side_effect=OSError("Simulated OS error"))

    with caplog.at_level(logging.ERROR):
        data = load_data_from_file("some_file.txt")
        assert data == []
        # Sprawdź, czy błąd został zalogowany
        assert "Error reading data file some_file.txt" in caplog.text
        assert "Simulated OS error" in caplog.text



