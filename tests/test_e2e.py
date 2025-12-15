from playwright.sync_api import Page, expect
import re
import secrets
from models import db

# Fixture `page` is provided by pytest-playwright
# Fixture `base_url` is provided by our conftest.py
# Fixture `registered_user` is provided by our conftest.py
# Fixture `access_key_service` is provided by our conftest.py


def test_full_user_journey(page: Page, base_url, registered_user):
    """
    Testuje pełną ścieżkę użytkownika: logowanie, wypełnianie formularza i weryfikację.
    """
    # 1. Otwórz stronę główną (powinno przekierować do logowania)
    page.goto(base_url)
    expect(page).to_have_url(f"{base_url}/login")

    # 2. Zaloguj się
    page.fill('input[name="username"]', registered_user["username"])
    page.fill('input[name="password"]', registered_user["password"])
    page.click('button:has-text("Zaloguj")')

    # Oczekuj przekierowania na stronę główną po zalogowaniu
    expect(page).to_have_url(base_url + "/")
    expect(page.locator("h1")).to_have_text("Podmieniacz Danych HTML")

    # 3. Wypełnij formularz
    page.fill('input[name="imie"]', "Jan")
    page.fill('input[name="nazwisko"]', "Kowalski")
    page.fill('input[name="obywatelstwo"]', "Polskie")
    page.fill('input[name="data_urodzenia"]', "01.01.1990")
    page.fill('input[name="pesel"]', "90010112345")
    page.fill('input[name="seria_numer_mdowodu"]', "ABC123456")
    page.fill('input[name="termin_waznosci_mdowodu"]', "2030-01-01")
    page.fill('input[name="data_wydania_mdowodu"]', "2020-01-01")
    page.fill('input[name="imie_ojca_mdowod"]', "Marek")
    page.fill('input[name="imie_matki_mdowod"]', "Anna")
    page.fill('input[name="seria_numer_dowodu"]', "DEF789012")
    page.fill('input[name="termin_waznosci_dowodu"]', "2030-01-01")
    page.fill('input[name="data_wydania_dowodu"]', "2020-01-01")
    page.fill('input[name="nazwisko_rodowe"]', "Kowalska")
    page.select_option('select[name="plec"]', 'M')
    page.fill('input[name="nazwisko_rodowe_ojca"]', "Kowalski")
    page.fill('input[name="nazwisko_rodowe_matki"]', "Nowak")
    page.fill('input[name="miejsce_urodzenia"]', "Warszawa")
    expect(page.locator('textarea[name="adres_zameldowania"]')).to_be_visible()
    page.fill('textarea[name="adres_zameldowania"]', "ul. Testowa 1, 00-001 Warszawa")
    page.fill('input[name="data_zameldowania"]', "2020-01-01")

    # Prześlij formularz
    page.click('button:has-text("Modyfikuj i Zapisz")')

    # Oczekuj komunikatu sukcesu w modalu
    expect(page.locator("#notificationModal")).to_be_visible()
    expect(page.locator("#notificationTitle")).to_have_text("Sukces!")
    expect(page.locator("#notificationMessage")).to_have_text(
        "Dane i pliki zostały przetworzone pomyślnie."
    )

    # Zamknij modal
    page.click('#notificationModal button:has-text("OK")')
    expect(page.locator("#notificationModal")).to_be_hidden()


def test_user_registration_e2e(page: Page, base_url, access_key_service):
    """
    Testuje proces rejestracji użytkownika od początku do końca.
    """
    # Generate a unique access key for this test
    access_key = access_key_service.generate_access_key("e2e_registration_key")
    db.session.commit()

    # 1. Przejdź do strony rejestracji
    page.goto(f"{base_url}/register")
    page.wait_for_load_state(
        "networkidle"
    )  # Poczekaj na załadowanie wszystkich zasobów
    expect(page).to_have_url(f"{base_url}/register")

    # 2. Wypełnij formularz rejestracyjny
    new_username = "e2e_new_user"
    new_password = "e2e_password123"

    page.fill('input[name="username"]', new_username)
    page.fill('input[name="password"]', new_password)
    page.fill('input[name="confirm_password"]', new_password)
    page.fill('textarea[name="accessKey"]', access_key)
    # Kliknij przycisk i poczekaj na odpowiedź z serwera
    with page.expect_response(f"{base_url}/register") as response_info:
        page.click('button:has-text("Zarejestruj")')

    response = response_info.value
    assert response.status == 200
    response_data = response.json()
    assert response_data["success"] is True
    assert response_data["recovery_token"] is not None

    # 3. Oczekuj, że modal z tokenem odzyskiwania się pojawi
    page.wait_for_load_state("domcontentloaded")  # Poczekaj na załadowanie DOM
    page.evaluate(
        "console.log('JavaScript executed in browser!')"
    )  # Sprawdź, czy JS działa
    page.screenshot(
        path="screenshot_after_register_click.png"
    )  # Zrzut ekranu po kliknięciu

    page.screenshot(path="screenshot_user_registration_e2e_before_overlay.png")
    # Czekaj na pojawienie się modala przez sprawdzenie jego klasy za pomocą wyrażenia regularnego
    expect(page.locator("#fullScreenOverlay")).to_have_class(
        re.compile(r"visible"), timeout=10000
    )
    expect(page.locator("#fullScreenOverlay h2")).to_have_text(
        "Rejestracja zakończona pomyślnie!"
    )
    expect(page.locator("#overlayActualRecoveryToken")).to_be_visible()

    # 4. Kliknij przycisk "Przejdź do logowania" w modalu
    page.click("#overlayProceedBtn")

    # Oczekuj na modal i pomiń go
    tutorial_modal = page.locator("#tutorialModal")
    if tutorial_modal.is_visible():
        page.click("#tutorialBtnSkip")
        expect(tutorial_modal).to_be_hidden()

    # 5. Oczekuj przekierowania na stronę logowania
    expect(page).to_have_url(f"{base_url}/login")

    # 6. Zaloguj się
    page.fill('input[name="username"]', new_username)
    page.fill('input[name="password"]', new_password)
    page.click('button:has-text("Zaloguj")')

    # Oczekuj przekierowania na stronę główną po zalogowaniu
    expect(page).to_have_url(base_url + "/")
    expect(page.locator("h1")).to_have_text("Podmieniacz Danych HTML")


def test_admin_generates_access_key_e2e(page: Page, base_url):
    """
    Testuje proces generowania klucza dostępu przez administratora w panelu admina.
    """
    # 1. Przejdź do strony logowania admina
    page.goto(f"{base_url}/admin/login")
    expect(page).to_have_url(f"{base_url}/admin/login")

    # 2. Zaloguj się jako admin (użyjemy danych z conftest.py)
    admin_username = "admin_test"
    admin_password = "password_test"

    page.fill('input[name="username"]', admin_username)
    page.fill('input[name="password"]', admin_password)
    page.click('button:has-text("Zaloguj")')

    # Oczekuj przekierowania do panelu admina
    expect(page).to_have_url(f"{base_url}/admin/")
    expect(page.locator("h1")).to_have_text("🔧 Panel Administracyjny")

    # 3. Przejdź do zakładki "Klucze Dostępu"
    page.click('button:has-text("Klucze Dostępu")')
    expect(
        page.locator('h2:has-text("Generowanie Nowego Klucza Dostępu")')
    ).to_be_visible()

    # 4. Wypełnij formularz generowania klucza
    key_description = "E2E Generated Key"
    page.fill("#keyDescription", key_description)
    page.select_option("#keyExpires", "30")  # Select 30 days validity
    page.click('button:has-text("Generuj Klucz")')

    # 5. Oczekuj, że modal z nowym kluczem się pojawi
    expect(page.locator("#keyModal")).to_be_visible()
    expect(page.locator("#generatedKey")).to_have_text(
        re.compile(r"^[a-zA-Z0-9_-]{32,}$")
    )  # Check format of generated key

    # 6. Zamknij modal
    page.click('#keyModal button:has-text("Zamknij")')
    expect(page.locator("#keyModal")).to_be_hidden()

    # 7. Sprawdź, czy nowy klucz pojawił się w tabeli
    # Możemy poczekać na element, który powinien się pojawić po odświeżeniu
    expect(page.locator(f'td:has-text("{key_description}")')).to_be_visible()
    # Możemy też sprawdzić, czy wiersz z nowym kluczem zawiera jego opis
    expect(page.locator(f'tr:has-text("{key_description}")')).to_be_visible()


def test_password_recovery_e2e(page: Page, base_url, registered_user, auth_manager):
    """
    Testuje pełny proces odzyskiwania hasła z perspektywy użytkownika,
    uwzględniając asynchroniczną naturę frontendu.
    """
    username = registered_user["username"]
    old_password = registered_user["password"]
    new_password = "new_super_secret_password_123!"

    # Krok 1: Użyj auth_manager, aby uzyskać token odzyskiwania dla naszego użytkownika testowego.
    # To symuluje sytuację, w której użytkownik otrzymał token (np. po rejestracji).
    user = auth_manager.get_user_by_id(username)
    recovery_token = user.recovery_token
    assert recovery_token is not None

    # Krok 2: Przejdź na stronę odzyskiwania hasła.
    page.goto(f"{base_url}/recover_password_page")
    expect(page).to_have_url(f"{base_url}/recover_password_page")

    # Krok 3: Wypełnij formularz odzyskiwania hasła.
    page.fill('input[name="username"]', username)
    page.fill('input[name="recovery_token"]', recovery_token)
    page.fill('input[name="new_password"]', new_password)
    page.fill('input[name="confirm_password"]', new_password)

    # Krok 4: Kliknij przycisk i poczekaj na odpowiedź z API.
    page.click('button:has-text("Odzyskaj Hasło")')

    # Krok 5: Sprawdź, czy pojawił się komunikat o sukcesie.
    success_alert = page.locator("#successAlert")
    expect(success_alert).to_be_visible()
    expect(success_alert).to_contain_text("Hasło zostało pomyślnie zresetowane")

    # Krok 6: Poczekaj na automatyczne przekierowanie na stronę logowania.
    page.wait_for_url(f"{base_url}/login", timeout=5000)
    expect(page).to_have_url(f"{base_url}/login")

    # Krok 7: Weryfikacja - spróbuj zalogować się starym hasłem (oczekiwany błąd).
    page.fill('input[name="username"]', username)
    page.fill('input[name="password"]', old_password)
    page.click('button:has-text("Zaloguj")')

    # Poczekaj na pojawienie się komunikatu o błędzie
    error_message = page.locator(".alert-error")  # Poprawiony selektor
    expect(error_message).to_be_visible(timeout=5000)
    expect(error_message).to_contain_text(
        "Nieprawidłowa nazwa użytkownika lub hasło"
    )  # Poprawiony tekst błędu

    # Krok 8: Weryfikacja - spróbuj zalogować się nowym hasłem (oczekiwany sukces).
    page.fill('input[name="password"]', new_password)
    page.click('button:has-text("Zaloguj")')
    expect(page).to_have_url(
        re.compile(r".*/$")
    )  # Oczekujemy przekierowania na stronę główną
    expect(page.locator("h1")).to_have_text("Podmieniacz Danych HTML")


def test_admin_deactivates_user_e2e(page: Page, base_url, registered_user):
    """
    Testuje scenariusz, w którym administrator deaktywuje użytkownika,
    a następnie użytkownik próbuje się zalogować.
    """
    username_to_deactivate = registered_user["username"]
    password = registered_user["password"]

    # Krok 1: Zaloguj się jako administrator.
    page.goto(f"{base_url}/admin/login")
    page.fill('input[name="username"]', "admin_test")
    page.fill('input[name="password"]', "password_test")
    page.click('button:has-text("Zaloguj")')
    expect(page).to_have_url(f"{base_url}/admin/")

    # Krok 2: Przejdź do zakładki "Zarejestrowani Użytkownicy".
    page.click('button:has-text("Zarejestrowani Użytkownicy")')
    expect(page.locator("#registered-users")).to_be_visible()

    # Krok 3: Znajdź wiersz z użytkownikiem i kliknij przycisk "Dezaktywuj".
    user_row = page.locator(f'tr:has-text("{username_to_deactivate}")')
    deactivate_button = user_row.locator('button:has-text("Dezaktywuj")')
    expect(deactivate_button).to_be_visible()
    deactivate_button.click()

    # Krok 4: Sprawdź, czy status użytkownika w tabeli się zmienił.
    expect(user_row.locator('button:has-text("Aktywuj")')).to_be_visible()
    expect(user_row.locator('span:has-text("Nieaktywny")')).to_be_visible()

    # Krok 5: Wyloguj się z panelu admina.
    page.click('a.logout-btn:has-text("Wyloguj")')
    expect(page).to_have_url(f"{base_url}/admin/login")

    # Krok 6: Przejdź na stronę logowania użytkownika i spróbuj się zalogować.
    page.goto(f"{base_url}/login")
    page.fill('input[name="username"]', username_to_deactivate)
    page.fill('input[name="password"]', password)
    page.click('button:has-text("Zaloguj")')

    # Krok 7: Sprawdź, czy pojawił się komunikat o błędzie.
    error_message = page.locator(".alert-error")
    expect(error_message).to_be_visible()
    expect(error_message).to_contain_text("Konto użytkownika zostało dezaktywowane")


def test_user_data_lifecycle_e2e(page: Page, base_url, registered_user):
    """
    Testuje pełny cykl życia danych użytkownika: tworzenie, weryfikację trwałości i modyfikację.
    """
    username = registered_user["username"]
    password = registered_user["password"]

    # --- Faza 1: Stworzenie Danych ---
    page.goto(f"{base_url}/login")
    page.fill('input[name="username"]', username)
    page.fill('input[name="password"]', password)
    page.click('button:has-text("Zaloguj")')
    expect(page).to_have_url(re.compile(r".*/$"))

    # Wypełnij formularz i wyślij obrazek v1
    page.fill('input[name="imie"]', "JAN")
    page.fill('input[name="nazwisko"]', "PIERWOTNY")
    page.set_input_files('input[name="image_upload"]', "tests/assets/image_v1.jpg")
    page.click('button:has-text("Modyfikuj i Zapisz")')
    expect(page.locator("#notificationModal")).to_be_visible()
    page.click('#notificationModal button:has-text("OK")')
    page.click("a.logout-btn")
    expect(page).to_have_url(re.compile(r".*/login"))

    # --- Faza 2: Weryfikacja Trwałości ---
    page.fill('input[name="username"]', username)
    page.fill('input[name="password"]', password)
    page.click('button:has-text("Zaloguj")')
    expect(page).to_have_url(re.compile(r".*/$"))

    # Sprawdź, czy dane w formularzu są poprawne
    expect(page.locator('input[name="imie"]')).to_have_value("JAN")
    expect(page.locator('input[name="nazwisko"]')).to_have_value("PIERWOTNY")

    # Sprawdź, czy podgląd obrazka v1 jest widoczny
    image_preview = page.locator("#imagePreview")
    expect(image_preview).to_be_visible()
    expect(image_preview).to_have_attribute(
        "src", re.compile(r".*/user_files/testuser/zdjecie_.*.jpg")
    )

    # --- Faza 3: Modyfikacja Danych ---
    page.fill('input[name="imie"]', "ADAM")
    page.fill('input[name="nazwisko"]', "ZMODYFIKOWANY")
    page.set_input_files('input[name="image_upload"]', "tests/assets/image_v2.png")
    page.click('button:has-text("Modyfikuj i Zapisz")')
    expect(page.locator("#notificationModal")).to_be_visible()
    page.click('#notificationModal button:has-text("OK")')
    page.click("a.logout-btn")
    expect(page).to_have_url(re.compile(r".*/login"))

    # --- Faza 4: Ostateczna Weryfikacja ---
    page.fill('input[name="username"]', username)
    page.fill('input[name="password"]', password)
    page.click('button:has-text("Zaloguj")')
    expect(page).to_have_url(re.compile(r".*/$"))

    # Sprawdź, czy dane w formularzu są zaktualizowane
    expect(page.locator('input[name="imie"]')).to_have_value("ADAM")
    expect(page.locator('input[name="nazwisko"]')).to_have_value("ZMODYFIKOWANY")

    # Sprawdź, czy podgląd obrazka v2 jest widoczny
    image_preview_final = page.locator("#imagePreview")
    expect(image_preview_final).to_be_visible()
    # Nazwa pliku obrazka jest stała, więc sprawdzamy ten sam URL
    expect(image_preview_final).to_have_attribute(
        "src", re.compile(r".*/user_files/testuser/zdjecie_.*.jpg")
    )


def test_referral_system_e2e(page: Page, base_url, access_key_service):
    """
    Testuje pełny cykl systemu poleceń, od rejestracji dwóch użytkowników po weryfikację w panelu admina.
    """
    # Unikalne nazwy dla tego testu, aby uniknąć konfliktów
    referrer_username = f"referrer_{secrets.token_hex(4)}"
    referred_username = f"referred_{secrets.token_hex(4)}"
    password = "password123"

    # --- Faza 1: Rejestracja "Polecającego" (Użytkownik A) ---
    key1 = access_key_service.generate_access_key(f"key_for_{referrer_username}")
    db.session.commit()
    page.goto(f"{base_url}/register")
    page.fill('input[name="username"]', referrer_username)
    page.fill('input[name="password"]', password)
    page.fill('input[name="confirm_password"]', password)
    page.fill('textarea[name="accessKey"]', key1)
    with page.expect_response(f"{base_url}/register") as response_info:
        page.click('button:has-text("Zarejestruj")')

    response = response_info.value
    assert response.status == 200
    response_data = response.json()
    assert response_data["success"] is True
    assert response_data["recovery_token"] is not None
    # Oczekujemy na modal i przechodzimy do logowania
    page.click("#overlayProceedBtn")
    expect(page).to_have_url(f"{base_url}/login")

    # --- Faza 2: Rejestracja "Poleconego" (Użytkownik B) z kodem polecającym ---
    key2 = access_key_service.generate_access_key(f"key_for_{referred_username}")
    db.session.commit()
    page.goto(f"{base_url}/register")
    page.fill('input[name="username"]', referred_username)
    page.fill('input[name="password"]', password)
    page.fill('input[name="confirm_password"]', password)
    page.fill(
        'input[name="referralCode"]', referrer_username
    )  # Używamy nazwy użytkownika A jako kodu
    page.fill('textarea[name="accessKey"]', key2)
    page.click('button:has-text("Zarejestruj")')
    expect(page.locator("#fullScreenOverlay")).to_be_visible()
    page.click("#overlayProceedBtn")

    # --- Faza 3: Weryfikacja przez Administratora ---
    page.goto(f"{base_url}/admin/login")
    page.fill('input[name="username"]', "admin_test")
    page.fill('input[name="password"]', "password_test")
    page.click('button:has-text("Zaloguj")')
    expect(page).to_have_url(f"{base_url}/admin/")

    page.click('button:has-text("Zarejestrowani Użytkownicy")')
    expect(page.locator("#registered-users")).to_be_visible()

    # --- Faza 4: Ostateczna Asercja ---
    # Znajdź wiersz dla użytkownika polecającego w konkretnej tabeli
    referrer_row = page.locator("#registeredUsersBody").locator(
        f'tr:has-text("{referrer_username}")'
    )
    expect(referrer_row).to_be_visible()

    # Sprawdź, czy ma 1 Hubert Coin (kolumna 6)
    hubert_coins_cell = referrer_row.locator("td").nth(8).locator("span")
    expect(hubert_coins_cell).to_have_text("1")

    # Znajdź wiersz dla użytkownika poleconego w konkretnej tabeli
    referred_row = page.locator("#registeredUsersBody").locator(
        f'tr:has-text("{referred_username}")'
    )
    expect(referred_row).to_be_visible()

    # Sprawdź, czy ma 0 Hubert Coinów
    hubert_coins_cell_referred = referred_row.locator("td").nth(8).locator("span")
    expect(hubert_coins_cell_referred).to_have_text("0")
