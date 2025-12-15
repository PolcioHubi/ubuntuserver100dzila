from playwright.sync_api import Page, expect
import secrets
import re

# Ten plik zawiera dodatkowe, zaawansowane testy E2E

def test_data_persistence_and_generation_e2e(page: Page, base_url, access_key_service, db_session):
    """
    Testuje pełny cykl życia danych użytkownika:
    1. Rejestracja nowego użytkownika.
    2. Użycie funkcji generowania losowych danych.
    3. Wysłanie formularza.
    4. Wylogowanie i ponowne zalogowanie.
    5. Weryfikacja, czy dane zostały poprawnie załadowane z poprzedniej sesji.
    """
    # --- Krok 1: Rejestracja unikalnego, nowego użytkownika ---
    new_username = f"e2e_user_{secrets.token_hex(4)}"
    new_password = "password123"
    access_key = access_key_service.generate_access_key(f"Key for {new_username}")
    db_session.commit()

    page.goto(f"{base_url}/register")
    page.fill('input[name="username"]', new_username)
    page.fill('input[name="password"]', new_password)
    page.fill('input[name="confirm_password"]', new_password)
    page.fill('textarea[name="accessKey"]', access_key)
    page.click('button:has-text("Zarejestruj się")')

    # Oczekuj na modal i przejdź do logowania
    expect(page.locator("#fullScreenOverlay")).to_be_visible(timeout=10000)
    page.click("#overlayProceedBtn")
    expect(page).to_have_url(f"{base_url}/login")

    # --- Krok 2: Logowanie ---
    page.fill('input[name="username"]', new_username)
    page.fill('input[name="password"]', new_password)
    page.click('button:has-text("Zaloguj się")')
    expect(page).to_have_url(re.compile(r".*/$"))
    expect(page.locator("h1")).to_have_text("Podmieniacz Danych HTML")

    # Oczekuj na modal i pomiń go
    tutorial_modal = page.locator("#tutorialModal")
    if tutorial_modal.is_visible():
        page.click("#tutorialBtnSkip")
        expect(tutorial_modal).to_be_hidden()

    # Oczekuj na modal i pomiń go
    tutorial_modal = page.locator("#tutorialModal")
    if tutorial_modal.is_visible():
        page.click("#tutorialBtnSkip")
        expect(tutorial_modal).to_be_hidden()

    # --- Krok 3: Generowanie i zapisywanie danych ---
    # Wybierz płeć, aby przycisk generowania zadziałał
    page.select_option('select[name="plec"]', 'M')
    page.click('button:has-text("Generuj losowe dane")')

    # Poczekaj, aż pole 'imie' zostanie wypełnione przez API
    imie_locator = page.locator('input[name="imie"]')
    nazwisko_locator = page.locator('input[name="nazwisko"]')
    expect(imie_locator).not_to_be_empty()
    expect(nazwisko_locator).not_to_be_empty()

    # Zapisz wygenerowane wartości do późniejszej weryfikacji
    imie_value = imie_locator.input_value()
    nazwisko_value = nazwisko_locator.input_value()

    # Wyślij formularz z wygenerowanymi danymi
    page.click('button:has-text("Modyfikuj i Zapisz")')
    expect(page.locator("#notificationModal")).to_be_visible()
    page.click('#notificationModal button:has-text("OK")')

    # --- Krok 4: Wylogowanie ---
    page.click('a.logout-btn:has-text("Wyloguj")')
    expect(page).to_have_url(f"{base_url}/login")

    # --- Krok 5: Ponowne logowanie i weryfikacja trwałości danych ---
    page.fill('input[name="username"]', new_username)
    page.fill('input[name="password"]', new_password)
    page.click('button:has-text("Zaloguj się")')
    expect(page).to_have_url(re.compile(r".*/$"))

    # Sprawdź, czy formularz został automatycznie wypełniony danymi z poprzedniej sesji
    expect(page.locator('input[name="imie"]')).to_have_value(imie_value)
    expect(page.locator('input[name="nazwisko"]')).to_have_value(nazwisko_value)