from playwright.sync_api import Page, expect
import secrets
import re
import os

# Ten plik zawiera kompleksowy test E2E dla głównego endpointu POST /.

def test_app_post_route_comprehensive_e2e(page: Page, base_url, access_key_service, db_session):
    """
    Testuje kompleksowo funkcjonalność głównego endpointu POST /,
    w tym różne scenariusze przesyłania formularzy i obrazów.
    """
    # --- Krok 1: Rejestracja i logowanie użytkownika ---
    new_username = f"post_test_user_{secrets.token_hex(4)}"
    new_password = "password123"
    access_key = access_key_service.generate_access_key(f"Key for {new_username}")
    db_session.commit()

    page.goto(f"{base_url}/register")
    page.fill('input[name="username"]', new_username)
    page.fill('input[name="password"]', new_password)
    page.fill('input[name="confirm_password"]', new_password)
    page.fill('textarea[name="accessKey"]', access_key)
    page.click('button:has-text("Zarejestruj się")')
    expect(page.locator("#fullScreenOverlay")).to_be_visible(timeout=10000)
    page.click("#overlayProceedBtn")

    page.fill('input[name="username"]', new_username)
    page.fill('input[name="password"]', new_password)
    page.click('button:has-text("Zaloguj się")')
    expect(page).to_have_url(re.compile(r".*/$"))

    # Oczekuj na modal i pomiń go
    tutorial_modal = page.locator("#tutorialModal")
    if tutorial_modal.is_visible():
        page.click("#tutorialBtnSkip")
        expect(tutorial_modal).to_be_hidden()

    # --- Krok 2: Przesłanie formularza z podstawowymi danymi i bez obrazu ---
    page.fill('input[name="imie"]', "TestImie")
    page.fill('input[name="nazwisko"]', "TestNazwisko")
    page.select_option('select[name="plec"]', 'M')
    page.click('button:has-text("Modyfikuj i Zapisz")')
    expect(page.locator("#notificationModal")).to_be_visible()
    expect(page.locator("#notificationMessage")).to_have_text("Dane i pliki zostały przetworzone pomyślnie.")
    page.click('#notificationModal button:has-text("OK")')

    # Weryfikacja, czy dane zostały zapisane (przez ponowne załadowanie strony)
    page.reload()
    expect(page.locator('input[name="imie"]')).to_have_value("TestImie")
    expect(page.locator('input[name="nazwisko"]')).to_have_value("TestNazwisko")

    # --- Krok 3: Przesłanie formularza z nowym obrazem ---
    # Użyjemy obrazu z tests/assets/image_v1.jpg
    image_path_v1 = os.path.join(os.getcwd(), "tests", "assets", "image_v1.jpg")
    page.set_input_files('input[name="image_upload"]', image_path_v1)
    page.click('button:has-text("Modyfikuj i Zapisz")')
    expect(page.locator("#notificationModal")).to_be_visible()
    expect(page.locator("#notificationMessage")).to_have_text("Dane i pliki zostały przetworzone pomyślnie.")
    page.click('#notificationModal button:has-text("OK")')

    # Weryfikacja, czy obrazek jest wyświetlany
    expect(page.locator('img#imagePreview')).to_be_visible()

    # --- Krok 4: Przesłanie formularza z identycznym obrazem ---
    # Zmieniamy tylko imię, aby wymusić ponowne przetworzenie formularza
    page.fill('input[name="imie"]', "TestImie2")
    page.set_input_files('input[name="image_upload"]', image_path_v1) # Ten sam obraz

    # Oczekujemy, że w logach serwera pojawi się informacja o niezapisywaniu identycznego obrazu
    # (tego nie możemy asertować bezpośrednio w E2E, ale testujemy ścieżkę kodu)
    page.click('button:has-text("Modyfikuj i Zapisz")')
    expect(page.locator("#notificationModal")).to_be_visible()
    expect(page.locator("#notificationMessage")).to_have_text("Dane i pliki zostały przetworzone pomyślnie.")
    page.click('#notificationModal button:has-text("OK")')

    # Weryfikacja, czy obrazek jest wyświetlany po ponownym załadowaniu strony
    page.reload()
    expect(page.locator('img#imagePreview')).to_be_visible()
    expect(page.locator('img#imagePreview')).to_have_attribute("src", re.compile(r".*/user_files/" + new_username + r"/zdjecie_.*\.jpg"))

    # --- Krok 5: Przesłanie formularza z nieprawidłowym typem obrazu ---
    invalid_image_path = os.path.join(os.getcwd(), "tests", "assets", "invalid_type.txt")
    page.set_input_files('input[name="image_upload"]', invalid_image_path)
    page.click('button:has-text("Modyfikuj i Zapisz")')
    expect(page.locator("#notificationModal")).to_be_visible()
    expect(page.locator("#notificationMessage")).to_have_text("Nieprawidłowy format pliku obrazu. Dozwolone: png, jpg, jpeg, gif.")
    page.click('#notificationModal button:has-text("OK")')

    

    # --- Krok 7: Wylogowanie ---
    page.click('a.logout-btn:has-text("Wyloguj")')
    expect(page).to_have_url(f"{base_url}/login")
