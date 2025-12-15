from playwright.sync_api import Page, expect
import secrets

# Ten plik zawiera jeden, kompleksowy test E2E dla panelu admina.
# Każdy krok jest starannie zaplanowany i używa precyzyjnych selektorów.


def test_admin_full_e2e_journey(
    page: Page, base_url, registered_user, access_key_service, auth_manager
):
    """
    Testuje pełną ścieżkę administratora, weryfikując każdą zakładkę i kluczowe funkcje.
    """
    username_to_manage = registered_user["username"]

    # Stwórz drugiego użytkownika, który przetrwa test do końcowej weryfikacji
    viewer_username = f"viewer_{secrets.token_hex(4)}"
    viewer_password = "password123"
    key = access_key_service.generate_access_key(f"key_for_{viewer_username}")
    auth_manager.register_user(viewer_username, viewer_password, key)

    # --- Krok 1: Logowanie i Weryfikacja Danych Początkowych ---
    page.goto(f"{base_url}/admin/login")
    page.fill('input[name="username"]', "admin_test")
    page.fill('input[name="password"]', "password_test")
    page.click('button:has-text("Zaloguj")')
    expect(page).to_have_url(f"{base_url}/admin/")
    page.click('button:has-text("Przegląd")')
    expect(page.locator("h2:has-text('nowe ogłoszenie')")).to_be_visible()

    # --- Krok 2: Zarządzanie Kluczami Dostępu (Pełen Cykl) ---
    page.click('button:has-text("Klucze Dostępu")')
    unique_description = f"Klucz E2E {secrets.token_hex(4)}"

    # Stworzenie
    page.fill("#keyDescription", unique_description)
    with page.expect_response("**/api/generate-access-key") as response_info:
        page.click('button:has-text("Generuj Klucz")')
    
    assert response_info.value.ok

    expect(page.locator("#keyModal")).to_be_visible()
    page.click('#keyModal button:has-text("Zamknij")')

    key_row = page.locator(f'#accessKeysBody tr:has-text("{unique_description}")')
    expect(key_row).to_be_visible()

    # Dezaktywacja
    page.once("dialog", lambda dialog: dialog.accept())
    key_row.locator('button:has-text("Dezaktywuj")').click()
    expect(key_row.locator('span:has-text("Nieaktywny")')).to_be_visible()

    # Usunięcie
    page.once("dialog", lambda dialog: dialog.accept())
    key_row.locator('button:has-text("Usuń")').click()
    expect(key_row).to_be_hidden()

    # --- Krok 3: Zarządzanie Użytkownikami (Pełen Cykl) ---
    page.click('button:has-text("Zarejestrowani Użytkownicy")')
    user_row = page.locator(f'#registeredUsersBody tr:has-text("{username_to_manage}")')
    expect(user_row).to_be_visible()

    # Modyfikacja Hubert Coinów
    coins_cell = user_row.locator("td").nth(8).locator("span")
    expect(coins_cell).to_have_text("0")
    user_row.locator('button:has-text("+")').click()
    expect(page.locator(".alert-success")).to_contain_text(
        "Zaktualizowano saldo Hubert Coins"
    )
    expect(coins_cell).to_have_text("1")

    # Reset hasła
    new_password = f"nowe_haslo_{secrets.token_hex(4)}"
    page.once("dialog", lambda dialog: dialog.accept(new_password))
    user_row.locator('button:has-text("Resetuj Hasło")').click()
    # Poczekaj na odświeżenie danych w tabeli
    expect(user_row.locator('button:has-text("Dezaktywuj")')).to_be_visible()

    # Usunięcie użytkownika
    page.once("dialog", lambda dialog: dialog.accept())
    # Uściślenie selektora, aby kliknąć konkretny przycisk (czerwony)
    user_row.locator('button.btn-danger:has-text("Usuń z Plikami")').click()
    expect(user_row).to_be_hidden()

    # --- Krok 4: Weryfikacja Logów Systemowych ---
    page.click('button:has-text("Logi Systemowe")')
    page.click('button:has-text("Pokaż app.log")')
    expect(page.locator("#logViewer")).not_to_be_empty()
    page.click('button:has-text("Pokaż user_activity.log")')
    expect(page.locator("#logViewer")).not_to_be_empty()

    # --- Krok 5: Wysłanie Ogłoszenia ---
    page.click('button:has-text("Przegląd")')
    announcement_title = f"Ważne Ogłoszenie E2E {secrets.token_hex(4)}"
    page.fill("#announcementTitle", announcement_title)
    page.fill(
        "#announcementMessage",
        "To jest testowe ogłoszenie dla wszystkich użytkowników.",
    )
    page.click('button:has-text("Wyślij Ogłoszenie")')
    expect(page.locator(".alert-success")).to_contain_text(
        "Ogłoszenie zostało wysłane!"
    )

    # --- Krok 6: Weryfikacja Ogłoszenia (jako NOWY Użytkownik w nowym kontekście)
    # Tworzymy całkowicie nowego użytkownika, aby mieć 100% pewności co do jego stanu.
    final_viewer_user = f"final_viewer_{secrets.token_hex(4)}"
    final_viewer_pass = "password123"
    final_key = access_key_service.generate_access_key(f"key_for_{final_viewer_user}")
    auth_manager.register_user(final_viewer_user, final_viewer_pass, final_key)

    browser = page.context.browser
    assert browser is not None, "Browser should be available"
    context = browser.new_context(base_url=base_url)
    user_page = context.new_page()

    user_page.goto("/login")
    user_page.fill('input[name="username"]', final_viewer_user)
    user_page.fill('input[name="password"]', final_viewer_pass)

    with user_page.expect_navigation(wait_until="networkidle"):
        user_page.click('button:has-text("Zaloguj")')

    expect(user_page.locator("h1:has-text('Podmieniacz Danych HTML')")).to_be_visible(
        timeout=10000
    )

    announcement_container = user_page.locator(".announcements-container")
    expect(announcement_container).to_be_visible(timeout=10000)
    announcement = announcement_container.locator(f':text("{announcement_title}")')
    expect(announcement).to_be_visible()

    context.close()
