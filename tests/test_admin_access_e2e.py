from playwright.sync_api import Page, expect
import secrets
import re

# Ten plik testuje kontrolę dostępu do panelu administracyjnego dla zwykłych użytkowników.

def test_regular_user_admin_access_e2e(page: Page, base_url, access_key_service, db_session):
    """
    Testuje, czy zwykły, zalogowany użytkownik nie ma dostępu do panelu administracyjnego
    ani do jego endpointów API.
    """
    # --- Krok 1: Rejestracja i logowanie zwykłego użytkownika ---
    new_username = f"regular_user_{secrets.token_hex(4)}"
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

    # Oczekuj na modal i pomiń go
    tutorial_modal = page.locator("#tutorialModal")
    if tutorial_modal.is_visible():
        page.click("#tutorialBtnSkip")
        expect(tutorial_modal).to_be_hidden()

    # --- Krok 2: Próba nawigacji do strony /admin/ ---
    page.goto(f"{base_url}/admin/")
    # Oczekujemy przekierowania na stronę logowania admina
    expect(page).to_have_url(f"{base_url}/admin/login")

    # --- Krok 3: Próba dostępu do endpointu API admina (bez CSRF tokena) ---
    response = page.request.get(f"{base_url}/admin/api/users")
    assert response.status == 401
    response_json = response.json()
    assert response_json["error"] == "Authentication required"

    # --- Krok 4: Próba dostępu do endpointu API admina (z CSRF tokenem, ale jako zwykły użytkownik) ---
    page.goto(f"{base_url}/")
    csrf_token = page.locator('meta[name="csrf-token"]').get_attribute("content")
    assert csrf_token is not None and csrf_token != ""

    response_with_csrf = page.request.get(f"{base_url}/admin/api/users", headers={'X-CSRFToken': csrf_token})
    assert response_with_csrf.status == 401
    response_with_csrf_json = response_with_csrf.json()
    assert response_with_csrf_json["error"] == "Authentication required"

    # --- Krok 5: Wylogowanie ---
    page.click('a.logout-btn:has-text("Wyloguj")')
    expect(page).to_have_url(f"{base_url}/login")
