from playwright.sync_api import Page, expect
import secrets

# Ten plik testuje walidację formularza rejestracji w czasie rzeczywistym i po stronie serwera.

def test_registration_form_validation_e2e(page: Page, base_url, access_key_service, db_session):
    """
    Testuje walidację formularza rejestracji krok po kroku, zgodnie ze scenariuszem.
    """
    # --- Krok 1: Przejdź na stronę /register ---
    page.goto(f"{base_url}/register")
    expect(page).to_have_url(f"{base_url}/register")

    username_input = page.locator('input[name="username"]')
    password_input = page.locator('input[name="password"]')
    confirm_password_input = page.locator('input[name="confirm_password"]')
    access_key_input = page.locator('textarea[name="accessKey"]')
    referral_code_input = page.locator('input[name="referralCode"]')
    register_button = page.locator('button:has-text("Zarejestruj się")')
    error_alert = page.locator("#errorAlert")

    # --- Krok 2: Test za krótkiej nazwy użytkownika ---
    username_input.fill("ab")
    # Sprawdzamy, czy JS poprawnie podświetla błąd
    expect(username_input).to_have_css("border-color", "rgb(231, 76, 60)")

    # --- Krok 3: Test za krótkiego hasła ---
    password_input.fill("12345")
    expect(password_input).to_have_css("border-color", "rgb(231, 76, 60)")

    # --- Krok 4: Test niezgodnych haseł ---
    password_input.fill("password123")
    confirm_password_input.fill("password456")
    # Kliknięcie poza polem, aby uruchomić ewentualną walidację JS
    page.locator("h1").click()

    # --- Krok 5: Próba wysłania z niezgodnymi hasłami ---
    access_key = access_key_service.generate_access_key("e2e_validation_key")
    db_session.commit()
    username_input.fill("valid_user_for_pass_test")
    access_key_input.fill(access_key)
    register_button.click()
    expect(error_alert).to_be_visible()
    expect(error_alert).to_have_text("Hasła nie są zgodne")

    # --- Krok 6: Test użytego tokenu ---
    # Najpierw użyjmy klucza poprawnie
    first_user = f"first_user_{secrets.token_hex(4)}"
    username_input.fill(first_user)
    password_input.fill("password123")
    confirm_password_input.fill("password123")
    access_key_input.fill(access_key)
    register_button.click()
    expect(page.locator("#fullScreenOverlay")).to_be_visible(timeout=10000)
    page.click("#overlayProceedBtn") # Wracamy do logowania

    # Teraz spróbujmy użyć tego samego klucza ponownie
    page.goto(f"{base_url}/register")
    second_user = f"second_user_{secrets.token_hex(4)}"
    username_input.fill(second_user)
    password_input.fill("password123")
    confirm_password_input.fill("password123")
    access_key_input.fill(access_key) # Używamy tego samego, zużytego klucza
    register_button.click()
    expect(error_alert).to_be_visible()
    expect(error_alert).to_have_text("Klucz dostępu został dezaktywowany")

    # --- Krok 7: Test polecenia samego siebie ---
    new_key = access_key_service.generate_access_key("self_referral_key")
    db_session.commit()
    self_referral_user = f"self_ref_{secrets.token_hex(4)}"
    username_input.fill(self_referral_user)
    password_input.fill("password123")
    confirm_password_input.fill("password123")
    access_key_input.fill(new_key)
    referral_code_input.fill(self_referral_user) # Użycie własnej nazwy jako kodu
    register_button.click()
    # Aplikacja powinna zarejestrować użytkownika, ale nie przyznać monet.
    # Sprawdzamy, czy rejestracja się powiodła (pojawi się modal)
    expect(page.locator("#fullScreenOverlay")).to_be_visible(timeout=10000)
    # Weryfikacja monet musiałaby nastąpić w teście jednostkowym lub przez panel admina,
    # ponieważ interfejs użytkownika nie pokazuje salda monet zaraz po rejestracji.