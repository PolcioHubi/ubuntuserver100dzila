
import pytest
from flask import session
from playwright.sync_api import Page, expect
import re
from models import User, db

# Fixtures `admin_client`, `logged_in_client`, `registered_user` are from conftest.py

# --- API / Integration Tests ---

def test_start_impersonation_success(admin_client, registered_user):
    """
    Tests if an admin can successfully start an impersonation session.
    """
    response = admin_client.post(
        "/admin/api/impersonate/start",
        json={"username": registered_user["username"]}
    )
    assert response.status_code == 200
    json_data = response.get_json()
    assert json_data["success"] is True

    # Check the session to confirm impersonation state
    with admin_client.session_transaction() as sess:
        assert sess["is_impersonating"] is True
        assert sess["original_admin_id"] == "admin_test"
        assert sess["_user_id"] == registered_user["username"]

def test_stop_impersonation_success(admin_client, registered_user):
    """
    Tests if an admin can successfully stop an impersonation session.
    """
    # First, start the impersonation
    admin_client.post("/admin/api/impersonate/start", json={"username": registered_user["username"]})

    # Now, stop it
    response = admin_client.post("/admin/api/impersonate/stop")
    assert response.status_code == 200
    json_data = response.get_json()
    assert json_data["success"] is True

    # Check the session to confirm impersonation has ended and admin session is restored
    with admin_client.session_transaction() as sess:
        assert "is_impersonating" not in sess
        assert "original_admin_id" not in sess
        assert sess["admin_logged_in"] is True
        assert sess["admin_username"] == "admin_test"

def test_start_impersonation_by_non_admin(logged_in_client, registered_user):
    """
    Ensures a regular user cannot start an impersonation session.
    """
    response = logged_in_client.post(
        "/admin/api/impersonate/start",
        json={"username": registered_user["username"]}
    )
    # The @require_admin_login decorator should return 401 for API requests
    assert response.status_code == 401

def test_start_impersonation_inactive_user(admin_client, registered_user, db_session):
    """
    Ensures an admin cannot impersonate an inactive user.
    """
    # Deactivate the user
    user = User.query.filter_by(username=registered_user["username"]).first()
    assert user is not None, "User should exist"
    user.is_active = False
    db.session.commit()

    response = admin_client.post(
        "/admin/api/impersonate/start",
        json={"username": registered_user["username"]}
    )
    assert response.status_code == 400
    json_data = response.get_json()
    assert json_data["success"] is False
    assert "Nie można impersonować nieaktywnego użytkownika" in json_data["error"]

def test_start_impersonation_nonexistent_user(admin_client):
    """
    Ensures an admin cannot impersonate a user that does not exist.
    """
    response = admin_client.post(
        "/admin/api/impersonate/start",
        json={"username": "user_that_does_not_exist"}
    )
    assert response.status_code == 404
    json_data = response.get_json()
    assert json_data["success"] is False
    assert "Użytkownik do impersonacji nie został znaleziony" in json_data["error"]


# --- E2E Test ---

def test_impersonation_full_e2e_journey(page: Page, base_url, registered_user, admin_credentials):
    """
    Tests the full impersonation lifecycle from the admin's browser perspective.
    """
    # --- Step 1: Admin logs in ---
    page.goto(f"{base_url}/admin/login")
    page.fill('input[name="username"]', admin_credentials["username"])
    page.fill('input[name="password"]', admin_credentials["password"])
    page.click('button:has-text("Zaloguj się")')
    expect(page).to_have_url(f"{base_url}/admin/")

    # --- Step 2: Navigate to users and start impersonation ---
    page.click('button:has-text("Zarejestrowani Użytkownicy")')
    user_row = page.locator(f'tr:has-text("{registered_user["username"]}")')
    expect(user_row).to_be_visible()

    impersonate_button = user_row.locator('button:has-text("Impersonuj")')
    expect(impersonate_button).to_be_enabled()

    # Accept the confirmation dialog automatically
    page.once("dialog", lambda dialog: dialog.accept())
    impersonate_button.click()

    # --- Step 3: Verify impersonation state ---
    # Expect to be redirected to the user's main page
    expect(page).to_have_url(re.compile(r".*/$"))
    
    # Verify the discrete impersonation widget is visible
    impersonation_widget = page.locator(".impersonation-widget")
    expect(impersonation_widget).to_be_visible()
    expect(impersonation_widget).to_contain_text(f'Impersonujesz: {registered_user["username"]}')

    # Verify that the normal user content is visible
    expect(page.locator("h1:has-text('Podmieniacz Danych HTML')")).to_be_visible()

    # --- Step 4: Stop impersonation ---
    stop_link = impersonation_widget.locator('a:has-text("[ Zakończ ]")')
    
    # Accept the confirmation dialog
    page.once("dialog", lambda dialog: dialog.accept())
    stop_link.click()

    # --- Step 5: Verify return to admin panel ---
    # Expect to be redirected back to the admin panel
    expect(page).to_have_url(f"{base_url}/admin/")
    expect(page.locator("h1:has-text('Panel Administracyjny')")).to_be_visible()

    # Verify the impersonation widget is now gone
    expect(page.locator(".impersonation-widget")).to_be_hidden()
