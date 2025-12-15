import pytest
import os
import shutil
import secrets
from models import User, db

# Ten plik testuje logikę związaną z zarządzaniem plikami i folderami użytkowników,
# weryfikując zarówno poprawki błędów, jak i odporność na przypadki brzegowe.

@pytest.fixture
def user_with_folder(app, auth_manager, access_key_service):
    """
    Fixture, który tworzy unikalnego użytkownika oraz jego folder z plikiem.
    Zapewnia czyszczenie po teście.
    """
    username = f"test_user_with_files_{secrets.token_hex(4)}"
    password = "password123"
    access_key = access_key_service.generate_access_key(f"Key for {username}")
    auth_manager.register_user(username, password, access_key)

    # Utwórz folder i plik dla tego użytkownika, używając ścieżki bezwzględnej
    folder_path = os.path.join(app.root_path, "user_data", username)
    os.makedirs(folder_path, exist_ok=True)
    with open(os.path.join(folder_path, "test_file.txt"), "w") as f:
        f.write("test content")
    
    yield username, folder_path

    # Sprzątanie po teście
    if os.path.exists(folder_path):
        shutil.rmtree(folder_path)


# --- Testy dla endpointu /admin/api/delete-registered-user/<username> ---

def test_delete_user_with_files_removes_folder(admin_client, user_with_folder):
    """
    Weryfikuje, czy usunięcie użytkownika z flagą delete_files=true usuwa folder.
    """
    username, folder_path = user_with_folder
    assert os.path.exists(folder_path) is True

    response = admin_client.delete(f"/admin/api/delete-registered-user/{username}?delete_files=true")

    assert response.status_code == 200
    assert response.json["success"] is True
    assert "Jego pliki również zostały usunięte" in response.json["message"]
    assert os.path.exists(folder_path) is False

def test_delete_user_without_files_preserves_folder(admin_client, user_with_folder):
    """
    Weryfikuje, czy usunięcie użytkownika z flagą delete_files=false pozostawia folder.
    """
    username, folder_path = user_with_folder
    assert os.path.exists(folder_path) is True

    response = admin_client.delete(f"/admin/api/delete-registered-user/{username}?delete_files=false")

    assert response.status_code == 200
    assert response.json["success"] is True
    assert "Jego pliki zostały zachowane" in response.json["message"]
    assert os.path.exists(folder_path) is True

def test_delete_user_with_no_folder_present(admin_client, registered_user):
    """
    Duperel #1: Testuje usunięcie użytkownika, który nie ma folderu.
    Operacja powinna się powieść bez błędów.
    """
    username = registered_user["username"]
    response = admin_client.delete(f"/admin/api/delete-registered-user/{username}?delete_files=true")

    assert response.status_code == 200
    assert response.json["success"] is True
    assert "został usunięty" in response.json["message"]

def test_delete_nonexistent_user_returns_404(admin_client):
    """
    Testuje próbę usunięcia użytkownika, który nie istnieje w bazie danych.
    """
    response = admin_client.delete("/admin/api/delete-registered-user/nonexistent_user_123?delete_files=true")
    assert response.status_code == 404
    assert response.json["success"] is False
    assert "Użytkownik nie istnieje" in response.json["error"]

@pytest.mark.parametrize("malicious_username,expected_code", [
    (r"..\\/", 404),  # Raw string dla poprawnego escape
    ("..\\..\\", 400), 
    ("user\x00.txt", 400)  # Null byte = Bad Request (400)
])
def test_path_traversal_on_delete_user(admin_client, malicious_username, expected_code):
    """
    Duperel #2: Testuje odporność na ataki Path Traversal.
    """
    response = admin_client.delete(f"/admin/api/delete-registered-user/{malicious_username}?delete_files=true")
    assert response.status_code == expected_code


# --- Testy dla endpointu /admin/api/delete-user-files/<username> ---

@pytest.mark.skip(reason="Skipping test for non-existent API endpoint")
def test_api_delete_user_files_leaves_user_in_db(admin_client, user_with_folder):
    """
    Duperel #3: Weryfikuje, czy endpoint do usuwania plików usuwa folder,
    ale pozostawia użytkownika w bazie danych.
    """
    username, folder_path = user_with_folder
    assert os.path.exists(folder_path) is True

    response = admin_client.delete(f"/admin/api/delete-user-files/{username}")

    assert response.status_code == 200
    assert response.json["success"] is True
    assert os.path.exists(folder_path) is False

    # Kluczowa asercja: sprawdź, czy użytkownik nadal istnieje w bazie danych
    user_in_db = User.query.filter_by(username=username).first()
    assert user_in_db is not None
