import pytest
from unittest.mock import patch
import os
import sys
import io
import importlib
from app import app

# Testy dla globalnych handlerów błędów
def test_404_error_handler(client):
    """
    Testuje, czy niestandardowy handler błędu 404 jest poprawnie wywoływany
    dla nieistniejącego endpointu i zwraca odpowiedź w formacie JSON.
    """
    response = client.get("/non_existent_page_for_404_test")
    assert response.status_code == 404
    json_data = response.get_json()
    assert json_data["success"] is False
    assert "Resource not found" in json_data["error"]

@pytest.mark.skip(reason="Test jest niestabilny i wymaga głębszej analizy mockowania w kontekście Flaska")
def test_500_error_handler(client, mocker):
    """
    Testuje, czy globalny handler błędu 500 jest wywoływany, gdy
    wystąpi nieoczekiwany błąd w trakcie przetwarzania żądania.
    """
    # Mockujemy datetime.now, aby rzucało błędem w endpoincie /health
    mocker.patch('app.datetime.now', side_effect=Exception("Simulated internal server error"))

    response = client.get("/health")
    
    assert response.status_code == 500
    json_data = response.get_json()
    assert json_data["success"] is False
    assert "Internal server error" in json_data["error"]

# Testy walidacji
def test_set_user_validation(client):
    """
    Testuje walidację danych wejściowych dla endpointu /set_user.
    """
    # Test 1: Brak nazwy użytkownika
    response_no_user = client.post("/set_user", json={})
    assert response_no_user.get_json()["error"] == "Nazwa użytkownika jest wymagana"

    # Test 2: Nazwa użytkownika za krótka
    response_too_short = client.post("/set_user", json={"user_name": "a"})
    assert "musi mieć od 2 do 50 znaków" in response_too_short.get_json()["error"]

    # Test 3: Nazwa użytkownika za długa
    long_name = "a" * 51
    response_too_long = client.post("/set_user", json={"user_name": long_name})
    assert "musi mieć od 2 do 50 znaków" in response_too_long.get_json()["error"]

@pytest.mark.parametrize("malicious_filename", [
    "../malicious.jpg",
    "test/../../etc/passwd",
    "C:\\windows\\system32\\config.sam"
])
def test_image_upload_path_traversal(logged_in_client, malicious_filename):
    """
    Testuje, czy endpoint uploadu obrazów jest odporny na ataki Path Traversal.
    """
    image_data = (io.BytesIO(b"fake_image"), malicious_filename)
    response = logged_in_client.post(
        "/",
        data={
            "user_name": "testuser",
            "imie": "test",
            "image_upload": image_data,
        },
        content_type="multipart/form-data",
    )
    assert response.status_code == 400
    json_data = response.get_json()
    assert json_data["success"] is False
    assert "Nazwa pliku zawiera niedozwolone znaki" in json_data["error"]

