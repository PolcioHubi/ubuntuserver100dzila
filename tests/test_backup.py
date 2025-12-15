import os
import shutil
import zipfile
import io

# Fixtures `client` and `app` are provided by pytest-flask, configured in conftest.py


def test_full_backup_as_admin(client):
    """
    Tests the full backup functionality as a logged-in admin.
    """
    # Arrange: Create temporary user data to be backed up
    test_user_folder = os.path.join("user_data", "backup_test_user")
    os.makedirs(test_user_folder, exist_ok=True)
    test_file_path = os.path.join(test_user_folder, "test_file.txt")
    with open(test_file_path, "w") as f:
        f.write("This is a test file for backup.")

    try:
        # Arrange: Log in as admin
        with client.session_transaction() as sess:
            sess["admin_logged_in"] = True

        # Act: Request the full backup
        response = client.get("/admin/api/backup/full")

        # Assert: Check the response
        assert response.status_code == 200
        assert response.mimetype == "application/zip"
        assert "attachment" in response.headers["Content-Disposition"]
        assert response.headers["Content-Disposition"].endswith(".zip")

        # Assert: Check the contents of the zip file
        zip_buffer = io.BytesIO(response.data)
        with zipfile.ZipFile(zip_buffer, "r") as zip_file:
            namelist = zip_file.namelist()

            # Check if database and our test file are in the archive
            assert "auth_data/database.db" in namelist
            # Corrected path for assertion to handle OS differences
            expected_file_in_zip = os.path.join(
                "user_data", "backup_test_user", "test_file.txt"
            ).replace("\\", "/")
            assert expected_file_in_zip in namelist

            # Check the content of the test file
            file_content = zip_file.read(expected_file_in_zip)
            assert file_content == b"This is a test file for backup."

    finally:
        # Cleanup: Remove the temporary test data
        if os.path.exists(test_user_folder):
            shutil.rmtree(test_user_folder)


def test_full_backup_unauthorized(client):
    """
    Tests that a non-admin cannot access the backup endpoint.
    """
    # Act: Request the full backup without being logged in
    response = client.get("/admin/api/backup/full")

    # Assert: Expect a 401 Unauthorized status for API endpoints
    assert response.status_code == 401
