import pytest
from datetime import datetime, timedelta
from models import db, AccessKey, Announcement, Notification, User, File
from services import (
    AccessKeyService,
    AnnouncementService,
    StatisticsService,
    NotificationService,
)


# Fixtures for services are now defined in conftest.py


# Tests for AccessKeyService
def test_generate_access_key(access_key_service, db_session):
    key = access_key_service.generate_access_key("Test Key")
    assert key is not None
    db_key = db.session.get(AccessKey, key)
    assert db_key is not None
    assert db_key.description == "Test Key"

def test_generate_access_key_no_expiration(access_key_service, db_session):
    key = access_key_service.generate_access_key("No Expiration Key", expires_days=0)
    assert key is not None
    db_key = db.session.get(AccessKey, key)
    assert db_key is not None, "Access key should exist in database"
    assert db_key.expires_at is None

def test_validate_access_key(access_key_service, db_session):
    key = access_key_service.generate_access_key("Valid Key")
    is_valid, msg = access_key_service.validate_access_key(key)
    assert is_valid is True
    assert msg == ""

def test_validate_invalid_access_key(access_key_service):
    is_valid, msg = access_key_service.validate_access_key("INVALID_KEY")
    assert is_valid is False
    assert msg == "Nieprawidłowy klucz dostępu"

def test_validate_expired_access_key(access_key_service, db_session):
    key = access_key_service.generate_access_key("Expired Key", expires_days=0)
    # Manually set expires_at to a past date
    key_obj = db.session.get(AccessKey, key)
    assert key_obj is not None, "Access key should exist"
    key_obj.expires_at = datetime.now() - timedelta(days=1)
    db.session.commit()

    is_valid, msg = access_key_service.validate_access_key(key)
    assert is_valid is False
    assert msg == "Klucz dostępu wygasł"
    # Check if the key is now marked as inactive in DB
    expired_key = db.session.get(AccessKey, key)
    assert expired_key is not None, "Access key should still exist"
    assert expired_key.is_active is False

def test_use_access_key(access_key_service, db_session):
    key = access_key_service.generate_access_key("Single Use Key")
    access_key_service.use_access_key(key)
    db_key = db.session.get(AccessKey, key)
    assert db_key is not None, "Access key should exist"
    assert db_key.is_active is False
    assert db_key.used_count == 1

def test_use_access_key_already_inactive(access_key_service, db_session):
    key = access_key_service.generate_access_key("Already Inactive Key")
    key_obj = db.session.get(AccessKey, key)
    assert key_obj is not None, "Access key should exist"
    key_obj.is_active = False
    db.session.commit()

    # Using the key should not change its state or raise error
    access_key_service.use_access_key(key)
    db_key = db.session.get(AccessKey, key)
    assert db_key is not None, "Access key should exist"
    assert db_key.is_active is False
    assert db_key.used_count == 0 # Should not increment if already inactive

def test_deactivate_access_key(access_key_service, db_session):
    key = access_key_service.generate_access_key("Deactivate Key")
    success = access_key_service.deactivate_access_key(key)
    assert success is True
    deactivated_key = db.session.get(AccessKey, key)
    assert deactivated_key is not None, "Access key should exist"
    assert deactivated_key.is_active is False

def test_deactivate_access_key_already_inactive(access_key_service, db_session):
    key = access_key_service.generate_access_key("Deactivate Inactive Key")
    key_obj = db.session.get(AccessKey, key)
    assert key_obj is not None, "Access key should exist"
    key_obj.is_active = False
    db.session.commit()
    success = access_key_service.deactivate_access_key(key)
    assert success is False # Should return False if already inactive

def test_deactivate_nonexistent_access_key(access_key_service):
    success = access_key_service.deactivate_access_key("NONEXISTENT_KEY")
    assert success is False

def test_delete_access_key(access_key_service, db_session):
    key = access_key_service.generate_access_key("Delete Key")
    success = access_key_service.delete_access_key(key)
    assert success is True
    assert db.session.get(AccessKey, key) is None

def test_delete_nonexistent_access_key(access_key_service):
    success = access_key_service.delete_access_key("NONEXISTENT_KEY")
    assert success is False

def test_get_all_access_keys(access_key_service, db_session):
    access_key_service.generate_access_key("Key 1")
    access_key_service.generate_access_key("Key 2")
    keys = access_key_service.get_all_access_keys()
    assert len(keys) >= 2 # Account for keys created by other fixtures

def test_get_all_access_keys_no_keys(access_key_service, db_session):
    # Clear all existing keys for this test
    db.session.query(AccessKey).delete()
    db.session.commit()
    keys = access_key_service.get_all_access_keys()
    assert len(keys) == 0


# Tests for AnnouncementService
def test_create_announcement(announcement_service, db_session):
    success = announcement_service.create_announcement(
        "New Feature", "Check out our new feature!", "info", None
    )
    assert success is True
    db_announcement = Announcement.query.filter_by(title="New Feature").first()
    assert db_announcement is not None

def test_create_announcement_with_expiration(announcement_service, db_session):
    expires_at = datetime.now() + timedelta(days=7)
    success = announcement_service.create_announcement(
        "Expiring Announcement", "This will expire.", "warning", expires_at
    )
    assert success is True
    db_announcement = Announcement.query.filter_by(title="Expiring Announcement").first()
    assert db_announcement is not None, "Announcement should exist"
    assert db_announcement.expires_at == expires_at

def test_create_announcement_invalid_expires_at_string(announcement_service):
    success = announcement_service.create_announcement(
        "Invalid Date", "Message", "info", "not-a-date"
    )
    assert success is False

def test_get_active_announcements(announcement_service, db_session):
    announcement_service.create_announcement("Active", "This is active", "info", None)
    announcement_service.create_announcement(
        "Expired",
        "This is expired",
        "info",
        expires_at=datetime.now() - timedelta(days=1),
    )
    active_announcements = announcement_service.get_active_announcements()
    assert len(active_announcements) == 1
    assert active_announcements[0].title == "Active"

def test_get_active_announcements_future_expiration(announcement_service, db_session):
    expires_at_future = datetime.now() + timedelta(days=1)
    announcement_service.create_announcement("Future", "Future message", "info", expires_at_future)
    active_announcements = announcement_service.get_active_announcements()
    assert any(a.title == "Future" for a in active_announcements)

def test_get_active_announcements_no_active(announcement_service, db_session):
    announcement_service.create_announcement("Expired", "Expired message", "info", datetime.now() - timedelta(days=1))
    # Manually deactivate any other active announcements from fixtures
    db.session.query(Announcement).filter(Announcement.is_active == True).update({'is_active': False})
    db.session.commit()
    active_announcements = announcement_service.get_active_announcements()
    assert len(active_announcements) == 0

def test_deactivate_announcement(announcement_service, db_session):
    success = announcement_service.create_announcement("To Deactivate", "Message", "info", None)
    announcement = Announcement.query.filter_by(title="To Deactivate").first()
    assert announcement is not None, "Announcement should exist"
    deactivated = announcement_service.deactivate_announcement(announcement.id)
    assert deactivated is True
    deactivated_ann = Announcement.query.filter_by(id=announcement.id).first()
    assert deactivated_ann is not None, "Deactivated announcement should exist"
    assert deactivated_ann.is_active is False

def test_deactivate_announcement_nonexistent(announcement_service):
    success = announcement_service.deactivate_announcement(99999) # Non-existent ID
    assert success is False

def test_get_all_announcements(announcement_service, db_session):
    announcement_service.create_announcement("Ann 1", "Msg 1", "info", None)
    announcement_service.create_announcement("Ann 2", "Msg 2", "info", None)
    all_announcements = announcement_service.get_all_announcements()
    assert len(all_announcements) >= 2

def test_get_all_announcements_no_announcements(announcement_service, db_session):
    db.session.query(Announcement).delete()
    db.session.commit()
    all_announcements = announcement_service.get_all_announcements()
    assert len(all_announcements) == 0


# Tests for NotificationService
def test_create_notification(notification_service, registered_user, db_session):
    user = User.query.filter_by(username=registered_user["username"]).first()
    assert user is not None, "User should exist"
    success = notification_service.create_notification(user.username, "Test notification")
    db_notification = Notification.query.filter_by(message="Test notification").first()
    assert db_notification is not None
    assert db_notification.user_id == user.username
    assert success is None # create_notification doesn't return a boolean

def test_get_user_notifications(notification_service, registered_user, db_session):
    user = User.query.filter_by(username=registered_user["username"]).first()
    assert user is not None, "User should exist"
    notification_service.create_notification(user.username, "Notification 1")
    notification_service.create_notification(user.username, "Notification 2")
    notifications = notification_service.get_notifications(user.username)
    assert len(notifications) == 3  # Including the welcome notification
    assert any(n["message"] == "Notification 1" for n in notifications)
    assert any(n["message"] == "Notification 2" for n in notifications)

def test_get_user_notifications_no_notifications(notification_service, registered_user, db_session):
    # Clear existing notifications for this user
    db.session.query(Notification).filter_by(user_id=registered_user["username"]).delete()
    db.session.commit()
    notifications = notification_service.get_notifications(registered_user["username"])
    assert len(notifications) == 0

def test_mark_notification_as_read(notification_service, registered_user, db_session):
    user = User.query.filter_by(username=registered_user["username"]).first()
    assert user is not None, "User should exist"
    notification_service.create_notification(user.username, "Unread Notification")
    notification = Notification.query.filter_by(user_id=user.username, message="Unread Notification").first()
    assert notification is not None, "Notification should exist"
    assert notification.is_read is False
    notification_service.mark_notification_as_read(notification.id)
    read_notification = db.session.get(Notification, notification.id)
    assert read_notification is not None, "Notification should exist after marking as read"
    assert read_notification.is_read is True

def test_mark_notification_as_read_nonexistent(notification_service):
    # Should not raise an error
    notification_service.mark_notification_as_read(99999) # Non-existent ID


# Tests for StatisticsService
def test_get_general_stats(statistics_service, registered_user, db_session):
    stats = statistics_service.get_overall_stats()
    assert stats["total_users"] >= 1
    assert stats["total_files"] == 0

def test_get_overall_stats_no_data(statistics_service, db_session):
    # Clear all users and files for this test
    db.session.query(User).delete()
    db.session.query(File).delete()
    db.session.commit()
    stats = statistics_service.get_overall_stats()
    assert stats["total_users"] == 0
    assert stats["total_files"] == 0
    assert stats["total_size"] == 0

def test_get_user_files_no_files(statistics_service, registered_user, db_session):
    # Ensure user has no files
    db.session.query(File).filter_by(user_username=registered_user["username"]).delete()
    db.session.commit()
    files = statistics_service.get_user_files(registered_user["username"])
    assert len(files) == 0

def test_add_or_update_file_update_existing(statistics_service, registered_user, db_session):
    username = registered_user["username"]
    filepath = "/path/to/existing_file.txt"
    # Add initial file
    statistics_service.add_or_update_file(username, "existing_file.txt", filepath, 100, "hash_old")
    # Update file
    statistics_service.add_or_update_file(username, "existing_file.txt", filepath, 200, "hash_new")
    updated_file = File.query.filter_by(filepath=filepath).first()
    assert updated_file is not None, "File should exist"
    assert updated_file.size == 200
    assert updated_file.file_hash == "hash_new"

def test_get_top_user_by_coins(statistics_service, registered_user, db_session):
    user = User.query.filter_by(username=registered_user["username"]).first()
    assert user is not None, "User should exist"
    user.hubert_coins = 100
    db.session.commit()

    top_user_stats = statistics_service.get_all_users_with_stats(page=1, per_page=1)
    top_user = top_user_stats["users"][0]
    assert top_user["name"] == registered_user["username"]
