import pytest
from unittest.mock import MagicMock
from models import User
from user_auth import UserAuthManager


@pytest.fixture
def mock_access_key_service():
    service = MagicMock()
    service.validate_access_key.return_value = (True, "Klucz dostępu jest prawidłowy.")
    return service


@pytest.fixture
def mock_notification_service():
    return MagicMock()


@pytest.fixture
def user_auth_manager(mock_access_key_service, mock_notification_service):
    return UserAuthManager(mock_access_key_service, mock_notification_service)


def test_register_user_with_referral(user_auth_manager, db_session):
    # 1. Create a referrer user
    referrer_username = "referrer_user"
    user_auth_manager.register_user(referrer_username, "password123", "key1")
    referrer = User.query.filter_by(username=referrer_username).first()
    assert referrer is not None, "Referrer user should exist"
    initial_coins = referrer.hubert_coins

    # 2. Register a new user with the referrer's code
    new_user_username = "new_user_with_referral"
    user_auth_manager.register_user(
        new_user_username, "password123", "key2", referral_code=referrer_username
    )

    # 3. Check if the referrer's coin balance has increased
    db_session.refresh(referrer)
    assert referrer.hubert_coins == initial_coins + 1


def test_register_user_with_invalid_referral(user_auth_manager, db_session):
    # 1. Register a new user with a non-existent referral code
    new_user_username = "new_user_invalid_referral"
    user_auth_manager.register_user(
        new_user_username, "password123", "key3", referral_code="non_existent_user"
    )

    # 2. Ensure no error occurred and the user was created
    new_user = User.query.filter_by(username=new_user_username).first()
    assert new_user is not None


def test_update_hubert_coins(user_auth_manager, registered_user, db_session):
    username = registered_user["username"]
    user = User.query.filter_by(username=username).first()
    assert user is not None, "User should exist"
    initial_coins = user.hubert_coins

    # Add coins
    success, msg = user_auth_manager.update_hubert_coins(username, 10)
    assert success is True
    db_session.refresh(user)
    assert user.hubert_coins == initial_coins + 10

    # Subtract coins
    success, msg = user_auth_manager.update_hubert_coins(username, -5)
    assert success is True
    db_session.refresh(user)
    assert user.hubert_coins == initial_coins + 5


def test_update_hubert_coins_insufficient_funds(
    user_auth_manager, registered_user, db_session
):
    username = registered_user["username"]
    user = User.query.filter_by(username=username).first()
    assert user is not None, "User should exist"
    user.hubert_coins = 2
    db_session.commit()

    success, msg = user_auth_manager.update_hubert_coins(username, -10)
    assert success is False
    assert msg == "Niewystarczająca ilość Hubert Coins"
    db_session.refresh(user)
    assert user.hubert_coins == 2


def test_get_user_info(user_auth_manager, registered_user):
    username = registered_user["username"]
    user_info = user_auth_manager.get_user_info(username)

    assert user_info is not None
    assert user_info["username"] == username
    assert "created_at" in user_info
    assert "last_login" in user_info
    assert "hubert_coins" in user_info
    assert "is_active" in user_info
    assert "referral_code" in user_info


def test_get_user_info_non_existent_user(user_auth_manager):
    user_info = user_auth_manager.get_user_info("non_existent_user")
    assert user_info is None
