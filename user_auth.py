import logging
import bcrypt
import secrets
import datetime
from typing import List, Optional, Tuple
from flask_login import UserMixin
from sqlalchemy.exc import IntegrityError
from models import db, User
from services import AccessKeyService, NotificationService
import threading


# Add UserMixin to the User model from models.py for Flask-Login compatibility
class AuthUser(User, UserMixin):
    def get_id(self):
        return self.username


class UserAuthManager:
    # Security settings
    BCRYPT_ROUNDS = 12  # Adjust based on performance needs (higher = more secure but slower)
    
    def __init__(
        self,
        access_key_service: AccessKeyService,
        notification_service: NotificationService,
    ):
        """Initializes the manager with its dependencies."""
        self.access_key_service = access_key_service
        self.notification_service = notification_service
        self.hubert_coins_lock = threading.Lock()

    def _hash_password(self, password: str) -> str:
        hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=self.BCRYPT_ROUNDS))
        return hashed.decode("utf-8")

    def _check_password(self, hashed_password: str, password: str) -> bool:
        try:
            return bcrypt.checkpw(
                password.encode("utf-8"), hashed_password.encode("utf-8")
            )
        except (ValueError, TypeError):
            return False

    def validate_referral_code(self, code: str) -> bool:
        """Checks if a referral code (username) exists and is active."""
        user = User.query.filter_by(username=code, is_active=True).first()
        return user is not None

    def register_user(
        self,
        username: str,
        password: str,
        access_key: str,
        referral_code: Optional[str] = None,
        mark_tutorial_seen: bool = False,
    ) -> Tuple[bool, str, Optional[str]]:
        try:
            username = username.strip()
            logging.info(f"Attempting to register user: {username}")
            
            # Validate access key length to prevent DoS
            if len(access_key) > 256:
                logging.warning(f"Registration failed for {username}: Access key too long")
                return False, "Nieprawidłowy klucz dostępu", None
            
            is_valid, error_msg = self.access_key_service.validate_access_key(
                access_key
            )
            logging.info(
                f"Access key validation result: is_valid={is_valid}, error_msg={error_msg}"
            )
            if not is_valid:
                logging.warning(
                    f"Registration failed for {username}: Invalid access key - {error_msg}"
                )
                return False, error_msg, None

            if len(username) < 3:
                logging.warning(
                    f"Registration failed for {username}: Username too short (length: {len(username)})."
                )
                return False, "Nazwa użytkownika musi mieć co najmniej 3 znaki", None
            if len(username) > 50:
                logging.warning(
                    f"Registration failed for {username}: Username too long (length: {len(username)})."
                )
                return False, "Nazwa użytkownika może mieć maksymalnie 50 znaków", None
            if len(password) < 6:
                logging.warning(
                    f"Registration failed for {username}: Password too short (length: {len(password)})."
                )
                return False, "Hasło musi mieć co najmniej 6 znaków", None
            if len(password) > 100: # Dodana walidacja maksymalnej długości hasła
                logging.warning(
                    f"Registration failed for {username}: Password too long (length: {len(password)})."
                )
                return False, "Hasło może mieć maksymalnie 100 znaków", None

            user_exists = User.query.filter_by(username=username).first()
            if user_exists:
                logging.warning(
                    f"Registration failed for {username}: Username already exists."
                )
                return False, "Użytkownik o tej nazwie już istnieje", None

            hashed_password = self._hash_password(password)
            recovery_token = secrets.token_urlsafe(16)

            new_user = User(
                username=username,
                password=hashed_password,
                access_key_used=access_key,
                recovery_token=recovery_token,
                has_seen_tutorial=mark_tutorial_seen,  # Set tutorial status
            )
            db.session.add(new_user)

            self.access_key_service.use_access_key(access_key)

            message = "Użytkownik zarejestrowany pomyślnie"
            if (
                referral_code
                and referral_code != username
                and self.validate_referral_code(referral_code)
            ):
                referrer = User.query.filter_by(username=referral_code).first()
                if referrer:
                    referrer.hubert_coins += 1
                    message += ". Otrzymałeś 1 Hubert Coin za polecenie!"

            self.notification_service.create_notification(
                username, "Witaj w mObywatel! Dziękujemy za rejestrację."
            )

            db.session.commit()
            logging.info(f"User {username} registered successfully.")
            return True, message, recovery_token
        except IntegrityError:
            db.session.rollback()
            logging.warning(
                f"Registration failed for {username}: IntegrityError - access key or username already used."
            )
            return (
                False,
                "Ten klucz dostępu został już wykorzystany lub nazwa użytkownika jest zajęta.",
                None,
            )
        except Exception as e:
            db.session.rollback()
            logging.error(
                f"Error during user registration for {username}: {e}", exc_info=True
            )
            return False, "Wystąpił wewnętrzny błąd serwera podczas rejestracji.", None

    def authenticate_user(
        self, username: str, password: str
    ) -> Tuple[bool, str, Optional[AuthUser]]:
        logging.info(f"Attempting to authenticate user: {username}")
        user = User.query.filter_by(username=username).first()

        if not user:
            logging.warning(f"Authentication failed for {username}: User not found.")
            return False, "Nieprawidłowa nazwa użytkownika lub hasło", None

        if not user.is_active:
            logging.warning(
                f"Authentication failed for {username}: User account is inactive."
            )
            return False, "Konto użytkownika zostało dezaktywowane", None

        if self._check_password(user.password, password):
            user.last_login = datetime.datetime.now()
            db.session.commit()
            auth_user = db.session.get(AuthUser, user.username)
            logging.info(f"User {username} authenticated successfully.")
            return True, "Logowanie pomyślne", auth_user

        logging.warning(f"Authentication failed for {username}: Incorrect password.")
        return False, "Nieprawidłowa nazwa użytkownika lub hasło", None

    def get_user_by_id(self, user_id: str) -> Optional[AuthUser]:
        return AuthUser.query.filter_by(username=user_id).first()

    def get_all_users(self, include_passwords: bool = False) -> List[User]:
        return User.query.order_by(User.created_at.desc()).all()

    def toggle_user_status(self, username: str) -> bool:
        user = User.query.filter_by(username=username).first()
        if user:
            user.is_active = not user.is_active
            db.session.commit()
            return True
        return False

    def delete_user(self, username: str) -> bool:
        user = User.query.filter_by(username=username).first()
        if user:
            db.session.delete(user)
            db.session.commit()
            return True
        return False

    def update_hubert_coins(self, username: str, amount: int) -> Tuple[bool, str]:
        with self.hubert_coins_lock:
            user = User.query.filter_by(username=username).first()
            if not user:
                return False, "Użytkownik nie został znaleziony"

            new_balance = user.hubert_coins + amount
            if new_balance < 0:
                return False, "Niewystarczająca ilość Hubert Coins"

            user.hubert_coins = new_balance
            db.session.commit()
            return True, f"Zaktualizowano saldo Hubert Coins do: {new_balance}"

    def reset_user_password(self, username: str, new_password: str) -> Tuple[bool, str]:
        if len(new_password) < 6 or len(new_password) > 100:
            return False, "Hasło musi mieć od 6 do 100 znaków"

        user = User.query.filter_by(username=username).first()
        if not user:
            return False, "Użytkownik nie został znaleziony"

        user.password = self._hash_password(new_password)
        db.session.commit()
        return True, "Hasło zostało zresetowane"

    def generate_password_reset_token(self, username: str) -> Optional[str]:
        user = User.query.filter_by(username=username).first()
        if not user:
            return None

        token = secrets.token_urlsafe(32)
        user.password_reset_token = token
        user.password_reset_expires = datetime.datetime.now() + datetime.timedelta(
            hours=1
        )
        db.session.commit()
        return token

    def reset_user_password_with_token(
        self, token: str, new_password: str
    ) -> Tuple[bool, str]:
        user = User.query.filter_by(password_reset_token=token).first()

        if not user:
            return False, "Nieprawidłowy token"

        if datetime.datetime.now() > user.password_reset_expires:
            return False, "Token wygasł"

        if len(new_password) < 6 or len(new_password) > 100:
            return False, "Nowe hasło musi mieć od 6 do 100 znaków"

        user.password = self._hash_password(new_password)
        user.password_reset_token = None
        user.password_reset_expires = None
        db.session.commit()
        return True, "Hasło zostało pomyślnie zresetowane"

    def reset_password_with_recovery_token(
        self, username: str, recovery_token: str, new_password: str
    ) -> Tuple[bool, str]:
        if len(new_password) < 6 or len(new_password) > 100:
            return False, "Nowe hasło musi mieć od 6 do 100 znaków"

        user = User.query.filter_by(
            username=username, recovery_token=recovery_token
        ).first()
        if not user:
            return False, "Nieprawidłowa nazwa użytkownika lub token odzyskiwania"

        user.password = self._hash_password(new_password)
        db.session.commit()
        return True, "Hasło zostało pomyślnie zresetowane"

    def get_user_info(self, username: str) -> Optional[dict]:
        user = User.query.filter_by(username=username).first()
        if not user:
            return None
        return {
            "username": user.username,
            "created_at": user.created_at,
            "last_login": user.last_login,
            "hubert_coins": user.hubert_coins,
            "is_active": user.is_active,
            "referral_code": user.username,  # User's own referral code is their username
        }