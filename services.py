import logging
import secrets
import datetime
from typing import Dict, List, Optional, Tuple, Any
from models import db, AccessKey, Announcement, File, Notification, User
from sqlalchemy import func, desc


class AccessKeyService:
    """Manages all operations related to access keys using SQLAlchemy."""

    def generate_access_key(self, description: str = "", expires_days: int = 30) -> str:
        try:
            key_val = secrets.token_urlsafe(32)
            expires_at = None
            if expires_days > 0:
                expires_at = datetime.datetime.now() + datetime.timedelta(
                    days=expires_days
                )

            new_key = AccessKey(
                key=key_val, description=description, expires_at=expires_at
            )
            db.session.add(new_key)
            db.session.commit()
            logging.info(
                f"Generated access key: {key_val} with description '{description}' and expires_at {expires_at}"
            )
            return key_val
        except Exception as e:
            db.session.rollback()
            logging.error(f"Error generating access key: {e}", exc_info=True)
            raise

    def validate_access_key(self, key_val: str) -> Tuple[bool, str]:
        logging.info(f"Validating access key: {key_val}")
        key_data = AccessKey.query.filter_by(key=key_val).first()
        logging.info(f"Access key data found: {key_data is not None}")
        if key_data:
            logging.info(
                f"Access key {key_val} active: {key_data.is_active}, expires: {key_data.expires_at}"
            )

        if not key_data:
            logging.warning(f"Access key {key_val} not found.")
            return False, "Nieprawidłowy klucz dostępu"

        if not key_data.is_active:
            logging.warning(f"Access key {key_val} is inactive.")
            return False, "Klucz dostępu został dezaktywowany"

        if key_data.expires_at:
            if datetime.datetime.now() > key_data.expires_at:
                key_data.is_active = False
                try:
                    db.session.commit()
                except Exception as e:
                    db.session.rollback()
                    logging.error(
                        f"Error deactivating expired key {key_val}: {e}", exc_info=True
                    )
                logging.warning(f"Access key {key_val} has expired.")
                return False, "Klucz dostępu wygasł"

        logging.info(f"Access key {key_val} is valid.")
        return True, ""

    def use_access_key(self, key_val: str) -> bool:
        """
        Atomically marks an access key as used.
        Uses SELECT FOR UPDATE to prevent race conditions.
        Returns True if key was successfully used, False otherwise.
        """
        try:
            # Use SELECT FOR UPDATE to lock the row and prevent race conditions
            key_data = (
                AccessKey.query
                .filter_by(key=key_val)
                .with_for_update()
                .first()
            )
            
            if key_data and key_data.is_active:
                key_data.used_count += 1
                key_data.last_used = datetime.datetime.now()
                key_data.is_active = False  # Deactivate after use
                db.session.commit()
                logging.info(f"Access key {key_val} marked as used and deactivated.")
                return True
            elif key_data and not key_data.is_active:
                db.session.rollback()  # Release the lock
                logging.info(f"Access key {key_val} is already inactive. Not incrementing usage.")
                return False
            else:
                logging.warning(f"Access key {key_val} not found for usage attempt.")
                return False
        except Exception as e:
            db.session.rollback()
            logging.error(f"Error using access key {key_val}: {e}", exc_info=True)
            raise

    def deactivate_access_key(self, key_val: str) -> bool:
        try:
            key_data = AccessKey.query.filter_by(key=key_val).first()
            if key_data:
                if not key_data.is_active:
                    logging.info(f"Access key {key_val} is already inactive. No action needed.")
                    return False
                key_data.is_active = False
                db.session.commit()
                logging.info(f"Access key {key_val} deactivated.")
                return True
            logging.warning(f"Access key {key_val} not found for deactivation attempt.")
            return False
        except Exception as e:
            db.session.rollback()
            logging.error(
                f"Error deactivating access key {key_val}: {e}", exc_info=True
            )
            return False

    def delete_access_key(self, key_val: str) -> bool:
        try:
            key_data = AccessKey.query.filter_by(key=key_val).first()
            if key_data:
                db.session.delete(key_data)
                db.session.commit()
                return True
            return False
        except Exception as e:
            db.session.rollback()
            logging.error(f"Error deleting access key {key_val}: {e}", exc_info=True)
            return False

    def get_all_access_keys(self) -> List[AccessKey]:
        return AccessKey.query.order_by(desc(AccessKey.created_at)).all()


class AnnouncementService:
    """Manages all operations related to announcements using SQLAlchemy."""

    def create_announcement(
        self,
        title: str,
        message: str,
        type: str,
        expires_at: Optional[datetime.datetime],
    ) -> bool:
        try:
            # Convert ISO format string to datetime object if it's a string
            if isinstance(expires_at, str):
                try:
                    expires_at = datetime.datetime.fromisoformat(expires_at)
                except ValueError:
                    logging.error(f"Invalid ISO format for expires_at: {expires_at}")
                    return False # Or raise an exception, depending on desired error handling

            new_announcement = Announcement(
                title=title,
                message=message,
                type=type,
                expires_at=expires_at,
            )
            db.session.add(new_announcement)
            db.session.commit()
            return True
        except Exception as e:
            logging.error(f"Error creating announcement: {e}")
            db.session.rollback()
            return False

    def get_active_announcements(self) -> List[Announcement]:
        now = datetime.datetime.now()
        return (
            Announcement.query.filter(
                Announcement.is_active,
                (Announcement.expires_at.is_(None)) | (Announcement.expires_at > now),  # type: ignore[attr-defined, operator]
            )
            .order_by(desc(Announcement.created_at))
            .all()
        )

    def deactivate_announcement(self, announcement_id: int) -> bool:
        try:
            announcement = db.session.get(Announcement, announcement_id)
            if announcement:
                announcement.is_active = False
                db.session.commit()
                return True
            return False
        except Exception as e:
            db.session.rollback()
            logging.error(
                f"Error deactivating announcement {announcement_id}: {e}", exc_info=True
            )
            return False

    def get_all_announcements(self) -> List[Announcement]:
        return Announcement.query.order_by(desc(Announcement.created_at)).all()


class StatisticsService:
    """Handles fetching statistics and file metadata using SQLAlchemy."""

    def get_user_files(self, username: str) -> List[File]:
        return (
            File.query.filter_by(user_username=username)
            .order_by(desc(File.modified_at))  # type: ignore[arg-type]
            .all()
        )

    def get_all_users_with_stats(self, page=1, per_page=10) -> Dict[str, Any]:
        # Using a subquery to count files and sum sizes for performance
        # Type ignore: SQLAlchemy column attributes are dynamically generated
        file_stats = (
            db.session.query(  # type: ignore[call-overload, arg-type]
                File.user_username,  # type: ignore[arg-type]
                func.count(File.id).label("file_count"),
                func.sum(File.size).label("total_size"),
            )
            .group_by(File.user_username)
            .subquery()
        )

        # Left join User with the stats subquery
        query = (
            db.session.query(User, file_stats.c.file_count, file_stats.c.total_size)
            .outerjoin(file_stats, User.username == file_stats.c.user_username)
            .order_by(desc(User.last_login))
        )
        
        # Manual pagination for compatibility
        total = query.count()
        items = query.limit(per_page).offset((page - 1) * per_page).all()
        
        # Calculate pagination info
        total_pages = (total + per_page - 1) // per_page  # Ceiling division
        has_next = page < total_pages
        has_prev = page > 1

        # Format the results into a list of dictionaries
        users_with_stats = []
        for user, file_count, total_size in items:
            users_with_stats.append(
                {
                    "name": user.username,
                    "created_date": user.created_at,
                    "last_activity": user.last_login,
                    "file_count": file_count or 0,
                    "total_size": total_size or 0,
                }
            )

        return {
            "users": users_with_stats,
            "total_pages": total_pages,
            "current_page": page,
            "has_next": has_next,
            "has_prev": has_prev,
        }

    def get_overall_stats(self) -> Dict:
        total_users = db.session.query(func.count(User.username)).scalar()  # type: ignore[arg-type]
        result = db.session.query(
            func.count(File.id), func.sum(File.size)
        ).first()
        total_files = result[0] if result else 0
        total_size = result[1] if result else 0
        return {
            "total_users": total_users or 0,
            "total_files": total_files or 0,
            "total_size": total_size or 0,
        }

    def add_or_update_file(
        self, username: str, filename: str, filepath: str, size: int, file_hash: str
    ):
        try:
            file_record = File.query.filter_by(filepath=filepath).first()
            modified_at = datetime.datetime.now()

            if file_record:
                # Update existing record
                file_record.size = size
                file_record.modified_at = modified_at
                file_record.file_hash = file_hash
            else:
                # Create new record
                file_record = File(
                    user_username=username,
                    filename=filename,
                    filepath=filepath,
                    size=size,
                    modified_at=modified_at,
                    file_hash=file_hash,
                )
                db.session.add(file_record)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            logging.error(
                f"Error adding/updating file {filepath} in DB: {e}", exc_info=True
            )
            raise

    def delete_file(self, filepath: str):
        try:
            file_record = File.query.filter_by(filepath=filepath).first()
            if file_record:
                db.session.delete(file_record)
                db.session.commit()
        except Exception as e:
            db.session.rollback()
            logging.error(f"Error deleting file {filepath} from DB: {e}", exc_info=True)
            raise


class NotificationService:
    """Manages user notifications using SQLAlchemy."""

    def create_notification(self, user_id: str, message: str):
        try:
            new_notification = Notification(user_id=user_id, message=message)
            db.session.add(new_notification)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            logging.error(
                f"Error creating notification for user {user_id}: {e}", exc_info=True
            )
            raise

    def get_notifications(self, user_id: str) -> List[Dict]:
        notifications = (
            Notification.query.filter_by(user_id=user_id)
            .order_by(desc(Notification.created_at))
            .all()
        )
        return [
            {
                "id": n.id,
                "message": n.message,
                "is_read": n.is_read,
                "created_at": n.created_at,
            }
            for n in notifications
        ]

    def mark_notification_as_read(self, notification_id: int):
        try:
            notification = db.session.get(Notification, notification_id)
            if notification:
                notification.is_read = True
                db.session.commit()
        except Exception as e:
            db.session.rollback()
            logging.error(
                f"Error marking notification {notification_id} as read: {e}",
                exc_info=True,
            )
            raise
