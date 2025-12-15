# Mobywatel-Creator: AI Agent Instructions

## Architecture: Strict 5-Layer Pattern

**Never mix layers.** This is a didactic Flask app demonstrating layered architecture:

| Layer | Files | Responsibility |
|-------|-------|----------------|
| Edge | `nginx.conf` | Reverse proxy, SSL, static files |
| WSGI | `wsgi.py` | Gunicorn process management |
| Controller | `app.py` | **Routing only** - delegates to services |
| Service | `user_auth.py`, `services.py` | **All business logic** |
| Data | `models.py` | SQLAlchemy ORM models |

### Critical Pattern: Thin Controllers
```python
# ✅ CORRECT - delegate to service
@app.route("/login", methods=["POST"])
def login():
    success, msg = auth_manager.authenticate_user(username, password)
    return jsonify({"success": success, "message": msg})

# ❌ WRONG - business logic in controller  
def login():
    user = User.query.filter_by(username=username).first()  # Don't query here!
```

## Quick Commands

```bash
# Development
flask run                                    # Dev server
docker-compose up --build                    # Docker stack

# Production  
gunicorn --workers 3 --bind 0.0.0.0:5000 wsgi:application

# Database migrations (REQUIRED after models.py changes)
flask db migrate -m "description"
flask db upgrade

# Testing (coverage auto-enabled via pytest.ini)
pytest                                       # All tests
pytest tests/test_user_auth_extended.py     # Specific file
```

## Key Services (`services.py`)

- **AccessKeyService** - Registration keys with expiration: `generate_access_key()`, `validate_access_key()`, `use_access_key()`
- **NotificationService** - Per-user notifications with read/unread state
- **AnnouncementService** - Site-wide announcements with expiration
- **StatisticsService** - User/system statistics aggregation

## Security Patterns

- **Passwords**: bcrypt with 12 rounds (`UserAuthManager.BCRYPT_ROUNDS = 12`)
- **Rate limiting**: `@limiter.limit()` on `/login`, `/register` (Redis-backed)
- **CSRF**: `CSRFProtect(app)` enabled by default, all forms need tokens
- **Sessions**: Redis-backed (`SESSION_TYPE = "redis"`)

## File Structure

```
user_data/<username>/    # User-specific files (dowodnowy.html, QR codes)
auth_data/database.db    # SQLite database
logs/                    # Rotating logs (app.log, user_activity.log)
static/                  # Frontend assets
templates/               # Jinja2 templates
tests/conftest.py        # Test fixtures (app, db_session, registered_user)
```

## Environment Variables

```bash
FLASK_ENV=production|development
SECRET_KEY=<required-in-prod>
ADMIN_USERNAME=<admin>
ADMIN_PASSWORD=<admin-pass>
APP_ENV_MODE=development|production|load_test  # load_test disables CSRF/rate-limits
RATELIMIT_STORAGE_URL=redis://redis:6379
```

## Admin Routes

All require `@admin_required` decorator, prefixed `/admin/`:
- `/admin/api/users` - User management
- `/admin/api/access-keys` - Key generation
- `/admin/api/backup/full` - System backup (DB + user files zip)
- `/admin/api/impersonate/start` - User impersonation

## Common Gotchas

1. **Always run migrations** after `models.py` changes
2. **Redis required** locally - sessions use port 6379
3. **Business logic → services** - never in `app.py` routes
4. **Use `@login_required`** from `flask_login` for protected routes
5. **File writes are hash-optimized** - `POST /` only writes if SHA256 differs
6. **PESEL generator** (`pesel_generator.py`) has century modifiers and gender logic

## Testing Patterns

Fixtures in `tests/conftest.py`:
- `app` - Flask app with in-memory SQLite, CSRF disabled
- `db_session` - Auto-rollback database session
- `user_auth_manager` - Initialized UserAuthManager
- `registered_user` - Pre-created test user

Test naming: `test_<functionality>_<scenario>`
