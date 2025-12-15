# GEMINI.md: Mobywatel-Creator

## Project Overview

This project, "Mobywatel-Creator," is a didactic web application built with Python and Flask. Its primary purpose is to serve as a comprehensive learning example for modern software engineering principles, including SOLID, DRY, Separation of Concerns, and layered architecture.

The application allows users to generate and manage mock "mObywatel" documents. It features user registration, authentication, and a dashboard for document manipulation.

**Core Technologies:**

*   **Backend:** Python, Flask
*   **WSGI Server:** Gunicorn
*   **Web Server/Reverse Proxy:** Nginx
*   **Database:** SQLite
*   **Frontend:** HTML, CSS, JavaScript (served via Flask templates)
*   **Testing:** Pytest
*   **Code Quality:** Black, Flake8 (managed via pre-commit)

**Architectural Design:**

The application follows a strict layered architecture to ensure separation of concerns and maintainability:

1.  **Edge Layer (Nginx):** Handles incoming requests, serves static files directly for performance, terminates SSL, and acts as a reverse proxy, forwarding application requests to Gunicorn.
2.  **Application Server Layer (Gunicorn):** Manages worker processes and translates HTTP requests into the WSGI standard for Flask.
3.  **Application/Controller Layer (Flask - `app.py`):** Routes incoming requests to the appropriate view functions, handles request/response orchestration, and manages user sessions.
4.  **Service/Business Logic Layer (`user_auth.py`, `services.py`):** Encapsulates the core business logic, such as user authentication, registration, and data processing, keeping it independent from the web layer.
5.  **Data Access Layer (`models.py`):** Defines the database schema and provides an interface for interacting with the SQLite database.

## Building and Running

### 1. Installation

First, install the required Python dependencies. It is recommended to use a virtual environment.

```bash
# Install production dependencies
pip install -r requirements.txt

# Install development dependencies (for testing and linting)
pip install -r requirements-dev.txt
```

### 2. Running the Application

**For Development:**

You can run the application using the built-in Flask development server.

```bash
# Make sure the .env file is configured with FLASK_APP=app.py and FLASK_ENV=development
flask run
```

Alternatively, you can run `app.py` directly:

```bash
python app.py
```

**For Production:**

The project is designed to be deployed with Gunicorn and Nginx. The `README.md` and associated scripts (`deploy_ubuntu.sh`, `start_server.sh`) detail a production setup using a `systemd` service.

The core command to run the application with Gunicorn is:

```bash
gunicorn --workers 3 --bind 0.0.0.0:5000 wsgi:app
```

*Note: The production setup described in the documentation uses a Unix socket for communication between Nginx and Gunicorn for better performance and security.*

### 3. Running Tests

The project uses `pytest` for testing.

```bash
pytest
```

## Development Conventions

*   **Code Style:** The project uses `black` for code formatting and `flake8` for linting. These are enforced automatically using pre-commit hooks. To set this up, run:
    ```bash
    pre-commit install
    ```
*   **Testing:** All new features should be accompanied by tests in the `tests/` directory. The project aims for high test coverage.
*   **Architecture:** Adherence to the layered architecture is critical. Business logic should reside in service files, not in the Flask view functions (`app.py`).
*   **Database:** Database interactions are managed through the `models.py` file, and schema initialization is handled by `init_db()` in the same file. For production, migrations would be a necessary addition.
*   **Secrets:** Application secrets (like `SECRET_KEY`) are managed via `production_config.py` and should be overridden with environment variables or a secure secret management system in production.
