# TraceIt Server

A Django REST Framework backend for the TraceIt application, which allows users to manage items, upload media, report stolen items, and search through records.

## Features

- JWT-based authentication (via Simple JWT)
- CRUD operations for Items, Item Media, and Stolen Reports
- File uploads with validation for images and videos
- Search endpoint for filtering items by name, serial number, or description
- Consistent response format with pagination
- Custom permissions to ensure resource ownership

## Tech Stack

- Python 3.13
- Django 5.x
- Django REST Framework
- Django Filters
- Simple JWT for authentication
- SQLite (default) or any supported Django database

## Prerequisites

- Python 3.11+ installed
- `pip` for package management
- (Optional) Virtual environment tool (`venv`, `virtualenv`, or similar)

## Setup & Installation

1. Clone the repository:
   ```powershell
   git clone <repo-url> traceit
   cd traceit/server
   ```

2. Create and activate a virtual environment:
   ```powershell
   python -m venv ../env
   & "../env/Scripts/activate.ps1"
   ```

3. Install dependencies:
   ```powershell
   pip install -r requirements.txt
   ```

4. Configure environment variables:
   Create a `.env` file in the `server/` directory (see `.env.example` if provided) and set:
   ```ini
   SECRET_KEY=your_django_secret_key
   DEBUG=True
   ALLOWED_HOSTS=localhost,127.0.0.1
   DATABASE_URL=sqlite:///db.sqlite3
   ```

5. Run database migrations:
   ```powershell
   python manage.py migrate
   ```

6. (Optional) Create a superuser:
   ```powershell
   python manage.py createsuperuser
   ```

## Running the Development Server

```powershell
python manage.py runserver
```

The API will be available at `http://127.0.0.1:8000/`.

## API Endpoints

All API routes are prefixed with `/api/`.

### Authentication

- `POST /api/users/auth/login/` — Obtain JWT access and refresh tokens
- `POST /api/users/auth/refresh/` — Refresh access token
- `POST /api/users/auth/register/` — Register new user (returns OTP email flow)
- `POST /api/users/auth/logout/` — Logout and blacklist refresh token
- `GET /api/users/auth/user/` — Retrieve current user profile
- `PUT /api/users/auth/update-user/` — Update profile
- `POST /api/users/auth/verify-otp/` — Verify registration OTP
- `POST /api/users/auth/resend-otp/` — Resend OTP email

### Items

- `GET /api/items/` — List items (supports filters, search, ordering, pagination)
- `POST /api/items/` — Create new item
- `GET /api/items/{id}/` — Retrieve item details
- `PUT/PATCH /api/items/{id}/` — Update item
- `DELETE /api/items/{id}/` — Delete item

### Item Media

- `GET /api/media/` — List all media files
- `POST /api/media/` — Upload a media file for an item
- `GET /api/media/{id}/` — Retrieve media details
- `DELETE /api/media/{id}/` — Delete media file

### Stolen Reports

- `GET /api/reports/` — List stolen reports
- `POST /api/reports/` — File a new stolen report
- `GET /api/reports/{id}/` — Retrieve a report
- `PUT/PATCH /api/reports/{id}/` — Update report (e.g., mark resolved)
- `DELETE /api/reports/{id}/` — Delete report

### Search

- `GET /api/search/items/?q=<keyword>` — Search items by name, serial number, or description (paginated)

## Response Format

All responses follow a consistent structure:

```json
{
  "message": "Informational message",
  "data": [... or object ...],
  "status": <HTTP status code>,
  "error": null,
  "count": <total items>,
  "next": "<next page URL>",
  "previous": "<previous page URL>"
}
```

Fields `count`, `next`, and `previous` appear only on paginated list endpoints.

## Running Tests

```powershell
python manage.py test
```

## Contributing

Contributions are welcome! Please fork the repo, create a feature branch, and open a pull request.

## License

[MIT License](LICENSE)
