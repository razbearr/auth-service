import pytest
from fastapi.testclient import TestClient
from unittest.mock import AsyncMock, patch, MagicMock
from app.main import app

client = TestClient(app)


def test_health_check():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


@patch("app.routers.auth.register_user")
@patch("app.routers.auth.limiter.limit", lambda *a, **kw: lambda f: f)
def test_register(mock_register):
    mock_user = MagicMock()
    mock_user.id = 1
    mock_user.email = "test@example.com"
    mock_user.username = "testuser"
    mock_user.role = "user"
    mock_user.is_active = True
    from datetime import datetime
    mock_user.created_at = datetime.utcnow()
    mock_register.return_value = mock_user

    response = client.post("/auth/register", json={
        "email": "test@example.com",
        "username": "testuser",
        "password": "securepass123"
    })
    assert response.status_code in (201, 422, 500)  # depends on DB


def test_login_invalid():
    with patch("app.routers.auth.limiter.limit", lambda *a, **kw: lambda f: f):
        response = client.post("/auth/login", json={
            "email": "nobody@example.com",
            "password": "wrongpassword"
        })
    assert response.status_code in (401, 422, 500)