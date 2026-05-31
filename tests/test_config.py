"""Tests for infrastructure configuration (RedisConfig)."""
import os
import pytest
from unittest.mock import patch, MagicMock


class TestRedisConfigDefaults:
    """Test RedisConfig with default (no env vars)."""

    def test_default_url(self):
        from agentic_ai.infrastructure.config import RedisConfig
        c = RedisConfig()
        assert c.url == "redis://localhost:6379"

    def test_default_password_empty(self):
        from agentic_ai.infrastructure.config import RedisConfig
        c = RedisConfig()
        assert c.password == ""

    def test_default_tls_false(self):
        from agentic_ai.infrastructure.config import RedisConfig
        c = RedisConfig()
        assert c.tls is False

    def test_default_client_kwargs_no_tls(self):
        from agentic_ai.infrastructure.config import RedisConfig
        c = RedisConfig()
        kwargs = c.get_client_kwargs()
        assert kwargs == {"decode_responses": True}
        assert "ssl" not in kwargs


class TestRedisConfigURL:
    """Test REDIS_URL override."""

    def test_url_from_env(self):
        from agentic_ai.infrastructure.config import RedisConfig
        with patch.dict(os.environ, {"REDIS_URL": "redis://myhost:6380"}):
            c = RedisConfig()
            assert c.url == "redis://myhost:6380"

    def test_url_with_password_in_url(self):
        from agentic_ai.infrastructure.config import RedisConfig
        with patch.dict(os.environ, {"REDIS_URL": "redis://:s3cret@myhost:6379/0"}):
            c = RedisConfig()
            assert c.url == "redis://:s3cret@myhost:6379/0"


class TestRedisConfigPassword:
    """Test REDIS_PASSWORD handling."""

    def test_password_from_env(self):
        from agentic_ai.infrastructure.config import RedisConfig
        with patch.dict(os.environ, {"REDIS_PASSWORD": "mypassword"}):
            c = RedisConfig()
            assert c.password == "mypassword"

    def test_password_default_empty(self):
        from agentic_ai.infrastructure.config import RedisConfig
        c = RedisConfig()
        assert c.password == ""


class TestRedisConfigTLS:
    """Test REDIS_TLS flag."""

    def test_tls_true(self):
        from agentic_ai.infrastructure.config import RedisConfig
        for val in ("1", "true", "True", "TRUE", "yes", "Yes", "YES"):
            with patch.dict(os.environ, {"REDIS_TLS": val}):
                c = RedisConfig()
                assert c.tls is True, f"Expected True for REDIS_TLS={val!r}"

    def test_tls_false(self):
        from agentic_ai.infrastructure.config import RedisConfig
        for val in ("0", "false", "no", ""):
            with patch.dict(os.environ, {"REDIS_TLS": val}, clear=False):
                # Need to unset if empty
                c = RedisConfig()
                # Empty string won't be in env for the default case
                if val == "":
                    os.environ.pop("REDIS_TLS", None)
                    c = RedisConfig()
                assert c.tls is False, f"Expected False for REDIS_TLS={val!r}"

    def test_tls_adds_ssl_kwarg(self):
        from agentic_ai.infrastructure.config import RedisConfig
        with patch.dict(os.environ, {"REDIS_TLS": "true"}):
            c = RedisConfig()
            kwargs = c.get_client_kwargs()
            assert kwargs["ssl"] is True

    def test_tls_default_no_ssl(self):
        from agentic_ai.infrastructure.config import RedisConfig
        c = RedisConfig()
        kwargs = c.get_client_kwargs()
        assert "ssl" not in kwargs


class TestRedisConfigCreateClient:
    """Test create_client() method."""

    def test_create_client_calls_from_url(self):
        from agentic_ai.infrastructure.config import RedisConfig
        mock_client = MagicMock()
        with patch("redis.Redis.from_url", return_value=mock_client) as mock_from_url:
            c = RedisConfig()
            client = c.create_client()
            mock_from_url.assert_called_once_with(
                "redis://localhost:6379", decode_responses=True
            )
            assert client is mock_client

    def test_create_client_with_custom_url(self):
        from agentic_ai.infrastructure.config import RedisConfig
        mock_client = MagicMock()
        with patch("redis.Redis.from_url", return_value=mock_client) as mock_from_url:
            with patch.dict(os.environ, {"REDIS_URL": "redis://custom:6380"}):
                c = RedisConfig()
                client = c.create_client()
                mock_from_url.assert_called_once_with(
                    "redis://custom:6380", decode_responses=True
                )

    def test_create_client_with_tls(self):
        from agentic_ai.infrastructure.config import RedisConfig
        mock_client = MagicMock()
        with patch("redis.Redis.from_url", return_value=mock_client) as mock_from_url:
            with patch.dict(os.environ, {"REDIS_TLS": "true"}):
                c = RedisConfig()
                client = c.create_client()
                mock_from_url.assert_called_once_with(
                    "redis://localhost:6379", decode_responses=True, ssl=True
                )


class TestRedisConfigURLWithEmbeddedPassword:
    """Test URL parsing with embedded password."""

    def test_url_with_user_and_password(self):
        from agentic_ai.infrastructure.config import RedisConfig
        with patch.dict(os.environ, {"REDIS_URL": "redis://user:pass@host:6379/0"}):
            c = RedisConfig()
            assert c.url == "redis://user:pass@host:6379/0"

    def test_create_client_uses_full_url(self):
        from agentic_ai.infrastructure.config import RedisConfig
        mock_client = MagicMock()
        with patch("redis.Redis.from_url", return_value=mock_client) as mock_from_url:
            with patch.dict(os.environ, {"REDIS_URL": "redis://user:pass@host:6379/0"}):
                c = RedisConfig()
                c.create_client()
                mock_from_url.assert_called_once_with(
                    "redis://user:pass@host:6379/0", decode_responses=True
                )