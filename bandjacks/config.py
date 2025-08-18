"""Configuration helper for Bandjacks."""

from bandjacks.services.api.settings import settings, Settings


def get_settings() -> Settings:
    """Get application settings."""
    return settings


__all__ = ["get_settings", "settings"]