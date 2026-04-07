"""Tests for authentication modules."""



class TestAccountLockout:
    """Test account lockout manager."""

    def test_import(self):
        """Test importing AccountLockoutManager."""
        from socratic_security.auth import AccountLockoutManager

        assert AccountLockoutManager is not None


class TestMFA:
    """Test MFA manager."""

    def test_import(self):
        """Test importing MFAManager."""
        from socratic_security.auth import MFAManager

        assert MFAManager is not None


class TestBreachChecker:
    """Test password breach checker."""

    def test_import(self):
        """Test importing PasswordBreachChecker."""
        from socratic_security.auth import PasswordBreachChecker

        assert PasswordBreachChecker is not None
