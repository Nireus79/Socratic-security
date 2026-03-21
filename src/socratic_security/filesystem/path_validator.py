"""Path Traversal Prevention"""
from pathlib import Path
from typing import Optional

class PathTraversalError(Exception):
    """Raised when path traversal attempt is detected."""
    pass

class PathValidator:
    """Validates file paths to prevent traversal attacks."""

    def __init__(self, allowed_base_dirs: Optional[list] = None):
        self.allowed_bases = [Path(p).resolve() for p in (allowed_base_dirs or [])]

    def validate_path(self, target_path: Path, base_dir: Path) -> Path:
        """Validate path doesn't escape base directory."""
        resolved = target_path.resolve()
        base_resolved = base_dir.resolve()

        # Check if path is within allowed directory
        try:
            resolved.relative_to(base_resolved)
        except ValueError:
            raise PathTraversalError(f"Path {target_path} escapes base directory")

        # Check for symlink attacks
        if resolved.is_symlink():
            raise PathTraversalError("Symlinks not allowed")

        return resolved

    @staticmethod
    def sanitize_filename(filename: str) -> str:
        """Remove dangerous characters from filename."""
        # Remove path separators and special chars
        sanitized = filename.replace("..", "").replace("\0", "")
        sanitized = sanitized.replace("/", "_").replace("\\", "_")
        return sanitized
