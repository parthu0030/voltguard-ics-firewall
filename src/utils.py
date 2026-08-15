"""
VoltGuard — Utility Helpers
==============================
Collection of pure-Python helper functions used throughout the application.

All functions here are:
  - Side-effect free (except where IO is the explicit purpose).
  - Fully type-annotated.
  - Qt-free and database-free (safe to import anywhere, including tests).
  - Documented with Args / Returns / Raises sections.

Usage:
    from src.utils import (
        create_directories,
        current_timestamp,
        calculate_sha256,
        file_size,
        safe_write,
        safe_read,
    )
"""

from __future__ import annotations

import hashlib
import logging
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Union

_log = logging.getLogger("VoltGuard.Utils")


# ---------------------------------------------------------------------------
# Directory Management
# ---------------------------------------------------------------------------

def create_directories(paths: list[Path]) -> dict[Path, bool]:
    """
    Ensure that all paths in ``paths`` exist as directories.

    Each directory (and any missing parents) is created with ``exist_ok=True``,
    so the function is safe to call multiple times.

    Args:
        paths: List of ``Path`` objects to create.

    Returns:
        A dict mapping each path to ``True`` (created / already exists)
        or ``False`` (creation failed due to an OS error).

    Example:
        results = create_directories([Path("logs"), Path("reports")])
        # {'logs': True, 'reports': True}
    """
    results: dict[Path, bool] = {}
    for path in paths:
        try:
            path.mkdir(parents=True, exist_ok=True)
            results[path] = True
            _log.debug("Directory ready: %s", path)
        except OSError as exc:
            _log.error("Failed to create directory %s: %s", path, exc)
            results[path] = False
    return results


# ---------------------------------------------------------------------------
# Timestamps
# ---------------------------------------------------------------------------

def current_timestamp(fmt: str = "%Y-%m-%dT%H:%M:%SZ") -> str:
    """
    Return the current UTC time as a formatted string.

    Args:
        fmt: ``strftime`` format string.
             Defaults to ISO-8601 with a trailing ``Z`` (UTC marker).

    Returns:
        Formatted UTC timestamp string.

    Example:
        ts = current_timestamp()
        # "2026-08-15T21:00:00Z"
    """
    return datetime.now(tz=timezone.utc).strftime(fmt)


def current_local_timestamp(fmt: str = "%Y-%m-%d %H:%M:%S") -> str:
    """
    Return the current **local** time as a formatted string.

    Useful for display in the UI where the user's timezone is preferred.

    Args:
        fmt: ``strftime`` format string.

    Returns:
        Formatted local timestamp string.
    """
    return datetime.now().strftime(fmt)


# ---------------------------------------------------------------------------
# Cryptographic Hash
# ---------------------------------------------------------------------------

def calculate_sha256(file_path: Union[str, Path]) -> Optional[str]:
    """
    Compute the SHA-256 hex digest of a file's contents.

    Reads the file in 64 KB chunks to handle large files without loading
    them entirely into memory.

    Args:
        file_path: Path to the file to hash.

    Returns:
        Lowercase hex digest string (64 characters), or ``None`` if the
        file cannot be read (does not exist, permission error, etc.).

    Example:
        digest = calculate_sha256(Path("voltguard.db"))
        # "3a7bd3e2360..."
    """
    path = Path(file_path)
    if not path.is_file():
        _log.warning("calculate_sha256: file not found at %s", path)
        return None

    sha256 = hashlib.sha256()
    try:
        with path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except OSError as exc:
        _log.error("calculate_sha256 failed for %s: %s", path, exc)
        return None


# ---------------------------------------------------------------------------
# File Size
# ---------------------------------------------------------------------------

def file_size(file_path: Union[str, Path]) -> str:
    """
    Return a human-readable file size string for the given path.

    Args:
        file_path: Path to the file.

    Returns:
        Human-readable size such as ``"4.2 KB"``, ``"1.3 MB"``, or
        ``"512 B"``.  Returns ``"—"`` if the file does not exist or its
        size cannot be determined.

    Example:
        print(file_size("voltguard.db"))  # "28.0 KB"
    """
    path = Path(file_path)
    try:
        size_bytes: int = path.stat().st_size
    except OSError:
        return "—"

    for unit in ("B", "KB", "MB", "GB"):
        if size_bytes < 1024:
            if unit == "B":
                return f"{size_bytes} B"
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024  # type: ignore[assignment]
    return f"{size_bytes:.1f} TB"


# ---------------------------------------------------------------------------
# Safe File I/O
# ---------------------------------------------------------------------------

def safe_write(
    file_path: Union[str, Path],
    content: Union[str, bytes],
    encoding: str = "utf-8",
) -> bool:
    """
    Write ``content`` to ``file_path`` atomically using a temporary file.

    The write is performed to a sibling temp file, then renamed over the
    target path.  This guarantees that a concurrent reader never sees a
    half-written file.

    Args:
        file_path: Destination path.
        content:   String or bytes to write.
        encoding:  Text encoding used when ``content`` is a ``str``.
                   Ignored for ``bytes`` content.

    Returns:
        ``True`` on success, ``False`` if an OS error occurred.

    Example:
        ok = safe_write(Path("reports/report.txt"), "Report content")
    """
    path = Path(file_path)
    mode = "wb" if isinstance(content, bytes) else "w"

    try:
        path.parent.mkdir(parents=True, exist_ok=True)

        # Write to a temporary file in the same directory so the final
        # rename is atomic on the same filesystem.
        fd, tmp_path = tempfile.mkstemp(dir=path.parent, prefix=".tmp_vg_")
        try:
            with os.fdopen(fd, mode, **({"encoding": encoding} if mode == "w" else {})) as fh:
                fh.write(content)
            os.replace(tmp_path, path)  # Atomic rename on POSIX & Windows.
        except Exception:
            # Clean up temp file if rename/write failed.
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise

        _log.debug("safe_write: wrote %d bytes to %s", len(content), path)
        return True

    except OSError as exc:
        _log.error("safe_write failed for %s: %s", path, exc)
        return False


def safe_read(
    file_path: Union[str, Path],
    default: Optional[str] = None,
    encoding: str = "utf-8",
) -> Optional[str]:
    """
    Read the text content of ``file_path``, returning ``default`` on error.

    Args:
        file_path: Path to the file to read.
        default:   Value returned if the file cannot be read.  Defaults
                   to ``None``.
        encoding:  Text encoding to use when reading.

    Returns:
        File content as a string, or ``default`` on any error.

    Example:
        content = safe_read(Path("config.json"), default="{}")
    """
    path = Path(file_path)
    try:
        return path.read_text(encoding=encoding)
    except OSError as exc:
        _log.warning("safe_read: could not read %s (%s); returning default.", path, exc)
        return default


# ---------------------------------------------------------------------------
# Miscellaneous
# ---------------------------------------------------------------------------

def is_writable(path: Union[str, Path]) -> bool:
    """
    Check whether ``path`` (file or directory) is writable by the current process.

    For directories, attempts to create a temporary file inside to perform
    a real write-permission probe rather than relying on ``os.access`` (which
    may return incorrect results on network filesystems).

    Args:
        path: File or directory path to test.

    Returns:
        ``True`` if the path is writable, ``False`` otherwise.
    """
    p = Path(path)
    if p.is_dir():
        try:
            test_file = p / ".voltguard_write_test"
            test_file.touch()
            test_file.unlink()
            return True
        except OSError:
            return False
    elif p.is_file():
        return os.access(p, os.W_OK)
    else:
        # Path does not exist — check parent directory.
        return os.access(p.parent, os.W_OK) if p.parent.exists() else False


def format_duration(seconds: float) -> str:
    """
    Format a duration in seconds as a human-readable string.

    Args:
        seconds: Duration in seconds (non-negative float).

    Returns:
        Human-readable string such as ``"2h 15m 30s"``, ``"4m 5s"``,
        or ``"42s"``.

    Example:
        format_duration(8130)  # "2h 15m 30s"
    """
    total = int(max(0.0, seconds))
    hours, remainder = divmod(total, 3600)
    minutes, secs = divmod(remainder, 60)
    if hours:
        return f"{hours}h {minutes}m {secs}s"
    if minutes:
        return f"{minutes}m {secs}s"
    return f"{secs}s"
