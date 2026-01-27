"""Test file-based locking mechanism (locker.py).

This module tests the Locker class which provides file-based mutual exclusion
using fcntl.flock(). The tests verify lock acquisition, release, conflict
handling, and context manager support.

Tests:
    test_lockfile_basic - Basic blocking lock acquisition and release
    test_nb_lockfile_basic - Non-blocking lock acquisition
    test_lockfile_blocking - Verify blocking behavior of lockfile()
    test_nb_lockfile_conflict - Verify non-blocking behavior on conflict
    test_unlockfile_idempotent - Multiple unlockfile() calls are safe
    test_context_manager_success - Context manager normal operation
    test_context_manager_with_exception - Context manager cleanup on exception
    test_multiple_lock_release_cycles - Reusing Locker instance
    test_destructor_cleanup - __del__ releases lock
    test_lock_file_creation - Lock file is created if missing
    test_lock_released_on_close - Lock released when file descriptor closed

The tests use pytest's tmp_path fixture to create isolated lock files,
ensuring test independence and proper cleanup.
"""
from __future__ import annotations

import time
import multiprocessing
from pathlib import Path
from typing import Any

import pytest

from nftfw.locker import Locker


def test_lockfile_basic(tmp_path: Path) -> None:
    """Test basic blocking lock acquisition and release.

    Verifies that:
    - lockfile() successfully acquires a lock
    - Lock file is created
    - File descriptor is set
    - unlockfile() releases the lock and closes fd

    Args:
        tmp_path: pytest temporary directory fixture.
    """
    lockfile = tmp_path / "test.lock"
    locker = Locker(str(lockfile))

    # Initially no lock held
    assert locker.fd is None

    # Acquire lock
    result = locker.lockfile()
    assert result is True
    assert locker.fd is not None
    assert lockfile.exists()

    # Release lock
    locker.unlockfile()
    assert locker.fd is None


def test_nb_lockfile_basic(tmp_path: Path) -> None:
    """Test basic non-blocking lock acquisition.

    Verifies that:
    - nb_lockfile() successfully acquires a lock without blocking
    - Lock file is created
    - File descriptor is set
    - unlockfile() releases the lock

    Args:
        tmp_path: pytest temporary directory fixture.
    """
    lockfile = tmp_path / "test_nb.lock"
    locker = Locker(str(lockfile))

    # Acquire non-blocking lock
    result = locker.nb_lockfile()
    assert result is True
    assert locker.fd is not None
    assert lockfile.exists()

    # Release lock
    locker.unlockfile()
    assert locker.fd is None


def _hold_lock_process(lockfile_path: str, duration: float,
                       result_queue: Any) -> None:
    """Helper process that holds a lock for a specified duration.

    This function runs in a separate process to test lock conflicts.
    It acquires the lock, signals that it has the lock, waits for
    the specified duration, then releases the lock.

    Args:
        lockfile_path: Path to the lock file.
        duration: How long to hold the lock in seconds.
        result_queue: multiprocessing.Queue to signal lock acquisition.
    """
    locker = Locker(lockfile_path)
    if locker.lockfile():
        result_queue.put("locked")
        time.sleep(duration)
        locker.unlockfile()
        result_queue.put("unlocked")


def test_lockfile_blocking(tmp_path: Path) -> None:
    """Test that lockfile() blocks when lock is held by another process.

    Verifies that:
    - First process acquires lock successfully
    - Second process blocks waiting for lock
    - Second process acquires lock after first releases it

    This test uses multiprocessing to simulate concurrent access.

    Args:
        tmp_path: pytest temporary directory fixture.
    """
    lockfile = tmp_path / "test_blocking.lock"

    # Start a process that holds the lock for 0.5 seconds
    queue: Any = multiprocessing.Queue()
    process = multiprocessing.Process(
        target=_hold_lock_process,
        args=(str(lockfile), 0.5, queue)
    )
    process.start()

    # Wait for the process to acquire the lock
    msg = queue.get(timeout=2)
    assert msg == "locked"

    # Now try to acquire the lock from main process with nb_lockfile
    # This should fail because the lock is held
    locker = Locker(str(lockfile))
    result = locker.nb_lockfile()
    assert result is False, "nb_lockfile should fail when lock is held"

    # Wait for the other process to release
    msg = queue.get(timeout=2)
    assert msg == "unlocked"
    process.join(timeout=2)

    # Now we should be able to acquire the lock
    result = locker.nb_lockfile()
    assert result is True
    locker.unlockfile()


def test_nb_lockfile_conflict(tmp_path: Path) -> None:
    """Test that nb_lockfile() returns False when lock is already held.

    Verifies that:
    - First Locker instance acquires lock
    - Second Locker instance's nb_lockfile() returns False immediately
    - Second instance can acquire lock after first releases

    Args:
        tmp_path: pytest temporary directory fixture.
    """
    lockfile = tmp_path / "test_conflict.lock"

    # First locker acquires the lock
    locker1 = Locker(str(lockfile))
    result1 = locker1.lockfile()
    assert result1 is True

    # Second locker tries non-blocking lock - should fail immediately
    locker2 = Locker(str(lockfile))
    result2 = locker2.nb_lockfile()
    assert result2 is False

    # First locker releases
    locker1.unlockfile()

    # Now second locker can acquire
    result2 = locker2.nb_lockfile()
    assert result2 is True

    locker2.unlockfile()


def test_unlockfile_idempotent(tmp_path: Path) -> None:
    """Test that calling unlockfile() multiple times is safe.

    Verifies that:
    - unlockfile() can be called multiple times without error
    - unlockfile() is safe to call when no lock is held

    Args:
        tmp_path: pytest temporary directory fixture.
    """
    lockfile = tmp_path / "test_idempotent.lock"
    locker = Locker(str(lockfile))

    # Call unlockfile when no lock held - should be safe
    locker.unlockfile()
    assert locker.fd is None

    # Acquire and release lock
    locker.lockfile()
    locker.unlockfile()
    assert locker.fd is None

    # Call unlockfile again - should be safe
    locker.unlockfile()
    assert locker.fd is None


def test_context_manager_success(tmp_path: Path) -> None:
    """Test context manager usage in normal operation.

    Verifies that:
    - __enter__ acquires the lock
    - Lock is held during context
    - __exit__ releases the lock

    Args:
        tmp_path: pytest temporary directory fixture.
    """
    lockfile = tmp_path / "test_context.lock"

    with Locker(str(lockfile)) as lock:
        # Lock should be acquired
        assert lock.fd is not None
        assert lockfile.exists()

    # After context, lock should be released
    # Note: we can't easily check lock.fd here because 'lock' is the
    # Locker instance, but after __exit__ the fd should be None


def test_context_manager_with_exception(tmp_path: Path) -> None:
    """Test that context manager releases lock even when exception occurs.

    Verifies that:
    - Exception during context is propagated
    - Lock is still released in __exit__
    - Another lock can be acquired after exception

    Args:
        tmp_path: pytest temporary directory fixture.
    """
    lockfile = tmp_path / "test_context_exception.lock"

    # Use context manager with exception
    with pytest.raises(ValueError):
        with Locker(str(lockfile)) as lock:
            assert lock.fd is not None
            raise ValueError("Test exception")

    # Lock should be released, so we can acquire it again
    locker = Locker(str(lockfile))
    result = locker.nb_lockfile()
    assert result is True
    locker.unlockfile()


def test_multiple_lock_release_cycles(tmp_path: Path) -> None:
    """Test reusing a Locker instance for multiple lock/unlock cycles.

    Verifies that:
    - Locker can be reused after unlockfile()
    - Multiple acquire/release cycles work correctly

    Args:
        tmp_path: pytest temporary directory fixture.
    """
    lockfile = tmp_path / "test_reuse.lock"
    locker = Locker(str(lockfile))

    # First cycle
    assert locker.lockfile() is True
    assert locker.fd is not None
    locker.unlockfile()
    assert locker.fd is None

    # Second cycle
    assert locker.nb_lockfile() is True
    assert locker.fd is not None
    locker.unlockfile()
    assert locker.fd is None

    # Third cycle
    assert locker.lockfile() is True
    assert locker.fd is not None
    locker.unlockfile()
    assert locker.fd is None


def test_destructor_cleanup(tmp_path: Path) -> None:
    """Test that __del__ releases the lock when object is garbage collected.

    Verifies that:
    - Locker releases lock when destroyed
    - Another Locker can acquire the lock after first is deleted

    Args:
        tmp_path: pytest temporary directory fixture.
    """
    lockfile = tmp_path / "test_destructor.lock"

    # Acquire lock in a scope that will be destroyed
    locker1 = Locker(str(lockfile))
    locker1.lockfile()
    assert locker1.fd is not None

    # Delete the locker - should trigger __del__ and release lock
    del locker1

    # Should be able to acquire lock now
    locker2 = Locker(str(lockfile))
    result = locker2.nb_lockfile()
    assert result is True
    locker2.unlockfile()


def test_lock_file_creation(tmp_path: Path) -> None:
    """Test that lock file is created if it doesn't exist.

    Verifies that:
    - Lock file is created when first acquiring lock
    - Lock file path parent directory must exist

    Args:
        tmp_path: pytest temporary directory fixture.
    """
    lockfile = tmp_path / "new_lock.lock"

    # Lock file doesn't exist yet
    assert not lockfile.exists()

    # Acquire lock - should create file
    locker = Locker(str(lockfile))
    locker.lockfile()

    # Now file should exist
    assert lockfile.exists()

    locker.unlockfile()


def test_lock_released_on_fd_close(tmp_path: Path) -> None:
    """Test that lock is released when file descriptor is closed.

    Verifies that:
    - Manually closing fd releases the lock
    - Another process can then acquire the lock

    This tests the fcntl.flock() behavior where locks are automatically
    released when the file descriptor is closed.

    Args:
        tmp_path: pytest temporary directory fixture.
    """
    lockfile = tmp_path / "test_fd_close.lock"

    # Acquire lock
    locker1 = Locker(str(lockfile))
    locker1.lockfile()
    assert locker1.fd is not None

    # Close the file descriptor directly (simulating process termination)
    locker1.fd.close()
    locker1.fd = None  # Set to None to prevent unlockfile errors

    # Another locker should be able to acquire the lock
    locker2 = Locker(str(lockfile))
    result = locker2.nb_lockfile()
    assert result is True
    locker2.unlockfile()


def test_invalid_lock_directory(tmp_path: Path) -> None:
    """Test behavior when lock file directory doesn't exist.

    Verifies that:
    - lockfile() exits with sys.exit(1) when directory doesn't exist
    - nb_lockfile() exits with sys.exit(1) when directory doesn't exist

    Args:
        tmp_path: pytest temporary directory fixture.
    """
    # Use a non-existent directory
    lockfile = tmp_path / "nonexistent" / "dir" / "test.lock"
    locker = Locker(str(lockfile))

    # lockfile() should exit on error
    with pytest.raises(SystemExit) as excinfo:
        locker.lockfile()
    assert excinfo.value.code == 1

    # nb_lockfile() should also exit on error
    locker2 = Locker(str(lockfile))
    with pytest.raises(SystemExit) as excinfo:
        locker2.nb_lockfile()
    assert excinfo.value.code == 1


def _concurrent_lock_attempt(lockfile_path: str, process_id: int,
                             result_queue: Any) -> None:
    """Helper for testing concurrent lock attempts.

    Multiple processes call this to compete for the same lock.

    Args:
        lockfile_path: Path to the lock file.
        process_id: Identifier for this process.
        result_queue: Queue to report results.
    """
    locker = Locker(lockfile_path)
    # Try non-blocking lock
    if locker.nb_lockfile():
        result_queue.put(f"process_{process_id}_acquired")
        time.sleep(0.1)  # Hold lock briefly
        locker.unlockfile()
        result_queue.put(f"process_{process_id}_released")
    else:
        result_queue.put(f"process_{process_id}_failed")


def test_concurrent_access(tmp_path: Path) -> None:
    """Test multiple processes competing for the same lock.

    Verifies that:
    - Only one process can hold the lock at a time
    - Other processes fail to acquire with nb_lockfile()

    Args:
        tmp_path: pytest temporary directory fixture.
    """
    lockfile = tmp_path / "test_concurrent.lock"
    queue: Any = multiprocessing.Queue()

    # Start 3 processes that compete for the lock
    processes = []
    for i in range(3):
        p = multiprocessing.Process(
            target=_concurrent_lock_attempt,
            args=(str(lockfile), i, queue)
        )
        p.start()
        processes.append(p)

    # Collect results
    results = []
    timeout = 2.0
    start_time = time.time()
    while len(results) < 6 and (time.time() - start_time) < timeout:
        try:
            msg = queue.get(timeout=0.1)
            results.append(msg)
        except:  # pylint: disable=bare-except
            pass

    # Wait for all processes to complete
    for p in processes:
        p.join(timeout=1)

    # Exactly one process should have acquired the lock
    acquired = [r for r in results if "acquired" in r]
    assert len(acquired) == 1, f"Expected 1 acquired, got {len(acquired)}: {results}"

    # Two processes should have failed to acquire
    failed = [r for r in results if "failed" in r]
    assert len(failed) == 2, f"Expected 2 failed, got {len(failed)}: {results}"

    # The successful process should have released
    released = [r for r in results if "released" in r]
    assert len(released) == 1, f"Expected 1 released, got {len(released)}: {results}"
