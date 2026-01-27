"""UTMP constants and file paths for user accounting.

This module defines constants used for reading UTMP (User Accounting) files
on Unix/Linux systems. UTMP files track user logins, system boots, and other
system state changes. These constants correspond to the values in the ut_type
field of the struct utmp C structure.

The module provides:
- Constants for UTMP record types (LOGIN_PROCESS, USER_PROCESS, etc.)
- Standard file paths for UTMP and WTMP files

Used by nftfw_utmp.py for reading successful login records to populate the
whitelist with authenticated user IP addresses.

Example:
    Checking for user login records::

        from nftfw.utmpconst import USER_PROCESS, WTMP_FILE

        # Read WTMP to find successful logins
        # Filter for records where ut_type == USER_PROCESS
        if record.ut_type == USER_PROCESS:
            print(f"User login from {record.ut_host}")

See Also:
    - nftfw_utmp: UTMP file reader implementation
    - whitelist: Uses UTMP data to generate whitelist entries
"""

from __future__ import annotations

from typing import Final

# UTMP record type constants (values for ut_type field)

EMPTY: Final[int] = 0         # No valid user accounting information
RUN_LVL: Final[int] = 1       # The system's runlevel
BOOT_TIME: Final[int] = 2     # Time of system boot
NEW_TIME: Final[int] = 3      # Time after system clock changed
OLD_TIME: Final[int] = 4      # Time when system clock changed
INIT_PROCESS: Final[int] = 5  # Process spawned by the init process
LOGIN_PROCESS: Final[int] = 6 # Session leader of a logged in user
USER_PROCESS: Final[int] = 7  # Normal process (successful login)
DEAD_PROCESS: Final[int] = 8  # Terminated process

# Standard UTMP file paths

UTMP_FILE: Final[str] = "/var/run/utmp"  # Current login sessions
WTMP_FILE: Final[str] = "/var/log/wtmp"  # Historical login records
