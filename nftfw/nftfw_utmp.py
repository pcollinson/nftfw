"""Access the utmp/wtmp file using the C library utmp API.

This module provides Python access to Unix/Linux user accounting databases
(utmp/wtmp) via ctypes bindings to the C library (glibc). It defines Python
equivalents of the C structures and wraps the utmp API functions.

**UTMP/WTMP Overview:**

utmp and wtmp are system files that record user login/logout information:
    - utmp: Current login sessions (/var/run/utmp)
    - wtmp: Historical login/logout records (/var/log/wtmp)

**Structure Definitions:**

This module defines Python ctypes structures that match the C utmp structures:
    - Exit_Status_t: Exit status for dead processes
    - UtTv_t: Timeval structure (seconds and microseconds)
    - Utmp_t: Main utmp record structure

**Classes:**

Utmp
    Low-level interface to C library utmp functions. Wraps setutent(),
    utmpname(), getutent(), and endutent() from libc.

UtmpDecode
    High-level wrapper that decodes binary utmp records into Python-friendly
    values. Converts C strings to Python strings and decodes IP addresses
    (both IPv4 and IPv6).

**Usage Pattern:**

1. Create Utmp instance (loads libc)
2. Call utmpname() to select file (wtmp or utmp)
3. Call setutent() to open file
4. Call getutent() or getutentbytype() to read records
5. Wrap records with UtmpDecode for easier access
6. Call endutent() to close file

**Related Modules:**
    - utmpconst: Constants for utmp record types (USER_PROCESS, etc.)
    - whitelist: Uses this module to scan wtmp for successful logins

Example:
    Read all user login records from wtmp::

        from nftfw.nftfw_utmp import Utmp, UtmpDecode
        from nftfw.utmpconst import USER_PROCESS, WTMP_FILE

        ut = Utmp()
        ut.utmpname(WTMP_FILE)
        ut.setutent()

        for rec in ut.getutentbytype(USER_PROCESS):
            decoded = UtmpDecode(rec)
            print(f"{decoded.ut_user} from {decoded.ut_addr}")

        ut.endutent()

    Find specific user's logins::

        for rec in ut.getutentbytype(USER_PROCESS):
            decoded = UtmpDecode(rec)
            if decoded.ut_user == "john":
                print(f"Login from {decoded.ut_addr} at {decoded.ut_tv.tv_sec}")
"""
from __future__ import annotations

# pylint: disable=wildcard-import, unused-wildcard-import, no-name-in-module

import socket
import struct
from typing import Any
from ctypes import (
    CDLL, POINTER, Structure,
    c_char, c_char_p, c_int, c_short
)
from ctypes.util import find_library
from .utmpconst import *


# Definitions are derived from running ccp
# on a c file containing
# #include <utmpx.h>

# Structure sizes
UT_LINESIZE = 32   # chars in ut_line
UT_IDSIZE = 4      # chars in ut_line
UT_USERSIZE = 32   # chars in ut_user
UT_HOSTSIZE = 256  # chars in ut_host

class Exit_Status_t(Structure):
    """Exit status structure for dead processes in utmp records.

    This ctypes Structure matches the C struct __exit_status from utmpx.h.
    It records process termination information for DEAD_PROCESS records.

    **C Definition:**

    .. code-block:: c

        struct __exit_status {
            short int __e_termination;
            short int __e_exit;
        };

    **Fields:**
        e_termination: Process termination status
        e_exit: Process exit status

    This structure is typically only meaningful for DEAD_PROCESS type records.
    """
    # pylint: disable=invalid-name,too-few-public-methods
    _fields_ = [("e_termination", c_short),
                ("e_exit", c_short)]

class UtTv_t(Structure):
    """Timeval structure for utmp records.

    This ctypes Structure matches the C struct for ut_tv from utmpx.h.
    It records the timestamp when the utmp record was created.

    **C Definition:**

    .. code-block:: c

        struct {
            __int32_t tv_sec;
            __int32_t tv_usec;
        } ut_tv;

    **Fields:**
        tv_sec: Seconds since Unix epoch (1970-01-01 00:00:00 UTC)
        tv_usec: Microseconds (0-999999)

    Use tv_sec for most purposes. The tv_usec field provides sub-second
    precision if needed.
    """
    # pylint: disable=invalid-name,too-few-public-methods
    _fields_ = [('tv_sec', c_int),
                ('tv_usec', c_int)]

class Utmp_t(Structure):          # pylint: disable=invalid-name
    """Main utmp record structure.

    This ctypes Structure matches the C struct utmpx from utmpx.h. Each record
    in the utmp/wtmp files is an instance of this structure.

    **C Definition:**

    .. code-block:: c

        typedef int __pid_t;
        typedef signed int __int32_t;

        struct utmpx {
            short int ut_type;
            __pid_t ut_pid;
            char ut_line[32];
            char ut_id[4];
            char ut_user[32];
            char ut_host[256];
            struct __exit_status ut_exit;
            __int32_t ut_session;
            struct {
                __int32_t tv_sec;
                __int32_t tv_usec;
            } ut_tv;
            __int32_t ut_addr_v6[4];
            char __glibc_reserved[20];
        };

    **Fields:**
        ut_type: Record type (USER_PROCESS, DEAD_PROCESS, etc. from utmpconst)
        ut_pid: Process ID of login process
        ut_line: Terminal device name (e.g., "tty1", "pts/0")
        ut_id: Terminal identifier (usually last 4 chars of ut_line)
        ut_user: Username (up to 32 characters)
        ut_host: Hostname or IP address of remote login (up to 256 characters)
        ut_exit: Exit status structure (for DEAD_PROCESS records)
        ut_session: Session ID
        ut_tv: Timestamp structure (seconds and microseconds)
        ut_addr_v6: IPv6 address (4 32-bit integers, also used for IPv4)
        reserved: Reserved space for future use

    **IP Address Storage:**

    The ut_addr_v6 array can store both IPv4 and IPv6 addresses:
        - IPv4: Stored in ut_addr_v6[0], other elements are 0
        - IPv6: All 4 elements used (128 bits total)

    Use UtmpDecode class to automatically decode IP addresses into strings.
    """
    # pylint: disable=invalid-name,too-few-public-methods

    _fields_ = [('ut_type', c_short),
                ('ut_pid', c_int),
                ('ut_line', c_char * UT_LINESIZE),
                ('ut_id', c_char * UT_IDSIZE),
                ('ut_user', c_char * UT_USERSIZE),
                ('ut_host', c_char * UT_HOSTSIZE),
                ('ut_exit', Exit_Status_t),
                ('ut_session', c_int),
                ('ut_tv', UtTv_t),
                ('ut_addr_v6', c_int * 4),
                ('reserved', c_char * 20)]

class Utmp:
    """Interface to the utmp reading functions in glibc.

    This class provides Python wrappers around the C library utmp functions
    using ctypes. It allows reading utmp/wtmp files which record user login
    and logout activity.

    **Attributes:**
        libc: CDLL instance for C library containing utmp functions

    **Typical Workflow:**

    1. Create Utmp instance (loads libc via ctypes)
    2. Call utmpname(filename) to select utmp or wtmp file
    3. Call setutent() to open/rewind file
    4. Call getutent() repeatedly to read records, or use getutentbytype()
    5. Call endutent() to close file

    **C Library Functions Wrapped:**
        - setutent(): Rewind to start of file
        - utmpname(): Select which utmp file to read
        - getutent(): Read next record
        - endutent(): Close file

    Example:
        Read all records from wtmp::

            from nftfw.nftfw_utmp import Utmp
            from nftfw.utmpconst import WTMP_FILE

            ut = Utmp()
            ut.utmpname(WTMP_FILE)
            ut.setutent()

            while True:
                rec = ut.getutent()
                if not rec:
                    break
                print(f"Type: {rec.ut_type}, User: {rec.ut_user.decode()}")

            ut.endutent()
    """

    libc: CDLL

    def __init__(self) -> None:
        """Initialise Utmp and load C library.

        Finds and loads the system C library (libc) using ctypes. This library
        contains the utmp functions we need to wrap.

        The library is loaded once during initialization and reused for all
        subsequent method calls.

        Returns:
            None

        Example:
            Standard initialization::

                ut = Utmp()
                # ut.libc is now available for wrapping functions
        """
        libname: str | None = find_library('c')
        self.libc = CDLL(libname)

    def wrap_function(
            self, funcname: str, restype: type | None,
            argtypes: tuple[Any, ...] | None):
        """Simplify wrapping ctypes functions.

        Helper method to set up ctypes function signatures. Retrieves the named
        function from libc, configures its return type and argument types, and
        returns the configured function object.

        Args:
            funcname: Name of C library function to wrap (e.g., "setutent")
            restype: Return type (ctypes type or None for void)
            argtypes: Tuple of argument types, or None for no arguments

        Returns:
            Configured ctypes function object ready to call

        Example:
            Wrap getutent() which returns a utmp pointer::

                fn = self.wrap_function('getutent', POINTER(Utmp_t), None)
                result = fn()
        """
        # pylint: disable=unnecessary-dunder-call
        func = self.libc.__getattr__(funcname)
        func.restype = restype
        func.argtypes = argtypes  # type: ignore[assignment]
        return func

    def setutent(self) -> None:
        """Rewind file pointer to start of utmp file.

        Calls the C library setutent() function to rewind the utmp file to the
        beginning. This allows re-reading the file from the start.

        Must be called after utmpname() to open/rewind the selected file.

        Returns:
            None

        Example:
            Rewind after partial read::

                ut = Utmp()
                ut.utmpname(WTMP_FILE)
                ut.setutent()
                # ... read some records ...
                ut.setutent()  # Rewind to start
                # ... read again from beginning ...
        """
        self.wrap_function('setutent', None, None)()

    def utmpname(self, name: str) -> int:
        """Set the utmp filename to read.

        Calls the C library utmpname() function to select which utmp file to
        read. Common values are WTMP_FILE (/var/log/wtmp) or UTMP_FILE
        (/var/run/utmp) from utmpconst module.

        Must be called before setutent() to select the file.

        Args:
            name: Path to utmp file (e.g., "/var/log/wtmp")

        Returns:
            0 on success, -1 on error (C library return value)

        Example:
            Select wtmp file::

                from nftfw.utmpconst import WTMP_FILE

                ut = Utmp()
                result = ut.utmpname(WTMP_FILE)
                if result == 0:
                    ut.setutent()
        """
        fn = self.wrap_function('utmpname', c_int, (c_char_p,))
        ret: int = fn(name.encode())
        return ret

    def getutent(self) -> Utmp_t | None:
        """Read next record from utmp file.

        Calls the C library getutent() function to read the next utmp record.
        Returns None when end of file is reached.

        Must be called after utmpname() and setutent() to read records.

        Returns:
            Utmp_t record structure, or None at end of file

        Example:
            Read all records::

                ut = Utmp()
                ut.utmpname(WTMP_FILE)
                ut.setutent()

                while True:
                    rec = ut.getutent()
                    if not rec:
                        break
                    # Process rec...

                ut.endutent()
        """
        fn = self.wrap_function('getutent', POINTER(Utmp_t), None)
        res = fn()
        if res:
            return res.contents
        return None

    def getutentbytype(self, ut_type: int):
        """Generator to return records of specific type.

        Yields utmp records matching the specified type. This is a convenience
        generator that filters records by ut_type field (e.g., USER_PROCESS,
        DEAD_PROCESS from utmpconst).

        Note: This implements filtering in Python rather than using C library's
        getutid() function, as getutid() proved difficult to wrap reliably.

        Args:
            ut_type: Record type constant from utmpconst (e.g., USER_PROCESS)

        Yields:
            Utmp_t records with matching ut_type

        Example:
            Find all user login records::

                from nftfw.utmpconst import USER_PROCESS, WTMP_FILE

                ut = Utmp()
                ut.utmpname(WTMP_FILE)
                ut.setutent()

                for rec in ut.getutentbytype(USER_PROCESS):
                    print(f"User: {rec.ut_user.decode()}")

                ut.endutent()
        """
        while True:
            res = self.getutent()
            if res:
                if res.ut_type == ut_type:
                    yield res
            else:
                break

    def endutent(self) -> None:
        """Close the utmp file.

        Calls the C library endutent() function to close the currently open
        utmp file and release associated resources.

        Should be called when finished reading to clean up properly.

        Returns:
            None

        Example:
            Standard cleanup::

                ut = Utmp()
                ut.utmpname(WTMP_FILE)
                ut.setutent()
                # ... read records ...
                ut.endutent()  # Clean up
        """
        self.wrap_function('endutent', None, None)()

class UtmpDecode:
    """Decode utmp record into helpful Python values.

    This class wraps a raw Utmp_t structure and converts its C data types into
    Python-friendly values. Specifically:

    **String Conversion:**
    Converts C byte strings to Python strings (decoded from UTF-8):
        - ut_line: Terminal device name
        - ut_id: Terminal identifier
        - ut_user: Username
        - ut_host: Hostname/IP of remote connection

    **IP Address Decoding:**
    Decodes the ut_addr_v6 array into string IP addresses:
        - ut_addr: IP address string (IPv4 or IPv6, or None if not present)
        - ut_addr_v4: IPv4 address string (or None if IPv6)
        - ut_addr_v6: IPv6 address string (or None if IPv4)

    **Pass-Through Fields:**
    These fields are copied directly without conversion:
        - ut_type: Record type (int)
        - ut_pid: Process ID (int)
        - ut_exit: Exit status structure
        - ut_session: Session ID (int)
        - ut_tv: Timestamp structure

    **IPv4 vs IPv6 Detection:**

    The ut_addr_v6 array holds both IPv4 and IPv6 addresses:
        - IPv4: Only addr[0] is non-zero, addr[1:3] are all zero
        - IPv6: Multiple array elements are non-zero (128-bit address)

    Example:
        Decode a user login record::

            from nftfw.nftfw_utmp import Utmp, UtmpDecode
            from nftfw.utmpconst import USER_PROCESS, WTMP_FILE

            ut = Utmp()
            ut.utmpname(WTMP_FILE)
            ut.setutent()

            for rec in ut.getutentbytype(USER_PROCESS):
                decoded = UtmpDecode(rec)
                print(f"User: {decoded.ut_user}")
                print(f"Terminal: {decoded.ut_line}")
                if decoded.ut_addr:
                    print(f"From: {decoded.ut_addr}")
                print(f"Time: {decoded.ut_tv.tv_sec}")

            ut.endutent()

        Check IP version::

            decoded = UtmpDecode(rec)
            if decoded.ut_addr_v4:
                print(f"IPv4: {decoded.ut_addr_v4}")
            elif decoded.ut_addr_v6:
                print(f"IPv6: {decoded.ut_addr_v6}")
    """

    # pylint: disable=too-few-public-methods

    ut_type: int
    ut_pid: int
    ut_line: str
    ut_id: str
    ut_user: str
    ut_host: str
    ut_exit: Exit_Status_t
    ut_session: int
    ut_tv: UtTv_t
    ut_addr: str | None
    ut_addr_v4: str | None
    ut_addr_v6: str | None

    def __init__(self, ut: Utmp_t) -> None:
        """Initialise UtmpDecode and decode raw utmp record.

        Extracts fields from the raw Utmp_t structure, converting C types to
        Python types:
            - Copies numeric and structure fields directly
            - Decodes C byte strings to Python strings
            - Decodes IP address array to string representation

        Args:
            ut: Raw Utmp_t structure to decode

        Returns:
            None

        Example:
            Decode a record::

                rec = ut.getutent()
                decoded = UtmpDecode(rec)
                print(decoded.ut_user)  # Python string, not bytes
        """
        for k in ('ut_type', 'ut_pid', 'ut_exit', 'ut_session', 'ut_tv'):
            setattr(self, k, getattr(ut, k))
        for k in ('ut_line', 'ut_id', 'ut_user', 'ut_host'):
            setattr(self, k, getattr(ut, k).decode())
        # translate the ip address into a string
        addr = ut.ut_addr_v6
        # will all be zero - so skip
        if addr[0] == 0:
            self.ut_addr = None
        else:
            # dealing with ipv4?
            if addr[1:] == [0, 0, 0]:
                s: bytes = struct.pack('I', addr[0]&0xFFFFFFFF)
                i: str = socket.inet_ntoa(s)
                self.ut_addr = i
                self.ut_addr_v4 = i
                self.ut_addr_v6 = None
            else:
                # dealing with ip6
                s = struct.pack('IIII', \
                                addr[0]&0xFFFFFFFF, \
                                addr[1]&0xFFFFFFFF, \
                                addr[2]&0xFFFFFFFF, \
                                addr[3]&0xFFFFFFFF)
                i = socket.inet_ntop(socket.AF_INET6, s)
                self.ut_addr = i
                self.ut_addr_v4 = None
                self.ut_addr_v6 = i
