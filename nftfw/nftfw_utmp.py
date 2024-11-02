"""Access the utmp/wtmp file using the c library utmp api
"""

# pylint: disable=wildcard-import, unused-wildcard-import

import socket
import struct
from ctypes import *
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
    """Defines
    struct __exit_status
    {
       short int __e_termination;
       short int __e_exit;
    };
    """
    # pylint: disable=invalid-name,too-few-public-methods
    _fields_ = [("e_termination", c_short),
                ("e_exit", c_short)]

class UtTv_t(Structure):
    """Defines
      struct
      {
        __int32_t tv_sec;
        __int32_t tv_usec;
      } ut_tv;
    """
    # pylint: disable=invalid-name,too-few-public-methods
    _fields_ = [('tv_sec', c_int),
                ('tv_usec', c_int)]

class Utmp_t(Structure):          # pylint: disable=invalid-name
    """Defines
    typedef int __pid_t;
    typedef signed int __int32_t;

    struct utmpx
    {
      short int ut_type;
      __pid_t ut_pid;
      char ut_line[32];
      char ut_id[4];
      char ut_user[32];
      char ut_host[256];
      struct __exit_status ut_exit;
      __int32_t ut_session;
      struct
      {
        __int32_t tv_sec;
        __int32_t tv_usec;
      } ut_tv;
      __int32_t ut_addr_v6[4];
      char __glibc_reserved[20];
    };
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
    """Interface to the utmp reading interface in libc """

    def __init__(self):
        """Load library """

        libname = find_library('c')
        self.libc = CDLL(libname)

    def wrap_function(self, funcname, restype, argtypes):
        """Simplify wrapping ctypes functions"""

        # pylint: disable=unnecessary-dunder-call
        func = self.libc.__getattr__(funcname)
        func.restype = restype
        func.argtypes = argtypes
        return func

    def setutent(self):
        """Rewind pointer to start of file """

        self.wrap_function('setutent', None, None)()

    def utmpname(self, name):
        """Set utmp filename """

        fn = self.wrap_function('utmpname', c_int, (c_char_p,))
        ret = fn(name.encode())
        return ret

    def getutent(self):
        """Access next line in utmp file """

        fn = self.wrap_function('getutent', POINTER(Utmp_t), None)
        res = fn()
        if res:
            return res.contents
        return None

    def getutentbytype(self, ut_type):
        """Generator to return record of specific type

        Cannot get getutid to work - unclear why
        But a generator is helpful
        """

        while True:
            res = self.getutent()
            if res:
                if res.ut_type == ut_type:
                    yield res
            else:
                break

    def endutent(self):
        """Close the file """

        self.wrap_function('endutent', None, None)

class UtmpDecode:
    """Class to turn a utmp record into helful Python values

    Changes 'ut_line', 'ut_id', 'ut_user' and 'ut_host' to strings
    IP address is decoded and placed into
    ut_addr  and
    ut_addr_v4 if a v4 or
    ut_addr_v6 if a v6

    """

    # pylint: disable=too-few-public-methods

    def __init__(self, ut):
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
                s = struct.pack('I', addr[0]&0xFFFFFFFF)
                i = socket.inet_ntoa(s)
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
