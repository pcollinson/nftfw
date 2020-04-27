"""nftfw - Manage logger instances

Provides an API for managing the two loggers, switching them on and
off and reconfiguring
"""

import logging
from logging.handlers import SysLogHandler

class LoggerManager:
    """Manage logger instances

    Allowing things to change dynamically

    The default logger will print things above ERROR
    when there are no logging handlers installed

    Managed by variables in config:
    loglevel: str - log level to use
    logfacility: str - syslog facility to use
    logprint: Boolean - use print logging
    logsyslog: Boolean - use syslog logging
    logfmt: str - format string to use

    """

    def __init__(self, cf, log):
        """Establish state

        Parameters
        ----------
        cf : Config
        log : Logger instance global to Config
        """

        self.cf = cf
        self.log = log
        self.syslog_handler = None
        self.print_handler = None
        self.formatter = None
        self.current_fmt = ""
        self.current_level = ""
        self.setup()

    def setup(self):
        """Change the logger setup
        or not if it doesn't need it
        """

        cf = self.cf

        if not cf.logprint \
           and not cf.logsyslog:
            # This is to stop the logger system printing when there is no
            # handler installed
            self.current_level = 'CRITICAL'
            self.log.setLevel('CRITICAL')
        elif cf.loglevel != self.current_level:
            self.current_level = cf.loglevel
            self.log.setLevel(cf.loglevel)

        if self.current_fmt != cf.logfmt:
            self.chg_format()

        self.chg_syslog()
        self.chg_print()

    def chg_syslog(self):
        """ Change syslog handler

        Lose the current one if it's there
        Build a new one if wanted
        """

        cf = self.cf
        # print('Syslog ', 'On' if cf.logsyslog else 'Off', self.current_level)
        if not cf.logsyslog:
            if self.syslog_handler is not None:
                self.log.removeHandler(self.syslog_handler)
                self.syslog_handler = None
        elif self.syslog_handler is None:
            self.syslog_handler = SysLogHandler(address="/dev/log",
                                                facility=cf.logfacility)
            self.syslog_handler.setFormatter(self.formatter)
            self.log.addHandler(self.syslog_handler)

    def chg_print(self):
        """ Change print handler """

        cf = self.cf
        # print('Print ', 'On' if cf.logprint else 'Off', self.current_level)
        if not cf.logprint:
            if self.print_handler is not None:
                self.log.removeHandler(self.print_handler)
                self.print_handler = None
        elif self.print_handler is None:
            self.print_handler = logging.StreamHandler()
            self.print_handler.setFormatter(self.formatter)
            self.log.addHandler(self.print_handler)

    def chg_format(self):
        """ Change formatter """

        cf = self.cf

        if self.current_fmt == cf.logfmt \
           and self.formatter is not None:
            return

        self.current_fmt = cf.logfmt
        self.formatter = logging.Formatter(fmt=cf.logfmt)

        # hopefully this is what we are supposed to do
        if self.syslog_handler is not None:
            self.syslog_handler.setFormatter(self.formatter)
        if self.print_handler is not None:
            self.print_handler.setFormatter(self.formatter)
