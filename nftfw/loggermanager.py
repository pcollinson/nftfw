"""Logging configuration system for nftfw.

This module provides dynamic logger management with support for multiple output
handlers (syslog and console) that can be reconfigured at runtime. The logger
configuration is controlled through Config settings.

The LoggerManager handles two logging destinations:
    - Syslog: System logging via /dev/log
    - Console: Stream output to stdout/stderr

Example usage:
    # Create logger manager (typically done by Config)
    import logging
    from .config import Config

    log = logging.getLogger('nftfw')
    cf = Config()
    lm = LoggerManager(cf, log)

    # Logger will automatically configure based on config settings:
    # - cf.loglevel: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
    # - cf.logfacility: Syslog facility (e.g., 'daemon', 'local0')
    # - cf.logprint: Enable/disable console output
    # - cf.logsyslog: Enable/disable syslog output
    # - cf.logfmt: Log message format string

    # Reconfigure at runtime by changing config and calling setup()
    cf.loglevel = 'DEBUG'
    lm.setup()

Note:
    When both logprint and logsyslog are False, the logger level is set to
    CRITICAL to prevent the Python logging system from printing default
    warnings about no handlers being configured.
"""

from __future__ import annotations

import logging
from logging.handlers import SysLogHandler
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from .config import Config

class LoggerManager:
    """Dynamic logger configuration manager.

    This class manages Python logging handlers and formatters, allowing runtime
    reconfiguration based on Config settings. It handles both syslog and console
    (print) handlers, and can switch them on/off without losing state.

    The logger behaviour is controlled by Config attributes:
        - loglevel: Log level name (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        - logfacility: Syslog facility name (e.g., 'daemon', 'local0')
        - logprint: Enable console/print logging
        - logsyslog: Enable syslog logging
        - logfmt: Log message format string

    Attributes:
        cf: Configuration object containing logging settings.
        log: Logger instance to manage.
        syslog_handler: Active SysLogHandler or None if disabled.
        print_handler: Active StreamHandler or None if disabled.
        formatter: Current log message formatter.
        current_fmt: Currently applied format string.
        current_level: Currently applied log level name.

    Example:
        >>> import logging
        >>> log = logging.getLogger('nftfw')
        >>> from .config import Config
        >>> cf = Config()
        >>> lm = LoggerManager(cf, log)
        >>> # Logger is now configured
        >>> cf.logprint = True
        >>> lm.setup()  # Reconfigure to enable console output
    """

    def __init__(self, cf: Config, log: logging.Logger) -> None:
        """Initialize the logger manager and configure handlers.

        Args:
            cf: Configuration object with logging settings.
            log: Logger instance to manage (typically the global nftfw logger).

        Note:
            This method calls setup() automatically to configure the logger
            based on the initial configuration settings.
        """
        self.cf: Config = cf
        self.log: logging.Logger = log
        self.syslog_handler: Optional[SysLogHandler] = None
        self.print_handler: Optional[logging.StreamHandler] = None
        self.formatter: Optional[logging.Formatter] = None
        self.current_fmt: str = ""
        self.current_level: str = ""
        self.setup()

    def setup(self) -> None:
        """Configure or reconfigure logger based on current config settings.

        This method updates the logger configuration by:
        1. Setting the log level (or CRITICAL if no handlers enabled)
        2. Updating the log format if changed
        3. Adding/removing syslog handler as needed
        4. Adding/removing console handler as needed

        The method is idempotent and only makes changes when configuration
        has actually changed since the last setup() call.

        Note:
            When both logprint and logsyslog are disabled, the level is set
            to CRITICAL to suppress Python's "no handlers configured" warnings.
        """
        cf = self.cf

        if not cf.logprint and not cf.logsyslog:
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

    def chg_syslog(self) -> None:
        """Add or remove syslog handler based on config.

        This method checks the config.logsyslog setting and:
        - Removes the syslog handler if disabled (logsyslog=False)
        - Creates and adds a syslog handler if enabled (logsyslog=True)

        The handler is connected to /dev/log using the facility specified
        in config.logfacility.

        Note:
            This method is idempotent - it only makes changes if the current
            handler state doesn't match the desired config state.
        """
        cf = self.cf

        if not cf.logsyslog:
            if self.syslog_handler is not None:
                self.log.removeHandler(self.syslog_handler)
                self.syslog_handler = None
        elif self.syslog_handler is None:
            self.syslog_handler = SysLogHandler(
                address="/dev/log",
                facility=SysLogHandler.facility_names[cf.logfacility]
            )
            self.syslog_handler.setFormatter(self.formatter)
            self.log.addHandler(self.syslog_handler)

    def chg_print(self) -> None:
        """Add or remove console/print handler based on config.

        This method checks the config.logprint setting and:
        - Removes the console handler if disabled (logprint=False)
        - Creates and adds a StreamHandler if enabled (logprint=True)

        The StreamHandler outputs to stdout/stderr (Python logging default).

        Note:
            This method is idempotent - it only makes changes if the current
            handler state doesn't match the desired config state.
        """
        cf = self.cf

        if not cf.logprint:
            if self.print_handler is not None:
                self.log.removeHandler(self.print_handler)
                self.print_handler = None
        elif self.print_handler is None:
            self.print_handler = logging.StreamHandler()
            self.print_handler.setFormatter(self.formatter)
            self.log.addHandler(self.print_handler)

    def chg_format(self) -> None:
        """Update log message format if changed in config.

        This method creates a new logging.Formatter with the format string
        from config.logfmt and applies it to all active handlers (both syslog
        and console).

        The method checks if the format has actually changed before creating
        a new formatter to avoid unnecessary work.

        Note:
            The formatter is applied to existing handlers by calling their
            setFormatter() method, which updates the format for all future
            log messages.
        """
        cf = self.cf

        if self.current_fmt == cf.logfmt and self.formatter is not None:
            return

        self.current_fmt = cf.logfmt
        self.formatter = logging.Formatter(fmt=cf.logfmt)

        # Apply new formatter to active handlers
        if self.syslog_handler is not None:
            self.syslog_handler.setFormatter(self.formatter)
        if self.print_handler is not None:
            self.print_handler.setFormatter(self.formatter)
