""" Utmp constants and sizes

Values for the `ut_type' field of a `struct utmp'. """

EMPTY = 0         # No valid user accounting information.

RUN_LVL = 1       # The system's runlevel.
BOOT_TIME = 2     # Time of system boot.
NEW_TIME = 3      # Time after system clock changed.
OLD_TIME = 4      # Time when system clock changed.

INIT_PROCESS = 5  # Process spawned by the init process.
LOGIN_PROCESS = 6 # Session leader of a logged in user.
USER_PROCESS = 7  # Normal process.
DEAD_PROCESS = 8  # Terminated process.

""" Files """
UTMP_FILE = "/var/run/utmp"
WTMP_FILE = "/var/log/wtmp"
