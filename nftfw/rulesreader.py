"""Shell script rule execution system for nftfw firewall generation.

This module provides the RulesReader class for managing and executing small
shell scripts that generate nftables commands. Rules are stored in rule.d with
optional local overrides in local.d.

Key Features:
    - Lazy loading and caching of rule scripts (singleton pattern)
    - Local override support (local.d overrides rule.d)
    - Syntax validation on first instantiation
    - Secure execution with user/group demotion
    - Environment variable support for rule scripts
    - Comprehensive error handling and reporting

Architecture:
    Rules are small shell scripts that generate nftables commands when executed
    with specific environment variables. The class uses a singleton pattern to
    load rules once and share them across all instances.

    Directory structure:
        - rule.d/: System-provided rule scripts (*.sh files)
        - local.d/: Local overrides and custom rules (*.sh files)

    Loading priority:
        local.d files override rule.d files with the same name (stem)

Usage Example:
    from .config import Config
    from .rulesreader import RulesReader

    cf = Config()
    reader = RulesReader(cf)  # Loads and validates all rules

    # Check if a rule exists
    if reader.exists('ssh'):
        # Execute rule with environment variables
        env = {'PROTO': 'tcp', 'PORT': '22'}
        result = reader.execute('ssh', env)
        print(result)  # nftables commands

    # Iterate over all rules
    for name, content in reader.items():
        print(f"Rule {name}: {len(content)} bytes")

Security:
    - Shell scripts are executed with demoted privileges (cf.execuid/execgid)
    - Scripts run in new session (start_new_session=True)
    - Empty environment unless explicitly provided
    - Syntax validation prevents loading broken scripts

See Also:
    - fwmanage.py: Main consumer of RulesReader for firewall generation
    - ruleserr.py: Defines RulesReaderError exception
    - firewallreader.py: Reads firewall rule definitions that reference rules
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Iterator
from pathlib import Path
import os
import subprocess
import logging

from .ruleserr import RulesReaderError

if TYPE_CHECKING:
    from .config import Config

log = logging.getLogger('nftfw')

class RulesReader:
    """Shell script rule loader and executor with singleton caching.

    This class loads shell script rules from rule.d and local.d directories,
    validates their syntax, and provides methods to execute them with
    environment variables. Rules are loaded once and cached at class level,
    so all instances share the same rule set.

    The class performs these operations on first instantiation:
        1. Scans rule.d for *.sh files
        2. Scans local.d for *.sh files (overrides rule.d)
        3. Reads all file contents into memory
        4. Validates syntax by executing each rule with empty environment
        5. Raises RulesReaderError if any validation fails

    Attributes:
        cf: Config instance for accessing paths and execution credentials
        rules_store: Class-level cache of rule content (name → content)
        rules_dir: Class-level cache of rule file paths (name → Path)

    Example:
        # First instantiation loads and validates all rules
        cf = Config()
        reader = RulesReader(cf)  # May raise RulesReaderError

        # Check and execute a rule
        if reader.exists('webserver'):
            env = {'PROTO': 'tcp', 'PORTS': '80,443'}
            nft_cmds = reader.execute('webserver', env)

        # Iterate over all available rules
        for name in reader.keys():
            print(f"Available rule: {name}")

    Note:
        - Rules are cached at class level, not instance level
        - Local.d files override rule.d files with same stem
        - Syntax validation happens only on first instantiation
        - All shell scripts execute with demoted privileges

    Raises:
        RulesReaderError: If any rule script has syntax errors during init
    """

    # Class-level storage for shared rule content (singleton pattern)
    # Populated on first instantiation, then shared across all instances
    rules_store: dict[str, str] | None = None
    rules_dir: dict[str, Path] | None = None

    def __init__(self, cf: Config) -> None:
        """Initialize RulesReader and load rules on first instantiation.

        On first call, this method:
            1. Loads all *.sh files from rule.d and local.d
            2. Merges them (local.d overrides rule.d)
            3. Reads file contents into class-level cache
            4. Validates syntax of all rules

        On subsequent calls, uses cached rules from class-level storage.

        Args:
            cf: Config instance providing directory paths and execution UIDs

        Raises:
            RulesReaderError: If any rule script fails syntax validation

        Example:
            # First instance loads and validates
            cf = Config()
            reader1 = RulesReader(cf)  # Loads from disk, validates

            # Second instance uses cached rules
            reader2 = RulesReader(cf)  # Uses class-level cache

        Note:
            - Syntax validation uses demoted privileges (cf.execuid/execgid)
            - Empty rules (files with no content) are skipped
            - rules_store and rules_dir are shared across all instances
        """
        self.cf: Config = cf
        if RulesReader.rules_store is None:
            localpath = cf.etcpath('local')
            rulepath = cf.etcpath('rule')
            # get file names
            localfiles = {p.stem:p \
                          for p in localpath.glob('*.sh') if p.is_file()} \
                              if localpath.exists() else {}
            rulefiles = {p.stem:p \
                         for p in rulepath.glob('*.sh') if p.is_file()} \
                             if rulepath.exists() else {}
            # merge: localfiles entries replace any rulefiles
            rulesdir = {**rulefiles, **localfiles}
            # read contents
            rules = ((stem, rulesdir[stem].read_text()) \
                     for stem in rulesdir)
            # create dictionary
            RulesReader.rules_store = {r:c for r, c in rules if any(c)}
            # and access to rulesdir - for testing purposes
            RulesReader.rules_dir = rulesdir
            # This may raise an exception
            # so starting this class needs to use a try to report any error
            self.checksyntax()

    @property
    def rules(self) -> dict[str, str]:
        """Access class-level rules cache.

        Returns:
            Dictionary mapping rule names to their shell script content.

        Example:
            reader = RulesReader(cf)
            all_rules = reader.rules
            print(f"Loaded {len(all_rules)} rules")

        Note:
            - Returns class-level storage (shared across all instances)
            - Never returns None after successful initialisation
        """
        return RulesReader.rules_store  # type: ignore[return-value]

    @property
    def rulesdir(self) -> dict[str, Path]:
        """Access class-level rules directory mapping.

        Returns:
            Dictionary mapping rule names to their file paths.

        Example:
            reader = RulesReader(cf)
            for name, path in reader.rulesdir.items():
                print(f"Rule {name} from {path}")

        Note:
            - Used primarily for error reporting and testing
            - Returns class-level storage (shared across all instances)
        """
        return RulesReader.rules_dir  # type: ignore[return-value]

    def items(self) -> Iterator[tuple[str, str]]:
        """Iterate over rule name and content pairs.

        Yields:
            Tuple of (rule_name, script_content) for each rule.

        Example:
            reader = RulesReader(cf)
            for name, content in reader.items():
                print(f"{name}: {len(content)} bytes")
                if 'tcp' in content:
                    print(f"  Rule {name} uses TCP")

        Note:
            - Yields in arbitrary order (dict iteration order)
            - Content is the raw shell script as string
        """
        for k, v in self.rules.items():
            yield (k, v)

    def exists(self, key: str) -> bool:
        """Check if a rule exists in the cache.

        Args:
            key: Rule name (stem of the .sh file)

        Returns:
            True if rule exists, False otherwise.

        Example:
            reader = RulesReader(cf)
            if reader.exists('ssh'):
                result = reader.execute('ssh', env)
            else:
                print("SSH rule not found")

        Note:
            - Always check exists() before calling execute() or contents()
            - Case-sensitive match on rule name
        """
        return key in self.rules  # pylint: disable=unsupported-membership-test

    def contents(self, key: str) -> str:
        """Get shell script content for a rule.

        Args:
            key: Rule name (stem of the .sh file)

        Returns:
            Shell script content as string.

        Raises:
            KeyError: If rule doesn't exist (should check with exists() first)

        Example:
            reader = RulesReader(cf)
            if reader.exists('webserver'):
                script = reader.contents('webserver')
                print(script)

        Note:
            - Returns raw shell script content
            - Prefer execute() to get actual nftables commands
        """
        return self.rules[key]  # pylint: disable=unsubscriptable-object

    def keys(self) -> Iterator[str]:
        """Iterate over all rule names.

        Yields:
            Rule name (stem of each .sh file).

        Example:
            reader = RulesReader(cf)
            print("Available rules:")
            for name in reader.keys():
                print(f"  - {name}")

        Note:
            - Yields in arbitrary order (dict iteration order)
            - Use exists() to check for a specific rule
        """
        yield from self.rules.keys()

    def checksyntax(self) -> None:
        """Validate syntax of all loaded rules by executing them.

        This method executes each rule with an empty environment to check for
        shell syntax errors. If any rule fails, it raises RulesReaderError with
        a list of problematic files. Called automatically during first __init__.

        Raises:
            RulesReaderError: If any rule has syntax errors. The error message
                             lists all failing rules in format "dir/file.sh".

        Example:
            # Usually called automatically during __init__
            reader = RulesReader(cf)  # checksyntax() runs here

            # Can be called manually for testing
            try:
                reader.checksyntax()
            except RulesReaderError as e:
                print(f"Syntax errors: {e}")

        Note:
            - Executes each rule with empty environment dict
            - Collects all errors before raising (not fail-fast)
            - Error messages include parent directory name for clarity
            - Uses demoted privileges during validation
        """
        env: dict[str, str] = {}
        errorkeys: list[str] = []
        for key in self.keys():
            try:
                self.execute(key, env)
            except RulesReaderError:
                errorkeys.append(key)

        if any(errorkeys):
            errorfiles: list[str] = []
            for key in errorkeys:
                errpath = self.rulesdir[key]  # pylint: disable=unsubscriptable-object
                filename = errpath.name
                parentname = errpath.parent.name
                shortname = f'{parentname}/{filename}'
                errorfiles.append(shortname)
            errors = ", ".join(errorfiles)
            errstr = f'Syntax problems with {errors}. Run /bin/sh on files to check for errors.'
            raise RulesReaderError(errstr)

    def demote(self) -> None:
        """Demote privileges for shell script execution (preexec_fn callback).

        This method is called by subprocess.run via preexec_fn to drop root
        privileges before executing shell scripts. It sets the effective GID
        and UID to cf.execgid and cf.execuid (typically 'nobody' user).

        Only demotes if currently running as root (UID 0). If not root, this
        is a no-op to allow testing without root privileges.

        Example:
            # Used internally by execute() via preexec_fn
            subprocess.run('/bin/sh', preexec_fn=self.demote, ...)

        Note:
            - Called in child process before script execution
            - GID must be set before UID (security requirement)
            - Required for Python 3.6/3.7 (3.9+ has user/group params)
            - No-op if not running as root (for testing)

        Security:
            - Prevents shell scripts from running with root privileges
            - Uses 'nobody' user (or configured execuid/execgid)
            - Combined with start_new_session for isolation
        """
        if os.getuid() == 0:
            os.setgid(self.cf.execgid)
            os.setuid(self.cf.execuid)

    def execute(self, key: str, env: dict[str, str]) -> str:
        """Execute a rule script with environment variables.

        This method executes a shell script rule by:
            1. Validating the rule exists
            2. Running /bin/sh with script content as stdin
            3. Passing environment variables to the script
            4. Demoting to cf.execuid/execgid before execution
            5. Capturing stdout as the result

        Args:
            key: Rule name (stem of the .sh file)
            env: Environment variables to pass to the script (e.g., {'PROTO': 'tcp'})

        Returns:
            Shell script stdout as string (typically nftables commands).

        Raises:
            RulesReaderError: If rule doesn't exist, returns non-zero exit code,
                             or writes to stderr.

        Example:
            reader = RulesReader(cf)

            # Execute SSH rule with TCP protocol
            env = {'PROTO': 'tcp', 'PORT': '22'}
            nft_cmds = reader.execute('ssh', env)
            print(nft_cmds)  # nftables add rule commands

            # Execute with multiple ports
            env = {'PROTO': 'tcp', 'PORTS': '80,443'}
            result = reader.execute('webserver', env)

        Security:
            - Script runs with demoted privileges (cf.execuid/execgid)
            - Starts new session (start_new_session=True) for isolation
            - Only provided environment variables are available
            - stderr output causes failure (prevents warning leakage)

        Note:
            - Check exists() before calling to avoid RulesReaderError
            - Scripts receive content via stdin, not as file
            - Both returncode != 0 and stderr != '' cause errors
            - Compatible with Python 3.6+ (uses preexec_fn, not user/group)
        """
        if key not in self.rules.keys():
            err = f'Attempted to use unknown rule {key}'
            raise RulesReaderError(err)

        compl = subprocess.run('/bin/sh',
                               input=bytes(self.contents(key), 'utf-8'),
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE,
                               env=env,
                               check=False,
                               preexec_fn=self.demote,
                               # user=self.cf.execuid,  # Python 3.9+
                               # group=self.cf.execgid,  # Python 3.9+
                               start_new_session=True)

        if compl.returncode != 0:
            err = f'Action {key}: returned error code'
            raise RulesReaderError(err)
        if compl.stderr != b'':
            err = f'Action {key}: returned error {compl.stderr.decode()}'
            raise RulesReaderError(err)
        return compl.stdout.decode()
