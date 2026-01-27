"""Custom exception for RulesReader errors.

This module defines RulesReaderError, a specialized exception class used by
the RulesReader class to signal errors during rule loading, validation, or
execution. It is defined in a separate file to allow external code to catch
this exception without importing the entire rulesreader module.

Usage Example:
    from .ruleserr import RulesReaderError
    from .rulesreader import RulesReader

    try:
        reader = RulesReader(cf)
        result = reader.execute('webserver', env)
    except RulesReaderError as e:
        print(f"Rule error: {e}")
        # Handle error appropriately

Common Scenarios:
    - Syntax errors in rule scripts during initialisation
    - Attempting to execute a non-existent rule
    - Rule script returns non-zero exit code
    - Rule script writes to stderr
    - Multiple syntax errors reported together

See Also:
    - rulesreader.py: Main user of this exception class
    - fwmanage.py: Catches this exception during firewall loading
"""
from __future__ import annotations


class RulesReaderError(Exception):
    """Exception raised for errors in rule script loading or execution.

    This exception is raised by RulesReader in the following situations:
        - Rule script syntax validation fails during initialisation
        - Attempt to execute a rule that doesn't exist
        - Rule script execution returns non-zero exit code
        - Rule script produces stderr output
        - Multiple rules fail syntax validation

    The exception message provides details about the error, including:
        - Which rule(s) failed
        - Error type (syntax, execution, stderr)
        - Guidance for fixing the issue

    Attributes:
        Inherits all attributes from Exception base class.

    Example:
        # Catching syntax errors during initialisation
        try:
            reader = RulesReader(cf)
        except RulesReaderError as e:
            print(f"Rule syntax errors: {e}")
            # Error message lists all failing rules
            # e.g., "Syntax problems with rule.d/bad.sh, local.d/broken.sh"

        # Catching execution errors
        try:
            result = reader.execute('unknown_rule', {})
        except RulesReaderError as e:
            print(f"Execution failed: {e}")
            # e.g., "Attempted to use unknown rule unknown_rule"

    Note:
        - Defined in separate file for import isolation
        - Provides actionable error messages
        - Can contain multiple rule failures in one exception
    """
