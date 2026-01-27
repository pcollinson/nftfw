"""Base class for SQLite3 database management.

This module provides the SqDb base class, a lightweight wrapper around SQLite3
that simplifies common database operations. It's used as the foundation for
nftfw's database layers (firewall database, file position tracking, etc.).

Key Features:
    - Automatic table creation and schema validation
    - Simple CRUD operations with dictionary-based API
    - Parameterized query support to prevent SQL injection
    - Complex WHERE clause builder for advanced queries
    - Row factory support for dict-based result access

Example:
    Basic database operations::

        from pathlib import Path
        from .config import Config
        from .sqdb import SqDb

        # Define table schema
        schema = {
            'users': '''
                CREATE TABLE users (
                    id INTEGER PRIMARY KEY,
                    name TEXT NOT NULL,
                    email TEXT UNIQUE
                );
            '''
        }

        # Create database instance
        cf = Config()
        db_path = Path('/var/lib/nftfw/app.db')
        db = SqDb(cf, db_path, schema)

        # Insert data
        user_data = {'name': 'Alice', 'email': 'alice@example.com'}
        user_id = db.insert('users', user_data)

        # Query data
        results = db.lookup('users', where='email = ?', vals=('alice@example.com',))

        # Update data
        db.update('users', {'name': 'Alice Smith'}, 'id', user_id)

        # Delete data
        db.remove('users', [('id', '=', user_id)])

        db.close()

See Also:
    - fwdb.py: Firewall database for IP tracking
    - fileposdb.py: File position tracking database
"""
from __future__ import annotations
from typing import TYPE_CHECKING, Any
import sqlite3
import time
import logging

if TYPE_CHECKING:
    from pathlib import Path
    from .config import Config

log = logging.getLogger('nftfw')

class SqDb:
    """SQLite3 database wrapper providing simple CRUD operations.

    This class provides a clean, dictionary-based interface to SQLite3 databases.
    It handles automatic table creation, parameterized queries, and result
    conversion to Python dictionaries.

    Attributes:
        cf: Config instance containing system configuration.
        dbfile: String path to the SQLite database file.
        conn: SQLite3 connection object with Row factory enabled.

    Note:
        The Row factory is enabled on the connection, allowing results to be
        accessed as dictionaries. All methods automatically commit changes
        and close cursors to prevent resource leaks.

    Example:
        Creating and using a database::

            schema = {'ips': 'CREATE TABLE ips (ip TEXT PRIMARY KEY, count INT);'}
            db = SqDb(config, Path('/var/lib/nftfw/firewall.db'), schema)
            db.insert('ips', {'ip': '192.168.1.1', 'count': 1})
            results = db.lookup('ips', where='count > ?', vals=(0,))
    """

    def __init__(self, cf: Config, dbpath: Path, check: dict[str, str] | None) -> None:
        """Initialize database connection and ensure tables exist.

        Opens or creates the SQLite database file and validates that required
        tables exist. If tables are missing, they are created using the provided
        SQL schema definitions.

        Args:
            cf: Config instance containing system configuration.
            dbpath: Path to the SQLite database file to open or create.
            check: Dictionary mapping table names to CREATE TABLE SQL statements.
                Each SQL statement should be complete with semicolons. If None,
                no table validation is performed. Example::

                    {
                        'users': 'CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT);',
                        'logs': 'CREATE TABLE logs (id INTEGER, msg TEXT);'
                    }

        Note:
            On database connection failure, a critical error is logged but no
            exception is raised. The Row factory is enabled for all queries,
            allowing results to be accessed as dictionaries.
        """
        self.cf: Config = cf
        self.dbfile: str = str(dbpath)
        try:
            self.conn: sqlite3.Connection = sqlite3.connect(self.dbfile)
        except sqlite3.Error as e:
            log.critical('Failed to open %s: %s', self.dbfile, str(e))
            return
        if check is not None:
            for table, create in check.items():
                cur = self.conn.cursor()
                tablecheck = f"""SELECT name FROM sqlite_master
                     WHERE type='table' AND name='{table}'"""
                cur.execute(tablecheck)
                ans = cur.fetchall()
                if not any(ans):
                    # No table exists - create it using provided SQL
                    cur.executescript(create)
                    self.conn.commit()
                cur.close()
        # Use the Row factory for lookups to enable dict-like access
        self.conn.row_factory = sqlite3.Row


    def lookup(self, table: str, what: str = '*', where: str | None = None,
               vals: tuple[Any, ...] | None = None, orderby: str = '') -> list[dict[str, Any]]:
        """Query the database and return results as a list of dictionaries.

        Executes a SELECT query with optional WHERE clause and ORDER BY clause.
        Results are converted from SQLite Row objects to plain Python dictionaries
        for easier manipulation.

        Args:
            table: Name of the table to query.
            what: Columns to select (default '*' for all columns). Can be comma-
                separated list like 'id,name' or expressions like 'COUNT(*)'.
            where: WHERE clause condition with '?' placeholders for values.
                Example: 'age > ? AND status = ?'. If None, no WHERE clause is used.
            vals: Tuple of values to substitute for '?' placeholders in where clause.
                Must match the number of placeholders. Required if where is provided.
            orderby: Column name(s) for ORDER BY clause. Do not include 'ORDER BY'
                keyword. Example: 'timestamp DESC' or 'name, age'.

        Returns:
            List of dictionaries, where each dict represents one row with column
            names as keys. Returns empty list if query fails or no results found.

        Example:
            Query with WHERE and ORDER BY::

                # Get all IPs with count > 5, ordered by count
                results = db.lookup('ips',
                                   what='ip,count',
                                   where='count > ?',
                                   vals=(5,),
                                   orderby='count DESC')
                for row in results:
                    print(f"IP: {row['ip']}, Count: {row['count']}")
        """
        # pylint: disable=too-many-arguments,too-many-positional-arguments

        cur = self.conn.cursor()
        ob = ''
        if orderby != '':
            ob = 'ORDER BY ' + orderby
        try:
            if where is None:
                statement = f'SELECT {what} FROM {table} {ob}'
                cur.execute(statement)
            else:
                statement = f'SELECT {what} FROM {table} WHERE {where} {ob}'
                assert vals is not None, "vals must be provided when where clause is used"
                cur.execute(statement, vals)
        except sqlite3.Error as e:
            log.error('Lookup failed in %s: %s', table, e)
            return []
        # Get result creating array of dicts
        # Remove Row indexability and create simpler dict objects
        ret: list[dict[str, Any]] = []
        for row in cur:
            d: dict[str, Any] = {}
            for k in row.keys():
                d[k] = row[k]
            ret.append(d)
        cur.close()
        return ret

    @staticmethod
    def _make_statement(table: str, argdict: dict[str, Any],
                       ignore: list[str] | None = None,
                       statement: str = 'INSERT') -> tuple[str, tuple[Any, ...]]:
        """Generate INSERT or REPLACE SQL statement from a dictionary.

        Creates a parameterized SQL statement with '?' placeholders for values,
        filtering out any keys specified in the ignore list.

        Args:
            table: Name of the table for the statement.
            argdict: Dictionary mapping column names to values.
            ignore: List of dictionary keys to exclude from the statement.
                Defaults to empty list if None.
            statement: SQL command type, either 'INSERT' or 'REPLACE'.
                Used internally by insert() and replace() methods.

        Returns:
            Tuple of (sql_statement, values_tuple). The SQL statement contains
            '?' placeholders and the values tuple contains the corresponding values
            in the correct order.

        Example:
            Internal usage::

                stmt, vals = SqDb._make_statement('users',
                                                   {'id': 1, 'name': 'Alice', 'temp': 'x'},
                                                   ignore=['temp'])
                # Returns: ('INSERT INTO users (id,name) VALUES (?,?)', (1, 'Alice'))
        """
        if ignore is None:
            ignore = []
        keys: list[str] = []
        cols: list[str] = []
        values: list[Any] = []
        for key, value in argdict.items():
            if key in ignore:
                continue
            keys.append(key)
            cols.append('?')
            values.append(value)
        allkeys = ",".join(keys)
        allcols = ",".join(cols)
        sqlcmd = f'{statement} INTO {table} ({allkeys}) VALUES ({allcols})'
        return sqlcmd, tuple(values)

    def insert(self, table: str, argdict: dict[str, Any],
               ignore: list[str] | None = None, statement: str = 'INSERT') -> int:
        """Insert a new row into the database.

        Inserts a row using values from a dictionary. Column names are taken from
        dictionary keys, and values are parameterized to prevent SQL injection.

        Args:
            table: Name of the table to insert into.
            argdict: Dictionary mapping column names to values to insert.
            ignore: List of dictionary keys to exclude from insertion.
                Useful for filtering out metadata or computed fields.
            statement: SQL command type ('INSERT' or 'REPLACE'). Internal parameter
                used by the replace() method, should not be specified by callers.

        Returns:
            The rowid of the last inserted row (SQLite's auto-increment ID).

        Example:
            Insert a new IP entry::

                new_id = db.insert('blacklist', {
                    'ip': '192.168.1.100',
                    'port': 22,
                    'count': 1,
                    'first_seen': db.db_timestamp()
                })
        """
        if ignore is None:
            ignore = []
        cur = self.conn.cursor()
        cur.execute(*self._make_statement(table, argdict, ignore, statement))
        lastrowid = cur.lastrowid
        self.conn.commit()
        cur.close()
        return lastrowid if lastrowid is not None else 0

    def replace(self, table: str, argdict: dict[str, Any],
                ignore: list[str] | None = None, statement: str = 'REPLACE') -> int:
        """Replace a row in the database (INSERT OR REPLACE).

        Similar to insert(), but uses SQL REPLACE which will update an existing
        row if a unique constraint conflict occurs, or insert a new row otherwise.

        Args:
            table: Name of the table to replace into.
            argdict: Dictionary mapping column names to values.
            ignore: List of dictionary keys to exclude from the statement.
            statement: SQL command type. Internal parameter, do not specify.

        Returns:
            The rowid of the inserted/replaced row.

        Note:
            REPLACE is equivalent to DELETE + INSERT if a conflict occurs, so
            any columns not specified in argdict will be set to their defaults.

        Example:
            Update or create an IP entry::

                db.replace('ips', {
                    'ip': '10.0.0.1',  # PRIMARY KEY
                    'count': 5,
                    'last_seen': db.db_timestamp()
                })
        """
        if ignore is None:
            ignore = []
        return self.insert(table, argdict, ignore, statement=statement)

    def update(self, table: str, argdict: dict[str, Any], key: str, val: Any,
               ignore: list[str] | None = None) -> None:
        """Update existing rows in the database.

        Updates columns specified in argdict for rows matching the WHERE condition.
        Uses parameterized queries to prevent SQL injection.

        Args:
            table: Name of the table to update.
            argdict: Dictionary mapping column names to new values.
            key: Column name to use in the WHERE clause.
            val: Value to match in the WHERE clause (WHERE key = val).
            ignore: List of dictionary keys to exclude from the update.

        Example:
            Update IP count::

                db.update('ips', {'count': 10, 'last_seen': time.time()},
                         key='ip', val='192.168.1.1')
                # Executes: UPDATE ips SET count=?, last_seen=? WHERE ip = ?
        """
        # pylint: disable=too-many-arguments,too-many-positional-arguments

        if ignore is None:
            ignore = []
        sets: list[str] = []
        values: list[Any] = []
        for arg, value in argdict.items():
            if arg in ignore:
                continue
            sets.append(f'{arg}=?')
            values.append(value)
        # Add WHERE clause value to end of values list
        values.append(val)
        allsets = ",".join(sets)
        sql = f'UPDATE {table} SET {allsets} WHERE {key} = ?'
        cur = self.conn.cursor()
        cur.execute(sql, tuple(values))
        self.conn.commit()
        cur.close()

    @staticmethod
    def compile_where(exprlist: list[tuple[str, str, Any]],
                     andor: str = 'AND') -> tuple[str, list[Any]]:
        """Build a WHERE clause from a list of conditions.

        Constructs a parameterized WHERE clause by combining multiple conditions
        with AND or OR operators. Each condition is specified as a tuple of
        (column, operator, value).

        Args:
            exprlist: List of tuples, each containing (column, operator, value).
                For example: [('count', '>', 5), ('status', '=', 'active')]
            andor: Logical operator to combine conditions, either 'AND' or 'OR'.
                Defaults to 'AND'.

        Returns:
            Tuple of (where_clause, values_list). The where_clause is a string
            with '?' placeholders, and values_list contains the corresponding
            values in order.

        Note:
            Added November 2024 to handle more complex deletion criteria.

        Example:
            Build complex WHERE clause::

                where, vals = SqDb.compile_where([
                    ('count', '>', 10),
                    ('port', '=', 22),
                    ('timestamp', '<', 1699999999)
                ], andor='AND')
                # Returns: ('count > ? AND port = ? AND timestamp < ?',
                #           [10, 22, 1699999999])
        """
        pred: list[str] = []
        vals: list[Any] = []
        for key, predicate, pval in exprlist:
            opr = f'{key} {predicate} ?'
            pred.append(opr)
            vals.append(pval)
        where = f' {andor} '.join(pred)
        return (where, vals)

    def remove(self, table: str, exprlist: list[tuple[str, str, Any]]) -> int:
        """Delete rows matching complex WHERE conditions.

        Removes rows from the table based on a list of conditions combined
        with AND logic. Uses compile_where() to build the WHERE clause.

        Args:
            table: Name of the table to delete from.
            exprlist: List of (column, operator, value) tuples defining the
                conditions. See compile_where() for format details.

        Returns:
            Number of rows deleted.

        Note:
            This method was renamed from 'delete' to 'remove' when the API
            changed to use exprlist format instead of simple key-value pairs.

        Example:
            Delete old entries::

                deleted = db.remove('logs', [
                    ('timestamp', '<', old_time),
                    ('level', '=', 'DEBUG')
                ])
                print(f"Deleted {deleted} old debug logs")
        """
        cur = self.conn.cursor()
        where, vals = self.compile_where(exprlist)
        query = f'DELETE FROM {table} WHERE {where}'
        cur.execute(query, tuple(vals))
        affected = cur.rowcount
        self.conn.commit()
        cur.close()
        return affected

    def remove_not_in(self, table: str, exprlist: list[tuple[str, str, Any]],
                     in_key: str, not_in_list: list[str]) -> int:
        """Delete rows matching conditions AND where a column is NOT IN a list.

        Combines standard WHERE conditions with a NOT IN clause for more
        complex deletion logic. Useful for cleaning up stale entries while
        preserving a whitelist.

        Args:
            table: Name of the table to delete from.
            exprlist: List of (column, operator, value) tuples for WHERE clause.
            in_key: Column name to check against the NOT IN list.
            not_in_list: List of values that should NOT be deleted. Rows where
                in_key has a value in this list will be preserved.

        Returns:
            Number of rows deleted.

        Note:
            Assumes not_in_list is non-empty. This method is not called when
            the list is potentially empty.

        Example:
            Delete old entries except for specific IPs::

                deleted = db.remove_not_in(
                    'blacklist',
                    [('timestamp', '<', cutoff_time)],
                    in_key='ip',
                    not_in_list=['192.168.1.1', '10.0.0.1']
                )
                # Deletes old entries but keeps the two specified IPs
        """
        where, vals = self.compile_where(exprlist)
        args = vals + not_in_list
        inq = ["?" for n in range(len(not_in_list))]
        inqs = ",".join(inq)

        cur = self.conn.cursor()
        query = f'DELETE FROM {table} WHERE {where} ' \
                + f'AND {in_key} NOT IN ({inqs})'
        cur.execute(query, tuple(args))
        affected = cur.rowcount
        self.conn.commit()
        cur.close()
        return affected

    def vacuum(self) -> None:
        """Reclaim unused space in the SQLite database.

        Executes the VACUUM command which rebuilds the database file, reclaiming
        space from deleted rows and defragmenting the database. This can improve
        performance and reduce file size.

        Note:
            VACUUM requires temporary disk space equal to the size of the database.
            It should be run periodically on databases with many deletions.

        Example:
            Clean up database after bulk deletions::

                db.remove('old_logs', [('timestamp', '<', cutoff)])
                db.vacuum()  # Reclaim the freed space
        """
        cur = self.conn.cursor()
        cur.execute('VACUUM')
        self.conn.commit()
        cur.close()

    @staticmethod
    def db_timestamp() -> int:
        """Get the current Unix timestamp as an integer.

        Returns the current time as seconds since the Unix epoch. This is a
        convenience function for creating timestamp values that are compact
        and easy to index in SQLite.

        Returns:
            Integer Unix timestamp (seconds since 1970-01-01 00:00:00 UTC).

        Note:
            SQLite can store datetime objects, but integer timestamps are shorter,
            faster to compare, and easier to index. Use this for all timestamp
            columns in nftfw databases.

        Example:
            Create a timestamp field::

                db.insert('events', {
                    'event': 'login_attempt',
                    'timestamp': db.db_timestamp(),
                    'ip': '192.168.1.1'
                })
        """
        return int(time.time())

    def close(self) -> None:
        """Close the database connection.

        Closes the SQLite connection, flushing any pending changes and releasing
        file locks. Should be called when finished with the database.

        Note:
            The connection will also be closed automatically when the object is
            garbage collected, but explicit closing is recommended for proper
            resource management.

        Example:
            Using close explicitly::

                db = SqDb(config, db_path, schema)
                try:
                    # Perform database operations
                    db.insert('table', data)
                finally:
                    db.close()
        """
        self.conn.close()
