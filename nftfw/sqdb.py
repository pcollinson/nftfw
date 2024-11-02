""" Base class for managing sqlite3 """

import sqlite3
import time
import logging
log = logging.getLogger('nftfw')

class SqDb:
    """ Basic interface to sqlite database

    Main idea is to provide a simple and tailored set of primitives so
    that db control is in one place
    """

    def __init__(self, cf, dbpath, check):
        """ Called with dbpath, Path to filename to open

        Check is a dictionary where
        key is table name that should exist
        value is the create execute sequence to make table if it doesn't.
        The value is executed as text, so lines need to terminated by ;
        """

        self.cf = cf
        self.dbfile = str(dbpath)
        try:
            self.conn = sqlite3.connect(self.dbfile)
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
                    # no table - create and add index
                    cur.executescript(create)
                    self.conn.commit()
                cur.close()
        # Use the row factory for lookups
        self.conn.row_factory = sqlite3.Row


    def lookup(self, table, what='*', where=None, vals=None, orderby=''):
        """Lookup a value in the table with a WHERE condition

        Parameters
        ----------
        table:str table name
        all remaining args are optional
        what:str  what is being looked up
        where:str where phrase with the condition
                  ? where values need replacing
        vals:tuple of values matching the ?
        orderby:  order by value

        Returns
        -------
        list of dicts indexed by keyname
        """

        # pylint: disable=too-many-arguments

        cur = self.conn.cursor()
        ob = ''
        if orderby != '':
            ob = 'ORDER BY '+orderby
        try:
            if where is None:
                statement = f'SELECT {what} FROM {table} {ob}'
                cur.execute(statement)
            else:
                statement = f'SELECT {what} FROM {table} WHERE {where} {ob}'
                cur.execute(statement, vals)
        except sqlite3.Error as e:
            log.error('Lookup failed in %s: %s', table, e)
            return []
        # get result creating array of dicts
        # removing indexability of row
        # and creating a simpler object
        ret = []
        for row in cur:
            d = {}
            for k in row.keys():
                d[k] = row[k]
            ret.append(d)
        cur.close()
        return ret

    @staticmethod
    def _make_statement(table, argdict, ignore=None, statement='INSERT'):
        """Generate an insert/replace statement in the named table.

        Use named values from argdict,
        ignore any keys in the ignore list
        """

        if ignore is None:
            ignore = []
        keys = []
        cols = []
        values = []
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

    def insert(self, table, argdict, ignore=None, statement='INSERT'):
        """Execute and commit insert statement in a named table
        from a dict with arguments,

        ignore dict entries if keys are in ignore list
        Returns last id inserted
        (statement argument is for internal use and is not needed
        from external calls)
        """
        if ignore is None:
            ignore = []
        cur = self.conn.cursor()
        cur.execute(*self._make_statement(table, argdict, ignore, statement))
        lastrowid = cur.lastrowid
        self.conn.commit()
        cur.close()
        return lastrowid

    def replace(self, table, argdict, ignore=None, statement='REPLACE'):
        """Execute and commit replace statement in a named table

        from a dict with arguments,
        ignore dict key entries if keys are in ignore list
        Returns last id inserted
        (statement argument is for internal use and is not needed
        from external calls)
        """

        if ignore is None:
            ignore = []
        return self.insert(table, argdict, ignore, statement=statement)

    def update(self, table, argdict, key, val, ignore=None):
        """ Update a table using set= syntax """

        # pylint: disable=too-many-arguments

        if ignore is None:
            ignore = []
        sets = []
        values = []
        for arg, value in argdict.items():
            if arg in ignore:
                continue
            sets.append(f'{arg}=?')
            values.append(value)
        # add key value to end of values
        values.append(val)
        allsets = ",".join(sets)
        sql = f'UPDATE {table} SET {allsets} WHERE {key} = ?'
        cur = self.conn.cursor()
        cur.execute(sql, tuple(values))
        self.conn.commit()
        cur.close()

    # added November 2024 to handle more complex
    # tests on deletes
    @staticmethod
    def compile_where(exprlist, andor='AND'):
        """ Compile a where clause from list of
            [key predicate value] in exprlist
            andor is the function to combine expressions

        returns (where, vals)
        where is a single string with the sql clause
        vals is a list of values that replace the ?
        in the expressions
        """

        pred = []
        vals = []
        for key, predicate, pval in exprlist:
            opr = f'{key} {predicate} ?'
            pred.append(opr)
            vals.append(pval)
        where = f' {andor} '.join(pred)
        return (where, vals)

    # was called delete, renamed because of different api
    # using exprlist
    def remove(self, table, exprlist):
        """ Delete from table using exprlost to create a
        complex where expression - see complile_where above

        returns rows affected
        """

        cur = self.conn.cursor()
        where, vals = self.compile_where(exprlist)
        query = f'DELETE FROM {table} WHERE {where}'
        cur.execute(query, tuple(vals))
        affected = cur.rowcount
        self.conn.commit()
        cur.close()
        return affected

    def remove_not_in(self, table, exprlist, in_key, not_in_list):
        """ Delete from table based on an expression, where the
        value of in_key is not in the list

        assume not_in_list is a list of strings, not called when
        possibly empty
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

    def vacuum(self):
        """Clean unused space in the sqlite3 database """

        cur = self.conn.cursor()
        cur.execute('VACUUM')
        self.conn.commit()
        cur.close()

    @staticmethod
    def db_timestamp():
        """ Get current timestamp as an int

        Convenience function. Sqlite can store
        dates, but int time values will be shorter
        and easier to index
        """

        return int(time.time())

    def close(self):
        """ Close a connection """

        self.conn.close()
