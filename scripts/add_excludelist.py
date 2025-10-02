#!/usr/bin/python3
# -*- coding: utf-8 -*-
import sqlite3
from sqlite3 import Error
import sys



def create_connection(db_file):
    """ create a database connection to the SQLite database
        specified by db_file
    :param db_file: database file
    :return: Connection object or None
    """
    conn = None
    try:
        conn = sqlite3.connect(db_file)
    except Error as e:
        print(e)

    return conn


def create_table(conn, create_table_sql):
    """ create a table from the create_table_sql statement
    :param conn: Connection object
    :param create_table_sql: a CREATE TABLE statement
    :return:
    """
    try:
        c = conn.cursor()
        c.execute(create_table_sql)
    except Error as e:
        print(e)


def add_row(conn, row):
    sql = ''' INSERT INTO whitelist(name)
              VALUES(?) '''
    cur = conn.cursor()
    cur.execute(sql, [row])
    conn.commit()
    return cur.lastrowid


def main():
    
    sql_create_projects_table = """ CREATE TABLE IF NOT EXISTS whitelist (
                                        name text NOT NULL,
                                        PRIMARY KEY (name)
                                    ); """
    if len(sys.argv) < 3:
        print("USAGE: db_path file_name\nExample: python3 ./scripts/add_excludelist.py ./goldenvalues.db /etc/ld.so.cache")
        sys.exit(1)

    database = sys.argv[1]
    name = sys.argv[2]
    print("db:", database, "path:", name)

    conn = create_connection(database)
    create_table(conn, sql_create_projects_table)
    #create_table(conn, sql_create_projects_table2)
    add_row(conn, name)
    conn.close

if __name__ == '__main__':
    main()