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
    database = r"./Protocols/Explicit/goldenvalues.db"
    sql_create_projects_table = """ CREATE TABLE IF NOT EXISTS whitelist (
                                        name text NOT NULL,
                                        PRIMARY KEY (name)
                                    ); """
    sql_create_projects_table2 = """ CREATE TABLE IF NOT EXISTS golden_values (
                                        name text NOT NULL,
                                        hash text NOT NULL,
                                        PRIMARY KEY (name,hash)
                                    ); """
    
    if len(sys.argv) < 2:
        print("Required the name to add in the whitelist")
        sys.exit(1)

    name = sys.argv[1]
    print(name)

    conn = create_connection(database)
    create_table(conn, sql_create_projects_table)
    #create_table(conn, sql_create_projects_table2)
    add_row(conn, name)
    conn.close
"""     cur = conn.cursor()
    cur.execute(''' CREATE INDEX index_name ON golden_values (name, hash); ''')
    conn.commit() """
    

"""     cur = conn.cursor()
    cur.execute(''' ALTER TABLE golden_values ORDER BY name asc; ''')
    conn.commit()

    conn.close """


if __name__ == '__main__':
    main()