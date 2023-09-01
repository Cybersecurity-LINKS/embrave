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
    sql = ''' INSERT INTO tpa(id, ak, ak_path, pcr10_sha256, pcr10_sha1, gv_db, tls_pem_path, timestamp)
              VALUES(?, ?, ?, ?, ?, ?, ?, ?) '''
    cur = conn.cursor()
    cur.execute(sql, row)
    conn.commit()
    return cur.lastrowid


def main():
    database = r"./Agents/Remote_Attestor/tpa.db"
    sql_create_projects_table = """ CREATE TABLE IF NOT EXISTS tpa (
                                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                                        ak text NOT NULL,
                                        ak_path text NOT NULL,
                                        pcr10_sha256 text,
                                        pcr10_sha1 text,
                                        gv_db text NOT NULL,
                                        tls_pem_path text NOT NULL,
                                        timestamp text
                                    ); """
    
    if len(sys.argv) < 5:
        print("Required the ak digest, ak path, tls pem path and goldenvalue db path")
        sys.exit(1)

    name = sys.argv[1]
    ak_path = sys.argv[2]
    pem_path = sys.argv[3]
    gv_db = sys.argv[4]

    row_1 = (None, name, ak_path, None, None, gv_db, pem_path, None)
    conn = create_connection(database)
    create_table(conn, sql_create_projects_table)

    add_row(conn, row_1)
    conn.close

if __name__ == '__main__':
    main()