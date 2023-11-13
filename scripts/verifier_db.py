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
    sql = ''' INSERT INTO tpa(id, ak, ak_path, pcr10_sha256, pcr10_sha1, gv_db, tls_pem_path, ca_pem_path, timestamp, resetCount, byte_rcv)
              VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) '''
    cur = conn.cursor()
    cur.execute(sql, row)
    conn.commit()
    return cur.lastrowid

def read_id(conn, sha256_ak):
    """
    Query all rows in the tasks table
    :param conn: the Connection object
    :return:
    """
    cur = conn.cursor()
    cur.execute("SELECT id FROM tpa WHERE ak=?", (sha256_ak,))

    rows = cur.fetchall()
    for row in rows:
        x=row[0]
        print("Id to lauch the RA:")
        print(x)


def main():
    database = r"./certs/tpa.db"
    sql_create_projects_table = """ CREATE TABLE IF NOT EXISTS tpa (
                                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                                        ak text NOT NULL,
                                        ak_path text NOT NULL,
                                        pcr10_sha256 text,
                                        pcr10_sha1 text,
                                        gv_db text NOT NULL,
                                        tls_pem_path text NOT NULL,
                                        ca_pem_path text NOT NULL,
                                        timestamp text,
                                        resetCount integer,
                                        byte_rcv integer
                                    ); """
    
    if len(sys.argv) < 5:
        print("Required the ak digest, ak path, tls pem path and goldenvalue db path")
        sys.exit(1)
    
    name = sys.argv[1]
    ak_path = sys.argv[2]
    pem_path = sys.argv[3]
    gv_db = sys.argv[4]
    ca_path = sys.argv[5]

    row_1 = (None, name, ak_path, None, None, gv_db, pem_path, ca_path, None, None, None)
    conn = create_connection(database)
    create_table(conn, sql_create_projects_table)

    add_row(conn, row_1)
    read_id(conn, name)
    conn.close

if __name__ == '__main__':
    main()