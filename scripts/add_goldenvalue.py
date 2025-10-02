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

def add_row(conn, name, file_hash):
    sql = ''' INSERT INTO golden_values(name, hash)
              VALUES(?, ?) '''
    cur = conn.cursor()
    row = (name, file_hash)
    cur.execute(sql, row)
    conn.commit()
    return cur.lastrowid


def main():
    

    if len(sys.argv) < 4:
        print("USAGE: db_path file_name sha256\nExample: python3 ./scripts/add_goldenvalue.py ./goldenvalues.db /etc/ld.so.cache 50d70673c1902a6e6427a28757ed5b3dc19e9718a96f5aa454a5ee3e71e4fce4")
        sys.exit(1)

    database = sys.argv[1]
    name = sys.argv[2]
    file_hash = sys.argv[3]
    print("db:", database, "path:", name, "sha256:", name)

    conn = create_connection(database)
    
    add_row(conn, name, file_hash)
    conn.close

if __name__ == '__main__':
    main()