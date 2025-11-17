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
    

    if len(sys.argv) < 3:
        print("USAGE: db_path file_path\nExample: python3 ./scripts/add_goldenvalue_from_file.py ./goldenvalues.db")

    database = sys.argv[1]
    file_name = sys.argv[2]
    print("Adding the following golden values to the database ", database, ":")
    conn = create_connection(database)
    file = open(file_name, 'r')

    lines = file.readlines()

    for line in lines:
        x = line.split()
        name = x[0]
        sha256 = x[1]
        print(name, sha256)
        add_row(conn, name, sha256)


    file.close()
    
    
    #add_row(conn, name, file_hash)
    conn.close()

if __name__ == '__main__':
    main()