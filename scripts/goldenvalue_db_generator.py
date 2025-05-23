#!/usr/bin/python3
# -*- coding: utf-8 -*-

#import codecs
import os
import pathlib
import sys
import sqlite3
from sqlite3 import Error


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
    #try:
    c = conn.cursor()
    c.execute(create_table_sql)
    #except Error as e:
        #print(e)


def add_row(conn, row):
    sql = ''' INSERT INTO golden_values(name,hash)
              VALUES(?,?) '''
    cur = conn.cursor()
    cur.execute(sql, row)
    conn.commit()
    return cur.lastrowid

def add_row_excludelist(conn, row):
    sql = ''' INSERT INTO whitelist(name)
              VALUES(?) '''
    cur = conn.cursor()
    cur.execute(sql, [row])
    conn.commit()
    return cur.lastrowid

def read_ima_log():
    file = open('/sys/kernel/security/integrity/ima/ascii_runtime_measurements', 'r')

    lines = file.readlines()

    for line in lines:
        x = line.split()
        a = x[3]
        row_1 = (x[4], a[7:])
        print(row_1)
        try:
            add_row(conn, row_1)
        except Error as e:
            print(e)
        

    file.close()

Include_paths = [
    "/bin", "/home", "/etc", "/lib", "/usr"
]

if __name__ == '__main__':

    database = r"./goldenvalues.db"
    sql_create_projects_table = """ CREATE TABLE IF NOT EXISTS golden_values (
                                        name text NOT NULL,
                                        hash text NOT NULL,
                                        PRIMARY KEY (name,hash)
                                    ); """
    sql_create_projects_table1 = """ CREATE TABLE IF NOT EXISTS whitelist (
                                        name text NOT NULL,
                                        PRIMARY KEY (name)
                                    ); """
    conn = create_connection(database)
    create_table(conn, sql_create_projects_table)
    create_table(conn, sql_create_projects_table1)

    for path in Include_paths:

        for (root,dirs,files) in os.walk(path):
            print(root)

            for file in files:
                file_path = root + "/" + file
                
                fp = pathlib.Path(file_path)
                if fp.is_dir() or fp.is_symlink() or fp.is_block_device() or fp.is_char_device():
                    continue

                else:
                    print(file_path)
                    try:
                        f = open(file_path, 'rb') 
                        f.close()    
                    except:
                        continue

    read_ima_log()
    
    with open('./scripts/exclude.txt', 'r') as excludelist:
        for lines in excludelist:
            print(lines[:-1])
            try:
                add_row_excludelist(conn, lines[:-1])
            except Error as e:
                print(e)
    conn.close
