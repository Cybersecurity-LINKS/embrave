#!/usr/bin/python3
# -*- coding: utf-8 -*-
import hashlib
import codecs
import os
import pathlib
import sys
import sqlite3
from sqlite3 import Error

class Hash:
    SHA1   = 'sha1'
    SHA256 = 'sha256'
    SHA384 = 'sha384'
    SHA512 = 'sha512'
    supported_algorithms = (SHA1, SHA256, SHA384, SHA512)

    @staticmethod
    def is_recognized(algorithm):
        return algorithm in Hash.supported_algorithms

    @staticmethod
    def sha1_hash(f):
        sha1_hash = hashlib.sha1()
        chunk = f.read(4096) #64 blocks of 64 bytes, which is the block size for sha1 and sha256
        while chunk:
            sha1_hash.update(chunk)
            chunk = f.read(4096)
        sha1_digest = sha1_hash.digest()
        return codecs.encode(sha1_digest, 'hex').decode('utf-8')

    @staticmethod
    def sha256_hash(f):
        sha256_hash = hashlib.sha256()
        try:
            chunk = f.read(4096) #64 blocks of 64 bytes, which is the block size for sha1 and sha256
        except:
            return None
        while chunk:
            sha256_hash.update(chunk)
            chunk = f.read(4096)
        sha256_digest = sha256_hash.digest()
        return codecs.encode(sha256_digest, 'hex').decode('utf-8')

    @staticmethod
    def sha384_hash(f):
        sha384_hash = hashlib.sha384()
        chunk = f.read(8192) #64 blocks of 128 bytes, which is the block size for sha384 and sha512
        while chunk:
            sha384_hash.update(chunk)
            chunk = f.read(8192)
        sha384_digest = sha384_hash.digest()
        return codecs.encode(sha384_digest, 'hex').decode('utf-8')

    @staticmethod
    def sha512_hash(f):
        sha512_hash = hashlib.sha512()
        chunk = f.read(8192) #64 blocks of 128 bytes, which is the block size for sha384 and sha512
        while chunk:
            sha512_hash.update(chunk)
            chunk = f.read(8192)
        sha512_digest = sha512_hash.digest()
        return codecs.encode(sha512_digest, 'hex').decode('utf-8')

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


def compute_hash(hash_algo, f, file_path, num_files):
    switch_algorithms = {
            Hash.SHA1: Hash.sha1_hash,
            Hash.SHA256: Hash.sha256_hash,
            Hash.SHA384: Hash.sha384_hash,
            Hash.SHA512: Hash.sha512_hash
        }
    digest_str = switch_algorithms[hash_algo](f)
    if digest_str == None:
        return
    row_1 = (file_path, digest_str)
    add_row(conn, row_1)
    num_files  = num_files + 1

def bootaggr():
    file = open('/sys/kernel/security/integrity/ima/ascii_runtime_measurements', 'r')

    first_line = file.readline()
    x = first_line.split()
    a = x[3];
    row_1 = (x[4], a[7:])
    add_row(conn, row_1)
    file.close()

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print("Required the hash algorithm and at least one path as parameters")
        sys.exit(1)

    hash_algo = sys.argv[1].lower()

    if not Hash.is_recognized(hash_algo):
        print("The hash algorithm %s is not supported. Supported hash algorithms are: [%s]" % (hash_algo, ', '.join(Hash.supported_algorithms)))
        sys.exit(1)


    paths = sys.argv[2:]

    first_path = True

    num_files = 0

    database = r"./Protocols/Explicit/goldenvalues.db"
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
    #create whitelist db
    create_table(conn, sql_create_projects_table1)

    for path in paths:
            # Display the current path
        print('   ' + path)

        p = pathlib.Path(path)

        if p.is_symlink() or p.is_block_device() or p.is_char_device():
            continue
        elif p.is_dir():
            for (root,dirs,files) in os.walk(path):
                for file in files:
                    file_path = root + "/" + file

                    fp = pathlib.Path(file_path)
                    if fp.is_dir() or fp.is_symlink() or fp.is_block_device() or fp.is_char_device():
                        continue
                    else:
                        #a = "/run/"
                        #b = "/sys/"
                        #c = "/proc/"
                        print(file_path)
                       # if file_path.startswith(a) or file_path.startswith(b) or file_path.startswith(c):
                        #    continue
                        try:
                            with open(file_path, 'rb') as f:
                                compute_hash(hash_algo, f, file_path, num_files)
                                num_files+=1
                        except:
                                continue
        else:
            with open(path, 'rb') as f:
                compute_hash(hash_algo, f, path, num_files)
                num_files+=1
    bootaggr()
    
    with open('./script/exclude.txt', 'r') as excludelist:
        for lines in excludelist:
            add_row_excludelist(conn, lines[:-1])
            
    conn.close
