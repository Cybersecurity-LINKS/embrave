#!/usr/bin/python3
# -*- coding: utf-8 -*-
import hashlib
import codecs
import os
import pathlib
import gzip
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

    # @staticmethod
    # def sha1_hash(f):
    #     sha1_hash = hashlib.sha1()
    #     while chunk := f.read(4096): #64 blocks of 64 bytes, which is the block size for sha1 and sha256
    #         sha1_hash.update(chunk)
    #     sha1_digest = sha1_hash.digest()
    #     return codecs.encode(sha1_digest, 'hex').decode('utf-8')

    # @staticmethod
    # def sha256_hash(f):
    #     sha256_hash = hashlib.sha256()
    #     while chunk := f.read(4096): #64 blocks of 64 bytes, which is the block size for sha1 and sha256
    #         sha256_hash.update(chunk)
    #     sha256_digest = sha256_hash.digest()
    #     return codecs.encode(sha256_digest, 'hex').decode('utf-8')

    # @staticmethod
    # def sha384_hash(f):
    #     sha384_hash = hashlib.sha384()
    #     while chunk := f.read(8192): #64 blocks of 128 bytes, which is the block size for sha384 and sha512
    #         sha384_hash.update(chunk)
    #     sha384_digest = sha384_hash.digest()
    #     return codecs.encode(sha384_digest, 'hex').decode('utf-8')

    # @staticmethod
    # def sha512_hash(f):
    #     sha512_hash = hashlib.sha512()
    #     while chunk := f.read(8192): #64 blocks of 128 bytes, which is the block size for sha384 and sha512
    #         sha512_hash.update(chunk)
    #     sha512_digest = sha512_hash.digest()
    #     return codecs.encode(sha512_digest, 'hex').decode('utf-8')

    # NOTE: assignment expressions via the := syntax requires Python version >= 3.8.
    #       Modified as follows, to work with Python 3.7

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
        chunk = f.read(4096) #64 blocks of 64 bytes, which is the block size for sha1 and sha256
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
    """
    Create a new task
    :param conn:
    :param task:
    :return:
    """

    sql = ''' INSERT INTO golden_values(name,hash)
              VALUES(?,?) '''
    cur = conn.cursor()
    cur.execute(sql, row)
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

    #whitelist.write(digest_str + " " + str(len(file_path)) + " " + file_path + "\n")
    row_1 = (file_path, digest_str)
    add_row(conn, row_1)
    num_files  = num_files + 1

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

    database = r"./Protocols/Explicit/TEEEEEST.db"
    sql_create_projects_table = """ CREATE TABLE IF NOT EXISTS golden_values (
                                        name text NOT NULL,
                                        hash text NOT NULL,
                                        PRIMARY KEY (name,hash)
                                    ); """
    conn = create_connection(database)
    create_table(conn, sql_create_projects_table)

    with open('exclude_list', 'w') as f:
        f.write('^')
        for path in paths:
            path = path.replace("\\", "\\\\")
            path = path.replace(".", "\\.")
            path = path.replace("^", "\\^")
            path = path.replace("$", "\\$")
            path = path.replace("*", "\\*")
            path = path.replace("+", "\\+")
            path = path.replace("-", "\\-")
            path = path.replace("?", "\\?")
            path = path.replace("(", "\\(")
            path = path.replace(")", "\\)")
            path = path.replace("[", "\\[")
            path = path.replace("]", "\\]")
            path = path.replace("{", "\\{")
            path = path.replace("}", "\\}")
            path = path.replace("|", "\\|")
            path = path.replace("^", "\\^")
            path = path.replace("/", "\\/")
            # f.write(f'(?!{path})')
        #f.write('.*$\n')
	    # NOTE: modified format of regular expression (generic, instead of Python only)
            if first_path:
              f.write(f'({path})')
              first_path=False
            else:
              f.write(f'|({path})')
        f.write('.*$\n')

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

                    if file_path.endswith('.gz'):
                        with gzip.open(file_path, 'rb') as f:
                            try:
                                compute_hash(hash_algo, f, file_path, num_files)
                                num_files+=1

                            except gzip.BadGzipFile:
                                pass
                    else:
                        a = "/run/"
                        b = "/sys/"
                        c = "/proc/"
                        print(file_path)
                        if file_path.startswith(a) or file_path.startswith(b) or file_path.startswith(c):
                            continue
                        with open(file_path, 'rb') as f:
                            compute_hash(hash_algo, f, file_path, num_files)
                            num_files+=1
        else:
            with open(path, 'rb') as f:
                compute_hash(hash_algo, f, path, num_files)
                num_files+=1

    conn.close

"""     with open('whitelist', 'r+') as whitelist:
        content = whitelist.read()
        whitelist.seek(0)
        whitelist.write(str(num_files) + "\n" + content) """
