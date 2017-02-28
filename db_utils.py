import sqlite3
import encrypt

db_file = 'authentication.sqlite'
auth_table = "authentication_table"
user_col = "user_name"
pswd_col = "password"
field_type = "TEXT"

def create_db():
    print db_file
    conn = sqlite3.connect(db_file)
    conn.commit()
    conn.close()

def execute_query (query_string):
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    cursor.execute(query_string)
    conn.commit()
    return conn, cursor

def drop_table (table_name):
    drop_query = 'DROP TABLE {tn}'.format(tn=table_name)
    print drop_query
    conn, cursor = execute_query(drop_query)
    conn.close()

def create_auth_table ():
    drop_table(auth_table)
    create_statement = 'CREATE TABLE {tn} ({uf} {ft} PRIMARY KEY, {pf} {ft})'\
                .format(tn=auth_table, uf=user_col, ft=field_type,
                    pf=pswd_col)

    print create_statement
    conn, cursor = execute_query(create_statement)
    conn.close()

def insert_to_auth_table (user_name, password):
    insert_query = "INSERT OR IGNORE INTO {tn} ({uc}, {pc}) VALUES (\'{un}\', \'{pswd}\')"\
        .format(tn=auth_table, uc=user_col, pc=pswd_col, un = user_name, pswd = password)
    print insert_query
    conn, cursor = execute_query(insert_query)
    conn.close()

def select_star_from_table (table_name):
    select_query = "SELECT * FROM {tn}".format(tn=table_name)
    conn, cursor = execute_query(select_query)
    rows = cursor.fetchall()
    conn.close()
    return rows

def select_from_table_where (table_name, user_name):
    select_query = "SELECT * FROM {tn} where {un} = \'{rhs}\'".format(
                    tn = table_name, un = user_col, rhs = user_name)
    conn, cursor = execute_query(select_query)
    row = cursor.fetchone()
    conn.close()
    return row

def get_user_tuple (user_name):
    return select_from_table_where (auth_table, user_name)

def main():
    create_db()
    create_auth_table()
    insert_to_auth_table('naren', encrypt.generate_hash_digest('password1'))
    insert_to_auth_table('susmi', encrypt.generate_hash_digest('password2'))
    insert_to_auth_table('uday', encrypt.generate_hash_digest('password3'))
    rows = select_star_from_table(auth_table)
    row = get_user_tuple("naren")
    print row

if __name__ == '__main__':
    main()
