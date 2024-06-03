import logging
import os
import pymysql

from datetime import datetime
from flask import jsonify

user = 'root'
password = 'root'
host = 'localhost'
port = 3306
database = 'logging_db'
db_tbl_logs = 'logs'

log_error_level = 'DEBUG'       # LOG error level (file)
log_to_db = True                # LOG to database?
sql_conn = None
sql_cursor = None


class LogDBHandler(logging.Handler):
    '''
    Customized logging handler that puts logs to the database.
    pymssql required
    '''
    def __init__(self, sql_conn, sql_cursor, db_tbl_logs):
        logging.Handler.__init__(self)
        self.sql_cursor = sql_cursor
        self.sql_conn = sql_conn
        self.db_tbl_logs = db_tbl_logs

    def emit(self, record):
        # current dateTime
        now = datetime.now()
        # convert to string
        date_time_str = now.strftime("%Y-%m-%d %H:%M:%S")
        # Make the SQL insert
        sql = f'INSERT INTO {self.db_tbl_logs} (created_at, log_level, message) VALUES (%s, %s, %s)'
        try:
            self.sql_cursor.execute(sql, (date_time_str, record.levelname, record.message))
            self.sql_conn.commit()
        # If error - print it out on screen. Since DB is not working - there's
        # no point making a log about it to the database :)
        except pymysql.Error as e:
            print("error: ", e)
            print(sql)
            print('CRITICAL DB ERROR! Logging to database not possible!')


def setup_db_logging():
    return


# Main settings for the database logging use
if log_to_db:
    # Make the connection to database for the logger
    sql_conn = pymysql.connect(
            host=host,
            port=port,
            user=user,
            password=password,
            database=database,
            charset='utf8'
        )
    sql_cursor = sql_conn.cursor()
    db_log_handler = LogDBHandler(sql_conn, sql_cursor, db_tbl_logs)

# Set logger
logging.basicConfig(filename='app.log')

# Set db handler for root logger
if log_to_db:
    logging.getLogger('').addHandler(db_log_handler)

# Register MY_LOGGER
log = logging.getLogger('MY_LOGGER')
log.setLevel(log_error_level)

# Log the variable contents as an error
log.error('Test logging')


def get_logs():
    if log_to_db:
        # Make the SQL SELECT
        sql = f'SELECT * FROM {db_tbl_logs}'
        try:
            sql_cursor.execute(sql)
            result = sql_cursor.fetchall()
            logs = [list(i) for i in result]
            return logs
        # If error - print it out on screen.
        except pymysql.Error as e:
            print("error: ", e)
            print(sql)
            print('CRITICAL DB ERROR! Failed to get thw logs from db!')
    else:
        logs = "No logs available."
        if os.path.exists('app.log'):
            with open('app.log', 'r') as file:
                logs = file.read()
        return jsonify(logs=logs)
