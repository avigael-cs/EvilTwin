import pymysql.cursors


def track_mysql_changes():
    """
    MySQL credentials for this project:

    $host="localhost";
    $username="dodgers";
    $pass="duck";
    $dbname="eviltwin";
    $tbl_name="wpa_keys";
    """
    connection = pymysql.connect(host='localhost',
                             user='root',
                             password='q1w2e3r4',
                             database='db',
                             charset='utf8mb4',
                             cursorclass=pymysql.cursors.DictCursor)
    with connection.cursor() as cursor:
        # Read a single record
        sql = "SELECT `*`, FROM `wpa_keys`"
        cursor.execute(sql)
        result = cursor.fetchone()
        print(result)

track_mysql_changes()