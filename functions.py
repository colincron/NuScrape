import sqlite3, re, random, sys, socket
from datetime import datetime
import urllib3.exceptions
from bs4 import BeautifulSoup
import socket, requests
import dns.resolver


def timestamp():
    dt = datetime.now()
    ts = dt.strftime("%H:%M:%S")
    return ts

def print_error(error):
    print("\n" + timestamp() + " " + str(error))

def sanitize_url(url):
    # Use regular expression to remove the protocol and trailing slash
    sanitized = re.sub(r'^(https?:\/\/)?(www\.)?(.+?)(\/)$', r'\3', url)
    return sanitized

    # TODO: save DNS information to database

def create_request_header():
    header_dict = {
        1: {"Accept": "text/html",
             "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/109.0",
             "Accept-Encoding": "gzip, deflate, br",
             "Referer": "127.0.0.1"},
        2: {"Accept": "text/html",
             "User-Agent": "Mozilla/5.0 (X11; CrOS x86_64 8172.45.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.64 Safari/537.36",
             "Accept-Encoding": "gzip, deflate, br",
             "Referer": "127.0.0.1"},
        3: {"Accept": "text/html",
             "User-Agent": "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/47.0.2526.111 Safari/537.36",
             "Accept-Encoding": "gzip, deflate, br",
             "Referer": "127.0.0.1"}
    }

    choice = random.randint(1, 3)
    return header_dict.get(choice, None)

def email_scraper(response):
    email_pattern = r"^[\w\-\.]+@([\w-]+\.)+[\w-]{2,}$"
    parsed_data = BeautifulSoup(response.content, "lxml")
    emails = [email.strip() for email in parsed_data.find_all(string=re.compile(email_pattern))]

    # Filter out any empty strings or duplicates
    unique_emails = list(dict.fromkeys(emails))

    if len(unique_emails) > 0:
        for email in unique_emails:
            write_to_email_database(email)

def request_and_parse(url):
    response = ""
    try:
        response = requests.get(url, headers=create_request_header())
        if response.status_code == 200:
            html_data = response.content
            parsed_data = BeautifulSoup(html_data, "lxml")  # lxml is fast and lenient
            anchors = parsed_data.find_all(lambda tag: tag.name == 'a' and tag.get('href'))
            email_scraper(response)
            return anchors
    except (requests.exceptions.ConnectionError, socket.gaierror,
            requests.exceptions.TooManyRedirects, requests.exceptions.InvalidURL,
            requests.exceptions.ChunkedEncodingError, requests.exceptions.InvalidSchema,
            urllib3.exceptions.LocationParseError) as error:
        print_error("\n" + timestamp() + " " + str(error))
    return None

def grab_title(url):
    try:
        response = requests.get(url, headers=create_request_header())
        if response.status_code == 200:
            html_data = response.content
            parsed_data = BeautifulSoup(html_data, "lxml")  # lxml is fast and lenient
            title = parsed_data.find('title')
            if title:
                return str(title.string).strip()
            return None
    except (requests.exceptions.ConnectionError, socket.gaierror,
            requests.exceptions.TooManyRedirects, requests.exceptions.InvalidURL) as error:
        print_error(str(error))
    return None

def get_server_info(domain_name):
    try:
        header_response = requests.head(domain_name, headers=create_request_header())

        # Extract title
        title = grab_title(domain_name)

        # Extract server and content type
        server = header_response.headers.get('Server', 'Unknown')
        content_type = header_response.headers.get('Content-Type', 'Unknown')

        # Get IP
        ip = socket.gethostbyname(sanitize_url(str(domain_name)))

        # DNS lookup
        dns_lookup(sanitize_url(str(domain_name)))

        # Write to database
        write_to_domain_database(str(domain_name), ip, server, content_type, title)

        return 0

    except (KeyError, TypeError, UnicodeEncodeError, socket.error,
            requests.exceptions.ConnectionError, requests.exceptions.InvalidURL) as err:
        print_error(str(err))
        return 0

def get_domain_names(anchors, url_list):
    try:
        for a in anchors:
            references = [a["href"]]
            for r in references:
                if r.startswith("http") and r not in url_list:
                    url_list.append(r)
                    if r.endswith((".com", ".gov/", ".net/", ".edu/", ".org/", ".io/", ".co.uk/", ".ie/", ".info/")):
                        get_server_info(r)
    except TypeError as err:
        print_error(str(err))
    return url_list

def create_db(conn, table_name):
    table_creation_map = {
        "Domains": '''CREATE TABLE IF NOT EXISTS '{}' (
                                    "url"	TEXT NOT NULL,
                                    "ip"	TEXT NOT NULL,
                                    "servertype"	TEXT,
                                    "content_type"  TEXT,
                                    "title"	TEXT
                                    )''',
        "Emails": '''CREATE TABLE IF NOT EXISTS '{}' (
                                    "email_address"	TEXT NOT NULL
                                    )'''
    }

    if table_name in table_creation_map:
        try:
            conn.execute(table_creation_map[table_name].format(table_name))
        except sqlite3.OperationalError as err:
            print_error(err)

def check_db_for_domain(conn, name, table_name):
    print(timestamp() + " Checking for " + name + " in database")

    table_checks = {
        "Domains": lambda: conn.execute("SELECT DISTINCT url FROM '{}' WHERE url='{}'".format(table_name, name)),
        "Emails": lambda: conn.execute("SELECT DISTINCT email_address FROM '{}' WHERE email_address='{}'".format(table_name, name))
    }

    entry_exists = table_checks.get(table_name, lambda: None)()
    if entry_exists:
        try:
            db_result = str(entry_exists.fetchall()[0]).replace("('", "").replace("',)", "")
        except IndexError:
            return True
        if db_result == name:
            print("\n" + timestamp() + " " + name + " is already in DB")
            return False
        else:
            return True
    return None

def write_to_domain_database(name, ip, server, content_type, title):
    table_name = "Domains"
    conn = sqlite3.connect("ScrapeDB", isolation_level=None)
    try:
        create_db(conn, table_name)
        if check_db_for_domain(conn, name, table_name):
            sql = """INSERT INTO '{}' (url, ip, servertype, content_type, title)
                        VALUES ('{}','{}','{}','{}','{}');""".format(table_name, name, ip, server, content_type, title)
            conn.execute(sql)
            print(timestamp() + " " + name + " saved to database")
    finally:
        conn.close()

def write_to_email_database(email_address):
    table_name = "Emails"
    conn = sqlite3.connect("ScrapeDB", isolation_level=None)
    try:
        create_db(conn, table_name)
        if check_db_for_domain(conn, email_address, table_name):
            sql = """INSERT INTO '{}' (email_address)
                        VALUES ('{}');""".format(table_name, email_address)
            conn.execute(sql)
            print(timestamp() + " " + email_address + " saved to database")
    finally:
        conn.close()

def main_crawler(start_url):
    url_list = [start_url, ]
    i = 0

    while len(url_list) > 0:
        url = url_list[0]
        print("\n" + timestamp() + " Length of url_list: " + str(len(url_list)))
        print(timestamp() + " Number of sites crawled:" + str(i) + "\n")
        print(timestamp() + " Now searching: " + url)

        anchors = request_and_parse(url)
        url_list.extend(get_domain_names(anchors, url_list))
        url_list.pop(0)
        i = i + 1

    else:
        sys.exit(timestamp() + " All done!")
