from ast import arguments
import psycopg2
import urllib
from io import BytesIO
import gzip
from settings import base_url
from multiprocessing import Pool
import urllib.request
from db import db_connect

db = db_connect()
cursor = db.cursor()
cursor.execute(
    """
    ALTER TABLE packages ADD COLUMN IF NOT EXISTS fetched boolean NOT NULL DEFAULT 'false';
    """
)
db.commit()

cursor.execute(
    """
    SELECT p.name, p.sha256, p.filename from packages p WHERE p.fetched='false'
    """
);
packages = cursor.fetchall()

def fetch(arg):
    name, sha256, filename = arg
    url = f"{base_url}{filename}"
    urllib.request.urlretrieve(url, f"./debs/{sha256}.deb")
    db = db_connect()
    cursor = db.cursor()
    cursor.execute(
        """
        UPDATE packages SET fetched='true' where name = %(name)s
        """,
        dict(name=name)
    )
    db.commit()
    print(name)
    db.close()


with Pool(64) as p:
    p.map(fetch, packages)

