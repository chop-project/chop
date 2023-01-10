#%%

import psycopg2
import urllib
from io import BytesIO
import gzip
from settings import base_url, distro
from db import db_connect

url = f"{base_url}dists/{distro}/main/binary-amd64/Packages.gz"

db = db_connect()
cursor = db.cursor()
cursor.execute(
    """
    CREATE TABLE IF NOT EXISTS packages (
        name TEXT PRIMARY KEY NOT NULL,
        version TEXT,
        filename TEXT NOT NULL,
        sha256 TEXT NOT NULL,
        size bigint
    );
    CREATE TABLE IF NOT EXISTS dependencies (
        ID SERIAL PRIMARY KEY,
        dependent TEXT NOT NULL REFERENCES packages(name),
        dependee TEXT NOT NULL,
        UNIQUE (dependent, dependee)
    );
    """
)
db.commit()

response = urllib.request.urlopen(url)
buffer = BytesIO(response.read())
packages = list(
    filter(
        lambda s: s != "", gzip.GzipFile(fileobj=buffer).read().decode().split("\n\n")
    )
)

#%%
def get_package_metadata(package_string: str):
    lines = package_string.split("\n")
    try:
        name = [
            line.split(maxsplit=1) for line in lines if line.startswith("Package: ")
        ][0][1]
    except:
        print(lines)
    filename = [
        line.split(maxsplit=1) for line in lines if line.startswith("Filename: ")
    ][0][1]
    size = int(
        [line.split(maxsplit=1) for line in lines if line.startswith("Size: ")][0][1]
    )
    sha256 = [line.split(maxsplit=1) for line in lines if line.startswith("SHA256: ")][0][1]
    try:
        dependencies = [
            line.split(maxsplit=1) for line in lines if line.startswith("Depends: ")
        ][0][1].split(", ")
    except IndexError:
        dependencies = []
    try:
        version = [
            line.split(maxsplit=1) for line in lines if line.startswith("Version: ")
        ][0][1]
    except IndexError:
        version = None

    return name, version, filename, sha256, size, dependencies


# %%
for name, version, filename, sha256, size, dependencies in map(get_package_metadata, packages):
    cursor.execute(
        """
        INSERT INTO packages (name, version, filename, sha256, size)
        VALUES (%(name)s, %(version)s, %(filename)s, %(sha256)s, %(size)s)
        ON CONFLICT (name) DO
        UPDATE SET filename = %(filename)s, version=%(version)s, sha256=%(sha256)s, size=%(size)s;
        """,
        dict(name=name, version=version, filename=filename, size=size, sha256=sha256),
    )
    print(name)
    for dep in dependencies:
        dep_name = dep.split(maxsplit=1)[0].split(":")[0]
        cursor.execute(
            """
            INSERT INTO dependencies (dependent, dependee)
            VALUES (%(name)s, %(dependency)s)
            ON CONFLICT DO NOTHING;
        """,
            dict(name=name, dependency=dep_name),
        )
    db.commit()

# %%
