import psycopg2
import unix_ar
import tarfile
import gzip
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from multiprocessing import Pool
from db import db_connect
db = db_connect()
cursor = db.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS symbols (
    id SERIAL PRIMARY KEY,
    file_id integer references files(id),
    name TEXT,
    UNIQUE(file_id, name)
);
CREATE TABLE IF NOT EXISTS sections (
    id SERIAL PRIMARY KEY,
    file_id integer references files(id),
    name TEXT,
    UNIQUE(file_id, name)
);
ALTER TABLE files ADD COLUMN IF NOT EXISTS elf_analyzed boolean NOT NULL DEFAULT 'False';
""")
db.commit()

cursor.execute("""
SELECT f.package, f.id, f.filename, f.sha256, p.sha256 FROM elf_files f
LEFT JOIN packages p ON f.package = p.name
WHERE f.elf_analyzed = 'false'
ORDER BY f.size DESC
""")
elffiles = cursor.fetchall()

def extract_one_file(filename, package_sha):
    ar_file = unix_ar.open(f'./debs/{package_sha}.deb')

    data_files = [f for f in  ar_file.infolist() if f.name[:4] == b'data']
    if len(data_files) != 1:
        return

    if data_files[0].name.endswith(b'.xz'):
        tarball = ar_file.open('data.tar.xz')
    elif data_files[0].name.endswith(b'.gz'):
        tarball = gzip.open(ar_file.open('data.tar.gz'))
    else:
        assert 1

    tar_file = tarfile.open(fileobj=tarball)
    return tar_file.extractfile(filename)

def iter_symbols(elf):
    for section in elf.iter_sections():
        if not isinstance(section, SymbolTableSection): continue
        yield from section.iter_symbols()

def do_one_file(arg):
    package, file_id, filename, file_sha256, package_sha256 = arg
    print(package, filename)
    file = extract_one_file(filename, package_sha256)
    e = ELFFile(file)
    db = db_connect()
    cursor = db.cursor()
    for section in e.iter_sections():
        if not section.name:
            continue

        cursor.execute("""
        INSERT INTO sections (file_id, name)
        VALUES (%(file_id)s, %(name)s)
        ON CONFLICT DO NOTHING;
        """,
        dict(
            name=section.name,
            file_id=file_id,
        ))
    for symbol in iter_symbols(e):
        cursor.execute("""
        INSERT INTO symbols (file_id, name)
        VALUES (%(file_id)s, %(name)s)
        ON CONFLICT DO NOTHING;
        """,
        dict(
            name=symbol.name,
            file_id=file_id,
        ))
    print(file_id)
    cursor.execute("""
    UPDATE files SET elf_analyzed = 'true' WHERE id = %(file_id)s
    """, dict(file_id=file_id))
    db.commit()

with Pool(16) as p:
    p.map(do_one_file, elffiles)
