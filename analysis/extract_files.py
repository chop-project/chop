#%%

import psycopg2
import unix_ar
import gzip
from multiprocessing import Pool
import tarfile
import magic
import hashlib
from os.path import exists
from db import db_connect
db = db_connect()
cursor = db.cursor()

# Commented out. We already added this column in the table.
'''
cursor.execute(
    """
    ALTER TABLE files ADD COLUMN IF NOT EXISTS elf_extracted boolean NOT NULL DEFAULT 'False';
    """
)
db.commit()

'''

cursor.execute("""
SELECT f.package, f.id, f.filename, f.sha256, p.sha256 FROM files f
LEFT JOIN packages p ON f.package = p.name
WHERE f.elf_extracted = 'false' and f.elf_analyzed = 'true' and 
        (f.magic = 'application/x-sharedlib' or  f.id IN 
              ( SELECT sections.file_id FROM sections
               WHERE sections.name = '.gcc_except_table'::text))
ORDER BY f.size ASC
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

def do_one_file(arg):
    package, file_id, filename, file_sha256, package_sha256 = arg
    print(package, filename, package_sha256, file_sha256)
    
    if not file_sha256:
       return
    if not exists(f'./extracted/{file_sha256}'): 
       file = extract_one_file(filename, package_sha256)
       # just a safety check, perhaps not necessary.
       if not file:
          return

       open(f'./extracted/{file_sha256}', 'wb').write(file.read())
       print(f'Extracted file {filename} into ./extracted/{file_sha256}')
    else:
       print("File already extracted...")

    # TODO too much code duplication. Should wrap all this database code in a script.
    db = db_connect()
    cursor = db.cursor()
    cursor.execute("""
    UPDATE files SET elf_extracted = 'true' WHERE id = %(file_id)s
    """, dict(file_id=file_id))
    db.commit()
    db.close()
# %%
with Pool(4) as p:
    p.map(do_one_file, elffiles)
# %%
