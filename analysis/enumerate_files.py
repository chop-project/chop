#%%

import psycopg2
import unix_ar
import gzip
from multiprocessing import Pool
import tarfile
import magic
import hashlib
from db import db_connect

db = db_connect()
cursor = db.cursor()
cursor.execute(
    """
    CREATE TABLE IF NOT EXISTS files (
        id SERIAL PRIMARY KEY,
        package TEXT NOT NULL references packages(name),
        filename TEXT NOT NULL,
        magic TEXT,
        size bigint,
        mode int,
        type TEXT,
        sha256 TEXT NOT NULL,
        header BYTEA NOT NULL,
        UNIQUE(filename, package)
    );
    ALTER TABLE packages ADD COLUMN IF NOT EXISTS files_enumerated boolean NOT NULL DEFAULT 'False';
    """
)
db.commit()


cursor.execute(
    """
    SELECT p.name, p.sha256 from packages p
    -- JOIN dependencies d ON d.dependent = p.name
    WHERE p.files_enumerated = 'false'
    AND p.fetched = 'true'
    -- AND d.dependee = 'libstdc++6'
    ORDER BY p.size ASC
    """
);
packages = cursor.fetchall()


#%%
types = {
    tarfile.REGTYPE: "reg",
    tarfile.AREGTYPE: "areg",
    tarfile.LNKTYPE: "lnk",
    tarfile.SYMTYPE: "sym",
    tarfile.CHRTYPE: 'chr',
    tarfile.BLKTYPE: 'blk',
    tarfile.DIRTYPE: 'dir',
    tarfile.FIFOTYPE: 'fifo',
    tarfile.CONTTYPE: 'cont',
}

def do_one_deb(arg):
    b  = bytearray(128*1024)
    mv = memoryview(b)

    package, sha256 = arg
    print(package)
    ar_file = unix_ar.open(f'./debs/{sha256}.deb')

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
    mag = magic.Magic(mime=True, uncompress=True)


    db = db_connect()
    cursor = db.cursor()
    for file in tar_file.getmembers():
        extracted = tar_file.extractfile(file) if file.isreg() else None
        magic_ = mag.from_buffer(extracted.read(2048)) if extracted else None
        sha256 = None
        header = None
        if extracted:
            h  = hashlib.sha256()
            extracted.seek(0)
            header = extracted.read(4)
            extracted.seek(0)
            for n in iter(lambda : extracted.readinto(mv), 0):
                h.update(mv[:n])
            sha256 = h.hexdigest()

        cursor.execute(
            """
            INSERT INTO files (package, filename, magic, size, mode, type, sha256, header)
            VALUES (%(package)s, %(filename)s, %(magic)s, %(size)s, %(mode)s, %(type)s, %(sha256)s, %(header)s)
            ON CONFLICT (filename, package)
            DO UPDATE
            SET magic=%(magic)s, size=%(size)s, mode=%(mode)s, type=%(type)s, sha256=%(sha256)s, header=%(header)s;
            """,
            dict(
                package=package,
                filename=file.path,
                magic=magic_,
                size=file.size,
                mode=file.mode,
                type=types.get(file.type, file.type.decode()),
                sha256=sha256,
                header=header,
            )
        )

    cursor.execute("""
    UPDATE packages SET files_enumerated = 'true' WHERE name = %(package)s
    """, dict(package=package))
    db.commit()
    db.close()

# %%
with Pool(1) as p:
    p.map(do_one_deb, packages)
# %%
