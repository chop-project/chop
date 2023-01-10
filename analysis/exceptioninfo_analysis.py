#%%
from db import db_connect
from multiprocessing import Pool, get_context
import ctypes
from ctypes import c_char_p, c_int
from os.path import exists
from analysis import AnalysisType

# Get a handle to the Rust library and set the types on the called lib functions.
dll = ctypes.cdll.LoadLibrary("./analysis/ehdump/target/debug/libehdump.so")
dll.write_exception_info_db.argtypes = (c_int, c_int, )

def analyze_one_file(arg):
    file_id, filename, file_sha256 = arg

    print(f'Parsing exception info for file:{filename} sha256:{file_sha256}')

    # Check if we extracted the file. Based on the query this should never happen.
    if not exists(f'./extracted/{file_sha256}'):
       print(f'Error: file {filename} was not extracted!')
       return
    # Parse .eh_frame and .gcc_exception_table and write analysis JSON to DB.
    dll.write_exception_info_db(int(file_id),  AnalysisType.EXCEPTION_INFO)
    
def main():

    db = db_connect()
    cursor = db.cursor()

    cursor.execute("""SELECT f.id, f.filename, f.sha256 FROM gcc_exception_files f 
                      WHERE f.id NOT IN (SELECT file_id from analysis WHERE file_id = f.id and type = %(type)s) 
                      ORDER BY f.size ASC
                   """, dict(type=AnalysisType.EXCEPTION_INFO))

    elffiles = cursor.fetchall()

    db.close()
# %%
    with get_context('forkserver').Pool(2) as p:
        p.map(analyze_one_file, elffiles, chunksize = 20)
# %%

if __name__ == '__main__':
    main()
