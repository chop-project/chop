from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from elftools.elf.dynamic import DynamicSection
import sys
from multiprocessing import Pool, get_context
from analysis import *
from os.path import exists
from db import db_connect
from binaryninja import *


def get_libraries(fileobj):
     fileobj.seek(0)
     libraries = []
     if fileobj.read(4) != b"\x7fELF":
           fileobj.seek(0)
           return []

     fileobj.seek(0)
     elf = ELFFile(fileobj)
     for section in [
          section
          for section in elf.iter_sections()
          if isinstance(section, DynamicSection)
      ]:
          for library in [
              tag.needed for tag in section.iter_tags() if hasattr(tag, "needed")
          ]:
             libraries.append(library)

     return libraries

def analyze_one_file(arg):
    file_id, filename, file_sha256, package = arg
    print(f'Creating dso links for file:{filename} file_id:{file_id} sha256:{file_sha256}')

    if not exists(f'./extracted/{file_sha256}'): 
        print(f'{filename} file_id:{file_id} sha256:{file_sha256} is missing...')
        return

    bv = open(f'./extracted/{file_sha256}', "rb")

    libs = get_libraries(bv)

    bv.close()

    if not len(libs):
       print(f'{filename} file_id:{file_id} sha256:{file_sha256} no libs...')
       return
    #pattern = "%" + libs[0] + "%|";

    pattern = "%(" + libs[0] + "|";

    for lib in libs[1:]: 
       #pattern = pattern + "%" + lib + "%|";
       pattern = pattern + lib + "|";

    pattern = pattern[:-1] + ")%"

    pattern = pattern.replace(".", "\.")
    pattern = pattern.replace("+", "\+")

    print(libs)

    db = db_connect()
    cursor = db.cursor()

    cursor.execute("""SELECT F.id, F.filename, F.sha256 from files F 
                      WHERE F.package in (SELECT dependee from dependencies where dependent = %(package)s)
                      AND F.filename SIMILAR TO %(pattern)s AND F.magic = 'application/x-sharedlib'
                   """, dict(package = package, pattern = pattern))

    candidates = cursor.fetchall()
    db.close()
    module_summary = DSOModuleSummary(imports = [])
 
    print(f'{filename} file_id:{file_id} sha256:{file_sha256} possible libs...')
    for candidate in candidates:
       print(candidate)
       module_summary.imports.append(candidate[0])

    print(module_summary)
    # Write module summary to db.
    writeAnalysisForFile(AnalysisType.DSO_LINKS, file_id, module_summary)

def main():

    db = db_connect()
    cursor = db.cursor()

    cursor.execute("""
                   SELECT F.id, F.filename, F.sha256, F.package FROM elf_files F
                   WHERE F.id NOT IN (SELECT file_id from analysis WHERE file_id = F.id and type = %(type)s) 
                   ORDER BY f.size ASC
                   """, dict(type=AnalysisType.DSO_LINKS))

    elffiles = cursor.fetchall()
    db.close()
    print("Selecting:" + str(len(elffiles)))
    with get_context('forkserver').Pool(2) as p:
        p.map(analyze_one_file, elffiles, chunksize = 20)


if __name__ == '__main__':
    main()

