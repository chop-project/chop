import csv
import subprocess
interesting_imports = []
boost_libs = {}
import_hitmap = {}
import_package = {}
package_hitmap = {}
workdir = '/home/victor/workspace/PHD/exceptions/extracted'
import_dictionary = dict()
from db import db_connect

def get_file_hash_and_name(file_id):

    db = db_connect()
    cursor = db.cursor()
    cursor.execute("""
                   SELECT sha256, filename from files f where f.id = %(file_id)s
                   """, dict(file_id=file_id))

    record = cursor.fetchone()

    db.close()
    return record

header = ["id", "total", "catching"]
with open('total_catching_libs.csv', 'w') as f_object:
 writer_object = csv.writer(f_object, delimiter=',')
 writer_object.writerow(header) # header
   
 with open('imports.csv') as csv_file:
    csv_reader = csv.reader(csv_file, delimiter=",")
    next(csv_reader) # header
    for row in csv_reader:
        imports = str(row[0])
        file_id = str(row[1])
        visited = []

        total_imports = 0
        exc_imports = 0
        for imp in imports.strip('[] ').split(','):
              imp = imp.strip(' ')
              if imp == "":
                  continue
              total_imports = total_imports + 1
              if imp in import_dictionary:
                 exc_imports = exc_imports + import_dictionary[imp]
                 continue
                 
              hash, name = get_file_hash_and_name(imp)
              
              cmd = "readelf -l %s/%s | grep '\.gcc_except_table' | wc -l" % (workdir, hash)
              ret = int(subprocess.getstatusoutput(cmd)[1])
              # Cache already searched imports
              import_dictionary[imp] = ret
              exc_imports = exc_imports + ret
        writer_object.writerow( [file_id, str(total_imports), str(exc_imports)] )
        #print("Num imports:", total_imports, "Handling imports:", exc_imports)
 f_object.close()
'''
num_boost_static = 0
with open('dataset.csv') as csv_file:
    csv_reader = csv.reader(csv_file, delimiter=",")
    next(csv_reader) # header
    for row in csv_reader:
        filename = str(row[0])
        sha256 = str(row[1])
        file_id = str(row[2])
        if filename == './sbin/ldconfig':
           continue
        cmd = "nm -D %s/%s | grep boost | awk '{print $3}' | c++filt | grep 'boost::' | grep exception | wc -l" % (workdir, sha256)
        nums = int(subprocess.getoutput(cmd))
        if nums != 0 and file_id not in users:
           print(filename, "boost-functions:" , nums, "sha:", sha256)
           num_boost_static = num_boost_static + 1
    csv_file.close()
'''
