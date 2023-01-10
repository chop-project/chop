from analysis import *
from os.path import exists
from db import db_connect
import sys
import pprint
import ntpath
packages = {}

package_summaries = []

def analyze_one_file(arg):
    global packages
    file_id, filename, package = arg
    if package not in packages.keys():
       packages[package] = []
    analysis_obj = getAnalysisForFile(AnalysisType.THREAT_INFO, file_id)
    if analysis_obj != None:
       packages[package].append((ntpath.basename(filename), file_id, analysis_obj.total_functions, analysis_obj.total_throw))
    else:
       packages[package].append((ntpath.basename(filename), file_id, None, None))

def print_package_file_stats(pname, vec):
    global package_summaries
    print("Summary of all throws for package:" + pname)
    tags = ["FILE", "TOTAL" , "THROWS" , "(%)" ]
    print(f"{tags[0]:<25}  {tags[1]:<10}  {tags[2]:<10}  {tags[3]:<10}")
    avgpercent = 0
    numfiles = 0
    numfunctions = 0
    throwfuncs = 0
    numfiles = 0
    for file in vec:
        percent = 0
        if file[2] == None:
           dash = "-"
           print(f"{file[0]:<15}  {dash:<10}  {dash:<10}  {dash:<10}") 
           continue 
        total = int(file[2])
        throws = int(file[3])
        if total != 0:
           percent = float(throws/total) * 100
        else:
           percent = 0 
        avgpercent = avgpercent + percent
        numfunctions = numfunctions + total
        throwfuncs = throwfuncs + throws
        numfiles = numfiles + 1
        per_Val = f"{round(percent, 2)}%"
        print(f"{file[0]:<25}  {total:<10}  {throws:<10}  {per_Val:<10}")  
    if numfunctions != 0:
       package_summaries.append((pname, numfunctions, throwfuncs, avgpercent, numfiles))
    print("")
    print("")  

def print_packages_summaries():
    tags = ["PACKAGE", "TOTAL" , "THROWS" , "ovr. (%)", "avg. (%)" ]
    print(f"{tags[0]:<25}  {tags[1]:<10}  {tags[2]:<10}  {tags[3]:<10}  {tags[4]:<10}")

    for package in package_summaries:
        ovr_percent = round(float(package[2]/package[1]) * 100, 2)
        avg_percent = round(package[3]/package[4], 2)
        ovr_Val = f"{ovr_percent}%"
        avg_Val = f"{avg_percent}%"
        print(f"{package[0]:<15}  {package[1]:<10}  {package[2]:<10}  {ovr_Val:<10}  {avg_Val:<10}")
        
def main():
    global packages;
    db = db_connect()
    cursor = db.cursor()

    rank = sys.argv[1]
    cursor.execute("""
                   SELECT id, filename, name from cpp_files_cutoff f where rk <= %(rank)s
                   """, dict(rank=rank))

    elffiles = cursor.fetchall()

    

    for file_tuple in elffiles:
        analyze_one_file(file_tuple)

    cursor.execute("""
                   SELECT distinct(name), rk from cpp_files_cutoff where rk <= %(rank)s order by 2
                   """, dict(rank=rank))

    elffiles = cursor.fetchall()

    db.close()

    for package in elffiles:
        print_package_file_stats(package[0], packages[package[0]])
    print_packages_summaries()
    #print(packages)

main()

