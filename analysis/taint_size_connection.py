from analysis import *
from os.path import exists
from db import db_connect
import sys
import pprint
import csv
import ntpath
packages = {}

HANDLES_EXCEPTIONS = 2
HANDLES_CLEANUP = 1


def count_sinks(file, eh):
    global packages;
    type = "notype"
    if (eh.mask & HANDLES_EXCEPTIONS):
        type = "catch"
    elif (eh.mask & HANDLES_CLEANUP) :
        type = "clean"
    file[type]["num_sinks"] +=  eh.num_sinks
    file[type]["num_leaks"] += eh.num_leaks
    file[type]["num_deletes"] += eh.num_deletes
    file[type]["num_www"] += eh.num_www
    file[type]["num_where"] += eh.num_where
    file[type]["num_what"] += eh.num_what
    file[type]["num_jumps"] += eh.num_jumps
    file[type]["num_icalls"] += eh.num_icalls

def mark_vulnerable(file, eh):
    if (eh.mask & HANDLES_EXCEPTIONS):
        file["num_vuln_ctc"] += 1
    elif (eh.mask & HANDLES_CLEANUP) :
        file["num_vuln_cln"] += 1
def populate_file(obj):
    file = {}
    # general info about package such as number of handlers, vulnerable handlers and number of sinks
    file["num_eh"] = obj.num_eh
    file["num_vuln"] = obj.num_vuln
    file["num_vuln_cln"] = 0
    file["num_vuln_ctc"] = 0
    file["num_sinks"] = 0
    file["num_affected_func"] = 0
    # cleanup and catch oriented info
    file["catch"] = {}
    file["clean"] = {}
    file["catch"]["num_sinks"] =  0
    file["catch"]["num_leaks"] =  0
    file["catch"]["num_deletes"] = 0
    file["catch"]["num_www"] = 0
    file["catch"]["num_where"] = 0
    file["catch"]["num_what"] = 0
    file["catch"]["num_jumps"] = 0
    file["catch"]["num_icalls"] = 0
    file["clean"]["num_sinks"] =  0
    file["clean"]["num_leaks"] =  0
    file["clean"]["num_deletes"] = 0
    file["clean"]["num_www"] = 0
    file["clean"]["num_where"] = 0
    file["clean"]["num_what"] = 0
    file["clean"]["num_jumps"] = 0
    file["clean"]["num_icalls"] = 0
    funcset = []
    if not obj.ehs:
        return file 
    for eh in obj.ehs:
        file["num_sinks"] = file["num_sinks"] + eh.num_sinks
        if eh.num_sinks:
            mark_vulnerable(file, eh)  
        if (eh.start not in funcset):
            funcset.append(eh.start)
            file["num_affected_func"] += 1

        count_sinks(file, eh)
    return file
    

def analyze_one_file(arg, writer_object):
    global packages
    file_id, filename, package = arg
    if package not in packages.keys():
       packages[package] = []
    analysis_obj = getAnalysisForFile(AnalysisType.TAINT_INFO, file_id)
    file_stats = {}
    if analysis_obj != None:
       file_stats = populate_file(analysis_obj)
    else:
       file_stats["num_sinks"] = 0

    db = db_connect()
    cursor = db.cursor()

    cursor.execute("""
                   SELECT size from files f where f.id = %(file_id)s
                   """, dict(file_id=file_id))

    record = cursor.fetchone()

    db.close()
    row = ["", "", "" , "" , ""]
    row[0] = file_id
    row[1] = ntpath.basename(filename)
    row[2] = package
    row[3] = record[0]
    row[4] = file_stats["num_sinks"]
    writer_object.writerow(row)

    print("id:", file_id, "filename:", ntpath.basename(filename), "package:", package, "size:", record[0], "num_sinks:", file_stats["num_sinks"])
    

def print_per_file_gadget_summary(pname, file_vec, type):
    print(f"{type}:Summary on the number of per-file gadget types for:" + pname)
    tags = ["FILE", "NUM_LEAKS." , "NUM_UAF.",  "NUM_WWW." , "NUM_W_WHAT.", "NUM_W_WHERE", "NUM_IJUMPS", "NUM_ICALLS" ]
    print(f"{tags[0]:<20} {tags[1]:<10}  {tags[2]:<10}  {tags[3]:<10} {tags[4]:<10} {tags[5]:<10} {tags[6]:<10} {tags[7]:<10}")    
    dash = "-"
    spc = " "
    for file in file_vec:
        if file[1] == None:

           print(f"{file[0]:<20} {dash:<10}  {dash:<10}  {dash:<10} {dash:<10}  {dash:<10}  {dash:<10} {dash:<10}") 
           continue 
        file_summary = file[1]
        num_leaks =   file_summary[type]["num_leaks"]
        num_deletes = file_summary[type]["num_deletes"]
        num_www =  file_summary[type]["num_www"]
        num_where =  file_summary[type]["num_where"]
        num_what =  file_summary[type]["num_what"]
        num_jumps =  file_summary[type]["num_jumps"]
        num_icalls =  file_summary[type]["num_icalls"]
        print(f"{file[0]:<20} {num_leaks:<10}  {num_deletes:<10}  {num_www:<10}  {num_where:<10}  {num_what:<10}  {num_jumps:<10}  {num_icalls:<10}")
       
    print("")
    print("")  

def print_package_file_stats(pname, file_vec):
    global package_summaries
    print("Summary on the number of per-file handlers + totalgadgets on package:" + pname)
    tags = ["FILE", "TOTAL." , "VULN.",  "CATCH." , "CLEAN.", "TOTAL_GADGETS", "TOTAL_CATCH_G", "TOTAL_CLN_G" ]
    print(f"{tags[0]:<20} {tags[1]:<10}  {tags[2]:<10}  {tags[3]:<10} {tags[4]:<10} {tags[5]:<10} {tags[6]:<10} {tags[7]:<10}")
    package_summary = {}
    dash = "-"
    spc = " "
    for file in file_vec:
        if file[1] == None:

           print(f"{file[0]:<20} {dash:<10}  {dash:<10}  {dash:<10} {dash:<10}  {dash:<10}  {dash:<10} {dash:<10}") 
           continue 
        file_summary = file[1]
        num_eh = file_summary["num_eh"]
        num_vuln = file_summary["num_vuln"]
        num_vuln_ctc = file_summary["num_vuln_ctc"]
        num_vuln_cln = file_summary["num_vuln_cln"]
        total_gadgets = file_summary["num_sinks"]
        total_gadgets_ctc = file_summary["catch"]["num_sinks"]
        total_gadgets_cln = file_summary["clean"]["num_sinks"]
        print(f"{file[0]:<20} {num_eh:<10}  {num_vuln:<10}  {num_vuln_ctc:<10}  {num_vuln_cln:<10}  {total_gadgets:<10}  {total_gadgets_ctc:<10}  {total_gadgets_cln:<10}")
       
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

    db.close()
    header = ['id','filename','package', 'size', 'num_sinks']
    with open('file_size_num_sinks.csv', 'w') as f_object:
      writer_object = csv.writer(f_object, delimiter=',')
      writer_object.writerow(header) # header
      for file_tuple in elffiles:
        analyze_one_file(file_tuple, writer_object)

      f_object.close()



main()

