from analysis import *
from os.path import exists
from db import db_connect
import sys
import pprint
import ntpath
import pickle

import numpy as np
import matplotlib.pyplot as plt
from matplotlib.ticker import PercentFormatter
import matplotlib.ticker as mtick
#plt.style.use('ggplot')


packages = {}

package_summaries = []
throws_list  = []

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
    global throws_list

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
        throws_list.append(round(percent))

    if numfunctions != 0:
       package_summaries.append((pname, numfunctions, throwfuncs, avgpercent, numfiles))
    print("")
    print("")



def do_histogram(data):
    fig, ax1 = plt.subplots()


    ax2 = ax1.twinx()
    # ax1.grid(True, linestyle='-.', linewidth=0.4)
    plt.grid(which='major', alpha=0.5, linestyle='--')
    plt.grid(which='minor', alpha=0.3, linestyle='--')


    bins = [-1, 1] + list(range(5, 101, 5))

    ax1.hist(data, weights=np.ones(len(data)) / len(data), bins=bins, edgecolor='black', linewidth=0.7,
             color='skyblue')
    ax1.set_ylabel('Percentage of binaries')
    ax1.set_xlabel('Percentage of functions that can throw exceptions');
    ax1.yaxis.set_major_formatter(PercentFormatter(1))
    ax1.set_xticks(range(0, 101, 10))

    values, base = np.histogram(data, bins=50)
    cumulative = np.cumsum(values)

    x = len(data) - cumulative
    z = [y * 100 / max(x) for y in x]

    ax2.plot(base[:-1], z, color='teal')
    ax2.set_ylim(bottom=0)
    ax2.set_ylabel('Inverse cumulative distribution function')
    ax2.yaxis.set_major_formatter(PercentFormatter(100))
    ax2.set_yticks(list(range(0, 100, 10)), minor=True)
    fig.savefig('/tmp/throws_histogram.png', dpi=300, bbox_inches="tight")


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

    with open('/tmp/histo.pickle', 'wb') as f:
        f.write(pickle.dumps(throws_list))

def main2():
    throws_list = [19, 22, 29, 30, 23, 18, 27, 23, 17, 16, 20, 30, 25, 32, 19, 19, 17, 21, 52, 49, 0, 0, 30, 34, 20, 19, 17, 0, 14, 26, 31, 27, 13, 18, 20, 25, 25, 10, 22, 24, 0, 4, 14, 14, 32, 30, 0, 4, 5, 50, 26, 59, 0, 50, 26, 41, 5, 12, 34, 12, 30, 1, 60, 15, 56, 46, 60, 57, 43, 47, 45, 13, 8, 28, 8, 25, 34, 10, 41, 63, 25, 16, 29, 28, 45, 11, 20, 0, 0, 22, 6, 6, 21, 41, 46, 41, 47, 35, 14, 68, 58, 51, 64, 58, 60, 67, 59, 59, 63, 63, 43, 55, 48, 52, 38, 49, 46, 59, 56, 20, 48, 37, 49, 61, 10, 31, 49, 37, 42, 52, 44, 61, 35, 71, 46, 60, 53, 58, 40, 36, 58, 47, 62, 69, 71, 24, 59, 55, 40, 41, 34, 40, 44, 58, 61, 18, 57, 56, 53, 51, 57, 58, 63, 31, 59, 54, 41, 46, 67, 35, 59, 59, 49, 39, 51, 67, 53, 41, 42, 30, 67, 35, 38, 65, 57, 22, 56, 57, 63, 53, 68, 52, 50, 43, 45, 55, 53, 62, 65, 47, 65, 50, 62, 54, 67, 45, 56, 54, 64, 37, 33, 47, 58, 56, 51, 57, 49, 48, 53, 22, 54, 21, 3, 2, 11, 11, 16, 10, 3, 55, 54, 46, 43, 38, 68, 42, 47, 45, 43, 56, 63, 53, 47, 41, 44, 28, 48, 32, 4, 38, 29, 28, 30, 39, 28, 45, 47, 75, 63, 52, 42, 40, 54, 33, 47, 67, 59, 44, 35, 35, 43, 39, 38, 35, 12, 26, 63, 41, 40, 38, 49, 48, 47, 65, 47, 52, 41, 68, 58, 36, 48, 2, 32, 19, 46, 55, 41, 29, 16, 12, 23, 61, 12, 45, 24, 10, 2, 40, 10, 49, 33, 41, 15, 32, 53, 40, 10, 15, 25, 25, 29, 39]

    # with open('/tmp/histo.pickle', 'rb') as f:
    #     throws_list = pickle.load(f)
    do_histogram(throws_list)

main2()

# Instruction to replicate the histogram:
# run first main (which pickles a list in '/tmp/', then main2)
