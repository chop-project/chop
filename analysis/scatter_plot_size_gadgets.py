#%%

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
import csv
from matplotlib.lines import Line2D
from scipy import stats
packages = {}

package_summaries = []
throws_list  = []

plt.rcParams.update({
    "text.usetex": True,
    "font.family": "serif",
    "font.size": "8",
    #"font.sans-serif": ["Helvetica"]
})


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


#%%
def do_histogram(data):
    fig, ax1 = plt.subplots(figsize=(3.5,1.33))
    ax2 = ax1.twinx()

    bins = [-1, 1] + list(range(5, 90, 5))

    ax1.hist(data, weights=np.ones(len(data)) / len(data), bins=bins, edgecolor='black', linewidth=0.5)
    ax1.set_ylabel('Percentage\nof binaries')
    ax1.set_xlabel('Percentage of functions that can throw exceptions');
    ax1.yaxis.set_major_formatter(PercentFormatter(1))

    ax1.set_xticks(range(0, 101, 10))
    ax1.set_xlim((0,100))

    values, base = np.histogram(data)
    cumulative = np.cumsum(values)

    x = len(data) - cumulative
    z = [round(y * 100 / max(x)) for y in x]
    ax2.plot(base[:-1], z, color='red')
    ax2.set_ylabel('Inverse CDF')
    ax2.yaxis.set_major_formatter(PercentFormatter(100))
    
    
    ax1.margins(x=0)
    ax2.margins(x=0)

    ax1.spines['top'].set_visible(False)
    ax1.get_xaxis().tick_bottom()
    ax2.spines['top'].set_visible(False)
    ax2.get_xaxis().tick_bottom()

    fig.tight_layout()
    fig.savefig('throws_histogram.pdf')


#%%
def do_histogram_2(data):
    fig, ax1 = plt.subplots()
    ax2 = ax1.twinx()

    bins = [-1, 1] + list(range(5, 90, 5))

    ax1.hist(data, weights=np.ones(len(data)) / len(data), bins=bins, edgecolor='black', linewidth=0.5)
    ax1.set_ylabel('Functions that can throw exceptions')
    ax1.set_xlabel('Percentage of throwers that use canaries');
    ax1.yaxis.set_major_formatter(PercentFormatter(1))
    ax1.set_xticks(range(0, 101, 10))

    values, base = np.histogram(data)
    cumulative = np.cumsum(values)

    x = len(data) - cumulative
    z = [round(y * 100 / max(x)) for y in x]
    ax2.plot(base[:-1], z, color='red')
    ax2.set_ylabel('Inverse cumulative distribution function')
    ax2.yaxis.set_major_formatter(PercentFormatter(100))
    fig.savefig('canaries.png', dpi=300, bbox_inches="tight")

def do_histogram_3(data):
    fig, ax1 = plt.subplots()


    ax2 = ax1.twinx()
    # ax1.grid(True, linestyle='-.', linewidth=0.4)
    plt.grid(which='major', alpha=0.5, linestyle='--')
    plt.grid(which='minor', alpha=0.3, linestyle='--')


    bins = [-1, 1] + list(range(5, 101, 5))

    ax1.hist(data, weights=np.ones(len(data)) / len(data), bins=bins, edgecolor='black', linewidth=0.7,
             color='skyblue')
    ax1.set_ylabel('Functions that can throw exceptions')
    ax1.set_xlabel('Percentage of throwers that use canaries');
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

    fig.savefig('canaries.png', dpi=300, bbox_inches="tight")

def update_prop(handle, orig):
    handle.update_from(orig)
    handle.set_marker("")

#%%
def do_cdf(total_libs, catch_libs, max_total):
    fig, ax1 = plt.subplots(figsize=(3.5, 1.33))

    #ax2 = ax1.twinx()
    # ax1.grid(True, linestyle='-.', linewidth=0.4)
    plt.grid(which='major', alpha=0.5, linestyle='--')
    plt.grid(which='minor', alpha=0.3, linestyle='--')


    bins =  list(range(0, max_total, 1)) + [np.inf]

    ax1.hist(total_libs, weights=np.ones(len(total_libs)) / len(total_libs), bins=bins, edgecolor='blue', linewidth=0.7, density = True, histtype ='step', cumulative = True,
             label='total', color = 'blue')
    ax1.margins(x=0)

    ax1.set_ylabel('Percentage\nof binaries')
    ax1.set_xlabel('Number of libraries');
    ax1.set_yticks(np.arange(0, 1.05, 0.2))
    ax1.yaxis.set_major_formatter(PercentFormatter(1))
    ax1.set_xticks(range(0, max_total+1, 1))
    
    ax1.xaxis.set_major_locator(mtick.MultipleLocator(5))
    ax1.xaxis.set_minor_locator(mtick.MultipleLocator(1))
    ax1.hist(catch_libs, weights=np.ones(len(total_libs)) / len(total_libs), bins=bins, edgecolor='red', linewidth=0.7, density = True, histtype ='step', cumulative = True,
             label='handle', color='red')
    box = ax1.get_position()
    custom_lines = [Line2D([0], [0], color='blue', lw=2), Line2D([0], [0], color='red', lw=2)]

    ax1.legend(custom_lines, ['number of\nlinked libraries', 'libraries that\nhandle exceptions'], loc="lower right")
    ax1.spines['top'].set_visible(False)
    ax1.spines['right'].set_visible(False)
    ax1.get_xaxis().tick_bottom()
    ax1.get_yaxis().tick_left()

    ratio = 0.25
    x_left, x_right = ax1.get_xlim()
    y_low, y_high = ax1.get_ylim()
    #ax1.set_aspect(abs((x_right-x_left)/(y_low-y_high))*ratio)

    fig.tight_layout()
    fig.savefig('linked_libs.pdf', dpi=300, bbox_inches="tight") 

def do_double_barplot(total_libs, catch_libs, max_total):
    fig, ax1 = plt.subplots()
    N = len(total_libs)
    ind = np.arange(N) 

    #ax2 = ax1.twinx()
    # ax1.grid(True, linestyle='-.', linewidth=0.4)
    plt.grid(which='major', alpha=0.5, linestyle='--')
    plt.grid(which='minor', alpha=0.3, linestyle='--')


    bins =  list(range(0, max_total, 1))

    ax1.hist(total_libs, weights=np.ones(len(total_libs)) / len(total_libs), bins=bins, edgecolor='blue', linewidth=0.7, density = True, histtype ='step', cumulative = True,
             label='total', color = 'blue')

    ax1.set_ylabel('percentage\nof binaries')
    ax1.set_xlabel('number of linked libraries');
    ax1.yaxis.set_major_formatter(PercentFormatter(1))
    #ax1.set_yticks(range(0, 100, 5))
    ax1.set_xticks(range(0, max_total+1, 5))

    #ax1.hist(catch_libs, weights=np.ones(len(catch_libs)) / len(catch_libs), bins=bins, edgecolor='black', linewidth=0.7,
    #         color='red')

    ax1.hist(catch_libs, weights=np.ones(len(total_libs)) / len(total_libs), bins=bins, edgecolor='red', linewidth=0.7, density = True, histtype ='step', cumulative = True,
             label='catch', color='red')
    #line1, = ax1.plot([1, 2, 3], label='label1')
    #line2, = ax1.plot([1, 2, 3], label='label2')
    #ax1.legend()
    ax1.legend(loc='upper center', bbox_to_anchor=(0.5, 1.05), ncol=3, fancybox=True, shadow=True)
     # Shrink current axis's height by 10% on the bottom
    box = ax1.get_position()
    #ax1.set_position([box.x0, box.y0 + box.height * 0.1,
    #             box.width, box.height * 0.9])

    # Put a legend below current axis
    #ax1.legend(loc='upper center', bbox_to_anchor=(0.5, -0.05),
    #      fancybox=True, shadow=True, ncol=5)
    #plt.legend(bbox_to_anchor =(0.65, 1.0))
    custom_lines = [Line2D([0], [0], color='blue', lw=2), Line2D([0], [0], color='red', lw=2)]

    plt.legend(custom_lines, ['total', 'catch'], loc=(1.04, 0.90))
    '''
    values, base = np.histogram(total_libs, bins=50)
    cumulative = np.cumsum(values)

    x = len(total_libs) - cumulative
    z = [y * 100 / max(x) for y in x]

    ax2.plot(base[:-1], z, color='teal')
    ax2.set_ylim(bottom=0)
    ax2.set_ylabel('Inverse cumulative distribution function')
    ax2.yaxis.set_major_formatter(PercentFormatter(100))
    ax2.set_yticks(list(range(0, 100, 10)), minor=True)
    '''
    fig.savefig('linked_libs.png', dpi=300, bbox_inches="tight")     


def do_bar_plot(data):

    # Fixing random state for reproducibility
    np.random.seed(19680801)


    plt.rcdefaults()
    fig, ax = plt.subplots()

     # Example data
    people = ('1', '2', '3', '4', '5', '6')
    y_pos = np.arange(len(people))
    performance = 3 + 10 * np.random.rand(len(people))
    error = np.random.rand(len(people))

    ax.barh(y_pos, performance, align='center')
    ax.set_yticks(y_pos)
    ax.set_yticklabels(people)
    ax.invert_yaxis()  # labels read top-to-bottom
    ax.set_xlabel('Percentage of callees')
    ax.set_title('How fast do you want to go today?')

    fig.savefig('bar_plot_callee_saved.png', dpi=300, bbox_inches="tight")

def do_simple_bar_plot(data):
    import matplotlib.pyplot as plt
    fig = plt.figure()
    ax = fig.add_axes([0,0,1,1])
    ax.yaxis.set_major_formatter(PercentFormatter(1))
    callees = ['0', '1', '2', '3', '4', '5' , '6 ' ]
    percents = data
    ax.bar(callees,percents)
    ax.set_xlabel('Number of callee saved registers')
    ax.set_ylabel('Percentage of throw functions')
    fig.savefig('bar_plot_callee_saved.png', dpi=300, bbox_inches="tight")

def do_scatter(x,y):
    import matplotlib.pyplot as plt
    #plt.style.use('seaborn-whitegrid')
    #plt.figure(1)
    plt.scatter(x, y, marker='.');
    m, b = np.polyfit(x, y, deg = 1)
    r = np.corrcoef(x, y)
    x1 = np. array(x)
    plt.plot(x, m*x1.astype(np. float)+b, color="red", lw=0.5);
    plt.ylabel('Number of gadgets')
    plt.xlabel('Size in MBytes')
    plt.title("r = %.2f"%(r[0,1])) 
    plt.savefig('scatterplot_size_gadget.png')

#%%
def do_scatter2(x,y):
    import matplotlib.pyplot as plt
    fig, ax = plt.subplots(figsize=(3.5, 1.5))
    ax.margins(x=0, y=0)
    #plt.style.use('seaborn-whitegrid')
    #plt.figure(1)
    #plt.scatter(x, y, marker='.');

    ax.set_yscale('log', base=2)
    ax.set_xscale('log', base=2)
    ax.plot(x, y, 'pr', marker='.', color = 'blue', alpha=0.5);
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.get_xaxis().tick_bottom()
    ax.get_yaxis().tick_left()
    ax.set_xlim((0, max(x)*2))
    ax.set_ylim((0, max(y)*2))

    logx = np.log10(x)
    logy = np.log10(np.array(y)+ 1)
    m, b = np.polyfit(logx, logy, deg = 1)
    print(m, b)
    #fity = np.exp(m*logx + b)
    fity = np.power(10, m*logx + b)
    ax.plot(x, fity, color="red", lw=0.5);
    #plt.plot(x, fity, color="red", lw=0.5);
    #m, b = np.polyfit(x, y, deg = 1)
    #r = np.corr(logx, logy, 'method=kendall')
    r = stats.spearmanr(x,y)
    ax.annotate(f'$\\rho = {r.correlation:.2f}$', xy = (2**14, 2**10))
    #x1 = np. array(x)
    #plt.plot(x, m*x1.astype(np. float)+b, color="red", lw=0.5);
    ax.set_ylabel('Gadget Count')
    ax.set_xlabel('Binary Size / KiB')
    # ax.set_title("\\rho = %.2f"%(r.correlation)) 
    fig.tight_layout()
    fig.savefig('scatterplot_size_gadget.pdf')

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

    # print_packages_summaries()
    #print(packages)
    # import IPython; IPython.embed()

def main2():
    throws_list = [19, 22, 29, 30, 23, 18, 27, 23, 17, 16, 20, 30, 25, 32, 19, 19, 17, 21, 52, 49, 0, 0, 30, 34, 20, 19, 17, 0, 14, 26, 31, 27, 13, 18, 20, 25, 25, 10, 22, 24, 0, 4, 14, 14, 32, 30, 0, 4, 5, 50, 26, 59, 0, 50, 26, 41, 5, 12, 34, 12, 30, 1, 60, 15, 56, 46, 60, 57, 43, 47, 45, 13, 8, 28, 8, 25, 34, 10, 41, 63, 25, 16, 29, 28, 45, 11, 20, 0, 0, 22, 6, 6, 21, 41, 46, 41, 47, 35, 14, 68, 58, 51, 64, 58, 60, 67, 59, 59, 63, 63, 43, 55, 48, 52, 38, 49, 46, 59, 56, 20, 48, 37, 49, 61, 10, 31, 49, 37, 42, 52, 44, 61, 35, 71, 46, 60, 53, 58, 40, 36, 58, 47, 62, 69, 71, 24, 59, 55, 40, 41, 34, 40, 44, 58, 61, 18, 57, 56, 53, 51, 57, 58, 63, 31, 59, 54, 41, 46, 67, 35, 59, 59, 49, 39, 51, 67, 53, 41, 42, 30, 67, 35, 38, 65, 57, 22, 56, 57, 63, 53, 68, 52, 50, 43, 45, 55, 53, 62, 65, 47, 65, 50, 62, 54, 67, 45, 56, 54, 64, 37, 33, 47, 58, 56, 51, 57, 49, 48, 53, 22, 54, 21, 3, 2, 11, 11, 16, 10, 3, 55, 54, 46, 43, 38, 68, 42, 47, 45, 43, 56, 63, 53, 47, 41, 44, 28, 48, 32, 4, 38, 29, 28, 30, 39, 28, 45, 47, 75, 63, 52, 42, 40, 54, 33, 47, 67, 59, 44, 35, 35, 43, 39, 38, 35, 12, 26, 63, 41, 40, 38, 49, 48, 47, 65, 47, 52, 41, 68, 58, 36, 48, 2, 32, 19, 46, 55, 41, 29, 16, 12, 23, 61, 12, 45, 24, 10, 2, 40, 10, 49, 33, 41, 15, 32, 53, 40, 10, 15, 25, 25, 29, 39]

    # with open('/tmp/histo.pickle', 'rb') as f:
    #     throws_list = pickle.load(f)
    do_histogram(throws_list)

def main3():
    total_files = 0
    data = []
    total_funcs = 0
    with open('calle_saved.csv', newline='') as csvfile:
        reader = csv.DictReader(csvfile)
        
        for row in reader:
           print(row['functions'], row['callee_saved'])
           total_funcs += int(row['functions'])
           data.append(int(row['functions']))
    rz = []
    for data_points in data:
        p = round(float(data_points/total_funcs), 2)
        rz.append(p)
    do_simple_bar_plot(rz)   
def main4():
    total_files = 0
    data = []
    total_funcs = 0
    map = {}
    map_has = {}
    with open('catch.csv', newline='') as csvfile:
        reader = csv.DictReader(csvfile)

        for row in reader:
           #print(row['num'], row['has_canary'])
           if  row['filename'] not in map.keys():
               map[row['filename']] = int(row['num'])
           else:
               map[row['filename']] += int(row['num'])
           if (row['has_canary'] == 'true'):
               map_has[row['filename']] = int(row['num'])
    percents = []
    for elem in map_has.keys():
        total = map[elem]
        canaries = map_has[elem]
        percent = round((canaries/total)*100)
        print(str(total) +" "+ str(canaries) + " " + str(percent))
        percents.append(percent)
    rang = range(8)
    for it in rang: 
       percents.append(0)
    sum = 0
    for i in percents:
       sum += i
    avg = sum/(len(percents))
    print(percents)
    print(avg)
    dev = 0
    for i in percents:
        dev += (i - avg)/100 * (i - avg)/100
    dev = dev/(len(percents))
    print(dev)
    print(round(avg,1))
    
    #do_histogram_2(percents)
    #do_bar_plot(None)

# Plot size/num_available_gadgets scatter plot for popular bins
def main5():
    x = []
    y = []
    num_size = 0
    num_s = 0
    with open('file_size_num_sinks.csv', newline='') as csvfile:
        reader = csv.DictReader(csvfile)

        for row in reader:
           #size = int(row['size']) 
           size = float(int(row['size'])/1024)
           #if size > 60:
           #   print(size)
           #   num_size = num_size + 1
           #   continue
           num_sinks = int(row['num_sinks'])
           #if num_sinks == 0:
           #   num_s = num_s + 1
           #   continue
           
           x.append(size)
           y.append(num_sinks)
    print(num_size, num_s)
    do_scatter2(x,y)

# Plot CDF for total number libraries/ total number of libraries that handle exception for popular bins.
def main6():
    x = []
    y = []
    max_x = 0
    total_catch = 0
    total_one = 0
    total_10 = 0
    with open('total_catching_libs.csv', newline='') as csvfile:
        reader = csv.DictReader(csvfile)

        for row in reader:
           new_x = int(row['total'])
           new_y = int(row['catching'])
           if (new_x > max_x):
              max_x = new_x
           x.append(new_x)
           y.append(new_y)
           if new_y >= 1:
              total_catch = total_catch + 1
           if new_y == 1:
              total_one = total_one + 1
           if new_y >= 5:
              total_10 = total_10 + 1
    print(round(float(total_catch/len(y)) * 100, 2))
    print(round(float(total_one/len(y)) * 100, 2))
    print(round(float(total_10/len(y)) * 100, 2))
    do_cdf(x,y, 30)

if sys.argv[1] == "histogram":
   main2()
if sys.argv[1] == "scatter":
   main5()

if sys.argv[1] == "cdf":
   main6()

# %%
