# Database
To bootstrap all plotting, package crawling and file analysis scripts set up
the database metadata (hostname, database name, username, password) in the 
db.py.

# Crawler scripts
Our crawler comprises of the following components: 
* import_packages_into_database.py : fetches the debian-main package index and creates entries for each package and all package dependencies in the database.
* fetch_packages.py : iterates over packages in the database and downloads the packages locally in the ../debs folder.
* enumerate_files.py : iterates over all downloaded packages and creates database entries for each file in each package.
* elf_info.py : iterates over all files in the database, extracts them from the downloaded packages and creates database entries for each symbol and section in the file.
* extract_files.py : iterates over all downloaded packages and extracts each file in the packages adding them in the ../extracted folder.
# Plots

## Generating histogram plot showing the distribution of functions that can throw exceptions (Fig 3.)

### Generating the plot (hardcoded numbers)

```bash
python3 scatter_plot_size_gadgets.py histogram
```

### Visualising the numbers used in the plot

```bash
python3 throw_statistics.py 100 > some_file
```

## Generating scatter plot showing correlation between binary sizes and number of gadgets (Fig 4.)

### Generating the csv for the plot

```bash
python3 taint_size_connection.py 100
```

### Generating the plot

```bash
python3 scatter_plot_size_gadgets.py scatter
```

## Generating plot showing cumulative distribution of dependencies and cdf dependencies with exception handling semantics (Fig 5.)

### Generating the csv for the plot

```bash
python3 infer_library_distribution.py
```

### Generating the plot

```bash
python3 scatter_plot_size_gadgets.py cdf
```

