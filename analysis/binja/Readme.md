# Compilation

First modify Makefile and set the environment variables to the correct binary
ninja core and C++ binja API from your system. Compile the rust plugin (check
cloned_name/ehdump) and then set the correct RUST_PLUGIN path this Makefile.
You also need libpqxx-7.7 installed (and the correct path set in the Makefile).


Compile the threat_analysis and taint_analysis binaries using:

```bash
make all
```

The binaries requires that all files from the debian packages be extracted.
Check cloned_repo/analysis/extract_files.py

From outside the directory where the repository is cloned run:

```bash
mkdir threatinfo
mkdir taintinfo
mkdir extracted
python3 cloned_repo/analysis/extract_files.py
./cloned_repo/binja_analyses/taint_analysis &
./cloned_repo/binja_analyses/threat_analysis &
```


