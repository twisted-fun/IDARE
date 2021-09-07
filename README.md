# IDARE
Automation of various reversing tasks in IDA. Tested on IDA Pro 7.5 with Python 3.7 but should work with Python 2.7 as well.

## Installation
Just put the scripts inside IDA Plugins directory and relaunch IDA.

## Scripts
### JumpTableFuncRename.py
- Bulk renaming of functions inside jump tables.
### VulnCandidateFinder.py
- Finds possible vulnerable invocation of dangerous functions in the binary.
- Lists all finding in a table view where address of function invocation, caller function name and repeatable comment are shown.
- View allows editing caller function name as well as repeatable comment by key shortcuts `n` and `;` respectively. Or by right click menu on any row.