
# File Hash Scanner

A PowerShell utility to scan directories, create file hashes, and track changes between scans.

## Overview

This tool creates a hash of files in a directory (and optionally its subdirectories), stores the hash values along with other file metadata, and allows comparison between scans to identify:

- Files that have been added
- Files that have been deleted
- Files that have been renamed
- Files that have been modified

The tool is useful for monitoring file system changes, identifying unauthorized modifications, or creating a baseline of system files.

## Features

- Scan directories and create SHA256 hashes of all files
- Record detailed file metadata (creation time, last access, size, etc.)
- Exclude previous scan reports from new scans
- Create baseline scans for future comparison
- Compare current scans with previous scans
- Identify added, removed, renamed, and modified files
- Generate change reports
- Optional GUI view of results using PowerShell's Out-GridView
- Support for recursive directory scanning

## Requirements

- PowerShell 5.1 or higher
- Windows operating system

## Usage

### Basic Usage

```powershell
.\finalFinal.ps1
```

When run without parameters, the script will prompt you for:
- The directory to scan
- Whether to scan subdirectories
- Which previous scan file to compare against (if any)
- Whether to view results in the GUI
- Whether to create a change file

### Command Line Parameters

```powershell
.\finalFinal.ps1 -Directory "C:\FolderToScan" -Recurse -Compare -ViewGUI
```

| Parameter  | Description |
|------------|-------------|
| -Directory | Specifies the directory to scan |
| -ViewGUI   | Show results in PowerShell's Out-GridView |
| -Base      | Create a baseline file (adds "_base" to filename) |
| -Recurse   | Scan subdirectories |
| -Compare   | Compare with a previous scan file |
| -ChangeFile| Create a report of changes between scans |
| -helpProgram| Display help information |

### Examples

#### Create a baseline scan:
```powershell
.\finalFinal.ps1 -Directory "C:\Windows\System32" -Base -Recurse
```

#### Compare current state with baseline:
```powershell
.\finalFinal.ps1 -Directory "C:\Windows\System32" -Compare -ViewGUI -ChangeFile
```

## Output Files

The script creates CSV files in the scanned directory with names like:
- `HashFile_20250427T143022123.csv` - Standard scan file
- `HashFile_20250427T143022123_base.csv` - Baseline scan file
- `HashFile_20250427T143022123_changefile.csv` - Change report file

## How It Works

1. The script scans all files in the specified directory
2. For each file, it creates a SHA256 hash and collects metadata
3. Results are saved to a timestamped CSV file
4. When comparing, it analyzes differences between file sets by:
   - Finding files only in the previous scan (deleted files)
   - Finding files only in the current scan (new files)
   - Finding files with the same content but different names (renamed files)
   - Finding files with the same names but different content (modified files)

## Functions

| Function | Description |
|----------|-------------|
| Get-StringHash | Creates a hash of a string using various algorithms |
| Test-FileIsLocked | Checks if a file is locked for reading |
| Scan-Directory | Scans a directory and creates hashes of all files |
| create-exportfilename | Creates a filename for the export CSV |
| Export-FileOut | Exports the file data to a CSV |
| Does-HashFileExist | Checks if a hash file exists |
| Get-HashFileList | Gets a list of previous hash files |
| redin-CSVFile | Reads in a CSV file |
| Display-Result | Displays results of the comparison |
| Display-GridViews | Displays results in Grid View windows |
| Write-ChangeFile | Writes a change file |
| compare-data2 | Compares two sets of file data |

## Notes

- The script creates files in the scanned directory, so the user running the script must have write permissions
- Scanning large directories with many files may take considerable time
- The script ignores its own output files (files matching the pattern "HashFile*.csv")
- When scanning locked files, the script will skip them

## License

[Specify your license here]

## Author

Robert Schwartz
