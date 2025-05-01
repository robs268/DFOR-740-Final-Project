# command line arguements - they are mean to be named pair.
# for example final.ps1 -Directory "C:\myfolder".  A switch
# parameter if you want to use it, you put it on the command
# line.  For example if you want to view the GUI stuff, just
# put -ViewGUI
param (
    [string]$Directory,              # Directory to scan (done)
    [switch]$ViewGUI,                # Checks if the user wants to view data in GUI (done)
    [switch]$Base,                   # Switch parameter (done)
    [switch]$Recurse,                # checks if the user wants to do sub-directories (done)
    [string]$Compare,                # Switch parameter (done)
    [bool]$ChangeFile,               # Switch parameter (done)
    [switch]$help,                   # user needs help on command line (done)
    [switch]$helpweb                 # Show Web Page of Help. (done)
)

###############################################
# Add-CustomError
###############################################
function Add-CustomError 
{
    param (
        [string]$Message,
        [string]$Category = "OperationStopped"
    )

    # Check if the error message already exists in $Error
    $existingError = $Error | Where-Object { $_.Exception.Message -eq $Message }

    if (-not $existingError) {
        Write-Error -Message $Message -Category $Category
    }
}

###############################################
# Get-StringHash 
###############################################
function Get-StringHash 
{
  param(
    [Parameter(Mandatory)]
    [string]$String,
    [ValidateSet('SHA1', 'SHA256', 'SHA384', 'SHA512', 'MD5')]
    [string]$Algorithm = 'SHA256'  # Default to SHA256
  )
  
  $StringBuilder = New-Object System.Text.StringBuilder
  $Hasher = [System.Security.Cryptography.HashAlgorithm]::Create($Algorithm)
  $HashBytes = $Hasher.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($String))
  
  foreach ($Byte in $HashBytes) {
    [void]$StringBuilder.AppendFormat("{0:x2}", $Byte)
  }
  
  # Return the actual hash string value (optionally in uppercase)
  return $StringBuilder.ToString().ToUpper()
}

###############################################
# Get-StringHash 
###############################################
function Test-FileIsLocked 
{
    param(
        [Parameter(Mandatory)]
        [string]$FilePath
    )
    
    try {
        $fileStream = [System.IO.File]::Open($FilePath, 'Open', 'Read', 'None')
        $fileStream.Close()
        $fileStream.Dispose()
        return $false # File is not locked
    }
    catch {
        return $true # File is locked
    }
}

###############################################
# Scan-Directory
###############################################
function Scan-Directory
{
    param (
        [string] $dname,
		[array] $NewFileArray,
        [bool] $recurseYes
    )

    $dirName = $dName

    # check if directory is valid:
    if (test-path $dirName -PathType Container)
    {
        Write-Host "Path Exists"
    }
    else 
    {
        write-host "path does not exist"    
        exit $false
    }

    Write-Host "Recures = $recurseYes"
    ######$ErrorLogFile = $dirname +
    [bool]$isLocked
    $Loop = 1
    if ($recurseYes) 
    {
		Write-Host "doing sub-directories... will take longer"
        $AllFiles = Get-ChildItem $dirName -File -Force -recurse | Where-Object {$_.FullName -notlike "*HashFile*.csv"} |
        Select-Object FullName, Length, CreationTime, CreationTimeUtc, LastAccessTime, LastAccessTimeUtc, LastWriteTime, LastWriteTimeUtc, VersionInfo,
        @{Name="HashValue"; Expression={(Get-FileHash $_.FullName).Hash}}
    }
    else
    {
        $AllFiles = Get-ChildItem $dirName -File -Force | Where-Object {$_.FullName -notlike "*HashFile*.csv"} |
        Select-Object FullName, Length, CreationTime, CreationTimeUtc, LastAccessTime, LastAccessTimeUtc, LastWriteTime, LastWriteTimeUtc, VersionInfo,
        @{Name="HashValue"; Expression={(Get-FileHash $_.FullName).Hash}}
    }

    foreach ($f in $AllFiles)
    {
        if ($null -eq $f.HashValue)
        {
            $f.HashValue = "ERROR - probably file open by something else"
        }
        $NewFileArray += [PsCustomObject]@{
            RecordNumber = $Loop
            FullName = $f.FullName
            FullNameHash = (Get-StringHash -string $f.fullname -Algorithm "SHA256").ToString()
            Length = $f.Length 
            CreateTime = $f.CreationTime
            CreateTimeUtc = $f.CreationTimeUtc
            LastAccess = $f.LastAccessTime
            LastAccessUtc = $f.LastAccessTimeUtc
            LastWrite = $f.LastWriteTime
            LastWriteUtc = $f.LastWriteTimeUtc
            Version = $f.VersionInfo
            HashValue = $f.HashValue
            #HashValue = $f.HashValue
            changed = ""
        } 
        $Loop++
    }

    return @{
        FileCreated = $true
        ArrayOrRecords = $NewFileArray
    }
}

###############################################
# create-exportfilename
###############################################
function create-exportfilename
{
    param(
        [Parameter(Mandatory=$true)]
        [string] $direcToSendFile,
        [Parameter(Mandatory=$false)]
        [string] $TypeOfFileToWrite
    )

    # check if the directory name has a \ at the end; if not add it.
    if ($direcToSendFile[-1] -eq "\")
    {
        $directoryToSendFile = $direcToSendFile
    }
    else
    {
        $directoryToSendFile = $direcToSendFile + "\"
    }

    # switch statement depending on the type of file I am writing out:
    # 1) base file
    # 2) change file
    # 3) default or standard file
    switch ($TypeOfFileToWrite)
    {
        'base' 
        {
            return $direcToSendFile + "HashFile_" + [string](Get-Date -Format FileDateTime) + "_base.csv"
        }
        'change'
        {
            return $direcToSendFile + "HashFile_" + [string](Get-Date -Format FileDateTime) + "_changefile.csv"
        }
        default
        {
            return $direcToSendFile + "HashFile_" + [string](Get-Date -Format FileDateTime) + ".csv"
        }
    }
}

###############################################
# Export-FileOut
###############################################
function Export-FileOut
{
    param (
        [Parameter(Mandatory=$true)]
        [string] $outfiled,
        [Parameter(Mandatory=$true)]
        [Array] $FileToWriteOut
    )

    $outfiled = $outfiled.Trim()

    try
    {
        $FileToWriteOut | Export-Csv -path $outfiled
    }
    catch [System.IO.FileNotFoundException]
    {
        Write-Output "File not created: $fileToWriteOut"
        $outfiled = $false
    }
    catch [System.UnauthorizedAccessException] 
    {
        Write-Output "You do not have permission to access this file: $fileToWriteOut"
        $outfiled = $false
    }
    catch 
    {
        Write-Output "An unexpected error occurred writing file: $fileToWriteOut"
        $outfiled = $false
    }

    if (Test-Path $outfiled)
    {
        return $true
    }
    else
    {
        return $false
    }

}

###############################################
# Does-HashFileExist
###############################################
function Does-HashFileExist
{
    param (
        [string] $filename
    )

    if (test-path -path $filename)
    {
        Return $True
    }
    else
    {
        return $False
    }
}

###############################################
# Change-FileNameToBase
###############################################
function Change-FileNameToBase
{
    param (
        [string] $filetochange
    )

    $parts = $filetochange -split '\.'
    $filetochangenew = "$($parts[0])_base.csv"
    Read-Host "filetochangenew = $filetochangenew"
    Move-Item $filetochange $filetochangenew
}

###############################################
# get-HashFileList
###############################################
function Get-HashFileList
{
    param (
        [string] $dirname,
        [bool] $base
    )

    $files = Get-ChildItem -Path $dirName -File -Filter HashFile*.csv |
    Where-Object {$_.Name -notlike "HashFile*_changefile.csv"} |
    Sort-Object

    # checking if there is one file, if so, we can continue;
    # if not return "nofile"
    if ($files.Count -eq 0)
    {
        Write-Host "There are no files"
        Read-Host "testing file.count = $($files.count) ...press any key to continue"
		$returntext = "nofile"
        return @($returntext, $returntext)
    }
    #means that the only file there, is the file we created.  We will make that the 
    # base file
	if ($files.Count -eq 1)
	{
		Change-FileNameToBase ($files[0])
		$returntext = "changed file to base"
		return @($returntext, $returntext)
	}

    Write-host "Please pick a number from the list:"
    # this makes an array of all the files.  Each spot in the
    # array is numbered.  So when the user picks a number,
    # I know which file in the array I need.
    $Loop = 0
    $fileArray = @()

    Foreach ($file in $files)
    {
        $Loop++
        $fileArray += $file
        if ($loop -le 9)
        {
            Write-Host "$Loop)   $($file.Name)"
        }
        else
        {
            Write-Host "$Loop)  $($file.Name)"
        }
    }

   if (-not $Base)
   {
        Write-Host ""
        Write-Host "Chose the largest number to make it the new base file."
        [int]$fileToLoad = Read-Host "Which Number? "
    
        if (($fileToLoad -ge 1) -and ($fileToLoad -lt $Loop))
        {
            #Write-Host "File to Load is: " $fileArray[$fileToLoad-1].Name
            return @("new",$fileArray[$fileToLoad-1])
        }
        elseif ($fileToLoad -eq $loop)
        {
            # make this file the new base file
            Write-Host "making new baseline file."
            return @("base",$fileArray[$fileToLoad-1])
        }
        else
        {
            return @("nofile", "nofile")
        }
   }
   else
   {
       return @("base", $filearray[$filearray.length - 1])
   }
}


###############################################
# redin-CSVFile
###############################################
function redin-CSVFile
{
    param(
        [String] $dirname
    )

    $p = Import-Csv $dirname 

    Return $p

}

###############################################
# Display-Result
###############################################
function Display-Result
{
	# Display results
	Write-Host "`n`nRESULTS OF COMPARISON:`n" -ForegroundColor Green
	Write-Host "===================================" -ForegroundColor Green

    # 1) Display Results
	Write-Host "`nFiles only in base scan ($($filesOnlyInPrevious.Count) files):" -ForegroundColor Yellow
	if ($filesOnlyInPrevious.Count -eq 0) 
    {
		Write-Host "None" -ForegroundColor Gray
	} 
    else 
    {
		$filesOnlyInPrevious | ForEach-Object { 
			Write-Host " - $($_.FullName), $($_.RecordNumber)." -ForegroundColor Gray
		}
	}

    # 2) Display Results
	Write-Host "`nFiles only in current scan ($($filesOnlyInCurrent.Count) files):" -ForegroundColor Yellow
	if ($filesOnlyInCurrent.Count -eq 0) 
    {
		Write-Host "None" -ForegroundColor Gray
	} 
    else 
    {
		$filesOnlyInCurrent | ForEach-Object {
			Write-Host " - $($_.FullName), $($_.RecordNumber)." -ForegroundColor Gray
		}
	}

    # 3) Renamed Results
    Write-Host "`nFiles with different hash values (renamed) ($($filesWithInCurrentRenamed.Count) files):" -ForegroundColor Yellow
    If ($filesWithInCurrentRenamed.Count -eq 0)
    {
        Write-Host "None" -ForegroundColor Gray
    }
    else
    {
		$filesWithInCurrentRenamed | ForEach-Object {
		    Write-Host " - $($_.FullName), $($_.RecordNumber)." -ForegroundColor Gray
        }
    }

    # 4) Changed Files
	Write-Host "`nFiles with different hash values ($($filesWithInCurrentChanged.Count) files) -changed:" -ForegroundColor Yellow
	if ($filesWithInCurrentChanged.Count -eq 0) 
    {
		Write-Host "None" -ForegroundColor Gray
	} 
    else 
    {
        $filesWithInCurrentChanged | ForEach-Object {
            Write-Host "New Values: FullName: $($_.FullName)    $($_.LastAccess)    $($_.HashValue)"
        }
		$filesWithDifferentHashes | ForEach-Object {
			Write-Host " - $($_.FullName)" -ForegroundColor Gray
			Write-Host "   Previous: $($_.PreviousHash) (Modified: $($_.PreviousLastWrite)) (Record Number: $($_.PreviousRecordNumber))" -ForegroundColor DarkGray
			Write-Host "   Current:  $($_.CurrentHash) (Modified: $($_.CurrentLastWrite)) (Record Number: $($_.CurrentRecordNumber))" -ForegroundColor DarkGray
		}
	}
}


###############################################
# Display-GridViews
###############################################
function Display-GridViews
{
	# Output to grid view for better visualization
	if ($filesOnlyInPrevious.Count -gt 0) 
    {
		Write-Host "`nOpening grid view for files only in previous scan..." -ForegroundColor Cyan
		$filesOnlyInPrevious | Out-GridView -Title "Files only in previous scan"
	}

	if ($filesOnlyInCurrent.Count -gt 0) 
    {
		Write-Host "`nOpening grid view for files only in current scan..." -ForegroundColor Cyan
		$filesOnlyInCurrent | Out-GridView -Title "Files only in current scan"
	}

	if ($filesWithInCurrentRenamed.Count -gt 0) 
    {
		Write-Host "`nOpening grid view for files only in current scan that renamed..." -ForegroundColor Cyan
		$filesWithInCurrentRenamed | Out-GridView -Title "Files in current scan -renamed"
	}

	if ($filesWithDifferentHashes.Count -gt 0) 
    {
		Write-Host "`nOpening grid view for files with different hashes..." -ForegroundColor Cyan
		$filesWithDifferentHashes | Out-GridView -Title "Files with different hash values - changed files"
	}
    if ( ($filesOnlyInPrevious.Count -eq 0) -and ($filesOnlyInCurrent.Count -eq 0) -and ($filesWithDifferentHashes.Count -eq 0) -and ($filesWithInCurrentRenamed.Count -eq 0))
    {
        Write-Host "no differences were found in the files"
    }
}

###############################################
# Write-ChangeFile
###############################################
function Write-ChangeFile
{
    # I want the changefile to have the same name as the last file we wrote out
    # since time moves, I don't want to grab time again. $dirname2 is the last
    # file we wrote out.  I going to split at the "." which will have the name
    # without the extension, and then add "changefile.csv"  
    $parts = $dirname2 -split '\.'
    $ChangefilenameToWriteOut = "$($parts[0])_changefile.csv"

    $changedRecords2 | Select-Object *, `
        @{Name="StatusDescription"; Expression={
            # Create a new field based on the "Changed" field
            switch ($_.Changed) {
                "delete" { "From Base File" }
                "added" { "From Current File" }
                "rename" { "From Current File" }
                "changed" { "From Current File" }
                default { "Unknown File" }
            }
        } } | 
    Export-Csv -Path $ChangefilenameToWriteOut 

}

###############################################
# compare-data2
###############################################
function compare-data2
{
    param(
        [Parameter(Mandatory)]
        [array]$previousLoad,
        [Parameter(Mandatory)]
        [array]$currentLoad,
        [Parameter(Mandatory)]
        $directoryToWriteFiles,
        [Parameter(Mandatory)]
        $dirname2,
        $ViewGUI,
        $ChangeFile
        
    )
	

    # dirname2 above^
    # dirname2 is the name of the recent of files and data
    # if the user wants to create a change file, I want it
    # to have the same date/time as the most recent file so
    # it can be easily seen.

	# Create comparison results containers
    Write-Host "Create comparison results containers"
	$filesOnlyInPrevious = @()
	$filesOnlyInCurrent = @()
	$filesWithInCurrentRenamed = @()
    $filesWithInCurrentChanged = @()
    $RecordsChanged2 = @()

	# First, create dictionaries for faster lookups
    Write-host "create dictionaries for faster lookups"
	$currentDict = @{}
	$previousDict = @{}

    #create arrays to know which records to add or delete from previous or base load
    Write-Host "create arrays to know which records to add or delete from previous or base load"
    $previousRecordNumber=@{}

	# Populate the dictionaries with FullNameHash as key
    Write-Host "Populate the dictionaries with FullNameHash as key"
	foreach ($file in $currentLoad) 
    {
		$currentDict[$file.HashValue] = $file
        $currentDict[$file.FullNameHash] = $file
        $currentDict[$file.RecordNumber] = $file
        $currentDict[$file.FullName] = $file
        $currentDict[$file.Length] = $file
        $currentDict[$file.CreateTime] = $file
        $currentDict[$file.CreateTimeUtc] = $file
        $currentDict[$file.LastAccess] = $file
        $currentDict[$file.LastAccessUtc] = $file
        $currentDict[$file.LastWrite] = $file
        $currentDict[$file.LastWriteUtc] = $file
        $currentDict[$file.Version] = $file
        $currentDict[$file.Changed] = $file
	}

	foreach ($file in $previousLoad) 
    {
		$previousDict[$file.HashValue] = $file
        $previousDict[$file.FullNameHash] = $file
        $previousDict[$file.RecordNumber] = $file
        $previousDict[$file.FullName] = $file
        $previousDict[$file.Length] = $file
        $previousDict[$file.CreateTime] = $file
        $previousDict[$file.CreateTimeUtc] = $file
        $previousDict[$file.LastAccess] = $file
        $previousDict[$file.LastAccessUtc] = $file
        $previousDict[$file.LastWrite] = $file
        $previousDict[$file.LastWriteUtc] = $file
        $previousDict[$file.Version] = $file
        $previousDict[$file.Changed] = $file
	}

    #######################################################################
    # There are four different kinds of change I am looking for:
    # 1) file does exist in the original/base file. 
    # 2) file does not exist in the current run/file.
    # 3) Hash value is the same, but the filename hash is different,
    #    which means the named changed (file renamed).
    # 4) files have a different hash value, which means the file changed
    ######################################################################

    # 1) file does not exist in the original or base file:
	# Find files only in previous or base load this means the file does not 
    # exist in the most recent check of files.  It should deleted from 
    # previous, so the base will have the most recent of files
	foreach ($file in $previousLoad) 
    {
		if ((-not $currentDict.ContainsKey($file.HashValue)) -and (-not $currentDict.ContainsKey($file.FullNameHash)))
        {
            $file.changed ="delete"
			$filesOnlyInPrevious += $file
            $filesOnlyInPrevious2 += $file
            $RecordsChanged2 += $file
            #Write-host "file= $file"
            #Read-Host "see if we get any"
		}
        else
        {
            #Write-host "file from in PreviousLoad. file= $file"
        }
	}

    # 2) File does not exist in the current file
	# Find files only in current scan. These files only exist in the most recent scan.
    # They should be added to previous so they are incorporated into the base.  
    #
    # This will only find differences between the two if the name and hash are the 
    # same.  If someone renames a file, it will not be found here
	foreach ($file in $currentLoad) 
    {
		if ((-not $previousDict.ContainsKey($file.HashValue)) -and (-not $previousDict.ContainsKey($file.FullNameHash)))
        {
            $file.changed = "added"
			$filesOnlyInCurrent += $file
            $RecordsChanged2 += $file
            #Write-Output "File not in current="
            #Write-Output $file
		}
	}

    # 3) Hash Value are the same, but the file hash value is different - file rename
    foreach ($file in $currentLoad) 
    {
		if (($previousDict.ContainsKey($file.HashValue)) -and (-not $previousDict.ContainsKey($file.FullNameHash)))
        {
            $file.changed = "rename"
            $filesWithInCurrentRenamed += $file
            #$filesWithInCurrentRenamed2 += $file
            $RecordsChanged2 += $file
            #Write-Output "File not in current="
            #Write-Output $file
            #Read-Host "Pausing in file rename"
		}
	}

    # 4) The File Hash is the same, but the hash value is different - file change.
    foreach ($file in $currentLoad) 
    {
		if ((-not $previousDict.ContainsKey($file.HashValue)) -and ($previousDict.ContainsKey($file.FullNameHash)))
        {
			$file.changed = "changed"
            $filesWithInCurrentChanged += $file
            #$filesWithInCurrentChanged2 += $file
            $RecordsChanged2 += $file
            #Write-Output "File not in current="
            #Write-Output $file
            #ead-Host "Pausing in file changed"
		}
	}



	# Find files with different hash values
	# We need to compare by full path since the hash of the path might be the same
	# but the content hash might differ
	$allFullPaths = @{}

	# Create a lookup dictionary by actual file path
	foreach ($file in $currentLoad) 
    {
		$allFullPaths[$file.FullName] = $file
	}

	foreach ($prevFile in $previousLoad) 
    {
		if ($allFullPaths.ContainsKey($prevFile.FullName)) 
        {
			$currentFile = $allFullPaths[$prevFile.FullName]
			# Compare hash values
			if ($currentFile.HashValue -ne $prevFile.HashValue) 
            {
				$filesWithDifferentHashes += [PSCustomObject]@{
					FullName = $prevFile.FullName
					PreviousHash = $prevFile.HashValue
					CurrentHash = $currentFile.HashValue
					PreviousLastWrite = $prevFile.LastWrite
					CurrentLastWrite = $currentFile.LastWrite
                    PreviousRecordNumber = $prevFile.RecordNumber
                    CurrentRecordNumber = $currentFile.RecordNumber
				}
			}
		}
	}


    # creating one table with all the changes
    $changedRecords2 += $filesOnlyInPrevious
    $changedRecords2 += $filesOnlyInCurrent
    $changedRecords2 += $filesWithInCurrentRenamed
    $changedRecords2 += $filesWithInCurrentChanged

    # function to display results in character mode:
    Display-Result

    # Function to display gridviews - allows user to 
    # see the data in GUI
    if ($ViewGUI -eq $false)
    {
		[string]$doGUI = Read-Host "Do you want to view the view in the GUI(Y/n)?"
		Write-Host "do GUI = $doGUI"
	
		if ($doGUI.ToUpper() -eq  "Y")
		{
			Display-GridViews
		}
    }
    # $ViewGui is set to true at the command line
    else           
    {
        Display-GridViews 
    }

    # function to write change file to disk allows user to decide if they want to 
    # or not.  This has become much more complicated because of the command line
    # arguments.  I need to check if $ChangeFile is true or false first from the 
    # command line.  If not, then the command line argument was not set, so I can
    # ask the user if they want a change file or not.

    Write-Host "ChangeFile = $ChangeFile"
    if ($changeFile -eq $false)
    {
            Write-Host "no change file created."
    }
    elseif ($changefile)
    {
        Write-Host "writing change file out."
		Write-ChangeFile
    }
    else
    {
        [string]$writechangefile = Read-Host "Do you want to create/write the change file(Y/n)?"

		if ($writechangefile.ToUpper() -eq  "Y")
		{
            Write-Host "writing change file out."
			Write-ChangeFile
		}
        else
        {
            Write-Host "no change file created."
        }
    }
}

###############################################
# help-menu
###############################################
function help-menu
{
    Write-Host "All parameters are name pair - that is you cannot just put The parameter "
    Write-Host "out there and expect it to be read because it is in order"
    Write-Host "The following parameters can be used:"
    Write-Host -NoNewLine "Directory " -ForegroundColor Red 
    Write-Host "- used to tell the program what directory to scan for example:"
    Write-Host "     finalFinal.ps1 -Directory `"MyFolder`"" -ForegroundColor Green
    Write-Host -NoNewLine "ViewGui " -ForegroundColor Red
    Write-Host "- used to tell the program if you want to see the results in the GUI."
    Write-Host "     finalFinal.ps1 -ViewGui" -ForegroundColor Green
    Write-Host -NoNewLine "Base "  -ForegroundColor Red
    Write-Host "- used to tell the program if you want the file that just to be a base file."
    Write-Host "No real difference between the files, but base files end with _base.  If"
    Write-Host "you want to run this process and make a base file do:"
    Write-Host "     finalFinal.ps1 -Base" -ForegroundColor Green
    Write-Host -NoNewLine "Recurse " -ForegroundColor Red
    Write-Host "if you want to do sub directories, use recurse.  It will assume you want"
    Write-Host "to do all sub directories below you main directory, so if you use it be careful."
    Write-Host "     finalFinal.ps1 -Recurse " -ForegroundColor Green
    Write-Host -NoNewLine "Compare " -ForegroundColor Red
    Write-Host "- checks if you want to compare it against the base file.  It assumes"
    Write-Host "the oldest file is the base file.  It is a boolean parameter.  If it is"
    Write-Host "not set on the command line it is null or empty.  If it is not set t"
    Write-Host "that if you have parameter it is true"
    Write-Host "     finalFinal.ps1 -Compare" -ForegroundColor Green
    Write-Host -NoNewLine "ChangelFile " -ForegroundColor Red
    Write-Host "- checks to see if you want make a compare of the difference"
    Write-Host "between the base file and most recent run.  Compare is a switch parameter,"
    Write-Host "so by adding it, you are yes to compare."
    Write-Host "     finalFinal.ps1 -ChangeFile `$true" -ForegroundColor Green
    Write-Host -NoNewLine "Help " -ForegroundColor Red
    Write-Host "- This screen - will exit the program when complete."
    Write-Host -NoNewline "helpweb " -ForegroundColor Red
    Write-Host "This screen as a web page."

}

###############################################
# main program
###############################################

# param list is at the top of the file

# clearing out $error log so it only shows errors for this run:
$Error.clear()

if ($help)
{
    help-menu
    exit
}

if ($helpweb)
{
    start ".\FinalHelpWeb.html"
    exit
}

# finding out what directory the user wants to scan
if ( (-not $Directory) -or ($Directory -eq "") )
{
    $dirName = Read-Host "What is the directory you want to scan?"
}
else
{
    $dirName = $Directory
}

if ($dirName[-1] -ne "`\'")
{
    $dirName = $dirName + "\"
}

# does the actual scanning of the directory.  
#
# Scan does not pick-up the filenames of the data collected
# from the program.  You will not find any files created by
# this program (HashFile_CCYYMMDDTHHMMSSmmmm.csv)
#
# $returnedvalue is object that has to values the first is FileCreated 
# and tells me if it made it through the routine successfully (true)
# the second is the array of records that is what we want to write to disk

if ($Recurse -eq $false)
{
    $recurseyesno = Read-Host "Do you want to do sub-directories (Y/n)?  It will take longer."
    if ($recurseyesno.ToUpper() -eq "Y")
    {
        $recurseYes = $true
    }
    else
    {
        $recurseYes = $false
    }
    $returnedvalue = Scan-Directory $dirName $NewFileListArray $recurseYes
}
else # recurse is switch so it is set to true to get here
{
    $returnedvalue = Scan-Directory $dirName $NewFileListArray $Recurse
}

# $returned value tells me if the Scan-Directory command
# succeeded or not
if ($returnedvalue.FileCreated)
{
    # creates the filename to hold the data.
    # format is HashFile_CCYYMMDDTHHMMSSmmmm.csv
    $dirname2 = create-ExportFileName $dirName

    # file is exported to the same directory 
    # the scan.  
    $filemade = Export-FileOut $dirName2 $returnedvalue.ArrayOrRecords
    if ($filemade)
    {
        Write-Host "List of files created."
    }
    else
    {
        # file was NOT written to disk.  Error was caused
        Write-Host "file was not able to be created." -ForegroundColor Green
        Add-CustomError "File was not able to be created from reading directory of all files.", "OperationStopped"
    }
}
else
{
    write-host "failed to read files in $dirname2"
}

# Read-Host "filemade = $filemade, press any key to continue..."

# write-host "dirname2 = " $dirname2

# checking to see if the file I just created exists
$result = Does-HashFileExist $dirname2
if ($result)
{
    write-host "hash file exists"
}
else
{
    write-host "hash file does not exist - exiting"
    exit
}

# gets a list of all the HashFile*.csv files so the user can compare against the file 
# they just created.  If the user does not choose from the list, the value returned is 0
#
# $compare is line arguement.  If it is null or "" that means the user did not set it.
# The program will ask the user if they want to compare.  User must answer "N" or "n"
# to not do the compare.
if ( ($Compare -eq $true) -or ($Compare -eq $false) )
{
        # we have a compare value we can use.
}
else    # compare value is not set correctly or is null
{
    $CompareQuestion = Read-Host "Do you want to compare files(Y/n)?"
    if ($CompareQuestion.ToUpper() -eq "N")
    {
        $Compare = $false
    }
    else
    {
        $Compare = $true
    }
}

if ($Compare -eq $true)
{
    $fileToLoadArray = get-HashFileList $dirname $base
    # Write-Host "total number of array spots = $($filetoloadarray.count)"
    # write-Host "filetoloadarray[0] = $($filetoloadarray[0])"
    # write-Host "filetoloadarray[1] = $($filetoloadarray[1])"
    # $l = 0
    # foreach ($f in $fileToLoadArray) 
    # { 
    #    Write-Host "$l = $f" 
    #    $l++
    # }
    # read-host "what the whole array is: $($filetoloadarray)"

    if ($($fileToLoadArray[1]) -eq "nofile")
    {
        write-host "done, the user did not want to compare a file"
    }

    elseif ($($fileToLoadArray[1]) -eq "changed file to base")
    {
        write-host "This was the first file in the directory.  Changed it to a base file."
    }
    elseif ($($fileToLoadArray[1]) -eq "base")
    {
        Write-Host "creating base file"
        $baseValue = $fileToLoadArray[2]
        $baseFileName = create-exportfilename $dirname $baseValue
        Export-FileOut $baseFileName $returnedvalue.ArrayOrRecords
        $showyes = Read-Host "Show file in Gridview (Y/n)?"
        if ($showyes.toUpper() -eq "Y")
        {
            $baseFileName | Out-GridView 
        }
    }
    # user has the base file and wants to compare it
    else
    {
        # reads in the file the user picked
        Write-Host "comparing files"
        # read in the base file
        $previousLoad = redin-CSVFile $fileToLoadArray[1]
        #$previousLoad | Out-GridView
        #returnedvalue.ArrayOrRecords | Out-GridView
        compare-data2 $previousLoad $returnedvalue.ArrayOrRecords $dirname $dirName2 $ViewGUI $ChangeFile
    }
}
else
{
    Write-Host "User chose NOT to compare."
}

if ($Error.Count -gt 0)
{
    $seeErrors = Read-Host "There are errors, do you want to see them(Y/n)?"
    if ($seeErrors.ToUpper() -eq "Y")
    {
        $Error | 
        ForEach-Object {
            $errorMessage = $_.Exception.Message
            Write-Host $errorMessage
            $errorLog += $errorMessage
        }
    }

    $seeErrors = Read-Host "Write the errors to a file (Y/n)?"

    if ($seeErrors.ToUpper() -eq "Y")
    {
        $parts = $dirname2 -split '\.'
        $ErrorLogFile = "$($parts[0])_Errors.txt"
        $errorLog | Out-File -FilePath $ErrorLogFile
        Write-Host "Errors were logged to $ErrorLogFile"
    }


}


#####################################################################################
# end of program
#####################################################################################

# Robs Notes
# things to do:
# 1) allow user to pick file from command line as original file - complete
# 2) read in original file - complete
# 3) add fields to compare - complete
#    different hash value (changed) - complete
#    new file (new) - complete
#    file deleted (deleted) - complete
# 4) Compare old hash file to new hash file - complete
# 5) Update hash table with new files; delete old files; update hash values
# 6) Allow for recursive directories  - complete
# 7) Add in arguements from the command line


