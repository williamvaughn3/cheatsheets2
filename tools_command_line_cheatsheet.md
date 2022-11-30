# 
# CheatSheet for windows forensics stuff
#

#### Windows Management Instrumentation CLI:
/node:\<remote-IP> /user:\<admin acct>

#### Get auto-start processes
wmic /node:10.1.1.1 startup list full

#### Remote process list:
wmic /node:10.1.1.1 process get

#### Network configuration
wmic /node:10.1.1.1 nicconfig get

##### Spot executables running from strange locations:
wmic PROCESS WHERE "NOT ExecutablePath LIKE '%Windows%'" GET ExecutablePath
#
### autorunsc example

autorunsc -accepteula -a * -s -c -h -vr > \\siftworksation\cases\Response\10.1.1.1-arun.csv
autorunsc.exe /accepteula -a * -c -h -s '*' -nobanner
<i>
##### Validate if code/file is signed by valid/known publisher; May need to reset columns in timeline explorer (under tools)
</i>
### Kansa examples:

.\kansa.ps1 -TargetList .\hostlist -Pushbin
.\kansa.ps1 -OutputPath .\Output\ -TargetList .\hostlist -TargetCount 250 -Verbose -Pushbin

### enumerate autorun files in a directory - Kansa Script

    Get-ASEPImagePathLaunchStringMD5UnsignedStack.ps1 > output.csv

    Select-String "<process name>"  *Autorunsc.csv 
    Select-String "perfmonsvc64.exe" *Autorunsc.csv

### use timeline explorer to view results
> filter by least occurance count and use powershell select-string to find which system

Example Below:
find stuff in files matching *SvcAll.csv - Kansa Script
```
    .\Get-LogparserStack.ps1 -FilePattern *SvcAll.csv -Delimiter "," -Direction asc -OutFile SvcAll-workstation-stack.csv
```
##### Will be returned output and optional sort / selection criterea:

>     Enter the field to pass to COUNT():  Name 
      Enter the fields you want to GROUP BY, one per line. Enter "quit" when finished:  Name
      Enter the fields you want to GROUP BY, one per line. Enter "quit" when finished:  DisplayName
      Enter the fields you want to GROUP BY, one per line. Enter "quit" when finished:  PathName

#### Once finding something interesting, use timeline explorer to view the results
<i> <b> Use select-string to find which system it is on in the csv file, pipe out to gridview or tableview </b></i>

    Select-String "string" *SvcAll.csv 
    .\Disk\Get-TempDirListing.ps1 | Out-GridView
    .\Log\Get-LogWinEvent.ps1 security | Out-GridView

### Amacheparser Syntax Examples

```
AmcacheParser.exe -f "C:\Temp\amcache\AmcacheWin10.hve" --csv C:\temp
AmcacheParser.exe -f "C:\Temp\amcache\AmcacheWin10.hve" -i on --csv C:\temp --csvf foo.csv
AmcacheParser.exe -f "C:\Temp\amcache\AmcacheWin10.hve" -w "c:\temp\whitelist.txt" --csv C:\temp
```

### Appcompatprocessor.py Syntax Examples
`./AppCompatProcessor.py ./database.db stack "filePath" "fileName like '%servicehost.exe'"`
    stacking by file path and file name

`./appcompatprocessor.py ./database.db stack fsearch Filepath -f "ProgramData"`
    stacking by filepath

`./AppCompatProcessor.py ./database.db fsearch FileName -F "cmd.exe"`
    Will search the FileName field for anything that contains 'cmd.exe' 

`./AppCompatProcessor.py ./database.db fsearch FileName -F "=cmd.exe"`
    Will search the FileName field for anything that exactly matches 'cmd.exe' 

`./AppCompatProcessor.py ./database.db fsearch Size -F "4096"`
    Will find files whose size contains "4096" 

`./AppCompatProcessor.py ./database.db fsearch Size -F "=4096"`
    Will find files whose size _is_ "4096" 
    
`./AppCompatProcessor.py ./database.db fsearch Size -F ">4096"`
    Will find files whose size is bigger than 4096 bytes (and has Size data of course: XP appcompat or AmCache data)

`./AppCompatProcessor.py ./test-AmCache.db fsearch Product -F "Microsoft@"`
    Will find files for some attackers that regularly screwed the trademark symbol on the versioning information on their tools.

`./AppCompatProcessor.py ./test-AmCache.db fsearch Product -F "Microsoft@"` 
    find by producet
    
##### also see the regex options and other modules

#

### Evtxcmd, yet another awesome tool by Eric Zimmerman.  A command line tool for parsing Windows Event Log (EVTX) files. It can be used to extract events from a single file or a directory of files. Can use to export events to CSV, JSON, or HTML.  Leverages the xpath with open/crowd sourced map files to make parsing much simplier.

Examples Syntax:
```        
    EvtxECmd.exe -f "C:\Temp\Application.evtx" --csv "c:\temp\out" --csvf MyOutputFile.csv
    EvtxECmd.exe -f "C:\Temp\Application.evtx" --csv "c:\temp\out"
    EvtxECmd.exe -f "C:\Temp\Application.evtx" --json "c:\temp\jsonout"
```