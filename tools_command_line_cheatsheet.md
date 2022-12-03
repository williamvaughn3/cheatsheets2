#
# <b><b>CheatSheet for windows forensics stuff</b></b>
## WMI CLI:
#### Syntax uses: `wmic /node:\<remote-IP> /user:\<admin acct>`
Get auto-start processes
`wmic /node:10.1.1.1 startup list full`
Remote process list:
`wmic /node:10.1.1.1 process get`
Network configuration
`wmic /node:10.1.1.1 nicconfig get`
Spot executables running from strange locations:
`wmic PROCESS WHERE "NOT ExecutablePath LIKE '%Windows%'" GET ExecutablePath`

#### Possible WMIC recon
```
wmic process get CSName,Description,ExecutablePath,ProcessId
 wmic useraccount list full; wmic group list full; wmic netuse list full;
 wmic qfe get Caption,Description,HotFixID,InstalledOn
 wmic startup get Caption,COmmand,Location,User
```
##### WMIC Priv Esc (from powerup.ps1)
```
#find unquoted services set to auto‐start
wmic service get name,displayname,pathname,startmode | findstr /i "Auto" | findstr /i /v "C:\Windows\\" |findstr /i/v"""
#find highly privileged processes that can be attacked
$Owners=@{}Get‐WmiObject ‐Classwin32_process|Where‐Object{$_}|ForEach‐Object{$Owners[$_.handle]=$_.getowner().user}
#find all paths to service.exe's that have a space in the path and aren't quoted
$VulnServices=Get‐WmiObject ‐Classwin32_service|Where‐Object{$_} | Where‐Object {($_.pathname ‐ne$null) ‐and ($_.pathname.trim() ‐ne"")} | Where‐Object {‐not $_.pathname.StartsWith("`"")} |Where‐Object{ ‐not $_.pathname.StartsWith("'")} |Where‐Object
```
#### process call
`wmic.exe PROCESS CALL CREATE \"C:\\Windows\\System32\\rundll32.exe \\\"C:\\Windows\\files.dat\\\" `
# <b>autorunsc </b>
### Syntax examples
```
autorunsc -accepteula -a * -s -c -h -vr > \\siftworksation\cases\Response\10.1.1.1-arun.csv
autorunsc.exe /accepteula -a * -c -h -s '*' -nobanner
```
*Validate if code/file is signed by valid/known publisher; May need to reset columns in timeline explorer (under tools)*
# <b>Kansa </b>
Syntax examples:


`.\kansa.ps1 -TargetList .\hostlist -Pushbin`
`.\kansa.ps1 -OutputPath .\Output\ -TargetList .\hostlist -TargetCount 250 -Verbose -Pushbin`
Kansa project uses this capability to scale collection.  Entire event logs can be collected using commands like the following:
`(Get-WmiObject -Class Win32_NTEventlogFile | Where-Object LogfileName -EQ 'System').BackupEventlog(‘G:\System.evtx')`
### enumerate autorun files in a directory - Kansa Script
```
    Get-ASEPImagePathLaunchStringMD5UnsignedStack.ps1 > output.csv
    Select-String "<process name>"  *Autorunsc.csv
        Select-String "perfmonsvc64.exe" *Autorunsc.csv
```
### use timeline explorer to view results
> filter by least occurance count and use powershell select-string to find which system

Example Below:
find stuff in files matching *SvcAll.csv - Kansa Script
```
    .\Get-LogparserStack.ps1 -FilePattern *SvcAll.csv -Delimiter "," -Direction asc -OutFile SvcAll-workstation-stack.csv
```
##### Will be returned output and optional sort / selection criterea:

>     Enter the field to pass to COUNT():  Name

>     Enter the fields you want to GROUP BY, one per line.
>     Enter "quit" when finished:  Name

>     Enter the fields you want to GROUP BY, one per line.
>     Enter "quit" when finished:  DisplayName

>     Enter the fields you want to GROUP BY, one per line.
>     Enter "quit" when finished:  PathName
#### Once finding something interesting, use timeline explorer to view the results
<i> <b> Use select-string to find which system it is on in the csv file, pipe out to gridview or tableview </b></i>
    Select-String "string" *SvcAll.csv
        .\Disk\Get-TempDirListing.ps1 | Out-GridView
    .\Log\Get-LogWinEvent.ps1 security | Out-GridView
# <b>Amacheparser </b>
### Syntax Examples
```
AmcacheParser.exe -f "C:\Temp\amcache\AmcacheWin10.hve" --csv C:\temp
 AmcacheParser.exe -f "C:\Temp\amcache\AmcacheWin10.hve" -i on --csv C:\temp --csvf foo.csv
 AmcacheParser.exe -f "C:\Temp\amcache\AmcacheWin10.hve" -w "c:\temp\whitelist.txt" --csv C:\temp
```
# <b>Appcompatprocessor.py </b>
### Syntax Examples
```
stacking by file path and file name
`./AppCompatProcessor.py ./database.db stack "filePath" "fileName like '%servicehost.exe'"`
stacking by filepath
`./appcompatprocessor.py ./database.db stack fsearch Filepath -f "ProgramData"`
Will search the FileName field for anything that contains 'cmd.exe'
`./AppCompatProcessor.py ./database.db fsearch FileName -F "cmd.exe"`
Will search the FileName field for anything that exactly matches 'cmd.exe'
`./AppCompatProcessor.py ./database.db fsearch FileName -F "=cmd.exe"`
Will find files whose size contains "4096"
`./AppCompatProcessor.py ./database.db fsearch Size -F "4096"`
Will find files whose size _is_ "4096"
`./AppCompatProcessor.py ./database.db fsearch Size -F "=4096"`
Will find files whose size is bigger than 4096 bytes (and has Size data of course: XP appcompat or AmCache data)
`./AppCompatProcessor.py ./database.db fsearch Size -F ">4096"`
Will find files for some attackers that regularly screwed the trademark symbol on the versioning information on their tools.
`./AppCompatProcessor.py ./test-AmCache.db fsearch Product -F "Microsoft@"`
find by producet
`./AppCompatProcessor.py ./test-AmCache.db fsearch Product -F "Microsoft@"`
```

##### also see the regex options and other modules

# <b>Evtxcmd</b>

> yet another awesome tool by Eric Zimmerman.  A command line tool for parsing Windows Event Log (EVTX) files. It can be used to extract events from a single file or a directory of files. Can use to export events to CSV, JSON, or HTML.  Leverages the xpath with open/crowd sourced map files to make parsing much simplier.
### Examples Syntax:
```
    EvtxECmd.exe -f "C:\Temp\Application.evtx" --csv "c:\temp\out" --csvf MyOutputFile.csv
    EvtxECmd.exe -f "C:\Temp\Application.evtx" --csv "c:\temp\out"
    EvtxECmd.exe -f "C:\Temp\Application.evtx" --json "c:\temp\jsonout"
    evtxecmd -f C:\Windows\system32\winevt\logs\Security.evtx --csv C:\Temp\event-logs --csvf security.csv
```
# <b>Get-WinEvent</b>
### PowerShell can be used to collect and filter logs
```
Get-WinEvent -ComputerName for remote collection
Get-WinEvent -Logname for local events
Get-WinEvent -Path for archived log files
Get-WinEvent -FilterHashtable @{Logname=“Security";id=4624} | Where {$_.Message -match “spsql"}
Get-WinEvent -FilterHashtable @{Path="C:\Path-To-Exported\Security*.evtx“ ;id=5140} | Where {$_.Message -match "\\Admin\$"}
```
# <b>KAPE</b>
https://ericzimmerman.github.io/KapeDocs

> Kroll Artifact Parser and Extractor (KAPE) is primarily a triage program that will target a device or storage location, find the most forensically relevant artifacts (based on your needs), and parse them within a few minutes. Because of its speed, KAPE allows investigators to find and prioritize the more critical systems to their case. Additionally, KAPE can be used to collect the most critical artifacts prior to the start of the imaging process. While the imaging completes, the data generated by KAPE can be reviewed for leads, building timelines, etc.
```
tsource
    The drive letter or directory to search. This should be formatted as C, D:, or F:\.

target
    The target configuration to run, without the extension. Get a list of all available targets with the --tlist switch.

tdest
    The directory where files should be copied to. This directory will be created if it does not exist. This can be a regular directory or a UNC path.Other important options:vssFind, mount, and search all available Volume Shadow Copies on --tsource.
vhdx and vhd
    Creates a VHDX virtual hard drive from the contents of --tdest. debugWhen true, enables debug messages.
```
# <b>Windows Memory Aquisition Tools</b>
<li> WinPMEM:  https://github.com/Velocidex/c-aff4/releases
<li> DumpIt:  http://www.comae.io
<li> F-Response and SANS SIFT  www.f-response.com
<li> Belkasoft Live RAM Capturer  forensic.belkasoft.com/en/am-capturer
<li> MagnetForensics Ram Capture  magnetforensics.com/free-tool-magnet-ram-capture

# <b>Volatility</b>
## https://code.google.com/p/volatility/wiki/CommandReference23
## Powerful Memory Analysis Framework with crowd source plugins
`vol.py -f [image] --profile=[profile] [plugin]`
```
# <b>Set an envviroment Variable to replace `-f [image]`</b>
function SetVsrc(){
 export VOLATILITY_LOCATION=$1
 }

 SetVsrc Myfile.mem
 vol.py --profile=Win10x64 pslist

 unset VOLATILITY_LOCATION
```
#### Options:

 `-h with plugin to get details`
```
vol.py malfind -h
    -D Dump_Dir, --dump-dir=DUMP_DIR, (dir in which to dump exe files)
    -Y Yara_Rules, --yara-rules=YARA_RLES (use rules as well as finding injected code)
    -K, --Kernal scan kernal modules
```
##### see profiles and registered objects, use `--info`
###### availabile plugins located in:
` /usr/local/src/Volatility/volatility/plugins/ `



