function Invoke-ATHCompiledHelp {
<#
.SYNOPSIS

Test runner for Compiled HTML (CHM) file for the purposes of validating detection coverage.

Technique ID: T1218.001 (Signed Binary Proxy Execution: Compiled HTML File)

.DESCRIPTION

Invoke-ATHCompiledHelp launches executable content within a CHM file using as many known variations as possible for the purposes of validating detection coverage.

Successful execution of the embedded template CHM file would be indicated by Invoke-ATHCompiledHelp returning an object where the TestSuccess property is set to True. TestSuccess is set to True when Invoke-ATHCompiledHelp detects that a unique (based on the presence of a generated GUID value) powershell.exe child process was spawned.

Template CHM Details:

A decision was made to include and drop a pre-built CHM template file. Normally, we would build it on the fly for the sake of modularity and transparency but currently there exists no CHM builder that doesn't take a dependency on HTML Help Workshop, a Microsoft-utility that is not built in to the OS.

The embedded CHM file contains multiple help topics, all of which spawn a powershell.exe child process which will read a GUID test value from %windir%\Temp\InvokeCHMTestGuid.txt, which will then call another powershell.exe child process that will call "Write-Host TESTGUID".

The CHM file consists of the following help topics, each containing their own Shortcut command or WSH script code:

1. TEMPLATE_SHORTCUT_1.html
  * When the CHM file is executed without specifying a specific help topic, this is the default option that will execute. This help file consists of a Shortcut command that launches powershell.exe.
2. TEMPLATE_SHORTCUT_2.htm
  * Identical to TEMPLATE_SHORTCUT_1.html but has an ".htm" extension.
3. TEMPLATE_WSH_JSCRIPT_1.html
  * Spawns powershell.exe via embedded JScript code.
4. TEMPLATE_WSH_JSCRIPT_2.htm
  * Identical to TEMPLATE_WSH_JSCRIPT_1.html but has an ".htm" extension.
5. TEMPLATE_WSH_VBSCRIPT_1.html
  * Spawns powershell.exe via embedded VBScript code.
6. TEMPLATE_WSH_VBSCRIPT_2.htm
  * Identical to TEMPLATE_WSH_VBSCRIPT_1.html but has an ".htm" extension.
7. TEMPLATE_WSH_JSCRIPT_ENCODE_1.html
  * Spawns powershell.exe via embedded JScript.Encode code.
8. TEMPLATE_WSH_JSCRIPT_ENCODE_2.htm
  * Identical to TEMPLATE_WSH_JSCRIPT_ENCODE_1.html but has an ".htm" extension.
9. TEMPLATE_WSH_VBSCRIPT_ENCODE_1.html
  * Spawns powershell.exe via embedded VBScript.Encode code.
10. TEMPLATE_WSH_VBSCRIPT_ENCODE_2.htm
  * Identical to TEMPLATE_WSH_VBSCRIPT_ENCODE_1.html but has an ".htm" extension.
11. TEMPLATE_WSH_JSCRIPT_COMPACT_1.html
  * Spawns powershell.exe via embedded JScript.Compact code.
12. TEMPLATE_WSH_JSCRIPT_COMPACT_2.htm
  * Identical to TEMPLATE_WSH_JSCRIPT_COMPACT_1.html but has an ".htm" extension.

.PARAMETER CHMFilePath

Specifies the file path where the CHM file will be saved and executed from. if -CHMFilePath is not specified, Invoke-ATHCompiledHelp will drop and executed Test.chm to the current directory.

The specified CHM filename must have a .chm file extension.

.PARAMETER HHFilePath

Specifies an alternate directory to execute hh.exe from. if -HHFilePath is not supplied, hh.exe will execute from %windir%.

.PARAMETER ScriptEngine

Specifies the WSH scripting engine to use when executing script code within an embedded help topic.

The following WSH scripting engines are supported: JScript, VBScript, VBScript.Encode, JScript.Encode, JScript.Compact

.PARAMETER InfoTechStorageHandler

Specifies the InfoTech Storage handler to use when referencing an embedded help topic. The storage handler selected will not impact the execution of the Shortcut command or WSH script code. The supported InfoTech Storage handlers can be used interchangeably.

The following InfoTech Storage handlers are supported: ms-its, its, mk:@MSITStore

.PARAMETER ExecuteShortcutCommand

Specifies that a Shortcut command should be explicitly executed via an embedded help topic.

.PARAMETER TopicExtension

Specifies the file extension to use for the embedded help topic. "htm" and "html" were the only extensions observed to be supported for the execution of Shortcut commands or WSH script code.

.PARAMETER SimulateUserDoubleClick

Specifies that a double click of an CHM file should be simulated. This is accomplished by launching the CHM file with explorer.exe which will invoke hh.exe via its registered file handler.

.PARAMETER TestGuid

Optionally, specify a test GUID value to use to override the generated test GUID behavior.

The test GUID is temporarily written to %windir%\Temp\InvokeCHMTestGuid.txt.

.OUTPUTS

PSObject

Outputs an object consisting of relevant execution details. The following object properties may be populated:

* TechniqueID - Specifies the relevant MITRE ATT&CK Technique ID.
* TestSuccess - Will be set to True if it was determined that the CHM file successfully executed.
* TestGuid - Specifies the test GUID that was used for the test.
* ExecutionType - Indicates how the CHM file was executed: ShortcutCommandDefault, ShortcutCommandDoubleClick, ShortcutCommandTopic, WSHScriptTopic
* ScriptEngine - Indicates the Windows Script Host script engine that launched the HTA script content: JScript, VBScript, JScript.Encode, VBScript.Encode, or JScript.Compact
* CHMFilePath - Specifies the path to the CHM file that was dropped.
* CHMFileHashSHA256 - Specifies the file hash of the dropped CHM content.
* RunnerFilePath - Specifies the full path of the hh.exe runner.
* RunnerProcessId - Specifies the process ID of the hh.exe runner.
* RunnerCommandLine - Specifies the command-line ID of the hh.exe runner.
* RunnerChildProcessId - Specifies the process ID of process that was executed as the result of the CHM content executing.
* RunnerChildProcessCommandLine - Specifies the command-line of process that was executed as the result of the CHM content executing.

.EXAMPLE

Invoke-ATHCompiledHelp

Executes a default Shortcut command shell command.

.EXAMPLE

Copy-Item -Path C:\Windows\hh.exe -Destination C:\Windows\Temp\notepad.exe
Invoke-ATHCompiledHelp -HHFilePath C:\Windows\Temp\notepad.exe

Executes a default Shortcut command shell command with a renamed and relocated hh.exe.

.EXAMPLE

Invoke-ATHCompiledHelp -CHMFilePath foo.chm

Executes a default Shortcut command shell command via a CHM file named foo.chm.

.EXAMPLE

Invoke-ATHCompiledHelp -InfoTechStorageHandler mk:@MSITStore

Executes a default Shortcut command shell command, specifying an optional InfoTech storage handler which has no effect on the resulting execution.

.EXAMPLE

Invoke-ATHCompiledHelp -SimulateUserDoubleClick

Executes a default Shortcut command shell command by simulating a user click by executing it via explorer.exe and the default file association for CHM files.

.EXAMPLE

Invoke-ATHCompiledHelp -ScriptEngine VBScript.Encode

Executes WSH script code using the specified scripting engine.

.EXAMPLE

Invoke-ATHCompiledHelp -ScriptEngine JScript.Compact -TopicExtension htm

Executes WSH script code using the specified scripting engine, specifying a topic file extension of ".htm".

.EXAMPLE

Invoke-ATHCompiledHelp -ExecuteShortcutCommand

Explicity executes a Shortcut command embedded within a specific help topic.
#>

    [CmdletBinding(DefaultParameterSetName = 'Default')]
    param (
        [Parameter(Position = 0, ParameterSetName = 'Default')]
        [Parameter(Position = 0, ParameterSetName = 'ShortcutTopic')]
        [Parameter(Position = 0, ParameterSetName = 'WSHScriptTopic')]
        [Parameter(Position = 0, ParameterSetName = 'SimulateDoubleClick')]
        [String]
        [ValidateNotNullOrEmpty()]
        $CHMFilePath = 'Test.chm',

        [Parameter(Position = 1, ParameterSetName = 'Default')]
        [Parameter(Position = 1, ParameterSetName = 'ShortcutTopic')]
        [Parameter(Position = 1, ParameterSetName = 'WSHScriptTopic')]
        [String]
        [ValidateNotNullOrEmpty()]
        $HHFilePath = "$Env:windir\hh.exe",

        [Parameter(Mandatory, Position = 2, ParameterSetName = 'WSHScriptTopic')]
        [String]
        [ValidateSet('JScript', 'VBScript', 'VBScript.Encode', 'JScript.Encode', 'JScript.Compact')]
        $ScriptEngine = 'JScript',

        [Parameter(Position = 2, ParameterSetName = 'Default')]
        [Parameter(Position = 2, ParameterSetName = 'ShortcutTopic')]
        [Parameter(Position = 3, ParameterSetName = 'WSHScriptTopic')]
        [String]
        [ValidateSet('ms-its', 'its', 'mk:@MSITStore')]
        $InfoTechStorageHandler = 'ms-its',

        [Parameter(Mandatory, ParameterSetName = 'ShortcutTopic')]
        [Switch]
        $ExecuteShortcutCommand,

        [Parameter(Position = 3, ParameterSetName = 'ShortcutTopic')]
        [Parameter(Position = 4, ParameterSetName = 'WSHScriptTopic')]
        [String]
        [ValidateSet('html', 'htm')]
        $TopicExtension = 'html',

        [Parameter(Position = 3, ParameterSetName = 'Default')]
        [Parameter(Position = 4, ParameterSetName = 'ShortcutTopic')]
        [Parameter(Position = 5, ParameterSetName = 'WSHScriptTopic')]
        [Parameter(Position = 1, ParameterSetName = 'SimulateDoubleClick')]
        [Guid]
        $TestGuid = (New-Guid),

        [Parameter(Mandatory, ParameterSetName = 'SimulateDoubleClick')]
        [Switch]
        $SimulateUserDoubleClick
    )

    if (-not $CHMFilePath.EndsWith('.chm')) {
        Write-Error 'The specified CHM file must have a ".chm" file extension.'

        return
    }

    $CHMExecuted = $null
    $ScriptEngineUsed = 'None'
    $ExecutedHHCommandLine = $null
    $ExecutedHHPID = $null
    $SpawnedProcCommandLine = $null
    $SpawnedProcProcessId = $null
    $CHMFileHashSHA256 = $null
    $ExecutionType = $null
    $PreviousZone0SettingValue = $null
    $DeleteZone0RegValue = $False

    # This registry key will be used to permit the execution of embedded WSH script code without prompting the user.
    # This step is necessary in order to properly automate WSH script execution.
    $InternetSettingsPath = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones'

    $HHFullPath = Resolve-Path -Path $HHFilePath -ErrorAction Stop

    # Validate that the HH supplied is actually HH.
    $HHFileInfo = Get-Item -Path $HHFullPath -ErrorAction Stop

    $HHValidVersion = @('HTML Help','Aide HTML')
    if (-not ($HHValidVersion -contains $HHFileInfo.VersionInfo.ProductName)){
        Write-Error "The HH executable supplied is not hh.exe: $HHFullPath"

        return
    }

    $ParentDir = Split-Path -Path $CHMFilePath -Parent
    $FileName = Split-Path -Path $CHMFilePath -Leaf

    if (($ParentDir -eq '') -or ($ParentDir -eq '.')) {
        $ParentDir = $PWD.Path
    }

    if (!(Test-Path -Path $ParentDir -PathType Container)) {
        Write-Error "The following directory does not exist: $ParentDir"
        return
    }

    $FullCHMPath = Join-Path -Path $ParentDir -ChildPath $FileName

    # Note: this is not designed to be arbitrarily swapped out. This function relies upon specific topic names embedded within the CHM file.

    # VirusTotal link for this template CHM file: https://www.virustotal.com/gui/file/f9fccc38771acec6ec2fd0042dc4417f7bcdde3d95fe4864d086e6641ca23cf8/detection
    $EncodedCHMTestFile = 'SVRTRgMAAABgAAAAAQAAAJgRcDsJBAAAEP0BfKp70BGeDACgySLm7BH9AXyqe9ARngwAoMki5uxgAAAAAAAAABgAAAAAAAAAeAAAAAAAAABUEAAAAAAAAMwQAAAAAAAA/gEAAAAAAADILwAAAAAAAAAAAAAAAAAASVRTUAEAAABUAAAACgAAAAAQAAACAAAAAQAAAP////8AAAAAAAAAAP////8BAAAACQQAAGqSAl0uIdARnfkAoMki5uxUAAAA////////////////UE1HTJULAAAAAAAA//////////8BLwAAAAgvI0lEWEhEUgHjXaAACC8jSVRCSVRTAAAACS8jU1RSSU5HUwGBigIBCC8jU1lTVEVNAIEGoQgILyNUT1BJQ1MBgYNdgUAILyNVUkxTVFIBgYYtg1UILyNVUkxUQkwBgYUdgRALLyRGSWZ0aU1haW4BAAAJLyRPQkpJTlNUAc4elT8VLyRXV0Fzc29jaWF0aXZlTGlua3MvAAAAHS8kV1dBc3NvY2lhdGl2ZUxpbmtzL1Byb3BlcnR5Ac4aBBEvJFdXS2V5d29yZExpbmtzLwAAABkvJFdXS2V5d29yZExpbmtzL1Byb3BlcnR5Ac4WBBkvVEVNUExBVEVfU0hPUlRDVVRfMS5odG1sAQCHIRgvVEVNUExBVEVfU0hPUlRDVVRfMi5odG0BhyGHIRwvVEVNUExBVEVfV1NIX0pTQ1JJUFRfMS5odG1sAY5ChiwbL1RFTVBMQVRFX1dTSF9KU0NSSVBUXzIuaHRtAZRuhiwkL1RFTVBMQVRFX1dTSF9KU0NSSVBUX0NPTVBBQ1RfMS5odG1sAcEqhjYjL1RFTVBMQVRFX1dTSF9KU0NSSVBUX0NPTVBBQ1RfMi5odG0Bx2CGNiMvVEVNUExBVEVfV1NIX0pTQ1JJUFRfRU5DT0RFXzEuaHRtbAGnXIY3Ii9URU1QTEFURV9XU0hfSlNDUklQVF9FTkNPREVfMi5odG0BrhOGNx0vVEVNUExBVEVfV1NIX1ZCU0NSSVBUXzEuaHRtbAGbGoYhHC9URU1QTEFURV9XU0hfVkJTQ1JJUFRfMi5odG0BoTuGISQvVEVNUExBVEVfV1NIX1ZCU0NSSVBUX0VOQ09ERV8xLmh0bWwBtEqGMCMvVEVNUExBVEVfV1NIX1ZCU0NSSVBUX0VOQ09ERV8yLmh0bQG6eoYwFDo6RGF0YVNwYWNlL05hbWVMaXN0AAA8KDo6RGF0YVNwYWNlL1N0b3JhZ2UvTVNDb21wcmVzc2VkL0NvbnRlbnQAog6bPiw6OkRhdGFTcGFjZS9TdG9yYWdlL01TQ29tcHJlc3NlZC9Db250cm9sRGF0YQBqHCk6OkRhdGFTcGFjZS9TdG9yYWdlL01TQ29tcHJlc3NlZC9TcGFuSW5mbwBiCC86OkRhdGFTcGFjZS9TdG9yYWdlL01TQ29tcHJlc3NlZC9UcmFuc2Zvcm0vTGlzdAA8Jl86OkRhdGFTcGFjZS9TdG9yYWdlL01TQ29tcHJlc3NlZC9UcmFuc2Zvcm0vezdGQzI4OTQwLTlEMzEtMTFEMC05QjI3LTAwQTBDOTFFOUM3Q30vSW5zdGFuY2VEYXRhLwAAAGk6OkRhdGFTcGFjZS9TdG9yYWdlL01TQ29tcHJlc3NlZC9UcmFuc2Zvcm0vezdGQzI4OTQwLTlEMzEtMTFEMC05QjI3LTAwQTBDOTFFOUM3Q30vSW5zdGFuY2VEYXRhL1Jlc2V0VGFibGUAvUwwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABTA4cCxwETAYcAPAAhAB4AAgAMAFUAbgBjAG8AbQBwAHIAZQBzAHMAZQBkAAAADABNAFMAQwBvAG0AcAByAGUAcwBzAGUAZAAAAHsANwBGAEMAMgA4ADkANAAwAC0AOQBEADMAMQAtADEAMQBEADAAA0UAAAAAAAAGAAAATFpYQwIAAAACAAAAAgAAAAEAAAAAAAAAAwAAAAoABADaLCRfCQAWAEhIQSBWZXJzaW9uIDQuNzQuODcwMgAEACQACQQAAAAAAAAAAAAAAAAAAAAAAAAMr207SGfWAQAAAAAAAAAAAgAZAFRFTVBMQVRFX1NIT1JUQ1VUXzEuaHRtbAAGAAUAdGVzdAAMAAQAAAAAAA0AABBUI1NNa9vRFAEAAAAMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA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'
    <#
    # To decompile and inspect the contents of the above CHM file, run the following:
    $CHMTestFileBytes = [Convert]::FromBase64String($EncodedCHMTestFile)
    [IO.File]::WriteAllBytes("$PWD\Template.chm", $CHMTestFileBytes)
    mkdir DecompiledCHM
    .\hh.exe -decompile DecompiledCHM Template.chm
    ls .\DecompiledCHM\*.htm* | Get-Content
    #>

    # The following code was used to build the above CHM:
    <#
$OutputCHMFilename = 'Test.chm'
$OutputDirectory = $PWD

$OutputCHMFilenameNoExtension = $OutputCHMFilename.Substring(0, $OutputCHMFilename.LastIndexOf('.'))
$OutputHHPFilename = $OutputCHMFilenameNoExtension + '.hhp'

$OutputCHMFullPath = Join-Path -Path $OutputDirectory -ChildPath $OutputCHMFilename
$OutputHHPFullPath = Join-Path -Path $OutputDirectory -ChildPath ($OutputCHMFilenameNoExtension + '.hhp')

$ShortcutCommandHTMLPath1 =    Join-Path -Path $OutputDirectory -ChildPath TEMPLATE_SHORTCUT_1.html
$ShortcutCommandHTMLPath2 =    Join-Path -Path $OutputDirectory -ChildPath TEMPLATE_SHORTCUT_2.htm
$WSHJScriptHTMLPath1 =         Join-Path -Path $OutputDirectory -ChildPath TEMPLATE_WSH_JSCRIPT_1.html
$WSHJScriptHTMLPath2 =         Join-Path -Path $OutputDirectory -ChildPath TEMPLATE_WSH_JSCRIPT_2.htm
$WSHVBScriptHTMLPath1 =        Join-Path -Path $OutputDirectory -ChildPath TEMPLATE_WSH_VBSCRIPT_1.html
$WSHVBScriptHTMLPath2 =        Join-Path -Path $OutputDirectory -ChildPath TEMPLATE_WSH_VBSCRIPT_2.htm
$WSHJScriptEncodeHTMLPath1 =   Join-Path -Path $OutputDirectory -ChildPath TEMPLATE_WSH_JSCRIPT_ENCODE_1.html
$WSHJScriptEncodeHTMLPath2 =   Join-Path -Path $OutputDirectory -ChildPath TEMPLATE_WSH_JSCRIPT_ENCODE_2.htm
$WSHVBScriptEncodeHTMLPath1 =  Join-Path -Path $OutputDirectory -ChildPath TEMPLATE_WSH_VBSCRIPT_ENCODE_1.html
$WSHVBScriptEncodeHTMLPath2 =  Join-Path -Path $OutputDirectory -ChildPath TEMPLATE_WSH_VBSCRIPT_ENCODE_2.htm
$WSHJScriptCompactHTMLPath1 =  Join-Path -Path $OutputDirectory -ChildPath TEMPLATE_WSH_JSCRIPT_COMPACT_1.html
$WSHJScriptCompactHTMLPath2 =  Join-Path -Path $OutputDirectory -ChildPath TEMPLATE_WSH_JSCRIPT_COMPACT_2.htm

# $EncodedCommand generated with the following:

$CommandToEncode = {
Start-Process -FilePath powershell.exe -ArgumentList '-WindowStyle','Hidden','-NoProfile','-Command',('Write-Host ' + (Get-Content -Path $Env:windir\Temp\InvokeCHMTestGuid.txt -ErrorAction SilentlyContinue))
}

$EncodedCommand = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($CommandToEncode.ToString()))

$EncodedCommand = 'CgBTAHQAYQByAHQALQBQAHIAbwBjAGUAcwBzACAALQBGAGkAbABlAFAAYQB0AGgAIABwAG8AdwBlAHIAcwBoAGUAbABsAC4AZQB4AGUAIAAtAEEAcgBnAHUAbQBlAG4AdABMAGkAcwB0ACAAJwAtAFcAaQBuAGQAbwB3AFMAdAB5AGwAZQAnACwAJwBIAGkAZABkAGUAbgAnACwAJwAtAE4AbwBQAHIAbwBmAGkAbABlACcALAAnAC0AQwBvAG0AbQBhAG4AZAAnACwAKAAnAFcAcgBpAHQAZQAtAEgAbwBzAHQAIAAnACAAKwAgACgARwBlAHQALQBDAG8AbgB0AGUAbgB0ACAALQBQAGEAdABoACAAJABFAG4AdgA6AHcAaQBuAGQAaQByAFwAVABlAG0AcABcAEkAbgB2AG8AawBlAEMASABNAFQAZQBzAHQARwB1AGkAZAAuAHQAeAB0ACAALQBFAHIAcgBvAHIAQQBjAHQAaQBvAG4AIABTAGkAbABlAG4AdABsAHkAQwBvAG4AdABpAG4AdQBlACkAKQAKAA=='

$ShortcutCommandPowerShellTemplate = ",powershell.exe, -WindowStyle Hidden -EncodedCommand $EncodedCommand"

$WSHScriptPowerShellTemplate = "powershell.exe -WindowStyle Hidden -EncodedCommand $EncodedCommand"

function ConvertTo-EncodedWSHScript {
    [CmdletBinding()]
    [OutputType([String])]
    param (
        [String]
        [ValidateNotNullOrEmpty()]
        $ScriptContent
    )

    $Encoder = New-Object -ComObject 'Scripting.Encoder'

    # The '.vbs' extension and 'VBScript' engine don't matter. The encoder doesn't
    # have different logic for JScript vs. VBScript
    $EncodedScriptContent = $Encoder.EncodeScriptFile('.vbs', $ScriptContent, 0, 'VBScript')

    # Return the encoded script string.
    $EncodedScriptContent.TrimEnd(([Char] 0))
}

$HelpCompilerProjectFileContents = @"
[FILES]
$ShortcutCommandHTMLPath1
$ShortcutCommandHTMLPath2
$WSHJScriptHTMLPath1
$WSHJScriptHTMLPath2
$WSHVBScriptHTMLPath1
$WSHVBScriptHTMLPath2
$WSHJScriptEncodeHTMLPath1
$WSHJScriptEncodeHTMLPath2
$WSHVBScriptEncodeHTMLPath1
$WSHVBScriptEncodeHTMLPath2
$WSHJScriptCompactHTMLPath1
$WSHJScriptCompactHTMLPath2
"@
    

$ShortCommandTemplate = @"
<HTML>
  <HEAD>
    <OBJECT id="Exec" type="application/x-oleobject" classid="clsid:52a2aaae-085d-4187-97ea-8c30db990436">
      <PARAM name="Command" value="ShortCut">
      <PARAM name="Item1" value="$ShortcutCommandPowerShellTemplate">
    </OBJECT>
    <SCRIPT>
      Exec.Click();
    </SCRIPT>
  </HEAD>
  <BODY>
  </BODY>
</HTML>
"@

$WSHJScriptTemplate = @"
<HTML>
  <HEAD>
    <SCRIPT language=JScript>
        var objShell = new ActiveXObject('Wscript.Shell');
        objShell.Run("$WSHScriptPowerShellTemplate", 1, true);
    </SCRIPT>
  </HEAD>
  <BODY>
  </BODY>
</HTML>
"@

$WSHJScriptCompactTemplate = @"
<HTML>
  <HEAD>
    <SCRIPT language="JScript.Compact">
        var objShell = new ActiveXObject('Wscript.Shell');
        objShell.Run("$WSHScriptPowerShellTemplate", 1, true);
    </SCRIPT>
  </HEAD>
  <BODY>
  </BODY>
</HTML>
"@

$WSHVBScriptTemplate = @"
<HTML>
  <HEAD>
    <SCRIPT language=VBScript>
      Set objShell = CreateObject("Wscript.Shell")
      objShell.Run "$WSHScriptPowerShellTemplate", 1, true
    </SCRIPT>
  </HEAD>
  <BODY>
  </BODY>
</HTML>
"@

$JScriptTemplate = @"
var objShell = new ActiveXObject('Wscript.Shell');
objShell.Run("$WSHScriptPowerShellTemplate", 1, true);
"@

$EncodedJScript = ConvertTo-EncodedWSHScript -ScriptContent $JScriptTemplate

$WSHJScriptEncodeTemplate = @"
<HTML>
  <HEAD>
    <SCRIPT language="JScript.Encode">$EncodedJScript</SCRIPT>
  </HEAD>
  <BODY>
  </BODY>
</HTML>
"@

$VBScriptTemplate = @"
Set objShell = CreateObject("Wscript.Shell")
objShell.Run "$WSHScriptPowerShellTemplate", 1, true
"@

$EncodedVBScript = ConvertTo-EncodedWSHScript -ScriptContent $VBScriptTemplate

$WSHVBScriptEncodeTemplate = @"
<HTML>
  <HEAD>
    <SCRIPT language="VBScript.Encode">$EncodedVBScript</SCRIPT>
  </HEAD>
  <BODY>
  </BODY>
</HTML>
"@


Out-File -InputObject $ShortCommandTemplate -FilePath $ShortcutCommandHTMLPath1 -Encoding ascii
Out-File -InputObject $ShortCommandTemplate -FilePath $ShortcutCommandHTMLPath2 -Encoding ascii
Out-File -InputObject $WSHJScriptTemplate -FilePath $WSHJScriptHTMLPath1 -Encoding ascii
Out-File -InputObject $WSHJScriptTemplate -FilePath $WSHJScriptHTMLPath2 -Encoding ascii
Out-File -InputObject $WSHVBScriptTemplate -FilePath $WSHVBScriptHTMLPath1 -Encoding ascii
Out-File -InputObject $WSHVBScriptTemplate -FilePath $WSHVBScriptHTMLPath2 -Encoding ascii
Out-File -InputObject $WSHJScriptEncodeTemplate -FilePath $WSHJScriptEncodeHTMLPath1 -Encoding ascii
Out-File -InputObject $WSHJScriptEncodeTemplate -FilePath $WSHJScriptEncodeHTMLPath2 -Encoding ascii
Out-File -InputObject $WSHVBScriptEncodeTemplate -FilePath $WSHVBScriptEncodeHTMLPath1 -Encoding ascii
Out-File -InputObject $WSHVBScriptEncodeTemplate -FilePath $WSHVBScriptEncodeHTMLPath2 -Encoding ascii
Out-File -InputObject $WSHJScriptCompactTemplate -FilePath $WSHJScriptCompactHTMLPath1 -Encoding ascii
Out-File -InputObject $WSHJScriptCompactTemplate -FilePath $WSHJScriptCompactHTMLPath2 -Encoding ascii

Out-File -InputObject $HelpCompilerProjectFileContents -FilePath $OutputHHPFullPath -Encoding ascii

$HelpCompilerFullPath = "C:\Program Files (x86)\HTML Help Workshop\hhc.exe"
& "$HelpCompilerFullPath" "$OutputHHPFullPath"
    #>

    $CHMTestFileBytes = [Convert]::FromBase64String($EncodedCHMTestFile)

    Write-Verbose "Writing template CHM to $FullCHMPath"

    # Write the CHM file to disk
    try {
        [IO.File]::WriteAllBytes($FullCHMPath, $CHMTestFileBytes)
    } catch {
        throw "Unable to write template CHM to $FullCHMPath. A handle to an existing CHM is likely being held by a running instance of hh.exe."
    }

    $CHMFileHashSHA256 = Get-FileHash -Algorithm SHA256 -Path $FullCHMPath -ErrorAction Stop | Select-Object -ExpandProperty Hash

    switch ($PSCmdlet.ParameterSetName) {
        'Default' {
            $ExecutionType = 'ShortcutCommandDefault'

            if ($PSBoundParameters['InfoTechStorageHandler']) {
                # Prepend a storage handler, if specified
                $hhCommandLine = "`"$HHFullPath`" `"$($InfoTechStorageHandler):$FullCHMPath`""
            } else {
                $hhCommandLine = "`"$HHFullPath`" `"$FullCHMPath`""
            }
        }

        'SimulateDoubleClick' {
            $ExecutionType = 'ShortcutCommandDoubleClick'

            $hhCommandLine = "explorer.exe `"$FullCHMPath`""
        }

        'WSHScriptTopic' {
            $ExecutionType = 'WSHScriptTopic'
            $ScriptEngineUsed = $ScriptEngine

            switch ($TopicExtension) {
                'html' { $TopicSuffix = '_1.html' }
                'htm'  { $TopicSuffix = '_2.htm' }
            }

            switch ($ScriptEngine) {
                'JScript'         { $TopicFilename = 'TEMPLATE_WSH_JSCRIPT' + $TopicSuffix }
                'VBScript'        { $TopicFilename = 'TEMPLATE_WSH_VBSCRIPT' + $TopicSuffix }
                'VBScript.Encode' { $TopicFilename = 'TEMPLATE_WSH_VBSCRIPT_ENCODE' + $TopicSuffix }
                'JScript.Encode'  { $TopicFilename = 'TEMPLATE_WSH_JSCRIPT_ENCODE' + $TopicSuffix }
                'JScript.Compact' { $TopicFilename = 'TEMPLATE_WSH_JSCRIPT_COMPACT' + $TopicSuffix }
            }

            # Set the appropriate registry values to not display a prompt when script content is to be executed.

            # First check for the presence of the 1201 reg value. 1201 corresponds to the following setting:
            # ActiveX controls and plug-ins: Initialize and script ActiveX controls not marked as safe for scripting
            # Zone 0 refers to the "My Computer" zone - i.e. executing from a local file
            # Reference: https://support.microsoft.com/en-us/help/182569/internet-explorer-security-zones-registry-entries-for-advanced-users
            $RegValueExists = $null
            $RegValueExists = Get-ItemProperty -Path "$InternetSettingsPath\0" -Name 1201 -ErrorAction SilentlyContinue

            if ($RegValueExists) {
                $SettingValue = $RegValueExists.1201

                if ($SettingValue -ne 0) {
                    # Save the previous value so that it can be restored
                    $PreviousZone0SettingValue = $SettingValue

                    Write-Verbose "Zone 0 '1201' setting ($InternetSettingsPath\0\1201) was previously set to $PreviousZone0SettingValue. Setting it to 'enabled' - 0x00000000"

                    # Set "My Computer" zone "ActiveX controls and plug-ins: Initialize and script ActiveX controls not marked as safe for scripting" setting to "enabled" - i.e. 0
                    Set-ItemProperty "$InternetSettingsPath\0" -Name 1201 -Value 0
                }
            } else {
                # The value does not exist. Create the value.
                Write-Verbose "Zone 0 '1201' registry value ($InternetSettingsPath\0\1201) is not defined. Creating the registry value and setting it to 'enabled' - 0x00000000"

                $RegValueExists = New-ItemProperty -Path "$InternetSettingsPath\0" -Name 1201 -PropertyType DWord -Value 0

                if ($RegValueExists) { $DeleteZone0RegValue = $True }
            }

            $hhCommandLine = "`"$HHFullPath`" `"$($InfoTechStorageHandler):$($FullCHMPath)::/$TopicFilename`""
        }

        'ShortcutTopic' {
            $ExecutionType = 'ShortcutCommandTopic'

            switch ($TopicExtension) {
                'html' { $TopicFilename = 'TEMPLATE_SHORTCUT_1.html' }
                'htm'  { $TopicFilename = 'TEMPLATE_SHORTCUT_2.htm' }
            }

            $hhCommandLine = "`"$HHFullPath`" `"$($InfoTechStorageHandler):$($FullCHMPath)::/$TopicFilename`""
        }
    }

    $TempFileName = 'InvokeCHMTestGuid.txt'
    $TempFileDirectory = Resolve-Path -Path "$Env:windir\Temp"

    # Path to where the current test GUID will be written and then subsequently read from.
    $TempFilePath = Join-Path -Path $TempFileDirectory -ChildPath $TempFileName

    Remove-Item -Path $TempFilePath -Force -ErrorAction SilentlyContinue

    Write-Verbose "Writing the following GUID to $($TempFilePath): $TestGuid"

    # Write the test guid to the temp file
    Out-File -FilePath $TempFilePath -InputObject $TestGuid.Guid -Encoding ascii

    # Remove any extra ChildProcSpawned events
    Unregister-Event -SourceIdentifier 'ProcessSpawned' -ErrorAction SilentlyContinue
    Get-Event -SourceIdentifier 'ChildProcSpawned' -ErrorAction SilentlyContinue | Remove-Event

    # Trigger an event any time powershell.exe has $TestGuid in the command line.
    # This event should correspond to the mshta or rundll process that launched it.
    $WMIEventQuery = "SELECT * FROM __InstanceCreationEvent WITHIN 0.1 WHERE TargetInstance ISA 'Win32_Process' AND TargetInstance.Name = 'powershell.exe' AND TargetInstance.CommandLine LIKE '%$($TestGuid)%'"

    Write-Verbose "Registering powershell.exe child process creation WMI event using the following WMI event query: $WMIEventQuery"

    $null = Register-CimIndicationEvent -SourceIdentifier 'ProcessSpawned' -Query $WMIEventQuery -Action {
        $SpawnedProcInfo = [PSCustomObject] @{
            ProcessId = $EventArgs.NewEvent.TargetInstance.ProcessId
            ProcessCommandLine = $EventArgs.NewEvent.TargetInstance.CommandLine
        }

        New-Event -SourceIdentifier 'ChildProcSpawned' -MessageData $SpawnedProcInfo
    }

    if ($SimulateUserDoubleClick) {
        # Since there is no precise way to determine the process ID of the hh.exe process that will be spawned, kill any running hh.exe processes.

        Write-Verbose 'Stopping any running hh.exe processes'

        Get-Process -Name hh -ErrorAction SilentlyContinue | Stop-Process -Force
    }

    Write-Verbose "Invoking the following command-line: $hhCommandLine"

    # Spawn hh.exe instance
    $ProcessStartup = New-CimInstance -ClassName Win32_ProcessStartup -ClientOnly
    $ProcessStartupInstance = Get-CimInstance -InputObject $ProcessStartup
    $ProcessStartupInstance.ShowWindow = [UInt16] 0 # Hide the window
    $ProcStartResult = Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{ CommandLine = $hhCommandLine; ProcessStartupInformation = $ProcessStartupInstance }

    if ($ProcStartResult.ReturnValue -eq 0) {
        # Retrieve the actual command-line of the spawned PowerShell process
        $ExecutedHHProcInfo = Get-CimInstance -ClassName Win32_Process -Filter "ProcessId = $($ProcStartResult.ProcessId)" -Property CommandLine, ExecutablePath
        $ExecutedHHCommandLine = $ExecutedHHProcInfo.CommandLine
        $ExecutedHHPID = $ProcStartResult.ProcessId
        $HHFullPath = $ExecutedHHProcInfo.ExecutablePath
    } else {
        Write-Error "hh.exe child process was not spawned."

        # Delete the test file if it hasn't been deleted already.
        Write-Verbose "Removing test GUID file: $TempFilePath)"
        Remove-Item -Path $TempFilePath -ErrorAction SilentlyContinue

        # If internet settings were modified, revert changes
        if ($PreviousZone0SettingValue) {
            Write-Verbose "Reverting Zone 0 '1201' setting ($InternetSettingsPath\0\1201) back to saved value: 0x$($PreviousZone0SettingValue.ToString('X8'))"
            Set-ItemProperty "$InternetSettingsPath\0" -Name 1201 -Value $PreviousZone0SettingValue
        }

        if ($DeleteZone0RegValue) {
            Write-Verbose "Deleting Zone 0 '1201' setting registry value ($InternetSettingsPath\0\1201)."
            Remove-ItemProperty -Path "$InternetSettingsPath\0" -Name 1201
        }

        return
    }

    # Wait for the test powershell.exe execution to run
    $ChildProcSpawnedEvent = Wait-Event -SourceIdentifier 'ChildProcSpawned' -Timeout 10
    $ChildProcInfo = $null

    # If internet settings were modified, revert changes
    if ($PreviousZone0SettingValue) {
        Write-Verbose "Reverting Zone 0 '1201' setting ($InternetSettingsPath\0\1201) back to saved value: 0x$($PreviousZone0SettingValue.ToString('X8'))"
        Set-ItemProperty "$InternetSettingsPath\0" -Name 1201 -Value $PreviousZone0SettingValue
    }

    if ($DeleteZone0RegValue) {
        Write-Verbose "Deleting Zone 0 '1201' setting registry value ($InternetSettingsPath\0\1201)."
        Remove-ItemProperty -Path "$InternetSettingsPath\0" -Name 1201
    }

    Write-Verbose "Removing test GUID file: $TempFilePath)"

    # Delete the test file if it hasn't been deleted already.
    Remove-Item -Path $TempFilePath -Force -ErrorAction SilentlyContinue

    if ($ExecutedHHPID) {
        if ($SimulateUserDoubleClick) {
            # There is no reliable way to capture the specific hh.exe process in this case so resort to killing all running hh.exe processes.
            $HHProcInfo = Get-CimInstance -ClassName Win32_Process -Filter 'Name = "hh.exe"' -Property ProcessId, CommandLine, ExecutablePath | Select-Object -First 1

            $HHFullPath = $HHProcInfo.ExecutablePath
            $ExecutedHHPID = $HHProcInfo.ProcessId
            $ExecutedHHCommandLine = $HHProcInfo.CommandLine

            Stop-Process -Id $ExecutedHHPID -Force
        } else {
            # Kill the hh.exe process directly
            Stop-Process -Id $ProcStartResult.ProcessId -Force
        }
    }

    if ($ChildProcSpawnedEvent) {
        $CHMExecuted = $True

        $ChildProcInfo = $ChildProcSpawnedEvent.MessageData
        $SpawnedProcCommandLine = $ChildProcInfo.ProcessCommandLine
        $SpawnedProcProcessId = $ChildProcInfo.ProcessId

        $ChildProcSpawnedEvent | Remove-Event
    } else {
        Write-Error "powershell.exe child process was not spawned."
    }

    # Cleanup
    Unregister-Event -SourceIdentifier 'ProcessSpawned'

    [PSCustomObject] @{
        TechniqueID = 'T1218.001'
        TestSuccess = $CHMExecuted
        TestGuid = $TestGuid
        ExecutionType = $ExecutionType
        ScriptEngine = $ScriptEngineUsed
        CHMFilePath = $FullCHMPath
        CHMFileHashSHA256 = $CHMFileHashSHA256
        RunnerFilePath = $HHFullPath
        RunnerProcessId = $ExecutedHHPID
        RunnerCommandLine = $ExecutedHHCommandLine
        RunnerChildProcessId = $SpawnedProcProcessId
        RunnerChildProcessCommandLine = $SpawnedProcCommandLine
    }
}
