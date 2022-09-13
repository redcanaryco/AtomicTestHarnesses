#Requires -Assembly "Microsoft.Deployment.WindowsInstaller, Version=3.0.0.0, Culture=neutral, PublicKeyToken=ce35f76fcda82bad"
# The above assembly refers to Dependencies\Microsoft.Deployment.WindowsInstaller.dll (SHA256: CF06D4ED4A8BAF88C82D6C9AE0EFC81C469DE6DA8788AB35F373B350A4B4CDCA)

function New-ATHMSI {
    <#
    .SYNOPSIS

    Creates an MSI file with embedded executable content.

    Technique ID: T1218.007 (Signed Binary Proxy Execution: Msiexec)

    .DESCRIPTION

    New-ATHMSI is designed to simplify the process of creating an MSI that executes a single embedded item (VBScript script, JScript script, Dll, or Exe) without having to install a complex MSI packaging utility.

    .PARAMETER FileName

    Specifies the filename of the MSI that will be written to disk.

    .PARAMETER OutputDirectory

    Specifies the output directory where the MSI that will be written to disk. If -OutputDirectory is not specified, the MSI file will be written to the current working directory.

    .PARAMETER ActionToImplement

    Specifies the type of execution action that the MSI will be designed to perform, Install, Admin, or Advertise. The execution action specified determines the arguments required to execute the MSI (e.g. "msiexec.exe /i" in the case of "Install").

    .PARAMETER ScriptContent

    Specifies VBScript or JScript content that the MSI will be emdebbed in the MSI and execute.

    .PARAMETER ScriptEngine

    Specifies the scripting engine to use: VBScript or JScript.

    .PARAMETER ExeBytes

    Specifies a byte array consisting of an EXE that will be emdebbed in the MSI and execute.

    .PARAMETER ExeArguments

    Specifies optional command-line arguments to supply to the embedded EXE.

    .PARAMETER DllBytes

    Specifies a byte array consisting of a DLL that will be emdebbed in the MSI and execute.

    .PARAMETER DllExportFunction

    Specifies the name of the DLL export function to execute.

    .PARAMETER CustomActionName

    Specifies the name of the custom action to run.

    .PARAMETER ActionSequenceNumber

    Specifies the sequence number of the custom action that will execute in its corresponding sequence table.

    .PARAMETER SourceName

    Specifies the name of the row in the Binary table that will store the executable contents.

    .PARAMETER Manufacturer

    Specifies the name of the application manufacturer.

    .PARAMETER ProductName

    Specifies the human readable name of an application.

    .PARAMETER CreatingApp

    Specifies which application created the installer database.

    .PARAMETER ProductCode

    Specifies a unique identifier for a specific product release.

    .PARAMETER RevisionNumber

    Specifies the package code for the installer package.

    .PARAMETER ProductVersion

    Specifies the product version as a numeric value.

    .PARAMETER WindowsInstallerVersion

    Specifies the minimum installer version required by the installation package. Supported values: 2.0, 3.0, 3.1, 4.0, 4.5, 5.0. Note: -WindowsInstallerVersion must be 4.0 or higher to support the -ElevatedPrivilegesNotRequired switch.

    .PARAMETER ProductLanguage

    Specifies the numeric language identifier (LANGID) for the database.

    .PARAMETER CodePage

    Specifies the numeric value of the ANSI code page used for any strings that are stored in the summary information.

    .PARAMETER LastPrintTime

    Specifies the date and time during an administrative installation to record when the administrative image was created.

    .PARAMETER CreateTime

    Specifies the time and date when an author created the installation package.

    .PARAMETER Architecture

    Specifies the platform that the MSI is designed to support x86 (Intel) or x64.

    .PARAMETER ElevatedPrivilegesNotRequired

    Specifies that the MSI does not require UAC elevation to execute. Note: -WindowsInstallerVersion must be 4.0 or higher to support this switch.

    .PARAMETER ReadOnlyEnforced

    Specifies that the MSI file should not be opened for editing.

    .OUTPUTS

    PSObject

    Outputs an object consisting of relevant MSI file details. The following object properties are populated:

    * FilePath - Specifies the full path to the generated MSI file
    * FileHash - Specifies the SHA256 hash of the generated MSI file

    .EXAMPLE

    $MSI = New-ATHMSI -FileName VBScriptRunner.msi -ElevatedPrivilegesNotRequired -ScriptContent 'CreateObject("WScript.Shell").Popup("Hello, VBScript!")' -ScriptEngine VBScript

    .EXAMPLE

    $ScriptContent = @'

    $MSI = New-ATHMSI -FileName JScriptRunner.msi -ElevatedPrivilegesNotRequired -ScriptContent 'var shell = new ActiveXObject("WScript.Shell");shell.Popup("Hello, VBScript!");' -ScriptEngine JScript

    .EXAMPLE

    Add-Type -TypeDefinition @'
        public class Test {
            public static void Main(string[] args) {
                System.Console.WriteLine(args[0]);
                System.Console.ReadLine();
            }
        }
    '@ -OutputAssembly PrintArg.exe

    $ExeBytes = [IO.File]::ReadAllBytes("$PWD\PrintArg.exe")

    $MSI = New-ATHMSI -FileName ExeRunner.msi -ElevatedPrivilegesNotRequired -ExeBytes $ExeBytes -ExeArguments '"Hello, EXE!"'
    #>

        [CmdletBinding(DefaultParameterSetName = 'Script')]
        param (
            [Parameter(Mandatory)]
            [String]
            [ValidateNotNullOrEmpty()]
            $FileName,

            [String]
            [ValidateScript({ Test-Path -Path $_ -PathType Container -IsValid })]
            $OutputDirectory = $PWD.Path,

            [String]
            [ValidateSet('Install', 'Admin', 'Advertise')]
            $ActionToImplement = 'Install',

            [Parameter(Mandatory, ParameterSetName = 'Script')]
            [String]
            [ValidateNotNullOrEmpty()]
            $ScriptContent,

            [Parameter(ParameterSetName = 'Script')]
            [String]
            [ValidateSet('VBScript', 'JScript')]
            $ScriptEngine = 'VBScript',

            [Parameter(Mandatory, ParameterSetName = 'Exe')]
            [Byte[]]
            $ExeBytes,

            [Parameter(ParameterSetName = 'Exe')]
            [String]
            $ExeArguments,

            [Parameter(Mandatory, ParameterSetName = 'Dll')]
            [Byte[]]
            $DllBytes,

            [Parameter(Mandatory, ParameterSetName = 'Dll')]
            [String]
            $DllExportFunction,

            [String]
            [ValidateNotNullOrEmpty()]
            $CustomActionName = 'RunMe',

            [UInt16]
            $ActionSequenceNumber = 100,

            [String]
            [ValidateNotNullOrEmpty()]
            $SourceName = 'ExecutableContents',

            [String]
            [ValidateNotNullOrEmpty()]
            $Manufacturer = 'AtomicTestHarness, Inc.',

            [String]
            [ValidateNotNullOrEmpty()]
            $ProductName = 'AtomicTestHarnesses Test Installer',

            [String]
            [ValidateNotNullOrEmpty()]
            $CreatingApp = 'AtomicTestHarnesses',

            [Guid]
            $ProductCode = (New-Guid),

            [Guid]
            $RevisionNumber = (New-Guid),

            [Version]
            [ValidateScript({ ($_.Major -le 255) -and ($_.Minor -le 255) -and ($_.Build -le 65535) })]
            $ProductVersion = ([Version] '1.0.0'),

            [String]
            [ValidateSet('2.0', '3.0', '3.1', '4.0', '4.5', '5.0')]
            $WindowsInstallerVersion = '4.0',

            [Int16]
            $ProductLanguage = 1033,

            [Int16]
            $CodePage = 1252,

            [DateTime]
            $LastPrintTime = (Get-Date),

            [DateTime]
            $CreateTime = (Get-Date),

            [String]
            [ValidateSet('Intel', 'x64')]
            $Architecture = 'Intel',

            [Switch]
            $ElevatedPrivilegesNotRequired,

            [Switch]
            $ReadOnlyEnforced
        )

        if ($ElevatedPrivilegesNotRequired -and ($('4.0', '4.5', '5.0') -notcontains $WindowsInstallerVersion)) {
            Write-Error 'A Windows Installer version of 4.0 and higher is required to specfiy that the installer not require elevated privileges.'
            return
        }

        $MSIFilePath = Join-Path -Path $OutputDirectory -ChildPath $FileName

        switch ($ActionToImplement) {
            'Install'   { $SequenceTableName = 'InstallExecuteSequence' }
            'Admin'     { $SequenceTableName = 'AdminExecuteSequence'   }
            'Advertise' { $SequenceTableName = 'AdvtExecuteSequence'    }
        }

        # "Letters used in this GUID must be uppercase"
        $ProductCodeNormalized = "{$($ProductCode.Guid.ToUpper())}"

        # "The format of the string is as follows: major.minor.build"
        $ProductVersionNormalized = "$($ProductVersion.Major).$($ProductVersion.Minor).$($ProductVersion.Build)"

        # Summary Information Stream values
        $Title = 'Installation Database'
        $Subject = $ProductName
        $Author = $Manufacturer
        $Keywords = 'Installer'
        $Comments = "This installer database contains the logic and data required to install $ProductName."
        $Template = "$Architecture;$ProductLanguage"
        $RevisionNumberNormalized = "{$($RevisionNumber.Guid.ToUpper())}"

        switch ($WindowsInstallerVersion) {
            '2.0' { $PageCount = 200 }
            '3.0' { $PageCount = 300 }
            '3.1' { $PageCount = 301 }
            '4.0' { $PageCount = 400 }
            '4.5' { $PageCount = 405 }
            '5.0' { $PageCount = 500 }
        }

        $WordCount = 0
        if ($ElevatedPrivilegesNotRequired) { $WordCount = 8 }

        $Security = 2 # Default to "Read-only recommended"
        if ($ReadOnlyEnforced) { $Security = 4 }

        try {
            $Database = New-Object -TypeName Microsoft.Deployment.WindowsInstaller.Database -ArgumentList $MSIFilePath, ([Microsoft.Deployment.WindowsInstaller.DatabaseOpenMode]::CreateDirect)
        } catch {
            # Likely to throw an exception if another process has an open handle to an existing file with the same name. e.g. if you have the MSI open in Orca.
            throw $_
        }

        $Database.Execute('CREATE TABLE `Property` (`Property` CHAR(72) NOT NULL, `Value` CHAR(0) NOT NULL LOCALIZABLE  PRIMARY KEY `Property`)')

        $PropertyInsertionQuery = "INSERT INTO ``Property`` (``Property``, ``Value``) VALUES ('{0}', '{1}')"

        $Database.Execute($PropertyInsertionQuery, [Object[]] @('Manufacturer', $Manufacturer))
        $Database.Execute($PropertyInsertionQuery, [Object[]] @('ProductName', $ProductName))
        $Database.Execute($PropertyInsertionQuery, [Object[]] @('ProductCode', $ProductCodeNormalized))
        $Database.Execute($PropertyInsertionQuery, [Object[]] @('ProductVersion', $ProductVersionNormalized))
        $Database.Execute($PropertyInsertionQuery, [Object[]] @('ProductLanguage', "$ProductLanguage"))

        $Database.SummaryInfo.Title =          $Title
        $Database.SummaryInfo.Subject =        $Subject
        $Database.SummaryInfo.Author =         $Author
        $Database.SummaryInfo.Keywords =       $Keywords
        $Database.SummaryInfo.Comments =       $Comments
        $Database.SummaryInfo.Template =       $Template
        $Database.SummaryInfo.RevisionNumber = $RevisionNumberNormalized
        $Database.SummaryInfo.CreatingApp =    $CreatingApp
        $Database.SummaryInfo.LastPrintTime =  $LastPrintTime
        $Database.SummaryInfo.CreateTime =     $CreateTime
        $Database.SummaryInfo.CodePage =       $CodePage
        $Database.SummaryInfo.PageCount =      $PageCount
        $Database.SummaryInfo.WordCount =      $WordCount
        $Database.SummaryInfo.Security =       $Security

        $Database.Execute('CREATE TABLE `Binary` (`Name` CHAR(72) NOT NULL, `Data` OBJECT NOT NULL  PRIMARY KEY `Name`)')

        $TargetName = 'NULL'

        switch ($PSCmdlet.ParameterSetName) {
            'Script' {
                switch ($ScriptEngine) {
                    'VBScript' { $CustomActionTypeValue = 0x46 } # msidbCustomActionTypeContinue (0x40) | msidbCustomActionTypeVBScript (0x06)
                    'JScript'  { $CustomActionTypeValue = 0x45 } # msidbCustomActionTypeContinue (0x40) | msidbCustomActionTypeJScript  (0x05)
                }

                # Script content must be ASCII encoded
                $BinaryBytes = [Text.Encoding]::ASCII.GetBytes($ScriptContent)
            }

            'Exe' {
                $CustomActionTypeValue = 0x42 # msidbCustomActionTypeContinue (0x40) | msidbCustomActionTypeExe (0x02)

                $BinaryBytes = $ExeBytes
                if ($ExeArguments) { $TargetName = "'$ExeArguments'" }
            }

            'Dll' {
                $CustomActionTypeValue = 0x41 # msidbCustomActionTypeContinue (0x40) | msidbCustomActionTypeDll (0x01)

                $BinaryBytes = $DllBytes
                $TargetName = "'$DllExportFunction'"
            }
        }

        $MemoryStream = New-Object -TypeName IO.MemoryStream -ArgumentList @(,$BinaryBytes)
        $BinaryRecord = New-Object -TypeName Microsoft.Deployment.WindowsInstaller.Record -ArgumentList 1
        $BinaryRecord.SetStream(1, $MemoryStream)

        # Create a row in the Binary table containing the executable content.
        $Database.Execute("INSERT INTO ``Binary`` (``Name``, ``Data``) VALUES ('$SourceName', ?)", $BinaryRecord)

        $BinaryRecord.Close()

        $Database.Execute('CREATE TABLE `CustomAction` (`Action` CHAR(72) NOT NULL, `Type` SHORT NOT NULL, `Source` CHAR(72), `Target` CHAR(255), `ExtendedType` LONG  PRIMARY KEY `Action`)')

        $Database.Execute("INSERT INTO ``CustomAction`` (``Action``, ``Type``, ``Source``, ``Target``, ``ExtendedType``) VALUES ('$CustomActionName', $CustomActionTypeValue, '$SourceName', $TargetName, NULL)")

        # Create the corresponding sequence table: InstallExecuteSequence, AdminExecuteSequence, or AdvtExecuteSequence
        $Database.Execute("CREATE TABLE ``$SequenceTableName`` (``Action`` CHAR(72) NOT NULL, ``Condition`` CHAR(255), ``Sequence`` SHORT  PRIMARY KEY ``Action``)")

        $Database.Execute("INSERT INTO ``$SequenceTableName`` (``Action``, ``Condition``, ``Sequence``) VALUES ('$CustomActionName', NULL, $ActionSequenceNumber)")

        $Database.Dispose()

        $Hash = Get-FileHash -Path $MSIFilePath -Algorithm SHA256 -ErrorAction Stop | Select-Object -ExpandProperty Hash

        [PSCustomObject] @{
            FilePath = $MSIFilePath
            FileHash = $Hash
        }
    }

filter Get-ATHMSI {
    <#
    .SYNOPSIS

    Extracts the contents of an MSI file.

    Technique ID: T1218.007 (Signed Binary Proxy Execution: Msiexec)

    .DESCRIPTION

    Get-ATHMSI extracts the Summary Information Stream and the contents of the CustomActions table of an MSI file. Get-ATHMSI is designed for rapid validation of MSI files, research, and for analysis. It is not designed to extract the entirety of the contents of an MSI file.

    .PARAMETER FilePath

    Specifies the file path to the MSI file to be extracted.

    .INPUTS

    System.IO.FileInfo

    Get-ATHMSI accepts the output of Get-Item and Get-ChildItem over the pipeline when the output is a file.

    .OUTPUTS

    PSObject

    Outputs an object consisting of relevant MSI file details. The following object properties are populated:

    * FilePath - Specifies the full path to the generated MSI file
    * SummaryInfo - Consists of the contents of the Summary Information Stream
    * CustomActions - Parsed, interpreted, and extracted contents of the CustomActions table

    .EXAMPLE

    $MSIInfo = Get-ATHMSI -FilePath test.msi

    .EXAMPLE

    $MSIInfo = ls *.msi | Get-ATHMSI
    #>

        [CmdletBinding()]
        param (
            [Parameter(Mandatory, Position = 0, ValueFromPipelineByPropertyName)]
            [String]
            [ValidateNotNullOrEmpty()]
            [Alias('FullName')]
            $FilePath
        )

        $FullFilePath = Resolve-Path -Path $FilePath | Select-Object -ExpandProperty Path

        $TargetTypeTable = @{
            [Int] 1 = 'Dll'      # msidbCustomActionTypeDll
            [Int] 2 = 'Exe'      # msidbCustomActionTypeExe
            [Int] 3 = 'TextData' # msidbCustomActionTypeTextData
            [Int] 5 = 'JScript'  # msidbCustomActionTypeJScript
            [Int] 6 = 'VBScript' # msidbCustomActionTypeVBScript
            [Int] 7 = 'Install'  # msidbCustomActionTypeInstall
        }

        $SourceTypeTable = @{
            [Int] 0x00 = 'BinaryData' # msidbCustomActionTypeBinaryData
            [Int] 0x10 = 'SourceFile' # msidbCustomActionTypeSourceFile
            [Int] 0x20 = 'Directory'  # msidbCustomActionTypeDirectory
            [Int] 0x30 = 'Property'   # msidbCustomActionTypeProperty
        }


        try {
            $Database = New-Object -TypeName Microsoft.Deployment.WindowsInstaller.Database -ArgumentList $FullFilePath, ([Microsoft.Deployment.WindowsInstaller.DatabaseOpenMode]::ReadOnly)
        } catch {
            # Likely to throw an exception if another process has an open handle to an existing file with the same name. e.g. if you have the MSI open in Orca.
            throw $_
        }

        $SummaryInfo = [PSCustomObject] @{
            Title          = $Database.SummaryInfo.Title
            Subject        = $Database.SummaryInfo.Subject
            Author         = $Database.SummaryInfo.Author
            Keywords       = $Database.SummaryInfo.Keywords
            Comments       = $Database.SummaryInfo.Comments
            Template       = $Database.SummaryInfo.Template
            LastSavedBy    = $Database.SummaryInfo.LastSavedBy
            RevisionNumber = $Database.SummaryInfo.RevisionNumber
            CreatingApp    = $Database.SummaryInfo.CreatingApp
            LastPrintTime  = $Database.SummaryInfo.LastPrintTime
            CreateTime     = $Database.SummaryInfo.CreateTime
            LastSaveTime   = $Database.SummaryInfo.LastSaveTime
            CodePage       = $Database.SummaryInfo.CodePage
            PageCount      = $Database.SummaryInfo.PageCount
            WordCount      = $Database.SummaryInfo.WordCount
            CharacterCount = $Database.SummaryInfo.CharacterCount
            Security       = $Database.SummaryInfo.Security
        }

        $CustomActions = $null

        if ($Database.Tables['CustomAction']) {
            $CustomActionTableView = $Database.OpenView('SELECT `Action`, `Type`, `Source`, `Target` FROM `CustomAction`')
            $CustomActionTableView.Execute()

            if ($CustomActionTableView) {
                $CustomActions = New-Object System.Collections.Generic.List[System.Management.Automation.PSObject]

                $CurrentRow = $CustomActionTableView.Fetch()

                while ($CurrentRow) {
                    $Action = $CurrentRow.GetString(1)
                    $Type   = $CurrentRow.GetInteger(2)
                    $Source = $CurrentRow.GetString(3)
                    $Target = $CurrentRow.GetString(4)

                    $TargetType = $TargetTypeTable[$Type -band 0x0F]
                    $SourceType = $SourceTypeTable[$Type -band 0x30]

                    $OptionFlags = New-Object System.Collections.Generic.List[System.String]

                    if (($Type -band 0x0400)     -eq 0x0400) { $OptionFlags.Add('InScript')         # msidbCustomActionTypeInScript
                        if (($Type -band 0x0100) -eq 0x0100) { $OptionFlags.Add('Rollback')       } # msidbCustomActionTypeRollback
                        if (($Type -band 0x0200) -eq 0x0200) { $OptionFlags.Add('Commit')         } # msidbCustomActionTypeCommit
                    } else {
                        if (($Type -band 0x0100) -eq 0x0100) { $OptionFlags.Add('FirstSequence')  } # msidbCustomActionTypeFirstSequence
                        if (($Type -band 0x0200) -eq 0x0200) { $OptionFlags.Add('OncePerProcess') } # msidbCustomActionTypeOncePerProcess
                    }

                    if (($Type -band 0x0040) -eq 0x0040) { $OptionFlags.Add('Continue')       } # msidbCustomActionTypeContinue
                    if (($Type -band 0x0080) -eq 0x0080) { $OptionFlags.Add('Async')          } # msidbCustomActionTypeAsync
                    if (($Type -band 0x0300) -eq 0x0300) { $OptionFlags.Add('ClientRepeat')   } # msidbCustomActionTypeClientRepeat
                    if (($Type -band 0x0800) -eq 0x0800) { $OptionFlags.Add('NoImpersonate')  } # msidbCustomActionTypeNoImpersonate
                    if (($Type -band 0x1000) -eq 0x1000) { $OptionFlags.Add('64BitScript')    } # msidbCustomActionType64BitScript
                    if (($Type -band 0x2000) -eq 0x2000) { $OptionFlags.Add('HideTarget')     } # msidbCustomActionTypeHideTarget
                    if (($Type -band 0x4000) -eq 0x4000) { $OptionFlags.Add('TSAware')        } # msidbCustomActionTypeTSAware
                    if (($Type -band 0x8000) -eq 0x8000) { $OptionFlags.Add('PatchUninstall') } # msidbCustomActionTypePatchUninstall

                    $SourceContents = $null

                    # Attempt to extract source contents
                    if (($TargetType -eq 'JScript') -or ($TargetType -eq 'VBScript')) {
                        switch ($SourceType) {
                            'BinaryData' {
                                # "The Source field of the CustomAction table contains a key to the Binary table. The Data column in the Binary table contains the stream data."
                                $TableView = $Database.OpenView("SELECT ``Name``, ``Data`` FROM ``Binary`` WHERE ``Name`` = '$Source'")
                                $TableView.Execute()

                                if ($TableView) {
                                    $Row = $TableView.Fetch()

                                    $BinaryStream = $Row.GetStream('Data')
                                    $BinaryReader = New-Object -TypeName IO.BinaryReader -ArgumentList $BinaryStream
                                    $BinaryBytes = $BinaryReader.ReadBytes($BinaryStream.Length)

                                    $BinaryReader.Close()
                                    $BinaryStream.Close()

                                    $Row.Close()

                                    # VBScript and JScript content appears to have to be ASCII encoded to work properly
                                    $SourceContents = [Text.Encoding]::ASCII.GetString($BinaryBytes)

                                    $TableView.Close()
                                }
                            }

                            'SourceFile' {
                                # "The script is installed with the application during the current session. The Source field of the CustomAction table contains a key to the File table."
                                Write-Warning "Custom action `"$Action`" has a source file of `"$Source`". File extraction is not currently supported."
                            }

                            'Directory' {
                                # "JScript/VBScript text stored in the Target column of the CustomAction table."
                                $SourceContents = $Target
                            }

                            'Property' {
                                # "The Source field of the CustomAction table contains a property name or a key to the Property table for a property containing the script text."
                                $SourceContents = $Database.ExecutePropertyQuery($Source)
                            }
                        }
                    }

                    if (($TargetType -eq 'Exe') -or ($TargetType -eq 'Dll')) {
                        switch ($SourceType) {
                            'BinaryData' {
                                # "The Source field of the CustomAction table contains a key to the Binary table. The Data column in the Binary table contains the stream data."
                                $TableView = $Database.OpenView("SELECT ``Name``, ``Data`` FROM ``Binary`` WHERE ``Name`` = '$Source'")
                                $TableView.Execute()

                                if ($TableView) {
                                    $Row = $TableView.Fetch()

                                    $BinaryStream = $Row.GetStream('Data')
                                    $BinaryReader = New-Object -TypeName IO.BinaryReader -ArgumentList $BinaryStream
                                    $SourceContents = $BinaryReader.ReadBytes($BinaryStream.Length)

                                    $BinaryReader.Close()
                                    $BinaryStream.Close()

                                    $Row.Close()

                                    $TableView.Close()
                                }
                            }

                            'SourceFile' {
                                Write-Warning "Custom action `"$Action`" has a source file of `"$Source`". File extraction is not currently supported."
                            }
                        }
                    }

                    $CustomAction = [PSCustomObject] @{
                        TargetType     = $TargetType
                        SourceType     = $SourceType
                        Action         = $Action
                        Type           = "0x$($Type.ToString('X8'))"
                        Source         = $Source
                        Target         = $Target
                        OptionFlags    = $OptionFlags
                        SourceContents = $SourceContents
                    }

                    $CustomActions.Add($CustomAction)

                    $CurrentRow = $CustomActionTableView.Fetch()
                }

                $CustomActionTableView.Close()
            }
        }

        $Database.Close()

        [PSCustomObject] @{
            FilePath      = $FullFilePath
            SummaryInfo   = $SummaryInfo
            CustomActions = $CustomActions
        }
    }

function Invoke-ATHMSI {
    <#
    .SYNOPSIS
    Installs a MSI file and executes specified code.

    Technique ID: T1218.007 (Signed Binary Proxy Execution: Msiexec)

    .DESCRIPTION
    Invoke-ATHMSI serves to pass parameters to the various other modules to create and install a MSI file.

    .PARAMETER Exe
    Specifies that the generated MSI file will execute an embedded Exe file.

    .PARAMETER Dll
    Specifies that the generated MSI file will execute an embedded Dll file.

    .PARAMETER ExecutionType
    Specifies what type of installation execution the user wants to use to install the MSI file: Msiexec, COM, WMI, Win32API

    .PARAMETER MsiAction
    Specifies what type of intallation action the user wants to use when installing a MSI file: Install, Admin, Advertise

    .PARAMETER MsiExecFilePath
    Specifies an alternate file path for msiexec.

    .PARAMETER MsiFileName
    Specifies the MSI file name to be created.

    .PARAMETER MsiOutputDirectory
    Specifies the output directory for the generated MSI file. If -MsiOutputDirectory is not supplied, the MSI file will be generated in the current working directory.

    .PARAMETER CustomActionName
    Specifies the name of the custom action to run.

    .PARAMETER ScriptEngine
    Specifies the Windows Script Host engine to use in the generated MSI, VBScript or JScript.

    .PARAMETER ScriptContent
    An optional parameter that allows the passing of script content for a VBScript or JScript CustomAction.

    .PARAMETER ExeBytes
    Specifies a byte array consisting of an EXE that will be emdebbed in the MSI and execute.

    .PARAMETER ExeArguments
    Specifies optional command-line arguments to supply to the embedded EXE.

    .PARAMETER DllBytes
    Specifies a byte array consisting of an DLL that will be emdebbed in the MSI and execute.

    .PARAMETER DllExportFunction
    Specifies the export function within the DLL that will be called within the MSI.

    .PARAMETER Architecture
    Specifies the platform that the MSI is designed to support x86 (Intel) or x64.

    .PARAMETER DLLArchitecture
    Specifies the platform that the DLL is designed to support x86 or x64.

    .PARAMETER DeleteMSI
    Switch parameter that will remove the MSI file after execution.

    .PARAMETER TestGuid
    Optionally, specify a test GUID value to use to override the generated test GUID behavior.

    .OUTPUTS

    PSObject

    Outputs an object consisting of relevant MSI file details. The following object properties are populated:

    * TechniqueID - Specifies the relevant MITRE ATT&CK Technique ID.
    * TestSuccess - Specifies if the MSI was successfully installed.
    * TestGuid - Specifies the test GUID that was used for the test.
    * TestCommand - Specifies the command-line arguments supplied to Invoke-ATHMSI.
    * ExecutionType - Specifies the method by which the MSI file executes.
    * MsiAction - Specifies the type of installation action the user wanted to use for installation.
    * MsiCustomAction - Specifies what type of code is to launch during MSI installation.
    * MsiScriptEngine - Specifies the scripting engine used to launch the embedded MSI script code.
    * MsiScriptContent - Specifies the VBScript or JScript content that was embedded and executed in the generated MSI file.
    * MsiFilePath - Specifies the full path to the generated/executed MSI file.
    * MsiFileHash - Specifies the SHA256 hash of the generated/executed MSI file.
    * MsiExecProcessId - The process ID of the Msiexec executable that was launched.
    * MsiExecProcessCommandLine - The command line of the Msiexec executable that was launched.
    * RunnerProcessId - The process ID of the Msiexec process that executed the generated MSI file.
    * RunnerProcessName - The command line of the Msiexec process that executed the generated MSI file.
    * RunnerChildProcessId - The process ID of the child process that spawned as the result of the MSI executing.
    * RunnerChildProcessName - The process name of the child process that spawned as the result of the MSI executing.
    * RunnerChildCommandLine - The command line of the child process that spawned as the result of the MSI executing.

    .EXAMPLE

    Invoke-ATHMSI

    .EXAMPLE

    Invoke-ATHMSI -ExecutionType COM

    .EXAMPLE

    Invoke-ATHMSI -Exe -ExecutionType WMI

    .EXAMPLE

    Invoke-ATHMSI -Dll -ExecutionType COM -MsiAction Install

    .EXAMPLE

    Invoke-ATHMSI -Dll -ExecutionType COM -MsiAction Install -DeleteMsi

    .EXAMPLE

    Invoke-ATHMSI -Dll -DLLArchitecture x64 -ExecutionType COM -MsiAction Install

    .EXAMPLE
    
    Invoke-ATHMSI -ExecutionType Win32API -MsiAction Advertise

    .EXAMPLE

    Invoke-ATHMSI -MsiFileName VBscript.msi -ScriptEngine VBscript -ScriptContent 'CreateObject("WScript.Shell").Popup("Hello, VBScript!")'

    #>

    [CmdletBinding(DefaultParameterSetName = 'Script')]
    param (
        [Parameter(Mandatory, ParameterSetName = 'Exe')]
        [Switch]
        $Exe,

        [Parameter(Mandatory, ParameterSetName = 'Dll')]
        [Switch]
        $Dll,

        [String]
        [ValidateSet('Msiexec', 'COM', 'WMI', 'Win32API')]
        $ExecutionType = 'Msiexec',

        [String]
        [ValidateSet('Install', 'Admin', 'Advertise')]
        $MsiAction = 'Install',

        [String]
        $MsiExecFilePath = "$([Environment]::SystemDirectory)\msiexec.exe",

        [String]
        $MsiFileName = 'Test.msi',

        [String]
        $MsiOutputDirectory,

        [String]
        [ValidateNotNullOrEmpty()]
        $CustomActionName = 'RunMe',

        [Parameter(ParameterSetName = 'Script')]
        [String]
        [ValidateSet('JScript', 'VBScript')]
        $ScriptEngine = 'VBScript',

        [Parameter(ParameterSetName = 'Script')]
        [String]
        $ScriptContent,

        [Parameter(ParameterSetName = 'Exe')]
        [Byte[]]
        $ExeBytes,

        [Parameter(ParameterSetName = 'Exe')]
        [String]
        $ExeArguments,

        [Parameter(ParameterSetName = 'Dll')]
        [Byte[]]
        $DllBytes,

        [Parameter(ParameterSetName = 'Dll')]
        [String]
        $DllExportFunction = 'CustomAction',

        [String]
        [ValidateSet('Intel', 'x64')]
        $Architecture = 'Intel',

        [Parameter(ParameterSetName = 'Dll')]
        [String]
        [ValidateSet('x86', 'x64')]
        $DLLArchitecture = 'x86',

        [Switch]
        $DeleteMsi,

        [Guid]
        $TestGuid = (New-Guid)
    )

    $ScriptEngineResult = $null

    # Drop the generated MSI file to the current directory if -MsiOutputDirectory is not specified.
    $OutputDirectory = $PWD
    if ($MsiOutputDirectory) { $OutputDirectory = $MsiOutputDirectory }

    switch ($PSCmdlet.ParameterSetName) {
        'Script' {
            $ScriptEngineResult = $ScriptEngine

            switch ($ScriptEngine) {
                'VBScript' {
                    if(-not ($PSBoundParameters.ContainsKey('ScriptContent'))) {
                        $ChildProcessCommand = "powershell.exe -nop -Command Write-Host $TestGuid;Start-Sleep -Seconds 5; exit"
                        #Setting default VBScript if ScriptContent is not supplied 
                        $ScriptContent = @"
Set objShell = CreateObject("Wscript.Shell")
objShell.Run "$ChildProcessCommand", 0, true
window.close()
"@
                    }

                    $MSIArguments = @{
                        FileName = $MsiFileName
                        ElevatedPrivilegesNotRequired = $True
                        OutputDirectory = $OutputDirectory
                        ScriptContent = $ScriptContent
                        ScriptEngine = $ScriptEngine
                        CustomActionName = $CustomActionName
                        ActionToImplement = $MsiAction
                        Architecture = $Architecture
                        ReadOnlyEnforced = $True
                    }
                }

                'JScript' {
                    $ScriptEngineResult = $ScriptEngine

                    if(-not ($PSBoundParameters.ContainsKey('ScriptContent'))) {
                        $ChildProcessCommand = "powershell.exe -nop -Command Write-Host $TestGuid;Start-Sleep -Seconds 3; exit"
                        #Setting default JScript if ScriptContent is not supplied 
                        $ScriptContent  = @"
var objShell = new ActiveXObject('Wscript.Shell');
objShell.Run("$ChildProcessCommand", 0, true);
window.close();
"@
                    }

                    $MSIArguments = @{
                        FileName = $MsiFileName
                        ElevatedPrivilegesNotRequired = $True
                        OutputDirectory = $OutputDirectory
                        ScriptContent = $ScriptContent
                        ScriptEngine = $ScriptEngine
                        CustomActionName = $CustomActionName
                        ActionToImplement = $MsiAction
                        Architecture = $Architecture
                        ReadOnlyEnforced = $True
                    }
                }
            }
        }

        'Exe' {
            if(($PSCmdlet.ParameterSetName -eq 'Exe') -and (-not ($PSBoundParameters.ContainsKey('ExeBytes')))) {
                # Generate a template test executable that only prints its first command-line argument (it will be the test guid) and sleep for 3 seconds to allow for the WMI event to trigger.
                Add-Type -OutputAssembly PrintArg.exe -TypeDefinition @'
                    public class Test {
                        public static void Main(string[] args) {
                            System.Console.WriteLine(args[0]);
                            System.Threading.Thread.Sleep(3000);
                        }
                    }
'@

                $ExeBytes = [IO.File]::ReadAllBytes("$PWD\PrintArg.exe")
            }

            if(($PSCmdlet.ParameterSetName -eq 'Exe') -and (-not ($PSBoundParameters.ContainsKey('ExeArguments')))) { $ExeArguments  = "$TestGuid" }

            $MSIArguments = @{
                FileName = $MsiFileName
                ElevatedPrivilegesNotRequired = $True
                OutputDirectory = $OutputDirectory
                CustomActionName = $CustomActionName
                ExeBytes = $ExeBytes
                ExeArguments = $ExeArguments
                ActionToImplement = $MsiAction
                Architecture = $Architecture
                ReadOnlyEnforced = $True
            }
        }

        'Dll' {
            # The following template code launches a PowerShell child process with the following command-line:
            # powershell.exe -nop -Command Write-Host AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA; Start-Sleep -Seconds 2; exit
            # The AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA guid is replaced dynamically based on $TestGuid and is used to validate the successful execution of the injected code in a safe fashion.

            # SHA256 Hash of 64 bit: ddb61d9f52508bd7d23b07ffb2ef3cd3af0554ed0bab250c58791dce2ef0242d
            # VirusTotal: https://www.virustotal.com/gui/file/ddb61d9f52508bd7d23b07ffb2ef3cd3af0554ed0bab250c58791dce2ef0242d/community

            # SHA256 Hash of 32 bit: 1ddd2674e556c57193cfede2382b8892d7f3010b44c510804bb7cc07397c5d1c
            # VirusTotal: https://www.virustotal.com/gui/file/1ddd2674e556c57193cfede2382b8892d7f3010b44c510804bb7cc07397c5d1c/community

            # The code below was generated with the following C code that was compiled in a position-indepedent fashion:
            <#
                #include <windows.h>
                #include <msi.h>
                #include <Msiquery.h>
                #pragma comment(lib, "msi.lib")

                UINT __stdcall CustomAction(MSIHANDLE hInstall) {
                    PROCESS_INFORMATION processInformation;
                    STARTUPINFO startupInfo;
                    BOOL creationResult;

                    WCHAR szCmdline[] = L"powershell.exe -nop -Command Write-Host AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA; Start-Sleep -Seconds 3; exit";

                    ZeroMemory(&processInformation, sizeof(processInformation));
                    ZeroMemory(&startupInfo, sizeof(startupInfo));
                    startupInfo.cb = sizeof(startupInfo);
                    creationResult = CreateProcess(
                        NULL,
                        szCmdline,
                        NULL,
                        NULL,
                        FALSE,
                        CREATE_NO_WINDOW,
                        NULL,
                        NULL,
                        &startupInfo,
                        &processInformation);

                    return 0;
                }

                BOOL APIENTRY DllMain( HMODULE hModule,
                                    DWORD  ul_reason_for_call,
                                    LPVOID lpReserved
                                    )
                {
                    switch (ul_reason_for_call)
                    {
                    case DLL_PROCESS_ATTACH:
                    case DLL_THREAD_ATTACH:
                    case DLL_THREAD_DETACH:
                    case DLL_PROCESS_DETACH:
                        break;
                    }
                    return TRUE;
                }
            #>

            if(-not ($PSBoundParameters.ContainsKey('DllBytes'))) {
                if($DLLArchitecture -eq "x64") {
                    $Base64String = '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
    '
                    $DLLBytes = [System.Convert]::FromBase64String($Base64String)


                    [Int[]] $GUIDCharOffsets = @(
                        0x15D0,0x15D2,0x15D4,0x15D6,0x15D8,0x15DA,0x15DC,0x15DE,
                        0x15E0,0x15E2,0x15E4,0x15E6,0x15E8,0x15EA,0x15EC,0x15EE,
                        0x15F0,0x15F2,0x15F4,0x15F6,0x15F8,0x15FA,0x15FC,0x15FE,
                        0x1600,0x1602,0x1604,0x1606,0x1608,0x160A,0x160C,0x160E,
                        0x1610,0x1612,0x1614,0x1616
                    )
                } else {
                    $Base64String = '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ZWF0ZVByb2Nlc3NXAABLRVJORUwzMi5kbGwAACUAX19zdGRfdHlwZV9pbmZvX2Rlc3Ryb3lfbGlzdAAASABtZW1zZXQAADUAX2V4Y2VwdF9oYW5kbGVyNF9jb21tb24AVkNSVU5USU1FMTQwLmRsbAAAOABfaW5pdHRlcm0AOQBfaW5pdHRlcm1fZQBBAF9zZWhfZmlsdGVyX2RsbAAZAF9jb25maWd1cmVfbmFycm93X2FyZ3YAADUAX2luaXRpYWxpemVfbmFycm93X2Vudmlyb25tZW50AAA2AF9pbml0aWFsaXplX29uZXhpdF90YWJsZQAAJABfZXhlY3V0ZV9vbmV4aXRfdGFibGUAFwBfY2V4aXQAAGFwaS1tcy13aW4tY3J0LXJ1bnRpbWUtbDEtMS0wLmRsbADHBVVuaGFuZGxlZEV4Y2VwdGlvbkZpbHRlcgAAhwVTZXRVbmhhbmRsZWRFeGNlcHRpb25GaWx0ZXIAJAJHZXRDdXJyZW50UHJvY2VzcwCmBVRlcm1pbmF0ZVByb2Nlc3MAAJsDSXNQcm9jZXNzb3JGZWF0dXJlUHJlc2VudABhBFF1ZXJ5UGVyZm9ybWFuY2VDb3VudGVyACUCR2V0Q3VycmVudFByb2Nlc3NJZAApAkdldEN1cnJlbnRUaHJlYWRJZAAA+gJHZXRTeXN0ZW1UaW1lQXNGaWxlVGltZQB4A0luaXRpYWxpemVTTGlzdEhlYWQAlANJc0RlYnVnZ2VyUHJlc2VudAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAALEZv0RO5kC7/////wAAAAABAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQEBAQEBAQEBAQEBAQEBAQEBAQEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAGAAAABgAAIAAAAAAAAAAAAAAAAAAAAEAAgAAADAAAIAAAAAAAAAAAAAAAAAAAAEACQQAAEgAAABgUAAAkQAAAAAAAAAAAAAAAAAAAAAAAAA8P3htbCB2ZXJzaW9uPScxLjAnIGVuY29kaW5nPSdVVEYtOCcgc3RhbmRhbG9uZT0neWVzJz8+DQo8YXNzZW1ibHkgeG1sbnM9J3VybjpzY2hlbWFzLW1pY3Jvc29mdC1jb206YXNtLnYxJyBtYW5pZmVzdFZlcnNpb249JzEuMCc+DQo8L2Fzc2VtYmx5Pg0KAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAkAQAACjAWMC8wrzDaMDwxaDF1MZYxmzG0MbkxxjEIMhAyQzJNMlsydjKOMvMyBTPEMwE0GzRQNFk0ZDRrNH40jDSSNJg0njSkNKo0sTS4NL80xjTNNNQ02zTjNOs08zT/NAg1DTUTNR01JzU3NUc1VzVgNX81jjWXNaQ1ujX0Nf01BDYKNhA2HDYiNpk2PTddN443wTfnN/Y3DTgTOBk4HzglOCs4MThGOFs4YjhoOHo4hDjsOPk4HTkwOfw5HDomOj86SDpNOmA6dDp5Oow6oTq+OgA7BTscOyY7LzvWO9875zsiPCw8NTw+PFM8XDyLPJQ8nTyrPLQ81jzdPPA8+jwAPQY9DD0SPRg9Hj0kPSo9MD02PUY90j3bPeE9AAAAIAAAKAAAAGgwlDCYMOwx8DH4MVAyaDIYNTg1RDVcNWA1fDWANQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
'
                    $DLLBytes = [System.Convert]::FromBase64String($Base64String)

                    [Int[]] $GUIDCharOffsets = @(
                        0x12F0,0x12F2,0x12F4,0x12F6,0x12F8,0x12FA,0x12FC,0x12FE,
                        0x1300,0x1302,0x1304,0x1306,0x1308,0x130A,0x130C,0x130E,
                        0x1310,0x1312,0x1314,0x1316,0x1318,0x131A,0x131C,0x131E,
                        0x1320,0x1322,0x1324,0x1326,0x1328,0x132A,0x132C,0x132E,
                        0x1330,0x1332,0x1334,0x1336
                    )
                }

                [Byte[]] $TestGuidChars = [Text.Encoding]::ASCII.GetBytes($TestGuid.Guid)

                for ($i = 0; $i -lt $GUIDCharOffsets.Length; $i++) {
                    $DLLBytes[([Int] $GUIDCharOffsets[$i])] = $TestGuidChars[$i]
                }

                $MSIArguments = @{
                    FileName = $MsiFileName
                    ElevatedPrivilegesNotRequired = $True
                    OutputDirectory = $OutputDirectory
                    CustomActionName = $CustomActionName
                    ActionToImplement = $MsiAction
                    DllBytes = $DllBytes
                    DllExportFunction = $DllExportFunction
                    Architecture = $Architecture
                    ReadOnlyEnforced = $True
                }
            }
        }
    }

    $MSI = New-ATHMSI @MSIArguments

    if (-not $MSI) { return }

    if (Test-Path -Path "$PWD\PrintArg.exe") {
        # Remove the generated template executable
        Remove-Item -Path "$PWD\PrintArg.exe" -ErrorAction SilentlyContinue
    }

    # The full path to the generated MSI file.
    $FilePath = Resolve-Path $MSI.FilePath

    $PerformWMIEventing = $True
    # Do not perform WMI eventing if user supplies their own custom executable content.
    if ($PSBoundParameters.ContainsKey('ScriptContent') -or $PSBoundParameters.ContainsKey('ExeBytes') -or $PSBoundParameters.ContainsKey('DllBytes')) { $PerformWMIEventing = $False }

    if ($PerformWMIEventing) {
        # Cleaning up any lingering events
        Get-EventSubscriber -SourceIdentifier 'ProcessSpawned' -ErrorAction SilentlyContinue | Unregister-Event

        $WMIEventQuery = "SELECT * FROM __InstanceCreationEvent WITHIN 0.1 WHERE TargetInstance ISA 'Win32_Process' AND TargetInstance.CommandLine LIKE '%$($TestGuid)%'"

        $null = Register-CimIndicationEvent -SourceIdentifier 'ProcessSpawned' -Query $WMIEventQuery -MaxTriggerCount 1
    }

    $INSTALLUILEVEL_NONE = 2 # Completely silent installation.

    switch ($ExecutionType) {
        'Msiexec' {
            $MSIExecCommandLine = $null
            $MsiExecResolvedPath = Resolve-Path $MsiExecFilePath
            $MSIExecCommandLine = "`"$MsiExecResolvedPath`""

            switch ($MsiAction) {
                'Install'   { $MSIExecCommandLine += " /i $FilePath /qn" }
                'Admin'     { $MSIExecCommandLine += " /a $FilePath /qn" }
                'Advertise' { $MSIExecCommandLine += " /j $FilePath /qn" }
            }

            $ProcessStartup = New-CimInstance -ClassName Win32_ProcessStartup -ClientOnly
            $ProcessStartupInstance = Get-CimInstance -InputObject $ProcessStartup
            $ProcessStartupInstance.ShowWindow = [UInt16] 0 # Hide the window
            $ProcStartResult = Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{ CommandLine = $MSIExecCommandLine; ProcessStartupInformation = $ProcessStartupInstance }
            $MsiexecProcessId = $ProcStartResult.ProcessId
            $MsiexecProcess = Get-CimInstance -ClassName 'Win32_Process' -Filter "ProcessId = $MsiexecProcessId" -Property 'CommandLine'
            $MsiexecProcessCommandLine = $MsiexecProcess.CommandLine
        }

        'COM' {
            $Installer = New-Object -ComObject WindowsInstaller.Installer
            $Installer.UILevel = $INSTALLUILEVEL_NONE # msiUILevelNone - Silent installation

            switch ($MsiAction) {
                'Install'   { $Installer.InstallProduct("$FilePath") }
                'Admin'     { $Installer.InstallProduct("$FilePath", 'ACTION=ADMIN') }
                'Advertise' { $Installer.AdvertiseProduct("$FilePath", 0) }
            }
        }

        'WMI' {
            switch ($MsiAction) {
                'Install'   { $null = Invoke-CimMethod -ClassName Win32_Product -MethodName Install -Arguments @{ PackageLocation = "$FilePath"; Options = "UILevel=$INSTALLUILEVEL_NONE" } }
                'Admin'     { $null = Invoke-CimMethod -ClassName Win32_Product -MethodName Admin -Arguments @{ PackageLocation = "$FilePath"; Options = "UILevel=$INSTALLUILEVEL_NONE" } }
                'Advertise' { $null = Invoke-CimMethod -ClassName Win32_Product -MethodName Advertise -Arguments @{ PackageLocation = "$FilePath"; Options = "UILevel=$INSTALLUILEVEL_NONE" } }
            }
        }

        'Win32API' {
            if (-not ('AtomicTestHarnesses_T1218_007.ProcessNativeMethods' -as [Type])) {
                Add-Type -TypeDefinition @'
                    using System;
                    using System.Diagnostics;
                    using System.Runtime.InteropServices;

                    namespace AtomicTestHarnesses_T1218_007 {
                        public static class ProcessNativeMethods {
                            [DllImport("msi.dll", CharSet=CharSet.Auto)]
                            public static extern int MsiInstallProduct(string PackagePath, string CommandLine);

                            [DllImport("msi.dll", CharSet=CharSet.Auto)]
                            public static extern int MsiAdvertiseProduct(string PackagePath, IntPtr ScriptfilePath, IntPtr Transforms, short Language);

                            [DllImport("msi.dll")]
                            public static extern int MsiSetInternalUI(int dwUILevel, IntPtr phWnd);
                        }
                    }
'@
            }

            switch ($MsiAction) {
                'Install' {
                    $null = [AtomicTestHarnesses_T1218_007.ProcessNativeMethods]::MsiSetInternalUI($INSTALLUILEVEL_NONE, [IntPtr]::Zero)
                    $null = [AtomicTestHarnesses_T1218_007.ProcessNativeMethods]::MsiInstallProduct("$FilePath", '')
                }

                'Admin' {
                    $null = [AtomicTestHarnesses_T1218_007.ProcessNativeMethods]::MsiSetInternalUI($INSTALLUILEVEL_NONE, [IntPtr]::Zero)
                    $null = [AtomicTestHarnesses_T1218_007.ProcessNativeMethods]::MsiInstallProduct("$FilePath", 'ACTION=ADMIN')
                }

                'Advertise' {
                    $null = [AtomicTestHarnesses_T1218_007.ProcessNativeMethods]::MsiSetInternalUI($INSTALLUILEVEL_NONE, [IntPtr]::Zero)
                    $null = [AtomicTestHarnesses_T1218_007.ProcessNativeMethods]::MsiAdvertiseProduct("$FilePath", [IntPtr]::Zero, [IntPtr]::Zero, 0)
                }
            }
        }
    }

    $ParentProcessId = $null
    $ParentProcessName = $null
    $ChildProcessId = $null
    $ChildProcessCommandLine = $null
    $ChildProcessName = $null

    if ($PerformWMIEventing) {
        $ChildProcSpawnedEvent = Wait-Event -SourceIdentifier 'ProcessSpawned' -Timeout 5 | Select-Object -First 1

        $ChildProcInfo = $null

        if ($ChildProcSpawnedEvent) {
            $ChildProcInfo = $ChildProcSpawnedEvent.SourceEventArgs.NewEvent.TargetInstance

            $ParentProcessName = Get-CimInstance -ClassName 'Win32_Process' -Filter "ProcessId = $($ChildProcInfo.ParentProcessId)" -Property 'Name' | Select-Object -ExpandProperty Name

            $TestSuccess             = $true
            $ChildProcessCommandLine = $ChildProcInfo.CommandLine
            $ChildProcessId          = $ChildProcInfo.ProcessId
            $ChildProcessName        = $ChildProcInfo.Name
            $ParentProcessId         = $ChildProcInfo.ParentProcessId
            $ParentProcessName       = $ParentProcessName

            Wait-Process -Id $ChildProcInfo.ProcessId -Timeout 10 -ErrorAction SilentlyContinue
        } else {
            Write-Error 'Template child process failed to launch or WMI failed to detect it launch.'
        }

        Get-Event -SourceIdentifier 'ProcessSpawned' -ErrorAction SilentlyContinue | Remove-Event
        Unregister-Event -SourceIdentifier 'ProcessSpawned' -ErrorAction SilentlyContinue
    }

    [PSCustomObject] @{
        TechniqueID                   = 'T1218.007'
        TestSuccess                   = $TestSuccess
        TestGuid                      = $TestGuid
        TestCommand                   = $MyInvocation.Line
        ExecutionType                 = $ExecutionType
        MsiAction                     = $MsiAction
        MsiCustomAction               = $PSCmdlet.ParameterSetName
        MsiScriptEngine               = $ScriptEngineResult
        MsiScriptContent              = $ScriptContent
        MsiFilePath                   = $FilePath
        MsiFileHash                   = $MSI.FileHash
        MsiExecProcessId              = $MsiexecProcessId
        MsiExecProcessCommandLine     = $MsiexecProcessCommandLine
        RunnerProcessId               = $ParentProcessId
        RunnerProcessName             = $ParentProcessName
        RunnerChildProcessId          = $ChildProcessId
        RunnerChildProcessName        = $ChildProcessName
        RunnerChildProcessCommandLine = $ChildProcessCommandLine
    }

    if($DeleteMsi) {
        $null = Remove-Item $FilePath -Force -ErrorAction SilentlyContinue
    }
}