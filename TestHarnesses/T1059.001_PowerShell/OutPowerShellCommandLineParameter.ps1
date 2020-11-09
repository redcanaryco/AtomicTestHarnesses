function Out-ATHPowerShellCommandLineParameter {
<#
.SYNOPSIS

A powershell.exe command-line generator.

Technique ID: T1059.001 (Command and Scripting Interpreter: PowerShell)

.DESCRIPTION

Out-ATHPowerShellCommandLineParameter helps to generate powershell.exe command-line invocations based on the set of all possible ways in which PowerShell code can be supplied at the command-line.

Many detections rely upon the extraction and interpretation of PowerShell code supplied at the command-line to powershell.exe. There are many different supported ways to supply PowerShell code at the command-line and Out-ATHPowerShellCommandLineParameter can generate them all for the purposes of validating powershell.exe detection coverage.

Note: PowerShell being a very broad technique, note that this test harness does not constitute full coverage for the technique. The specific scope of this test harness is as follows:

* powershell.exe command-line parameter variations where PowerShell code is explicitly supplied in-line at the command-line.

Technique variations (non-exhaustive list) that fall outside the scope of this test harness:

* A script file supplied via the command-line. For example, using the -File parameter.
* Malicious PowerShell code executed by installing a malicious profile and executing powershell.exe with no arguments.
* The use of command-line parameters that are not directly related to the execution of inline PowerShell code.

.PARAMETER CommandParamVariation

Specifies one of the support "Command" parameter variations. The following case-insensitive options are supported by powershell.exe:

C, Co, Com, Comm, Comma, Comman, Command

.PARAMETER EncodedCommandParamVariation

Specifies one of the support "EncodedCommand" parameter variations. The following case-insensitive options are supported by powershell.exe:

EC, E, En, Enc, Enco, Encod, Encode, Encoded, EncodedC, EncodedCo, EncodedCom, EncodedComm, EncodedComma, EncodedComman, EncodedCommand

.PARAMETER CommandLineSwitchType

Specifies the command-line switch type to use. powershell.exe supports the following switches:

Hyphen, EnDash, EmDash, HorizontalBar, ForwardSlash

.PARAMETER UseEncodedArguments

Specifies that "EncodedArguments" will be supplied to the command-line. powershell.exe supports an undocumented feature where arguments can be supplied to script code in the form of a serialized ArrayList object that is then base64-encoded.

.PARAMETER EncodedArgumentsParamVariation

Specifies one of the support "EncodedArguments" parameter variations. The following case-insensitive options are supported by powershell.exe:

EA, EncodedA, EncodedAr, EncodedArg, EncodedArgu, EncodedArgum, EncodedArgume, EncodedArgume, EncodedArgumen, EncodedArgument, EncodedArguments

.PARAMETER Arguments

Specifies one or more arguments to supply to your PowerShell code. If -UseEncodedArguments is specified, but -Arguments is not specified, a generated GUID value will serve as the argument. In PowerShell code, these arguments are received via the $args built-in variable: e.g. $args[0], $args[1], etc.

.PARAMETER GenerateAllParamVariations

Specifies that all command-line parameters should be generated. This must be used in combination with either -UseCommandParam or -UseEncodedCommandParam.

Note: Mixed-case variations are not generated. powershell.exe interprets command-line parameters in a case-insensitive fashion so ensure that any detection logic, accordingly, is not case-sensitive.

.PARAMETER UseCommandParam

Specifies that "Command" parameter variations are to be generated.

.PARAMETER UseEncodedCommandParam

Specifies that "EncodedCommand" parameter variations are to be generated.

.PARAMETER ScriptBlock

Optionally, specify a PowerShell scriptblock to execute. If -ScriptBlock is not specified, a default ScriptBlock calling Write-Host on a generated GUID will be used.

.PARAMETER TestGuid

Optionally, specify a test GUID value to use to override the generated test GUID behavior.

.PARAMETER Execute

Specifies that the generated command line should be executed. The generated command-line will be spawned with the WMI Win32_Process Create method.

.OUTPUTS

String

When the -Execute switch is not supplied, Out-ATHPowerShellCommandLineParameter returns a string representation of the generated powershell.exe invocation.

PSObject

When the -Execute switch is specified, Out-ATHPowerShellCommandLineParameter returns an object consisting of relevant execution details. The following object properties may be populated:

* TechniqueID - Specifies the relevant MITRE ATT&CK Technique ID.
* TestSuccess - Indicates that the powershell.exe process successfully spawned.
* TestGuid - Specifies the test GUID that was used for the test. This property will not be populated when arguments are manually supplied.
* ProcessId - Specifies the process ID of the spawned powershell.exe process.
* CommandLine - Specifies the command-line of the spawned powershell.exe process.

.EXAMPLE

Out-ATHPowerShellCommandLineParameter

Generates a powershell.exe command-line string using "C".

.EXAMPLE

Out-ATHPowerShellCommandLineParameter -CommandParamVariation Comman -Execute

Executes a powershell.exe command-line using "Comman" as the specified execution parameter.

.EXAMPLE

Out-ATHPowerShellCommandLineParameter -CommandParamVariation Command -CommandLineSwitchType EmDash -Execute

Executes a powershell.exe command-line using "Command" as the specified execution parameter and an EmDash as the switch type.

.EXAMPLE

Out-ATHPowerShellCommandLineParameter -CommandParamVariation Command -CommandLineSwitchType HorizontalBar -ScriptBlock { Write-Host Foo } -Execute

Executes a powershell.exe command-line using "Command" as the specified execution parameter, a HorizontalBar as the switch type, and specifies a PowerShell scriptblock to execute versus the default scriptblock.

.EXAMPLE

Out-ATHPowerShellCommandLineParameter -CommandParamVariation C -UseEncodedArguments

Generates a powershell.exe command-line string using "C", passing the embedded PowerShell code encoded arguments.

.EXAMPLE

Out-ATHPowerShellCommandLineParameter -EncodedCommandParamVariation EC -UseEncodedArguments -EncodedArgumentsParamVariation EncodedA

Generates a powershell.exe command-line string using "EC", passing the embedded PowerShell code encoded arguments with the "EncodedA" parameter.

.EXAMPLE

Out-ATHPowerShellCommandLineParameter -EncodedCommandParamVariation Enc -ScriptBlock { Write-Host $args[0] $args[1] } -UseEncodedArguments -Arguments 'foo', 'bar' -Execute

Executes an encoded command that receives custom arguments via encoded arguments.

.EXAMPLE

Out-ATHPowerShellCommandLineParameter -CommandParamVariation Comma -TestGuid 11111111-1111-1111-1111-111111111111 -Execute

Executes a "Command" variation using the specified test GUID.

.EXAMPLE

Out-ATHPowerShellCommandLineParameter -GenerateAllParamVariations -UseCommandParam -CommandLineSwitchType Hyphen

Generate all "Command" variations using hyphen as the command-line switch type.

.EXAMPLE

Out-ATHPowerShellCommandLineParameter -GenerateAllParamVariations -UseCommandParam -UseEncodedArguments -CommandLineSwitchType Hyphen -Execute

Generate and execute all "Command" variations using hyphen as the command-line switch type.

.EXAMPLE

Out-ATHPowerShellCommandLineParameter -GenerateAllParamVariations -UseEncodedCommandParam -CommandLineSwitchType ForwardSlash

Generate all "EncodedCommand" variations using forward slash as the command-line switch type.
#>

    [CmdletBinding(DefaultParameterSetName = 'Command')]
    param (
        [Parameter(ParameterSetName = 'Command')]
        [Parameter(ParameterSetName = 'UseEncodedArgumentsCommand')]
        [String]
        [ValidateSet('C', 'Co', 'Com', 'Comm', 'Comma', 'Comman', 'Command')]
        $CommandParamVariation = 'C',

        [Parameter(ParameterSetName = 'EncodedCommand')]
        [Parameter(ParameterSetName = 'UseEncodedArgumentsEncodedCommand')]
        [String]
        [ValidateSet('EC', 'E', 'En', 'Enc', 'Enco', 'Encod', 'Encode', 'Encoded', 'EncodedC', 'EncodedCo', 'EncodedCom', 'EncodedComm', 'EncodedComma', 'EncodedComman', 'EncodedCommand')]
        $EncodedCommandParamVariation = 'EC',

        [String]
        [ValidateSet('Hyphen', 'EnDash', 'EmDash', 'HorizontalBar', 'ForwardSlash')]
        $CommandLineSwitchType = 'Hyphen',

        [Parameter(Mandatory, ParameterSetName = 'UseEncodedArgumentsCommand')]
        [Parameter(Mandatory, ParameterSetName = 'UseEncodedArgumentsEncodedCommand')]
        [Parameter(ParameterSetName = 'CommandAllVariations')]
        [Parameter(ParameterSetName = 'EncodedCommandAllVariations')]
        [Switch]
        $UseEncodedArguments,

        [Parameter(ParameterSetName = 'UseEncodedArgumentsCommand')]
        [Parameter(ParameterSetName = 'UseEncodedArgumentsEncodedCommand')]
        [String]
        [ValidateSet('EA', 'EncodedA', 'EncodedAr', 'EncodedArg', 'EncodedArgu', 'EncodedArgum', 'EncodedArgume', 'EncodedArgume', 'EncodedArgumen', 'EncodedArgument', 'EncodedArguments')]
        $EncodedArgumentsParamVariation = 'EA',

        [Parameter(ParameterSetName = 'UseEncodedArgumentsCommand')]
        [Parameter(ParameterSetName = 'UseEncodedArgumentsEncodedCommand')]
        [String[]]
        $Arguments,

        [Parameter(Mandatory, ParameterSetName = 'CommandAllVariations')]
        [Parameter(Mandatory, ParameterSetName = 'EncodedCommandAllVariations')]
        [Switch]
        $GenerateAllParamVariations,

        [Parameter(Mandatory, ParameterSetName = 'CommandAllVariations')]
        [Switch]
        $UseCommandParam,

        [Parameter(Mandatory, ParameterSetName = 'EncodedCommandAllVariations')]
        [Switch]
        $UseEncodedCommandParam,

        [ScriptBlock]
        $ScriptBlock,

        [Guid]
        $TestGuid = (New-Guid),

        [Switch]
        $Execute
    )

    function New-EncodedArgument {
        [CmdletBinding()]
        [OutputType([String])]
        param (
            [String[]]
            $Arguments
        )

        $ArgumentList = New-Object -TypeName System.Collections.ArrayList

        foreach ($Argument in $Arguments) { $null = $ArgumentList.Add($Argument) }

        $TempCliXmlFile = New-TemporaryFile

        # Save the serialized ArrayList object to disk.
        Export-Clixml -Path $TempCliXmlFile.FullName -InputObject $ArgumentList

        # Read the contents of the serialized ArrayList object
        $CliXmlText = Get-Content -Path $TempCliXmlFile.FullName -Raw
        $CliXmlEncoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($CliXmlText))

        $TempCliXmlFile | Remove-Item

        $CliXmlEncoded
    }

    $PowerShellCommandLine = $null
    $SpawnedProcCommandLine = $null
    $EncodedArguments = $null
    $TestGuidToUse = $null

    switch($CommandLineSwitchType) {
        'Hyphen'        { $SwitchChar = [Char] '-' }
        'EnDash'        { $SwitchChar = [Char] 0x2013 }
        'EmDash'        { $SwitchChar = [Char] 0x2014 }
        'HorizontalBar' { $SwitchChar = [Char] 0x2015 }
        'ForwardSlash'  { $SwitchChar = [Char] '/' }
    }

    if (-not $ScriptBlock) { $TestGuidToUse = $TestGuid }

    if ($UseEncodedArguments) {
        if ($Arguments) {
            $TestGuidToUse = $null
            $EncodedArguments = New-EncodedArgument -Arguments $Arguments
        } else {
            $EncodedArguments = New-EncodedArgument -Arguments $TestGuid.Guid
        }
    }

    switch ($PSCmdlet.ParameterSetName) {
        'Command' {
            if ($ScriptBlock) { $PowerShellCommand = "`"$($ScriptBlock.ToString().Trim())`"" } else { $PowerShellCommand = "Write-Host $TestGuid" }

            $PowerShellCommandLine = "powershell.exe {0}NoProfile {0}$CommandParamVariation $PowerShellCommand" -f $SwitchChar
            }

        'EncodedCommand' {
            if ($ScriptBlock) { $PowerShellCommand = "`"$($ScriptBlock.ToString().Trim())`"" } else { $PowerShellCommand = "Write-Host $TestGuid" }

            $EncodedPowerShellCommand = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($PowerShellCommand))

            $PowerShellCommandLine = "powershell.exe {0}NoProfile {0}$EncodedCommandParamVariation $EncodedPowerShellCommand" -f $SwitchChar
        }

        'UseEncodedArgumentsCommand' {
            if ($ScriptBlock) { $PowerShellCommand = "`"$($ScriptBlock.ToString().Trim())`"" } else { $PowerShellCommand = 'Write-Host $args[0]' }

            $PowerShellCommandLine = "powershell.exe {0}NoProfile {0}$EncodedArgumentsParamVariation $EncodedArguments {0}$CommandParamVariation $PowerShellCommand" -f $SwitchChar
        }

        'UseEncodedArgumentsEncodedCommand' {
            if ($ScriptBlock) { $PowerShellCommand = "`"$($ScriptBlock.ToString().Trim())`"" } else { $PowerShellCommand = 'Write-Host $args[0]' }

            $EncodedPowerShellCommand = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($PowerShellCommand))

            $PowerShellCommandLine = "powershell.exe {0}NoProfile {0}$EncodedArgumentsParamVariation $EncodedArguments {0}$EncodedCommandParamVariation $EncodedPowerShellCommand" -f $SwitchChar
        }

        'CommandAllVariations' {
            'C', 'Co', 'Com', 'Comm', 'Comma', 'Comman', 'Command' | ForEach-Object {
                $CurrentParamVariation = $_

                # Preserve all arguments except -GenerateAllParamVariations and -UseCommandParam
                $ArgsToPassThru = @{}

                $PSBoundParameters.Keys |
                    Where-Object { ($_ -ne 'GenerateAllParamVariations') -and ($_ -ne 'UseCommandParam') } |
                    ForEach-Object { $ArgsToPassThru[$_] = $PSBoundParameters[$_] }

                if ($PSBoundParameters['UseEncodedArguments']) {
                    'EA', 'EncodedA', 'EncodedAr', 'EncodedArg', 'EncodedArgu', 'EncodedArgum', 'EncodedArgume', 'EncodedArgume', 'EncodedArgumen', 'EncodedArgument', 'EncodedArguments' |
                        ForEach-Object { Out-ATHPowerShellCommandLineParameter -CommandParamVariation $CurrentParamVariation -EncodedArgumentsParamVariation $_ @ArgsToPassThru }
                } else {
                    Out-ATHPowerShellCommandLineParameter -CommandParamVariation $CurrentParamVariation @ArgsToPassThru
                }
            }
        }

        'EncodedCommandAllVariations' {
            'EC', 'E', 'En', 'Enc', 'Enco', 'Encod', 'Encode', 'Encoded', 'EncodedC', 'EncodedCo', 'EncodedCom', 'EncodedComm', 'EncodedComma', 'EncodedComman', 'EncodedCommand' | ForEach-Object {
                $CurrentParamVariation = $_

                # Preserve all arguments except -GenerateAllParamVariations and -UseEncodedCommandParam
                $ArgsToPassThru = @{}

                $PSBoundParameters.Keys |
                    Where-Object { ($_ -ne 'GenerateAllParamVariations') -and ($_ -ne 'UseEncodedCommandParam') } |
                    ForEach-Object { $ArgsToPassThru[$_] = $PSBoundParameters[$_] }

                if ($PSBoundParameters['UseEncodedArguments']) {
                    'EA', 'EncodedA', 'EncodedAr', 'EncodedArg', 'EncodedArgu', 'EncodedArgum', 'EncodedArgume', 'EncodedArgume', 'EncodedArgumen', 'EncodedArgument', 'EncodedArguments' |
                        ForEach-Object { Out-ATHPowerShellCommandLineParameter -EncodedCommandParamVariation $CurrentParamVariation -EncodedArgumentsParamVariation $_ @ArgsToPassThru }
                } else {
                    Out-ATHPowerShellCommandLineParameter -EncodedCommandParamVariation $CurrentParamVariation @ArgsToPassThru
                }
            }
        }
    }

    if (-not $GenerateAllParamVariations) {
        if ($Execute) {
            $ProcessStartup = New-CimInstance -ClassName Win32_ProcessStartup -ClientOnly
            $ProcessStartupInstance = Get-CimInstance -InputObject $ProcessStartup
            $ProcessStartupInstance.ShowWindow = [UInt16] 0 # Hide the window
            $ProcStartResult = Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{ CommandLine = $PowerShellCommandLine; ProcessStartupInformation = $ProcessStartupInstance }

            if ($ProcStartResult.ReturnValue -eq 0) {
                # Retrieve the actual command-line of the spawned PowerShell process
                $SpawnedProcCommandLine = Get-CimInstance -ClassName Win32_Process -Filter "ProcessId = $($ProcStartResult.ProcessId)" -Property CommandLine | Select-Object -ExpandProperty CommandLine

                [PSCustomObject] @{
                    TechniqueID = 'T1059.001'
                    TestSuccess = $True
                    TestGuid    = $TestGuidToUse
                    ProcessId   = $ProcStartResult.ProcessId
                    CommandLine = $SpawnedProcCommandLine
                }
            } else {
                Write-Error "powershell.exe child process was not spawned."
            }
        } else {
            $PowerShellCommandLine
        }
    }
}