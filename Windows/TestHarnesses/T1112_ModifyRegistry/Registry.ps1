function Set-ATHRegistry {
<#
.SYNOPSIS

Creates a registry key or sets a registry value.

Technique ID: T1112 (Modify Registry)

.DESCRIPTION

Set-ATHRegistry automates the creation of registry keys and values using a variety of methods. Depending upon the tool or API, the implementation of each method is unique and differs. Set-ATHRegistry abstracts the complexity of building registry modification test cases in a way that is implementation-independent.

.PARAMETER Method

Specifies the method by which the registry key/value will be created. The following methods are supported:

* PowerShell - Performs registry operations natively in PowerShell
* RegExeCommandLine - Performs registry operations with the reg.exe command-line
* WMI - Performs registry operations using the StdRegProv WMI class within the root/default namespace. All registry modifications will occur within the context of a wmiprvse.exe process.
* VBScriptWscriptShellRegWrite - Executes VBScript code that calls the WScript.Shell RegWrite method. Note: this method can only be used to set registry values. The RegWrite method does not support creating registry keys. The RegWrite method also does not support registry value types of MultiString, Binary, and QWord.
* JScriptWscriptShellRegWrite - Executes JScript code that calls the WScript.Shell RegWrite method. Note: this method can only be used to set registry values. The RegWrite method does not support creating registry keys. The RegWrite method also does not support registry value types of MultiString, Binary, and QWord.

.PARAMETER Hive

Specifies the desired registry hive. Supported hives: HKCR, HKCU, HKLM, HKU

.PARAMETER KeyPath

Specifies the registry key path.

.PARAMETER ValueName

Specifies the registry value name to set.

.PARAMETER ValueString

Specifies a string to set for the specified registry value.

.PARAMETER ValueExpandString

Specifies a string containing unexpanded references to environment variables (for example, "%PATH%") to set for the specified registry value.

.PARAMETER ValueMultiString

Specifies a string array to set for the specified registry value.

.PARAMETER ValueBinary

Specifies a byte array to set for the specified registry value.

.PARAMETER ValueDword

Specifies a 32-bit value to set for the specified registry value.

.PARAMETER ValueQword

Specifies a 64-bit value to set for the specified registry value.

.PARAMETER Force

Specifies that if the registry key or value already exists, Set-ATHRegistry will overwrite the key/value.

.PARAMETER OnlyOutputTestSample

Specifies that the registry key/value should not be set. This switch is intended to have Set-ATHRegistry auto-generate copy-pastable code that can be used elsewhere. This auto-generated content is surfaced via the TestSampleContent property.

.OUTPUTS

PSObject

Outputs an object consisting of relevant execution details. The following object properties may be populated:

* TechniqueID - Specifies the relevant MITRE ATT&CK Technique ID.
* TestSuccess - Will be set to True if it was determined that the registry was successfully set. This property will not be set if -OnlyOutputTestSample is supplied.
* Method - Specifies the method by which the registry key/value was set. Supported values: PowerShell, RegExeCommandLine, WMI, VBScriptWscriptShellRegWrite, JScriptWscriptShellRegWrite
* SetKeyOnly - Will be set to True if only a registry key is being created.
* KeyPath - Specifies the registry key path including the hive name.
* ValueName - Specifies the registry value that was modified.
* ValueType - Specifies the registry value type that was set. Supported values: String, ExpandString, MultiString, Binary, DWord, QWord
* ValueContent - Specifies the registry content that was set.
* PreviousValueType - Specifies the registry value type prior to being set. This property will be empty if the value was created for the first time.
* PreviousValueContent - Specifies the registry content prior to being set. This property will be empty if the value was created for the first time.
* ProcessId - Specifies the process ID of the process that set the registry key/value. Note, this property will be empty if the WMI method is used since there is no straightforward way to infer the correct wmiprvse.exe process.
* ProcessPath - Specifies the process path of the process that set the registry key/value. Note, this property will be empty if the WMI method is used since there is no straightforward way to infer the correct wmiprvse.exe process.
* ProcessCommandLine - Specifies the process command-line of the process that set the registry key/value. Note, this property will be empty if the WMI method is used since there is no straightforward way to infer the correct wmiprvse.exe process.
* TestSampleContent - Specifies auto-generated content that can be used to set the registry key/value in other testing contexts depending upon which method was selected.

.EXAMPLE

Set-ATHRegistry -Method PowerShell -Hive HKCU -KeyPath 'Foo\Bar\Baz\Bin'

Creates a HKEY_CURRENT_USER\Foo\Bar\Baz\Bin key using PowerShell.

.EXAMPLE

Set-ATHRegistry -Method RegExeCommandLine -Hive HKCU -KeyPath 'Foo\Bar\Baz\Bin'

Creates a HKEY_CURRENT_USER\Foo\Bar\Baz\Bin key using reg.exe.

.EXAMPLE

Set-ATHRegistry -Method WMI -Hive HKCU -KeyPath 'Foo\Bar\Baz\Bin' -ValueName 'Hello' -ValueString 'World' -Force

Writes the string "World" to the "Hello" value in the HKEY_CURRENT_USER\Foo\Bar\Baz\Bin using WMI, overwriting any existing value.

.EXAMPLE

Set-ATHRegistry -Method VBScriptWscriptShellRegWrite -Hive HKCU -KeyPath 'Foo\Bar\Baz\Bin' -ValueName 'Hello' -ValueExpandString '%windir%' -Force

Writes the expand string "%windir%" to the "Hello" value in the HKEY_CURRENT_USER\Foo\Bar\Baz\Bin using VBScript, overwriting any existing value.

#>

    [CmdletBinding()]
    param (
        [String]
        [ValidateSet('PowerShell', 'RegExeCommandLine', 'WMI', 'VBScriptWscriptShellRegWrite', 'JScriptWscriptShellRegWrite')]
        $Method = 'PowerShell',

        [Parameter(Mandatory)]
        [String]
        [ValidateSet('HKCR', 'HKCU', 'HKLM', 'HKU')]
        $Hive,

        [Parameter(Mandatory, ParameterSetName = 'ValueQword')]
        [Parameter(Mandatory, ParameterSetName = 'ValueDword')]
        [Parameter(Mandatory, ParameterSetName = 'ValueBinary')]
        [Parameter(Mandatory, ParameterSetName = 'ValueMultiString')]
        [Parameter(Mandatory, ParameterSetName = 'ValueExpandString')]
        [Parameter(Mandatory, ParameterSetName = 'ValueString')]
        [Parameter(Mandatory, ParameterSetName = 'KeyOnly')]
        [String]
        $KeyPath,

        [Parameter(Mandatory, ParameterSetName = 'ValueString')]
        [Parameter(Mandatory, ParameterSetName = 'ValueExpandString')]
        [Parameter(Mandatory, ParameterSetName = 'ValueMultiString')]
        [Parameter(Mandatory, ParameterSetName = 'ValueBinary')]
        [Parameter(Mandatory, ParameterSetName = 'ValueDword')]
        [Parameter(Mandatory, ParameterSetName = 'ValueQword')]
        [String]
        $ValueName,

        [Parameter(Mandatory, ParameterSetName = 'ValueString')]
        [String]
        $ValueString,

        [Parameter(Mandatory, ParameterSetName = 'ValueExpandString')]
        [String]
        $ValueExpandString,

        [Parameter(Mandatory, ParameterSetName = 'ValueMultiString')]
        [String[]]
        $ValueMultiString,

        [Parameter(Mandatory, ParameterSetName = 'ValueBinary')]
        [Byte[]]
        $ValueBinary,

        [Parameter(Mandatory, ParameterSetName = 'ValueDword')]
        [Int32]
        $ValueDword,

        [Parameter(Mandatory, ParameterSetName = 'ValueQword')]
        [Int64]
        $ValueQword,

        [Switch]
        $Force,

        [Switch]
        $OnlyOutputTestSample
    )

    $DefaultDirectory = $PWD.Path
    $DefaultVBScriptFileName = 'test.vbs'
    $DefaultJScriptFileName  = 'test.js'

    $SetKeyOnly = $False
    $DeleteKeyFirst = $False
    $OverwriteValue = $False
    $PreviousValueType = $null
    $PreviousValueContent = $null
    $ValueType = $null
    $ValueContent = $null
    $SetKeyResult = $null
    $SuppliedValueName = $null
    $ValueContent = $null
    $TestSuccess = $null
    $ProcessId = $null
    $ProcessPath = $null
    $ProcessCommandLine = $null
    $TestSampleContent = $null

    # Resolve the full hive name
    switch ($Hive) {
        'HKCR' { $HiveName = 'HKEY_CLASSES_ROOT'  }
        'HKCU' { $HiveName = 'HKEY_CURRENT_USER'  }
        'HKLM' { $HiveName = 'HKEY_LOCAL_MACHINE' }
        'HKU'  { $HiveName = 'HKEY_USERS'         }
    }

    [UInt32] $HiveValue = @{
        'HKCR' = ([UInt32] 2147483648) # 0x80000000
        'HKCU' = ([UInt32] 2147483649) # 0x80000001
        'HKLM' = ([UInt32] 2147483650) # 0x80000002
        'HKU'  = ([UInt32] 2147483651) # 0x80000003
    }[$Hive]

    $ResolvedKeyPath = "$HiveName\$KeyPath"
    $ResolvedKeyParentPath = Split-Path -Path $ResolvedKeyPath -Parent
    $ResolvedKeyName = Split-Path -Path $ResolvedKeyPath -Leaf

    if ($PSCmdlet.ParameterSetName -eq 'KeyOnly') {
        $SetKeyOnly = $True

        if (@('VBScriptWscriptShellRegWrite', 'JScriptWscriptShellRegWrite') -contains $Method) {
            Write-Error 'This method does not support the creation of just registry keys. To use this method, you must supply a value name.'
            return
        }
    }

    $KeyItem = Get-Item -Path "Registry::$ResolvedKeyPath" -ErrorAction Ignore

    if ($SetKeyOnly) {
        if ($KeyItem -and $Force) {
            $DeleteKeyFirst = $True
        } elseif ($KeyItem -and !$OnlyOutputTestSample) {
            Write-Error "The following key path already exists: $ResolvedKeyPath. Either first delete the key or use the -Force switch to delete the key and recreate it."
            return
        }
    } else {
        $IsDefaultValueName = $False

        if ($ValueName -eq '(Default)') { $IsDefaultValueName = $True }

        $SuppliedValueName = $ValueName

        switch ($PSCmdlet.ParameterSetName) {
            'ValueString' {
                $ValueContent = $ValueString
                $ValueType = ([Microsoft.Win32.RegistryValueKind]::String)
                $ValueTypeString = 'REG_SZ'
            }

            'ValueExpandString' {
                $ValueContent = $ValueExpandString
                $ValueType = ([Microsoft.Win32.RegistryValueKind]::ExpandString)
                $ValueTypeString = 'REG_EXPAND_SZ'

                # Extract the supplied environment variables exist
                # Don't perform strict validation on them. Only extract them for debugging/validation purposes.
                $PercentSignCount = $ValueExpandString.ToCharArray() | Where-Object { $_ -eq '%' } | Measure-Object | Select-Object -ExpandProperty Count

                if (($PercentSignCount -eq 0) -or (($PercentSignCount % 2) -eq 1)) {
                    Write-Warning 'Either an odd number of percent signs was supplied or none were supplied at all. Validate the supplied expand string and ensure that environment variables to be expanded were supplied correctly.'
                }

                $EnvRegex = [Regex] '%(?<envvar>.*?)%'

                foreach ($Match in $EnvRegex.Matches($ValueExpandString)) {
                    $EnvVarSupplied = $Match.Groups['envvar'].Value

                    Write-Verbose "The following environment variable was supplied: %$($EnvVarSupplied)%"

                    if (-not (Get-Item -Path "Env:\$EnvVarSupplied" -ErrorAction Ignore)) {
                        Write-Warning "The following environment variable is not currently defined: %$($EnvVarSupplied)%"
                    }
                }
            }

            'ValueMultiString' {
                $ValueContent = $ValueMultiString
                $ValueType = ([Microsoft.Win32.RegistryValueKind]::MultiString)
                $ValueTypeString = 'REG_MULTI_SZ'
            }

            'ValueBinary' {
                $ValueContent = $ValueBinary
                $ValueType = ([Microsoft.Win32.RegistryValueKind]::Binary)
                $ValueTypeString = 'REG_BINARY'
            }

            'ValueDword' {
                $ValueContent = $ValueDword
                $ValueType = ([Microsoft.Win32.RegistryValueKind]::DWord)
                $ValueTypeString = 'REG_DWORD'
            }

            'ValueQword' {
                $ValueContent = $ValueQword
                $ValueType = ([Microsoft.Win32.RegistryValueKind]::QWord)
                $ValueTypeString = 'REG_QWORD'
            }
        }

        # See if the registry value already exists
        $ValueItem = Get-ItemProperty -Path "Registry::$ResolvedKeyPath" -Name $ValueName -ErrorAction Ignore

        if ($ValueItem) {
            if ($IsDefaultValueName) {
                $PreviousValueType = $KeyItem.GetValueKind('')
                $PreviousValueContent = $KeyItem.GetValue('', $null, 'DoNotExpandEnvironmentNames')
            } else {
                $PreviousValueType = $KeyItem.GetValueKind($ValueName)
                $PreviousValueContent = $KeyItem.GetValue($ValueName, $null, 'DoNotExpandEnvironmentNames')
            }
        }

        if ($ValueItem -and $Force) {
            $OverwriteValue = $True
        } elseif ($ValueItem -and !$OnlyOutputTestSample) {
            Write-Error "The following key path/value already exists: $ResolvedKeyPath - $ValueName ($PreviousValueType). Either first delete the value or use the -Force switch to overwrite it."
            return
        }
    }

    switch ($Method) {
        'PowerShell' {
            if ($SetKeyOnly) {
                $TestSampleContent = "New-Item -Path 'Registry::$ResolvedKeyParentPath' -Name '$ResolvedKeyName' -Force"

                if ($DeleteKeyFirst) { $TestSampleContent = "Remove-Item -Path 'Registry::$ResolvedKeyPath' -Recurse; $TestSampleContent" }

                if (-not $OnlyOutputTestSample) {
                    if ($DeleteKeyFirst) {
                        Remove-Item -Path "Registry::$ResolvedKeyPath" -Recurse -ErrorAction Stop
                    }

                    $SetKeyResult = New-Item -Path "Registry::$ResolvedKeyParentPath" -Name $ResolvedKeyName -Force -ErrorAction Stop

                    if ($SetKeyResult) {
                        $TestSuccess = $True
                        $ProcessId = $PID

                        $ProcessInfo = Get-CimInstance -ClassName Win32_Process -Property CommandLine, ExecutablePath -Filter "ProcessID = $PID" -Verbose:$False
                        $ProcessPath = $ProcessInfo.ExecutablePath
                        $ProcessCommandLine = $ProcessInfo.CommandLine
                    }
                }
            } else {
                switch ("$ValueType") {
                    'String' { $ValueString = "'$ValueContent'" }

                    'ExpandString' { $ValueString = "'$ValueContent'" }

                    'MultiString' { $ValueString = "@($(($ValueContent | ForEach-Object { "'$_'" }) -join ', '))" }

                    'Binary' { $ValueString = "@($(($ValueContent | ForEach-Object { "0x$($_.ToString('X2'))" }) -join ','))" }

                    'DWord' { $ValueString = $ValueContent }

                    'QWord' { $ValueString = $ValueContent }
                }

                $TestSampleContent = "Set-ItemProperty -Path 'Registry::$ResolvedKeyPath' -Name '$ValueName' -Type $ValueType -Value $ValueString"

                if (-not $KeyItem) {
                    # PowerShell first needs to create the key
                    $TestSampleContent = "New-Item -Path 'Registry::$ResolvedKeyParentPath' -Name '$ResolvedKeyName'; $TestSampleContent"
                }

                if (-not $OnlyOutputTestSample) {
                    # First create the key
                    if (-not $KeyItem) { $null = New-Item -Path "Registry::$ResolvedKeyParentPath" -Name $ResolvedKeyName -ErrorAction Stop }

                    $SetValueResult = Set-ItemProperty -Path "Registry::$ResolvedKeyPath" -Name $ValueName -Value $ValueContent -Type $ValueType -PassThru -ErrorAction Stop

                    if ($SetValueResult) {
                        $TestSuccess = $True
                        $ProcessId = $PID

                        $ProcessInfo = Get-CimInstance -ClassName Win32_Process -Property CommandLine, ExecutablePath -Filter "ProcessID = $PID"  -Verbose:$False
                        $ProcessPath = $ProcessInfo.ExecutablePath
                        $ProcessCommandLine = $ProcessInfo.CommandLine
                    }
                }
            }
        }

        'VBScriptWscriptShellRegWrite' {
            $CScriptExePath = Get-Command -Name cscript.exe -ErrorAction Stop | Select-Object -ExpandProperty Source

            $ResolvedScriptFilePath = Join-Path -Path $DefaultDirectory -ChildPath $DefaultVBScriptFileName

            $ResolvedKeyPathValue = "$Hive\$KeyPath\$ValueName"

            if ($IsDefaultValueName) { $ResolvedKeyPathValue = "$HiveName\$KeyPath\" }

            $TestSampleContentTemplate = "WScript.CreateObject(`"WScript.Shell`").RegWrite `"$ResolvedKeyPathValue`", REPLACEVALUECONTENT, `"REPLACEREGVALUETYPE`""

            switch ("$ValueType") {
                'String' {
                    $TestSampleContent = $TestSampleContentTemplate.Replace('REPLACEREGVALUETYPE', $ValueTypeString).Replace('REPLACEVALUECONTENT', "`"$ValueContent`"")
                }

                'ExpandString' {
                    $TestSampleContent = $TestSampleContentTemplate.Replace('REPLACEREGVALUETYPE', $ValueTypeString).Replace('REPLACEVALUECONTENT', "`"$ValueContent`"")
                }

                'MultiString' {
                    Write-Error 'The WScript.Shell RegWrite method does not support REG_MULTI_SZ writing more than 4 bytes. RegWrite supports the following registry value types: REG_SZ, REG_EXPAND_SZ, REG_DWORD.'
                    return
                }

                'Binary' {
                    Write-Error 'The WScript.Shell RegWrite method does not support REG_BINARY writing more than 4 bytes. RegWrite supports the following registry value types: REG_SZ, REG_EXPAND_SZ, REG_DWORD.'
                    return
                }

                'DWord' {
                    $TestSampleContent = $TestSampleContentTemplate.Replace('REPLACEREGVALUETYPE', $ValueTypeString).Replace('REPLACEVALUECONTENT', $ValueContent)
                }

                'QWord' {
                    Write-Error 'The WScript.Shell RegWrite method does not support REG_QWORD. RegWrite supports the following registry value types: REG_SZ, REG_EXPAND_SZ, REG_MULTI_SZ, REG_DWORD.'
                    return
                }
            }

            if (-not $OnlyOutputTestSample) {
                # Write the script to disk and execute it
                Out-File -FilePath $ResolvedScriptFilePath -InputObject $TestSampleContent -ErrorAction Stop

                $ProcessCommandLine = "`"$CScriptExePath`" `"$ResolvedScriptFilePath`""

                Write-Verbose "cscript.exe command line: $ProcessCommandLine"

                $Process = Start-Process -FilePath $CScriptExePath -ArgumentList @("`"$ResolvedScriptFilePath`"") -PassThru -Wait -ErrorAction Stop

                if ($Process.ExitCode -ne 0) {
                    Write-Error "cscript.exe exited with a non-successful error code: $($Process.ExitCode)"
                    return
                }

                $ProcessId = $Process.Id
                $ProcessPath = $Process.StartInfo.FileName
            }
        }

        'JScriptWscriptShellRegWrite' {
            $CScriptExePath = Get-Command -Name cscript.exe -ErrorAction Stop | Select-Object -ExpandProperty Source

            $ResolvedScriptFilePath = Join-Path -Path $DefaultDirectory -ChildPath $DefaultJScriptFileName

            $ResolvedKeyPathValue = "$Hive\$KeyPath\$ValueName".Replace('\', '\\')

            if ($IsDefaultValueName) { $ResolvedKeyPathValue = "$HiveName\$KeyPath\".Replace('\', '\\') }

            $TestSampleContentTemplate = "(new ActiveXObject(`"WScript.Shell`")).RegWrite(`"$ResolvedKeyPathValue`", REPLACEVALUECONTENT, `"REPLACEREGVALUETYPE`");"

            switch ("$ValueType") {
                'String' {
                    $TestSampleContent = $TestSampleContentTemplate.Replace('REPLACEREGVALUETYPE', $ValueTypeString).Replace('REPLACEVALUECONTENT', "`"$ValueContent`"")
                }

                'ExpandString' {
                    $TestSampleContent = $TestSampleContentTemplate.Replace('REPLACEREGVALUETYPE', $ValueTypeString).Replace('REPLACEVALUECONTENT', "`"$ValueContent`"")
                }

                'MultiString' {
                    Write-Error 'The WScript.Shell RegWrite method does not support REG_MULTI_SZ writing more than 4 bytes. RegWrite supports the following registry value types: REG_SZ, REG_EXPAND_SZ, REG_DWORD.'
                    return
                }

                'Binary' {
                    Write-Error 'The WScript.Shell RegWrite method does not support REG_BINARY writing more than 4 bytes. RegWrite supports the following registry value types: REG_SZ, REG_EXPAND_SZ, REG_DWORD.'
                    return
                }

                'DWord' {
                    $TestSampleContent = $TestSampleContentTemplate.Replace('REPLACEREGVALUETYPE', $ValueTypeString).Replace('REPLACEVALUECONTENT', $ValueContent)
                }

                'QWord' {
                    Write-Error 'The WScript.Shell RegWrite method does not support REG_QWORD. RegWrite supports the following registry value types: REG_SZ, REG_EXPAND_SZ, REG_MULTI_SZ, REG_DWORD.'
                    return
                }
            }

            if (-not $OnlyOutputTestSample) {
                # Write the script to disk and execute it
                Out-File -FilePath $ResolvedScriptFilePath -InputObject $TestSampleContent -ErrorAction Stop

                $ProcessCommandLine = "`"$CScriptExePath`" `"$ResolvedScriptFilePath`""

                Write-Verbose "cscript.exe command line: $ProcessCommandLine"

                $Process = Start-Process -FilePath $CScriptExePath -ArgumentList @("`"$ResolvedScriptFilePath`"") -PassThru -Wait -ErrorAction Stop

                if ($Process.ExitCode -ne 0) {
                    Write-Error "cscript.exe exited with a non-successful error code: $($Process.ExitCode)"
                    return
                }

                $ProcessId = $Process.Id
                $ProcessPath = $Process.StartInfo.FileName
            }
        }

        'RegExeCommandLine' {
            $RegExePath = Get-Command -Name reg.exe -ErrorAction Stop | Select-Object -ExpandProperty Source

            $ResolvedKeyPathRegExe = "$Hive\$KeyPath"

            $RegCommandLineArgs = New-Object -TypeName 'System.Collections.Generic.List[String]'
            $RegCommandLineArgs.Add('ADD')

            if ($ResolvedKeyPathRegExe -match '\s') {
                # Wrap the key path in double quotes if it contains whitespace
                $RegCommandLineArgs.Add("`"$ResolvedKeyPathRegExe`"")
            } else {
                $RegCommandLineArgs.Add($ResolvedKeyPathRegExe)
            }

            if ($SetKeyOnly) {
                if ($DeleteKeyFirst) {
                    $RegCommandLineArgs.Add('/f')
                }

                $TestSampleContent = "`"$RegExePath`" $($RegCommandLineArgs -join ' ')"

                Write-Verbose "reg.exe command line: $TestSampleContent"

                if (-not $OnlyOutputTestSample) {
                    $ProcessCommandLine = $TestSampleContent

                    $Process = Start-Process -FilePath $RegExePath -ArgumentList $RegCommandLineArgs -PassThru -Wait -ErrorAction Stop

                    if ($Process.ExitCode -ne 0) {
                        Write-Error "reg.exe exited with a non-successful error code: $($Process.ExitCode)"
                        return
                    }

                    $ProcessId = $Process.Id
                    $ProcessPath = $Process.StartInfo.FileName
                }
            } else {
                $WrapValueStringInQuotes = $False

                switch ("$ValueType") {
                    'String' {
                        if ($ValueContent -match '\s') { $WrapValueStringInQuotes = $True }

                        $ValueString = $ValueContent
                    }

                    'ExpandString' {
                        if ($ValueContent -match '\s') { $WrapValueStringInQuotes = $True }

                        $ValueString = $ValueContent
                    }

                    'MultiString' {
                        $ValueString = $ValueContent -join '\0'
                    }

                    'Binary' {
                        $ValueString = ($ValueContent | ForEach-Object { $_.ToString('x2') }) -join ''
                    }

                    'DWord' {
                        $ValueString = "0x$($ValueContent.ToString('x8'))"
                    }

                    'QWord' {
                        $ValueString = "0x$($ValueContent.ToString('x16'))"
                    }
                }

                if ($IsDefaultValueName) {
                    # "adds an empty value name (Default) for the key."
                    $RegCommandLineArgs.Add('/ve')
                    $RegCommandLineArgs.Add('/t')
                    $RegCommandLineArgs.Add($ValueTypeString)
                } else {
                    $RegCommandLineArgs.Add('/v')

                    if ($ValueName -match '\s') {
                        # Wrap the value name in double quotes if it contains whitespace
                        $RegCommandLineArgs.Add("`"$ValueName`"")
                    } else {
                        $RegCommandLineArgs.Add($ValueName)
                    }

                    $RegCommandLineArgs.Add('/t')
                    $RegCommandLineArgs.Add($ValueTypeString)
                }

                # The '/d' arg won't be appended if the supplied value is null. Not supplying '/d' will null out the value.
                if ($null -ne $ValueContent) {
                    $RegCommandLineArgs.Add('/d')

                    if ($WrapValueStringInQuotes) {
                        $RegCommandLineArgs.Add("`"$ValueString`"")
                    } else {
                        $RegCommandLineArgs.Add($ValueString)
                    }
                }

                if ($OverwriteValue) { $RegCommandLineArgs.Add('/f') }

                $TestSampleContent = "`"$RegExePath`" $($RegCommandLineArgs -join ' ')"

                if (-not $OnlyOutputTestSample) {
                    Write-Verbose "reg.exe command line: $ProcessCommandLine"
                    $ProcessCommandLine = $TestSampleContent

                    $Process = Start-Process -FilePath $RegExePath -ArgumentList $RegCommandLineArgs -PassThru -Wait -ErrorAction Stop

                    if ($Process.ExitCode -ne 0) {
                        Write-Error "reg.exe exited with a non-successful error code: $($Process.ExitCode)"
                        return
                    }

                    $ProcessId = $Process.Id
                    $ProcessPath = $Process.StartInfo.FileName
                }
            }
        }

        'WMI' {
            $StdRegProvMethodArgs = @{
                hDefKey = $HiveValue
                sSubKeyName = $KeyPath
            }

            if ($SetKeyOnly) {
                $StdRegProvMethod = 'CreateKey'
            } else {
                if ($IsDefaultValueName) {
                    $ValueNameToSupply = ''
                    $StdRegProvMethodArgs['sValueName'] = $ValueNameToSupply
                } else {
                    $ValueNameToSupply = $ValueName
                    $StdRegProvMethodArgs['sValueName'] = $ValueNameToSupply
                }

                switch ("$ValueType") {
                    'String' {
                        $StdRegProvMethod = 'SetStringValue'
                        $ParamName = 'sValue'
                        $StdRegProvMethodArgs[$ParamName] = $ValueContent
                        $ValueString = "'$ValueContent'"
                    }

                    'ExpandString' {
                        $StdRegProvMethod = 'SetExpandedStringValue'
                        $ParamName = 'sValue'
                        $StdRegProvMethodArgs[$ParamName] = $ValueContent
                        $ValueString = "'$ValueContent'"
                    }

                    'MultiString' {
                        $StdRegProvMethod = 'SetMultiStringValue'
                        $ParamName = 'sValue'
                        $StdRegProvMethodArgs[$ParamName] = $ValueContent
                        $ValueString = "@($(($ValueContent | ForEach-Object { "'$_'" }) -join ', '))"
                    }

                    'Binary' {
                        $StdRegProvMethod = 'SetBinaryValue'
                        $ParamName = 'uValue'
                        $StdRegProvMethodArgs[$ParamName] = $ValueContent
                        $ValueString = "([Byte[]] @($(($ValueContent | ForEach-Object { "0x$($_.ToString('X2'))" }) -join ', ')))"
                    }

                    'DWord' {
                        $StdRegProvMethod = 'SetDWORDValue'
                        $ParamName = 'uValue'
                        # Convert the Int32 argument to UInt32
                        [UInt32] $UnsignedValue = [UInt32] "0x$($ValueContent.ToString('X8'))"
                        $ValueString = "([UInt32] '0x$($ValueContent.ToString('X8'))')"
                        $StdRegProvMethodArgs[$ParamName] = $UnsignedValue
                    }

                    'QWord' {
                        $StdRegProvMethod = 'SetQWORDValue'
                        $ParamName = 'uValue'
                        # Convert the Int64 argument to UInt64
                        [UInt64] $UnsignedValue = [UInt64] "0x$($ValueContent.ToString('X16'))"
                        $ValueString = "([UInt64] '0x$($ValueContent.ToString('X16'))')"
                        $StdRegProvMethodArgs[$ParamName] = $UnsignedValue
                    }
                }
            }

            $SetKeyTemplate = @"
Invoke-CimMethod -Namespace 'ROOT/default' -ClassName 'StdRegProv' -MethodName 'CreateKey' -Arguments @{
    hDefKey = ([UInt32] $HiveValue)
    sSubKeyName = '$KeyPath'
}
"@

            $SetValueTemplate = @"
Invoke-CimMethod -Namespace 'ROOT/default' -ClassName 'StdRegProv' -MethodName '$StdRegProvMethod' -Arguments @{
    hDefKey = ([UInt32] $HiveValue)
    sSubKeyName = '$KeyPath'
    sValueName = '$ValueNameToSupply'
    $ParamName = $ValueString
}
"@

            if ($SetKeyOnly) {
                $TestSampleContent = $SetKeyTemplate
            } else {
                if (-not $KeyItem) {
                    # The key needs to first be set
                    $TestSampleContent = @"
$SetKeyTemplate

$SetValueTemplate
"@
                } else {
                    $TestSampleContent = $SetValueTemplate
                }
            }

            if (-not $OnlyOutputTestSample) {
                if ((-not $SetKeyOnly) -and (-not $KeyItem)) {
                    # The key needs to be created prior to setting the value
                    $StdRegProvMethodResult = Invoke-CimMethod -Namespace 'ROOT/default' -ClassName 'StdRegProv' -MethodName 'CreateKey' -Verbose:$False -ErrorAction Stop -Arguments @{
                        hDefKey = $HiveValue
                        sSubKeyName = $KeyPath
                    }

                    if ($StdRegProvMethodResult.ReturnValue -ne 0) {
                        Write-Error "Failed to successfully execute the StdRegProv CreateKey method. Error code: $($StdRegProvMethodResult.ReturnValue)"
                        return
                    }
                }
                
                $StdRegProvMethodResult = Invoke-CimMethod -Namespace 'ROOT/default' -ClassName 'StdRegProv' -MethodName $StdRegProvMethod -Arguments $StdRegProvMethodArgs -Verbose:$False -ErrorAction Stop

                if ($StdRegProvMethodResult.ReturnValue -ne 0) {
                    Write-Error "Failed to successfully execute the StdRegProv $StdRegProvMethod method. Error code: $($StdRegProvMethodResult.ReturnValue)"
                    return
                }
            }
        }
    }

    if (-not $OnlyOutputTestSample) {
        # Validate that the key/value was set as expected
        if ($SetKeyOnly) {
            $KeyItem = Get-Item -Path "Registry::$ResolvedKeyPath" -ErrorAction Ignore

            if ((-not $KeyItem) -or ($KeyItem.Name -ne $ResolvedKeyPath)) {
                Write-Error "reg.exe failed to set the following key path: $ResolvedKeyPath"
                return
            }
        } else {
            $ValueItem = Get-ItemProperty -Path "Registry::$ResolvedKeyPath" -Name $ValueName -ErrorAction Stop

            if ($ValueItem) {
                $KeyItem = Get-Item -Path "Registry::$ResolvedKeyPath" -ErrorAction Stop

                if ($IsDefaultValueName) {
                    $SetValueType = $KeyItem.GetValueKind('')
                    $SetValueContent = $KeyItem.GetValue('', $null, 'DoNotExpandEnvironmentNames')
                } else {
                    $SetValueType = $KeyItem.GetValueKind($ValueName)
                    $SetValueContent = $KeyItem.GetValue($ValueName, $null, 'DoNotExpandEnvironmentNames')
                }
            } else {
                Write-Error "Failed to set the following registry value: $ResolvedKeyPath - $ValueName ($PreviousValueType)"
                return
            }

            if ($SetValueType -ne $ValueType) {
                Write-Error "Failed to set the expected registry value content. Actual: $SetValueType. Expected: $ValueType."
                return
            }

            if (Compare-Object -ReferenceObject $SetValueContent -DifferenceObject $ValueContent) {
                Write-Error 'Failed to set the expected registry value content.'
                return
            }
        }

        $TestSuccess = $True
    }

    [PSCustomObject] @{
        TechniqueID = 'T1112'
        TestSuccess = $TestSuccess
        Method = $Method
        SetKeyOnly = $SetKeyOnly
        KeyPath = $ResolvedKeyPath
        ValueName = $SuppliedValueName
        ValueType = $ValueType
        ValueContent = $ValueContent
        PreviousValueType = $PreviousValueType
        PreviousValueContent = $PreviousValueContent
        ProcessId = $ProcessId
        ProcessPath = $ProcessPath
        ProcessCommandLine = $ProcessCommandLine
        TestSampleContent = $TestSampleContent
    }
}

