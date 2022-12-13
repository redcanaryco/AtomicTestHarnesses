Set-StrictMode -Version Latest

$TestScriptRoot = Split-Path $MyInvocation.MyCommand.Path -Parent
$ModuleRoot = Resolve-Path "$TestScriptRoot\..\..\..\"
$ModuleManifest = "$ModuleRoot\AtomicTestHarnesses.psd1"

Remove-Module [A]tomicTestHarnesses
Import-Module $ModuleManifest -Force -ErrorAction Stop

Describe 'Set-ATHRegistry' {
    BeforeAll {
        $Help = Get-Help -Name Set-ATHRegistry -Full
    
        $ExpectedTechniqueID = $null

        $RegistryKeyPath = 'AtomicTestHarnesses\T1112'
        $ValueName = 'TestValue'

        if ($Help.Synopsis.Split("`r`n")[-1] -match '^(?-i:Technique ID: )(?<TechniqueID>\S+) (?<TechniqueDescription>\(.+\))$') {
            $ExpectedTechniqueID = $Matches['TechniqueID']
        }
    }

    Context 'Validating error conditions' -Tag 'Unit', 'T1112' {
        It 'should throw an error when an attempt is made to create just a registry key with VBScript.' -Tag 'Unit', 'T1112' {
            { Set-ATHRegistry -Method VBScriptWscriptShellRegWrite -Hive HKCU -KeyPath 'Foo\Bar' -ErrorAction Stop } | Should -Throw
        }

        It 'should throw an error when an attempt is made to create just a registry key with JScript.' -Tag 'Unit', 'T1112' {
            { Set-ATHRegistry -Method JScriptWscriptShellRegWrite -Hive HKCU -KeyPath 'Foo\Bar' -ErrorAction Stop } | Should -Throw
        }

        It 'should not accept REG_MULTI_SZ when the VBScript RegWrite method is called.' -Tag 'Unit', 'T1112' {
            { Set-ATHRegistry -Method VBScriptWscriptShellRegWrite -Hive HKCU -KeyPath 'Foo\Bar' -ValueName 'Hello' -ValueMultiString 'hello', 'wrold' -ErrorAction Stop } | Should -Throw
        }

        It 'should not accept REG_MULTI_SZ when the JScript RegWrite method is called.' -Tag 'Unit', 'T1112' {
            { Set-ATHRegistry -Method JScriptWscriptShellRegWrite -Hive HKCU -KeyPath 'Foo\Bar' -ValueName 'Hello' -ValueMultiString 'hello', 'wrold' -ErrorAction Stop } | Should -Throw
        }

        It 'should not accept REG_BINARY when the VBScript RegWrite method is called.' -Tag 'Unit', 'T1112' {
            { Set-ATHRegistry -Method VBScriptWscriptShellRegWrite -Hive HKCU -KeyPath 'Foo\Bar' -ValueName 'Hello' -ValueBinary @(1,2,3) -ErrorAction Stop } | Should -Throw
        }

        It 'should not accept REG_BINARY when the JScript RegWrite method is called.' -Tag 'Unit', 'T1112' {
            { Set-ATHRegistry -Method JScriptWscriptShellRegWrite -Hive HKCU -KeyPath 'Foo\Bar' -ValueName 'Hello' -ValueBinary @(1,2,3) -ErrorAction Stop } | Should -Throw
        }

        It 'should not accept REG_QWORD when the VBScript RegWrite method is called.' -Tag 'Unit', 'T1112' {
            { Set-ATHRegistry -Method VBScriptWscriptShellRegWrite -Hive HKCU -KeyPath 'Foo\Bar' -ValueName 'Hello' -ValueQword 1 -ErrorAction Stop } | Should -Throw
        }

        It 'should not accept REG_QWORD when the JScript RegWrite method is called.' -Tag 'Unit', 'T1112' {
            { Set-ATHRegistry -Method JScriptWscriptShellRegWrite -Hive HKCU -KeyPath 'Foo\Bar' -ValueName 'Hello' -ValueQword 1 -ErrorAction Stop } | Should -Throw
        }

        It 'should not modify a registry key that already exists.' -Tag 'Unit', 'T1112' {
            { Set-ATHRegistry -Method WMI -Hive HKCU -KeyPath 'SOFTWARE' -ErrorAction Stop } | Should -Throw
        }

        It 'should not modify a registry value that already exists.' -Tag 'Unit', 'T1112' {
            { Set-ATHRegistry -Method WMI -Hive HKCR -KeyPath '.psc1' -ValueName 'Content Type' -ValueString 'foo' -ErrorAction Stop } | Should -Throw
        }
    }

    Context 'Expected artifacts and behaviors when exercising the attack technique' -Tag 'Technique', 'T1112' {
        It 'should create a new registry key using the following method: PowerShell' -Tag 'Technique', 'T1112' {
            # First, ensure that the key doesn't exist
            Remove-Item -Path "Registry::HKEY_CURRENT_USER\$RegistryKeyPath" -Force -ErrorAction Ignore

            $Result = Set-ATHRegistry -Method PowerShell -Hive HKCU -KeyPath $RegistryKeyPath -ErrorAction Stop
            
            $Result | Should -Not -BeNullOrEmpty

            $Result.TechniqueID          | Should -BeExactly $ExpectedTechniqueID
            $Result.TestSuccess          | Should -BeTrue
            $Result.Method               | Should -BeExactly 'PowerShell'
            $Result.SetKeyOnly           | Should -BeTrue
            $Result.KeyPath              | Should -BeExactly "HKEY_CURRENT_USER\$RegistryKeyPath"
            $Result.ValueName            | Should -BeNullOrEmpty
            $Result.ValueType            | Should -BeNullOrEmpty
            $Result.ValueContent         | Should -BeNullOrEmpty
            $Result.PreviousValueType    | Should -BeNullOrEmpty
            $Result.PreviousValueContent | Should -BeNullOrEmpty
            $Result.ProcessId            | Should -Be $PID
            $Result.ProcessPath          | Should -BeExactly ((Get-Process -Id $PID).MainModule.FileName)
            $Result.ProcessCommandLine   | Should -Not -BeNullOrEmpty
            $Result.TestSampleContent    | Should -Not -BeNullOrEmpty
            $Result.TestSampleContent.StartsWith('New-Item') | Should -BeTrue
            $Result.TestSampleContent    | Should -Match 'Registry::HKEY_CURRENT_USER'
        }

        It 'should create a new registry key using the following method: RegExeCommandLine' -Tag 'Technique', 'T1112' {
            # First, ensure that the key doesn't exist
            Remove-Item -Path "Registry::HKEY_CURRENT_USER\$RegistryKeyPath" -Force -ErrorAction Ignore

            $Result = Set-ATHRegistry -Method RegExeCommandLine -Hive HKCU -KeyPath $RegistryKeyPath -ErrorAction Stop
            
            $Result | Should -Not -BeNullOrEmpty

            $Result.TechniqueID          | Should -BeExactly $ExpectedTechniqueID
            $Result.TestSuccess          | Should -BeTrue
            $Result.Method               | Should -BeExactly 'RegExeCommandLine'
            $Result.SetKeyOnly           | Should -BeTrue
            $Result.KeyPath              | Should -BeExactly "HKEY_CURRENT_USER\$RegistryKeyPath"
            $Result.ValueName            | Should -BeNullOrEmpty
            $Result.ValueType            | Should -BeNullOrEmpty
            $Result.ValueContent         | Should -BeNullOrEmpty
            $Result.PreviousValueType    | Should -BeNullOrEmpty
            $Result.PreviousValueContent | Should -BeNullOrEmpty
            $Result.ProcessId            | Should -Not -BeNullOrEmpty
            $Result.ProcessPath          | Should -Not -BeNullOrEmpty
            $Result.ProcessCommandLine   | Should -Not -BeNullOrEmpty
            $Result.TestSampleContent    | Should -Not -BeNullOrEmpty
            $Result.TestSampleContent    | Should -BeExactly $Result.ProcessCommandLine
        }

        It 'should create a new registry key using the following method: WMI' -Tag 'Technique', 'T1112' {
            # First, ensure that the key doesn't exist
            Remove-Item -Path "Registry::HKEY_CURRENT_USER\$RegistryKeyPath" -Force -ErrorAction Ignore

            $Result = Set-ATHRegistry -Method WMI -Hive HKCU -KeyPath $RegistryKeyPath -ErrorAction Stop
            
            $Result | Should -Not -BeNullOrEmpty

            $Result.TechniqueID          | Should -BeExactly $ExpectedTechniqueID
            $Result.TestSuccess          | Should -BeTrue
            $Result.Method               | Should -BeExactly 'WMI'
            $Result.SetKeyOnly           | Should -BeTrue
            $Result.KeyPath              | Should -BeExactly "HKEY_CURRENT_USER\$RegistryKeyPath"
            $Result.ValueName            | Should -BeNullOrEmpty
            $Result.ValueType            | Should -BeNullOrEmpty
            $Result.ValueContent         | Should -BeNullOrEmpty
            $Result.PreviousValueType    | Should -BeNullOrEmpty
            $Result.PreviousValueContent | Should -BeNullOrEmpty
            $Result.ProcessId            | Should -BeNullOrEmpty
            $Result.ProcessPath          | Should -BeNullOrEmpty
            $Result.ProcessCommandLine   | Should -BeNullOrEmpty
            $Result.TestSampleContent    | Should -Not -BeNullOrEmpty
            $Result.TestSampleContent.StartsWith("Invoke-CimMethod -Namespace 'ROOT/default' -ClassName 'StdRegProv' -MethodName 'CreateKey'") | Should -BeTrue
        }

        It 'should force creation of an existing key with the -Force switch using the following method: PowerShell' -Tag 'Technique', 'T1112' {
            # First, ensure that the key doesn't exist
            Remove-Item -Path "Registry::HKEY_CURRENT_USER\$RegistryKeyPath" -Force -ErrorAction Ignore

            # Now, ensure that the key already exists
            $NewKey = New-Item -Path 'Registry::HKEY_CURRENT_USER\AtomicTestHarnesses' -Name 'T1112' -Force -ErrorAction Stop
            $NewKey | Should -Not -BeNullOrEmpty

            $Result = Set-ATHRegistry -Method PowerShell -Hive HKCU -KeyPath $RegistryKeyPath -Force -ErrorAction Stop
            
            $Result | Should -Not -BeNullOrEmpty

            $Result.TechniqueID          | Should -BeExactly $ExpectedTechniqueID
            $Result.TestSuccess          | Should -BeTrue
            $Result.Method               | Should -BeExactly 'PowerShell'
            $Result.SetKeyOnly           | Should -BeTrue
            $Result.KeyPath              | Should -BeExactly "HKEY_CURRENT_USER\$RegistryKeyPath"
            $Result.ValueName            | Should -BeNullOrEmpty
            $Result.ValueType            | Should -BeNullOrEmpty
            $Result.ValueContent         | Should -BeNullOrEmpty
            $Result.PreviousValueType    | Should -BeNullOrEmpty
            $Result.PreviousValueContent | Should -BeNullOrEmpty
            $Result.ProcessId            | Should -Be $PID
            $Result.ProcessPath          | Should -BeExactly ((Get-Process -Id $PID).MainModule.FileName)
            $Result.ProcessCommandLine   | Should -Not -BeNullOrEmpty
            $Result.TestSampleContent    | Should -Not -BeNullOrEmpty
            $Result.TestSampleContent.StartsWith('Remove-Item') | Should -BeTrue
            $Result.TestSampleContent    | Should -Match 'Registry::HKEY_CURRENT_USER'
        }

        It 'should force creation of an existing key with the -Force switch using the following method: RegExeCommandLine' -Tag 'Technique', 'T1112' {
            # First, ensure that the key doesn't exist
            Remove-Item -Path "Registry::HKEY_CURRENT_USER\$RegistryKeyPath" -Force -ErrorAction Ignore

            # Now, ensure that the key already exists
            $NewKey = New-Item -Path 'Registry::HKEY_CURRENT_USER\AtomicTestHarnesses' -Name 'T1112' -Force -ErrorAction Stop
            $NewKey | Should -Not -BeNullOrEmpty

            $Result = Set-ATHRegistry -Method RegExeCommandLine -Hive HKCU -KeyPath $RegistryKeyPath -Force -ErrorAction Stop
            
            $Result | Should -Not -BeNullOrEmpty

            $Result.TechniqueID          | Should -BeExactly $ExpectedTechniqueID
            $Result.TestSuccess          | Should -BeTrue
            $Result.Method               | Should -BeExactly 'RegExeCommandLine'
            $Result.SetKeyOnly           | Should -BeTrue
            $Result.KeyPath              | Should -BeExactly "HKEY_CURRENT_USER\$RegistryKeyPath"
            $Result.ValueName            | Should -BeNullOrEmpty
            $Result.ValueType            | Should -BeNullOrEmpty
            $Result.ValueContent         | Should -BeNullOrEmpty
            $Result.PreviousValueType    | Should -BeNullOrEmpty
            $Result.PreviousValueContent | Should -BeNullOrEmpty
            $Result.ProcessId            | Should -Not -BeNullOrEmpty
            $Result.ProcessPath          | Should -Not -BeNullOrEmpty
            $Result.ProcessCommandLine   | Should -Not -BeNullOrEmpty
            $Result.TestSampleContent    | Should -Not -BeNullOrEmpty
            $Result.TestSampleContent    | Should -BeExactly $Result.ProcessCommandLine
        }

        It 'should force creation of an existing key with the -Force switch using the following method: WMI' -Tag 'Technique', 'T1112' {
            # First, ensure that the key doesn't exist
            Remove-Item -Path "Registry::HKEY_CURRENT_USER\$RegistryKeyPath" -Force -ErrorAction Ignore

            # Now, ensure that the key already exists
            $NewKey = New-Item -Path 'Registry::HKEY_CURRENT_USER\AtomicTestHarnesses' -Name 'T1112' -Force -ErrorAction Stop
            $NewKey | Should -Not -BeNullOrEmpty

            $Result = Set-ATHRegistry -Method WMI -Hive HKCU -KeyPath $RegistryKeyPath -Force -ErrorAction Stop
            
            $Result | Should -Not -BeNullOrEmpty

            $Result.TechniqueID          | Should -BeExactly $ExpectedTechniqueID
            $Result.TestSuccess          | Should -BeTrue
            $Result.Method               | Should -BeExactly 'WMI'
            $Result.SetKeyOnly           | Should -BeTrue
            $Result.KeyPath              | Should -BeExactly "HKEY_CURRENT_USER\$RegistryKeyPath"
            $Result.ValueName            | Should -BeNullOrEmpty
            $Result.ValueType            | Should -BeNullOrEmpty
            $Result.ValueContent         | Should -BeNullOrEmpty
            $Result.PreviousValueType    | Should -BeNullOrEmpty
            $Result.PreviousValueContent | Should -BeNullOrEmpty
            $Result.ProcessId            | Should -BeNullOrEmpty
            $Result.ProcessPath          | Should -BeNullOrEmpty
            $Result.ProcessCommandLine   | Should -BeNullOrEmpty
            $Result.TestSampleContent    | Should -Not -BeNullOrEmpty
            $Result.TestSampleContent.StartsWith("Invoke-CimMethod -Namespace 'ROOT/default' -ClassName 'StdRegProv' -MethodName 'CreateKey'") | Should -BeTrue
        }

        It 'should mock creating a new registry key with the -OnlyOutputTestSample switch using the following method: PowerShell' -Tag 'Technique', 'T1112' {
            # First, ensure that the key doesn't exist
            Remove-Item -Path "Registry::HKEY_CURRENT_USER\$RegistryKeyPath" -Force -ErrorAction Ignore

            $Result = Set-ATHRegistry -Method PowerShell -Hive HKCU -KeyPath $RegistryKeyPath -OnlyOutputTestSample -ErrorAction Stop
            
            $Result | Should -Not -BeNullOrEmpty

            $Result.TechniqueID          | Should -BeExactly $ExpectedTechniqueID
            $Result.TestSuccess          | Should -BeNullOrEmpty
            $Result.Method               | Should -BeExactly 'PowerShell'
            $Result.SetKeyOnly           | Should -BeTrue
            $Result.KeyPath              | Should -BeExactly "HKEY_CURRENT_USER\$RegistryKeyPath"
            $Result.ValueName            | Should -BeNullOrEmpty
            $Result.ValueType            | Should -BeNullOrEmpty
            $Result.ValueContent         | Should -BeNullOrEmpty
            $Result.PreviousValueType    | Should -BeNullOrEmpty
            $Result.PreviousValueContent | Should -BeNullOrEmpty
            $Result.ProcessId            | Should -BeNullOrEmpty
            $Result.ProcessPath          | Should -BeNullOrEmpty
            $Result.ProcessCommandLine   | Should -BeNullOrEmpty
            $Result.TestSampleContent    | Should -Not -BeNullOrEmpty
            $Result.TestSampleContent.StartsWith('New-Item') | Should -BeTrue
            $Result.TestSampleContent    | Should -Match 'Registry::HKEY_CURRENT_USER'
        }

        It 'should mock creating a new registry key with the -OnlyOutputTestSample switch using the following method: RegExeCommandLine' -Tag 'Technique', 'T1112' {
            # First, ensure that the key doesn't exist
            Remove-Item -Path "Registry::HKEY_CURRENT_USER\$RegistryKeyPath" -Force -ErrorAction Ignore

            $Result = Set-ATHRegistry -Method RegExeCommandLine -Hive HKCU -KeyPath $RegistryKeyPath -OnlyOutputTestSample -ErrorAction Stop
            
            $Result | Should -Not -BeNullOrEmpty

            $Result.TechniqueID          | Should -BeExactly $ExpectedTechniqueID
            $Result.TestSuccess          | Should -BeNullOrEmpty
            $Result.Method               | Should -BeExactly 'RegExeCommandLine'
            $Result.SetKeyOnly           | Should -BeTrue
            $Result.KeyPath              | Should -BeExactly "HKEY_CURRENT_USER\$RegistryKeyPath"
            $Result.ValueName            | Should -BeNullOrEmpty
            $Result.ValueType            | Should -BeNullOrEmpty
            $Result.ValueContent         | Should -BeNullOrEmpty
            $Result.PreviousValueType    | Should -BeNullOrEmpty
            $Result.PreviousValueContent | Should -BeNullOrEmpty
            $Result.ProcessId            | Should -BeNullOrEmpty
            $Result.ProcessPath          | Should -BeNullOrEmpty
            $Result.ProcessCommandLine   | Should -BeNullOrEmpty
            $Result.TestSampleContent    | Should -Not -BeNullOrEmpty
        }

        It 'should mock creating a new registry key with the -OnlyOutputTestSample switch using the following method: WMI' -Tag 'Technique', 'T1112' {
            # First, ensure that the key doesn't exist
            Remove-Item -Path "Registry::HKEY_CURRENT_USER\$RegistryKeyPath" -Force -ErrorAction Ignore

            $Result = Set-ATHRegistry -Method WMI -Hive HKCU -KeyPath $RegistryKeyPath -OnlyOutputTestSample -ErrorAction Stop
            
            $Result | Should -Not -BeNullOrEmpty

            $Result.TechniqueID          | Should -BeExactly $ExpectedTechniqueID
            $Result.TestSuccess          | Should -BeNullOrEmpty
            $Result.Method               | Should -BeExactly 'WMI'
            $Result.SetKeyOnly           | Should -BeTrue
            $Result.KeyPath              | Should -BeExactly "HKEY_CURRENT_USER\$RegistryKeyPath"
            $Result.ValueName            | Should -BeNullOrEmpty
            $Result.ValueType            | Should -BeNullOrEmpty
            $Result.ValueContent         | Should -BeNullOrEmpty
            $Result.PreviousValueType    | Should -BeNullOrEmpty
            $Result.PreviousValueContent | Should -BeNullOrEmpty
            $Result.ProcessId            | Should -BeNullOrEmpty
            $Result.ProcessPath          | Should -BeNullOrEmpty
            $Result.ProcessCommandLine   | Should -BeNullOrEmpty
            $Result.TestSampleContent    | Should -Not -BeNullOrEmpty
            $Result.TestSampleContent.StartsWith("Invoke-CimMethod -Namespace 'ROOT/default' -ClassName 'StdRegProv' -MethodName 'CreateKey'") | Should -BeTrue
        }

        It 'should mock creation of an existing key with the -Force switch using the following method: PowerShell' -Tag 'Technique', 'T1112' {
            # First, ensure that the key doesn't exist
            Remove-Item -Path "Registry::HKEY_CURRENT_USER\$RegistryKeyPath" -Force -ErrorAction Ignore

            # Now, ensure that the key already exists
            $NewKey = New-Item -Path 'Registry::HKEY_CURRENT_USER\AtomicTestHarnesses' -Name 'T1112' -Force -ErrorAction Stop
            $NewKey | Should -Not -BeNullOrEmpty

            $Result = Set-ATHRegistry -Method PowerShell -Hive HKCU -KeyPath $RegistryKeyPath -Force -OnlyOutputTestSample -ErrorAction Stop
            
            $Result | Should -Not -BeNullOrEmpty

            $Result.TechniqueID          | Should -BeExactly $ExpectedTechniqueID
            $Result.TestSuccess          | Should -BeNullOrEmpty
            $Result.Method               | Should -BeExactly 'PowerShell'
            $Result.SetKeyOnly           | Should -BeTrue
            $Result.KeyPath              | Should -BeExactly "HKEY_CURRENT_USER\$RegistryKeyPath"
            $Result.ValueName            | Should -BeNullOrEmpty
            $Result.ValueType            | Should -BeNullOrEmpty
            $Result.ValueContent         | Should -BeNullOrEmpty
            $Result.PreviousValueType    | Should -BeNullOrEmpty
            $Result.PreviousValueContent | Should -BeNullOrEmpty
            $Result.ProcessId            | Should -BeNullOrEmpty
            $Result.ProcessPath          | Should -BeNullOrEmpty
            $Result.ProcessCommandLine   | Should -BeNullOrEmpty
            $Result.TestSampleContent    | Should -Not -BeNullOrEmpty
            $Result.TestSampleContent.StartsWith('Remove-Item') | Should -BeTrue
            $Result.TestSampleContent    | Should -Match 'Registry::HKEY_CURRENT_USER'
        }

        It 'should mock creation of an existing key with the -Force switch using the following method: RegExeCommandLine' -Tag 'Technique', 'T1112' {
            # First, ensure that the key doesn't exist
            Remove-Item -Path "Registry::HKEY_CURRENT_USER\$RegistryKeyPath" -Force -ErrorAction Ignore

            # Now, ensure that the key already exists
            $NewKey = New-Item -Path 'Registry::HKEY_CURRENT_USER\AtomicTestHarnesses' -Name 'T1112' -Force -ErrorAction Stop
            $NewKey | Should -Not -BeNullOrEmpty

            $Result = Set-ATHRegistry -Method RegExeCommandLine -Hive HKCU -KeyPath $RegistryKeyPath -Force -OnlyOutputTestSample -ErrorAction Stop
            
            $Result | Should -Not -BeNullOrEmpty

            $Result.TechniqueID          | Should -BeExactly $ExpectedTechniqueID
            $Result.TestSuccess          | Should -BeNullOrEmpty
            $Result.Method               | Should -BeExactly 'RegExeCommandLine'
            $Result.SetKeyOnly           | Should -BeTrue
            $Result.KeyPath              | Should -BeExactly "HKEY_CURRENT_USER\$RegistryKeyPath"
            $Result.ValueName            | Should -BeNullOrEmpty
            $Result.ValueType            | Should -BeNullOrEmpty
            $Result.ValueContent         | Should -BeNullOrEmpty
            $Result.PreviousValueType    | Should -BeNullOrEmpty
            $Result.PreviousValueContent | Should -BeNullOrEmpty
            $Result.ProcessId            | Should -BeNullOrEmpty
            $Result.ProcessPath          | Should -BeNullOrEmpty
            $Result.ProcessCommandLine   | Should -BeNullOrEmpty
            $Result.TestSampleContent    | Should -Not -BeNullOrEmpty
        }

        It 'should mock creation of an existing key with the -Force switch using the following method: WMI' -Tag 'Technique', 'T1112' {
            # First, ensure that the key doesn't exist
            Remove-Item -Path "Registry::HKEY_CURRENT_USER\$RegistryKeyPath" -Force -ErrorAction Ignore

            # Now, ensure that the key already exists
            $NewKey = New-Item -Path 'Registry::HKEY_CURRENT_USER\AtomicTestHarnesses' -Name 'T1112' -Force -ErrorAction Stop
            $NewKey | Should -Not -BeNullOrEmpty

            $Result = Set-ATHRegistry -Method WMI -Hive HKCU -KeyPath $RegistryKeyPath -Force -OnlyOutputTestSample -ErrorAction Stop
            
            $Result | Should -Not -BeNullOrEmpty

            $Result.TechniqueID          | Should -BeExactly $ExpectedTechniqueID
            $Result.TestSuccess          | Should -BeNullOrEmpty
            $Result.Method               | Should -BeExactly 'WMI'
            $Result.SetKeyOnly           | Should -BeTrue
            $Result.KeyPath              | Should -BeExactly "HKEY_CURRENT_USER\$RegistryKeyPath"
            $Result.ValueName            | Should -BeNullOrEmpty
            $Result.ValueType            | Should -BeNullOrEmpty
            $Result.ValueContent         | Should -BeNullOrEmpty
            $Result.PreviousValueType    | Should -BeNullOrEmpty
            $Result.PreviousValueContent | Should -BeNullOrEmpty
            $Result.ProcessId            | Should -BeNullOrEmpty
            $Result.ProcessPath          | Should -BeNullOrEmpty
            $Result.ProcessCommandLine   | Should -BeNullOrEmpty
            $Result.TestSampleContent    | Should -Not -BeNullOrEmpty
            $Result.TestSampleContent.StartsWith("Invoke-CimMethod -Namespace 'ROOT/default' -ClassName 'StdRegProv' -MethodName 'CreateKey'") | Should -BeTrue
        }

        It 'should create a registry value from a key that does not currently exist using the following method: <Method>' -Tag 'Technique', 'T1112' {
            # First, ensure that the key doesn't exist
            Remove-Item -Path "Registry::HKEY_CURRENT_USER\$RegistryKeyPath" -Force -ErrorAction Ignore

            $Result = Set-ATHRegistry -Method $Method -Hive HKCU -KeyPath $RegistryKeyPath -ValueName $ValueName -ValueString 'Hello' -ErrorAction Stop

            $Result | Should -Not -BeNullOrEmpty

            $Result.TechniqueID          | Should -BeExactly $ExpectedTechniqueID
            $Result.TestSuccess          | Should -BeTrue
            $Result.Method               | Should -BeExactly $Method
            $Result.SetKeyOnly           | Should -BeFalse
            $Result.KeyPath              | Should -BeExactly "HKEY_CURRENT_USER\$RegistryKeyPath"
            $Result.ValueName            | Should -BeExactly $ValueName
            $Result.ValueType            | Should -BeExactly 'String'
            $Result.ValueContent         | Should -BeExactly 'Hello'
            $Result.PreviousValueType    | Should -BeNullOrEmpty
            $Result.PreviousValueContent | Should -BeNullOrEmpty
            $Result.TestSampleContent    | Should -Not -BeNullOrEmpty
        } -TestCases @(
            @{ Method = 'PowerShell' },
            @{ Method = 'RegExeCommandLine' },
            @{ Method = 'WMI' },
            @{ Method = 'VBScriptWscriptShellRegWrite' },
            @{ Method = 'JScriptWscriptShellRegWrite' }
        )

        It 'should overwrite an existing registry value using the following method: <Method>' -Tag 'Technique', 'T1112' {
            # First, ensure that the key doesn't exist
            Remove-Item -Path "Registry::HKEY_CURRENT_USER\$RegistryKeyPath" -Force -ErrorAction Ignore

            # Ensure that the key and the value exist prior to the overwrite
            $null = New-Item -Path 'Registry::HKEY_CURRENT_USER\AtomicTestHarnesses' -Name 'T1112' -ErrorAction Stop
            Set-ItemProperty -Path 'Registry::HKEY_CURRENT_USER\AtomicTestHarnesses\T1112' -Name $ValueName -Type String -Value 'Hello' -ErrorAction Stop

            $Result = Set-ATHRegistry -Method $Method -Hive HKCU -KeyPath $RegistryKeyPath -ValueName $ValueName -ValueDword 4 -Force -ErrorAction Stop

            $Result | Should -Not -BeNullOrEmpty

            $Result.TechniqueID          | Should -BeExactly $ExpectedTechniqueID
            $Result.TestSuccess          | Should -BeTrue
            $Result.Method               | Should -BeExactly $Method
            $Result.SetKeyOnly           | Should -BeFalse
            $Result.KeyPath              | Should -BeExactly "HKEY_CURRENT_USER\$RegistryKeyPath"
            $Result.ValueName            | Should -BeExactly $ValueName
            $Result.ValueType            | Should -BeExactly 'DWord'
            $Result.ValueContent         | Should -Be 4
            $Result.PreviousValueType    | Should -BeExactly 'String'
            $Result.PreviousValueContent | Should -BeExactly 'Hello'
            $Result.TestSampleContent    | Should -Not -BeNullOrEmpty
        } -TestCases @(
            @{ Method = 'PowerShell' },
            @{ Method = 'RegExeCommandLine' },
            @{ Method = 'WMI' },
            @{ Method = 'VBScriptWscriptShellRegWrite' },
            @{ Method = 'JScriptWscriptShellRegWrite' }
        )

        It 'should mock the creation of a new value with the -OnlyOutputTestSample switch using the following method: <Method>' -Tag 'Technique', 'T1112' {
            # First, ensure that the key doesn't exist
            Remove-Item -Path "Registry::HKEY_CURRENT_USER\$RegistryKeyPath" -Force -ErrorAction Ignore

            $Result = Set-ATHRegistry -Method $Method -Hive HKCU -KeyPath $RegistryKeyPath -ValueName $ValueName -ValueDword 4 -OnlyOutputTestSample -ErrorAction Stop

            $Result | Should -Not -BeNullOrEmpty

            $Result.TechniqueID          | Should -BeExactly $ExpectedTechniqueID
            $Result.TestSuccess          | Should -BeNullOrEmpty
            $Result.Method               | Should -BeExactly $Method
            $Result.SetKeyOnly           | Should -BeFalse
            $Result.KeyPath              | Should -BeExactly "HKEY_CURRENT_USER\$RegistryKeyPath"
            $Result.ValueName            | Should -BeExactly $ValueName
            $Result.ValueType            | Should -BeExactly 'DWord'
            $Result.ValueContent         | Should -Be 4
            $Result.PreviousValueType    | Should -BeNullOrEmpty
            $Result.PreviousValueContent | Should -BeNullOrEmpty
            $Result.ProcessId            | Should -BeNullOrEmpty
            $Result.ProcessPath          | Should -BeNullOrEmpty
            $Result.ProcessCommandLine   | Should -BeNullOrEmpty
            $Result.TestSampleContent    | Should -Not -BeNullOrEmpty
        } -TestCases @(
            @{ Method = 'PowerShell' },
            @{ Method = 'RegExeCommandLine' },
            @{ Method = 'WMI' },
            @{ Method = 'VBScriptWscriptShellRegWrite' },
            @{ Method = 'JScriptWscriptShellRegWrite' }
        )

        It 'should mock the overwriting of an exising value with the -OnlyOutputTestSample switch using the following method: <Method>' -Tag 'Technique', 'T1112' {
            # First, ensure that the key doesn't exist
            Remove-Item -Path "Registry::HKEY_CURRENT_USER\$RegistryKeyPath" -Force -ErrorAction Ignore

            # Ensure that the key and the value exist prior to the overwrite
            $null = New-Item -Path 'Registry::HKEY_CURRENT_USER\AtomicTestHarnesses' -Name 'T1112' -ErrorAction Stop
            Set-ItemProperty -Path 'Registry::HKEY_CURRENT_USER\AtomicTestHarnesses\T1112' -Name $ValueName -Type String -Value 'Hello' -ErrorAction Stop

            $Result = Set-ATHRegistry -Method $Method -Hive HKCU -KeyPath $RegistryKeyPath -ValueName $ValueName -ValueDword 4 -OnlyOutputTestSample -ErrorAction Stop

            $Result | Should -Not -BeNullOrEmpty

            $Result.TechniqueID          | Should -BeExactly $ExpectedTechniqueID
            $Result.TestSuccess          | Should -BeNullOrEmpty
            $Result.Method               | Should -BeExactly $Method
            $Result.SetKeyOnly           | Should -BeFalse
            $Result.KeyPath              | Should -BeExactly "HKEY_CURRENT_USER\$RegistryKeyPath"
            $Result.ValueName            | Should -BeExactly $ValueName
            $Result.ValueType            | Should -BeExactly 'DWord'
            $Result.ValueContent         | Should -Be 4
            $Result.PreviousValueType    | Should -BeExactly 'String'
            $Result.PreviousValueContent | Should -BeExactly 'Hello'
            $Result.ProcessId            | Should -BeNullOrEmpty
            $Result.ProcessPath          | Should -BeNullOrEmpty
            $Result.ProcessCommandLine   | Should -BeNullOrEmpty
            $Result.TestSampleContent    | Should -Not -BeNullOrEmpty
        } -TestCases @(
            @{ Method = 'PowerShell' },
            @{ Method = 'RegExeCommandLine' },
            @{ Method = 'WMI' },
            @{ Method = 'VBScriptWscriptShellRegWrite' },
            @{ Method = 'JScriptWscriptShellRegWrite' }
        )

        It 'should set a String registry value using the following method: <Method>' -Tag 'Technique', 'T1112' {
            # First, ensure that the key doesn't exist
            Remove-Item -Path "Registry::HKEY_CURRENT_USER\$RegistryKeyPath" -Force -ErrorAction Ignore

            $Result = Set-ATHRegistry -Method $Method -Hive HKCU -KeyPath $RegistryKeyPath -ValueName $ValueName -ValueString 'Hello' -ErrorAction Stop

            $Result | Should -Not -BeNullOrEmpty

            $Result.TechniqueID          | Should -BeExactly $ExpectedTechniqueID
            $Result.TestSuccess          | Should -BeTrue
            $Result.Method               | Should -BeExactly $Method
            $Result.SetKeyOnly           | Should -BeFalse
            $Result.KeyPath              | Should -BeExactly "HKEY_CURRENT_USER\$RegistryKeyPath"
            $Result.ValueName            | Should -BeExactly $ValueName
            $Result.ValueType            | Should -BeExactly 'String'
            $Result.ValueContent         | Should -Be 'Hello'
            $Result.PreviousValueType    | Should -BeNullOrEmpty
            $Result.PreviousValueContent | Should -BeNullOrEmpty

            if ($Method -eq 'WMI') {
                $Result.ProcessId            | Should -BeNullOrEmpty
                $Result.ProcessPath          | Should -BeNullOrEmpty
                $Result.ProcessCommandLine   | Should -BeNullOrEmpty
            } else {
                $Result.ProcessId            | Should -Not -BeNullOrEmpty
                $Result.ProcessPath          | Should -Not -BeNullOrEmpty
                $Result.ProcessCommandLine   | Should -Not -BeNullOrEmpty
            }
            
            $Result.TestSampleContent    | Should -Not -BeNullOrEmpty
        } -TestCases @(
            @{ Method = 'PowerShell' },
            @{ Method = 'RegExeCommandLine' },
            @{ Method = 'WMI' },
            @{ Method = 'VBScriptWscriptShellRegWrite' },
            @{ Method = 'JScriptWscriptShellRegWrite' }
        )

        It 'should set a ExpandString registry value using the following method: <Method>' -Tag 'Technique', 'T1112' {
            # First, ensure that the key doesn't exist
            Remove-Item -Path "Registry::HKEY_CURRENT_USER\$RegistryKeyPath" -Force -ErrorAction Ignore

            $Result = Set-ATHRegistry -Method $Method -Hive HKCU -KeyPath $RegistryKeyPath -ValueName $ValueName -ValueExpandString '%windir%' -ErrorAction Stop

            $Result | Should -Not -BeNullOrEmpty

            $Result.TechniqueID          | Should -BeExactly $ExpectedTechniqueID
            $Result.TestSuccess          | Should -BeTrue
            $Result.Method               | Should -BeExactly $Method
            $Result.SetKeyOnly           | Should -BeFalse
            $Result.KeyPath              | Should -BeExactly "HKEY_CURRENT_USER\$RegistryKeyPath"
            $Result.ValueName            | Should -BeExactly $ValueName
            $Result.ValueType            | Should -BeExactly 'ExpandString'
            $Result.ValueContent         | Should -Be '%windir%'
            $Result.PreviousValueType    | Should -BeNullOrEmpty
            $Result.PreviousValueContent | Should -BeNullOrEmpty

            if ($Method -eq 'WMI') {
                $Result.ProcessId            | Should -BeNullOrEmpty
                $Result.ProcessPath          | Should -BeNullOrEmpty
                $Result.ProcessCommandLine   | Should -BeNullOrEmpty
            } else {
                $Result.ProcessId            | Should -Not -BeNullOrEmpty
                $Result.ProcessPath          | Should -Not -BeNullOrEmpty
                $Result.ProcessCommandLine   | Should -Not -BeNullOrEmpty
            }
            
            $Result.TestSampleContent    | Should -Not -BeNullOrEmpty
        } -TestCases @(
            @{ Method = 'PowerShell' },
            @{ Method = 'RegExeCommandLine' },
            @{ Method = 'WMI' },
            @{ Method = 'VBScriptWscriptShellRegWrite' },
            @{ Method = 'JScriptWscriptShellRegWrite' }
        )

        It 'should set a MultiString registry value using the following method: <Method>' -Tag 'Technique', 'T1112' {
            # First, ensure that the key doesn't exist
            Remove-Item -Path "Registry::HKEY_CURRENT_USER\$RegistryKeyPath" -Force -ErrorAction Ignore

            $Result = Set-ATHRegistry -Method $Method -Hive HKCU -KeyPath $RegistryKeyPath -ValueName $ValueName -ValueMultiString @('Hello', 'World') -ErrorAction Stop

            $Result | Should -Not -BeNullOrEmpty

            $Result.TechniqueID          | Should -BeExactly $ExpectedTechniqueID
            $Result.TestSuccess          | Should -BeTrue
            $Result.Method               | Should -BeExactly $Method
            $Result.SetKeyOnly           | Should -BeFalse
            $Result.KeyPath              | Should -BeExactly "HKEY_CURRENT_USER\$RegistryKeyPath"
            $Result.ValueName            | Should -BeExactly $ValueName
            $Result.ValueType            | Should -BeExactly 'MultiString'
            $Result.ValueContent -is ([String[]]) | Should -BeTrue
            $Result.ValueContent.Count   | Should -Be 2
            $Result.ValueContent[0]      | Should -Be 'Hello'
            $Result.ValueContent[1]      | Should -Be 'World'
            $Result.PreviousValueType    | Should -BeNullOrEmpty
            $Result.PreviousValueContent | Should -BeNullOrEmpty

            if ($Method -eq 'WMI') {
                $Result.ProcessId            | Should -BeNullOrEmpty
                $Result.ProcessPath          | Should -BeNullOrEmpty
                $Result.ProcessCommandLine   | Should -BeNullOrEmpty
            } else {
                $Result.ProcessId            | Should -Not -BeNullOrEmpty
                $Result.ProcessPath          | Should -Not -BeNullOrEmpty
                $Result.ProcessCommandLine   | Should -Not -BeNullOrEmpty
            }
            
            $Result.TestSampleContent    | Should -Not -BeNullOrEmpty
        } -TestCases @(
            @{ Method = 'PowerShell' },
            @{ Method = 'RegExeCommandLine' },
            @{ Method = 'WMI' }
        )

        It 'should set a Binary registry value using the following method: <Method>' -Tag 'Technique', 'T1112' {
            # First, ensure that the key doesn't exist
            Remove-Item -Path "Registry::HKEY_CURRENT_USER\$RegistryKeyPath" -Force -ErrorAction Ignore

            $Result = Set-ATHRegistry -Method $Method -Hive HKCU -KeyPath $RegistryKeyPath -ValueName $ValueName -ValueBinary @(1,2,3) -ErrorAction Stop

            $Result | Should -Not -BeNullOrEmpty

            $Result.TechniqueID          | Should -BeExactly $ExpectedTechniqueID
            $Result.TestSuccess          | Should -BeTrue
            $Result.Method               | Should -BeExactly $Method
            $Result.SetKeyOnly           | Should -BeFalse
            $Result.KeyPath              | Should -BeExactly "HKEY_CURRENT_USER\$RegistryKeyPath"
            $Result.ValueName            | Should -BeExactly $ValueName
            $Result.ValueType            | Should -BeExactly 'Binary'
            $Result.ValueContent -is ([Byte[]]) | Should -BeTrue
            $Result.ValueContent.Count   | Should -Be 3
            $Result.ValueContent[0]      | Should -Be 1
            $Result.ValueContent[1]      | Should -Be 2
            $Result.ValueContent[2]      | Should -Be 3
            $Result.PreviousValueType    | Should -BeNullOrEmpty
            $Result.PreviousValueContent | Should -BeNullOrEmpty

            if ($Method -eq 'WMI') {
                $Result.ProcessId            | Should -BeNullOrEmpty
                $Result.ProcessPath          | Should -BeNullOrEmpty
                $Result.ProcessCommandLine   | Should -BeNullOrEmpty
            } else {
                $Result.ProcessId            | Should -Not -BeNullOrEmpty
                $Result.ProcessPath          | Should -Not -BeNullOrEmpty
                $Result.ProcessCommandLine   | Should -Not -BeNullOrEmpty
            }
            
            $Result.TestSampleContent    | Should -Not -BeNullOrEmpty
        } -TestCases @(
            @{ Method = 'PowerShell' },
            @{ Method = 'RegExeCommandLine' },
            @{ Method = 'WMI' }
        )

        It 'should set a DWord registry value using the following method: <Method>' -Tag 'Technique', 'T1112' {
            # First, ensure that the key doesn't exist
            Remove-Item -Path "Registry::HKEY_CURRENT_USER\$RegistryKeyPath" -Force -ErrorAction Ignore

            $Result = Set-ATHRegistry -Method $Method -Hive HKCU -KeyPath $RegistryKeyPath -ValueName $ValueName -ValueDword 4 -ErrorAction Stop

            $Result | Should -Not -BeNullOrEmpty

            $Result.TechniqueID          | Should -BeExactly $ExpectedTechniqueID
            $Result.TestSuccess          | Should -BeTrue
            $Result.Method               | Should -BeExactly $Method
            $Result.SetKeyOnly           | Should -BeFalse
            $Result.KeyPath              | Should -BeExactly "HKEY_CURRENT_USER\$RegistryKeyPath"
            $Result.ValueName            | Should -BeExactly $ValueName
            $Result.ValueType            | Should -BeExactly 'DWord'
            $Result.ValueContent         | Should -Be 4
            $Result.PreviousValueType    | Should -BeNullOrEmpty
            $Result.PreviousValueContent | Should -BeNullOrEmpty

            if ($Method -eq 'WMI') {
                $Result.ProcessId            | Should -BeNullOrEmpty
                $Result.ProcessPath          | Should -BeNullOrEmpty
                $Result.ProcessCommandLine   | Should -BeNullOrEmpty
            } else {
                $Result.ProcessId            | Should -Not -BeNullOrEmpty
                $Result.ProcessPath          | Should -Not -BeNullOrEmpty
                $Result.ProcessCommandLine   | Should -Not -BeNullOrEmpty
            }
            
            $Result.TestSampleContent    | Should -Not -BeNullOrEmpty
        } -TestCases @(
            @{ Method = 'PowerShell' },
            @{ Method = 'RegExeCommandLine' },
            @{ Method = 'WMI' },
            @{ Method = 'VBScriptWscriptShellRegWrite' },
            @{ Method = 'JScriptWscriptShellRegWrite' }
        )

        It 'should set a QWord registry value using the following method: <Method>' -Tag 'Technique', 'T1112' {
            # First, ensure that the key doesn't exist
            Remove-Item -Path "Registry::HKEY_CURRENT_USER\$RegistryKeyPath" -Force -ErrorAction Ignore

            $Result = Set-ATHRegistry -Method $Method -Hive HKCU -KeyPath $RegistryKeyPath -ValueName $ValueName -ValueQword 4 -ErrorAction Stop

            $Result | Should -Not -BeNullOrEmpty

            $Result.TechniqueID          | Should -BeExactly $ExpectedTechniqueID
            $Result.TestSuccess          | Should -BeTrue
            $Result.Method               | Should -BeExactly $Method
            $Result.SetKeyOnly           | Should -BeFalse
            $Result.KeyPath              | Should -BeExactly "HKEY_CURRENT_USER\$RegistryKeyPath"
            $Result.ValueName            | Should -BeExactly $ValueName
            $Result.ValueType            | Should -BeExactly 'QWord'
            $Result.ValueContent         | Should -Be 4
            $Result.PreviousValueType    | Should -BeNullOrEmpty
            $Result.PreviousValueContent | Should -BeNullOrEmpty

            if ($Method -eq 'WMI') {
                $Result.ProcessId            | Should -BeNullOrEmpty
                $Result.ProcessPath          | Should -BeNullOrEmpty
                $Result.ProcessCommandLine   | Should -BeNullOrEmpty
            } else {
                $Result.ProcessId            | Should -Not -BeNullOrEmpty
                $Result.ProcessPath          | Should -Not -BeNullOrEmpty
                $Result.ProcessCommandLine   | Should -Not -BeNullOrEmpty
            }
            
            $Result.TestSampleContent    | Should -Not -BeNullOrEmpty
        } -TestCases @(
            @{ Method = 'PowerShell' },
            @{ Method = 'RegExeCommandLine' },
            @{ Method = 'WMI' }
        )

        It 'should set a String registry value for an existing registry value using the following method: <Method>' -Tag 'Technique', 'T1112' {
            # First, ensure that the key doesn't exist
            Remove-Item -Path "Registry::HKEY_CURRENT_USER\$RegistryKeyPath" -Force -ErrorAction Ignore

            # Ensure that the key and the value exist prior to the overwrite
            $null = New-Item -Path 'Registry::HKEY_CURRENT_USER\AtomicTestHarnesses' -Name 'T1112' -ErrorAction Stop
            Set-ItemProperty -Path 'Registry::HKEY_CURRENT_USER\AtomicTestHarnesses\T1112' -Name $ValueName -Type Dword -Value 4 -ErrorAction Stop

            $Result = Set-ATHRegistry -Method $Method -Hive HKCU -KeyPath $RegistryKeyPath -ValueName $ValueName -ValueString 'Hello' -Force -ErrorAction Stop

            $Result | Should -Not -BeNullOrEmpty

            $Result.TechniqueID          | Should -BeExactly $ExpectedTechniqueID
            $Result.TestSuccess          | Should -BeTrue
            $Result.Method               | Should -BeExactly $Method
            $Result.SetKeyOnly           | Should -BeFalse
            $Result.KeyPath              | Should -BeExactly "HKEY_CURRENT_USER\$RegistryKeyPath"
            $Result.ValueName            | Should -BeExactly $ValueName
            $Result.ValueType            | Should -BeExactly 'String'
            $Result.ValueContent         | Should -BeExactly 'Hello'
            $Result.PreviousValueType    | Should -BeExactly 'DWord'
            $Result.PreviousValueContent | Should -Be 4

            if ($Method -eq 'WMI') {
                $Result.ProcessId            | Should -BeNullOrEmpty
                $Result.ProcessPath          | Should -BeNullOrEmpty
                $Result.ProcessCommandLine   | Should -BeNullOrEmpty
            } else {
                $Result.ProcessId            | Should -Not -BeNullOrEmpty
                $Result.ProcessPath          | Should -Not -BeNullOrEmpty
                $Result.ProcessCommandLine   | Should -Not -BeNullOrEmpty
            }
            
            $Result.TestSampleContent    | Should -Not -BeNullOrEmpty
        } -TestCases @(
            @{ Method = 'PowerShell' },
            @{ Method = 'RegExeCommandLine' },
            @{ Method = 'WMI' },
            @{ Method = 'VBScriptWscriptShellRegWrite' },
            @{ Method = 'JScriptWscriptShellRegWrite' }
        )

        It 'should set a ExpandString registry value for an existing registry value using the following method: <Method>' -Tag 'Technique', 'T1112' {
            # First, ensure that the key doesn't exist
            Remove-Item -Path "Registry::HKEY_CURRENT_USER\$RegistryKeyPath" -Force -ErrorAction Ignore

            # Ensure that the key and the value exist prior to the overwrite
            $null = New-Item -Path 'Registry::HKEY_CURRENT_USER\AtomicTestHarnesses' -Name 'T1112' -ErrorAction Stop
            Set-ItemProperty -Path 'Registry::HKEY_CURRENT_USER\AtomicTestHarnesses\T1112' -Name $ValueName -Type String -Value 'Hello' -ErrorAction Stop

            $Result = Set-ATHRegistry -Method $Method -Hive HKCU -KeyPath $RegistryKeyPath -ValueName $ValueName -ValueExpandString '%windir%' -Force -ErrorAction Stop

            $Result | Should -Not -BeNullOrEmpty

            $Result.TechniqueID          | Should -BeExactly $ExpectedTechniqueID
            $Result.TestSuccess          | Should -BeTrue
            $Result.Method               | Should -BeExactly $Method
            $Result.SetKeyOnly           | Should -BeFalse
            $Result.KeyPath              | Should -BeExactly "HKEY_CURRENT_USER\$RegistryKeyPath"
            $Result.ValueName            | Should -BeExactly $ValueName
            $Result.ValueType            | Should -BeExactly 'ExpandString'
            $Result.ValueContent         | Should -Be '%windir%'
            $Result.PreviousValueType    | Should -BeExactly 'String'
            $Result.PreviousValueContent | Should -BeExactly 'Hello'

            if ($Method -eq 'WMI') {
                $Result.ProcessId            | Should -BeNullOrEmpty
                $Result.ProcessPath          | Should -BeNullOrEmpty
                $Result.ProcessCommandLine   | Should -BeNullOrEmpty
            } else {
                $Result.ProcessId            | Should -Not -BeNullOrEmpty
                $Result.ProcessPath          | Should -Not -BeNullOrEmpty
                $Result.ProcessCommandLine   | Should -Not -BeNullOrEmpty
            }
            
            $Result.TestSampleContent    | Should -Not -BeNullOrEmpty
        } -TestCases @(
            @{ Method = 'PowerShell' },
            @{ Method = 'RegExeCommandLine' },
            @{ Method = 'WMI' },
            @{ Method = 'VBScriptWscriptShellRegWrite' },
            @{ Method = 'JScriptWscriptShellRegWrite' }
        )

        It 'should set a MultiString registry value for an existing registry value using the following method: <Method>' -Tag 'Technique', 'T1112' {
            # First, ensure that the key doesn't exist
            Remove-Item -Path "Registry::HKEY_CURRENT_USER\$RegistryKeyPath" -Force -ErrorAction Ignore

            # Ensure that the key and the value exist prior to the overwrite
            $null = New-Item -Path 'Registry::HKEY_CURRENT_USER\AtomicTestHarnesses' -Name 'T1112' -ErrorAction Stop
            Set-ItemProperty -Path 'Registry::HKEY_CURRENT_USER\AtomicTestHarnesses\T1112' -Name $ValueName -Type String -Value 'Hello' -ErrorAction Stop

            $Result = Set-ATHRegistry -Method $Method -Hive HKCU -KeyPath $RegistryKeyPath -ValueName $ValueName -ValueMultiString @('Hello', 'World') -Force -ErrorAction Stop

            $Result | Should -Not -BeNullOrEmpty

            $Result.TechniqueID          | Should -BeExactly $ExpectedTechniqueID
            $Result.TestSuccess          | Should -BeTrue
            $Result.Method               | Should -BeExactly $Method
            $Result.SetKeyOnly           | Should -BeFalse
            $Result.KeyPath              | Should -BeExactly "HKEY_CURRENT_USER\$RegistryKeyPath"
            $Result.ValueName            | Should -BeExactly $ValueName
            $Result.ValueType            | Should -BeExactly 'MultiString'
            $Result.ValueContent -is ([String[]]) | Should -BeTrue
            $Result.ValueContent.Count   | Should -Be 2
            $Result.ValueContent[0]      | Should -Be 'Hello'
            $Result.ValueContent[1]      | Should -Be 'World'
            $Result.PreviousValueType    | Should -BeExactly 'String'
            $Result.PreviousValueContent | Should -BeExactly 'Hello'

            if ($Method -eq 'WMI') {
                $Result.ProcessId            | Should -BeNullOrEmpty
                $Result.ProcessPath          | Should -BeNullOrEmpty
                $Result.ProcessCommandLine   | Should -BeNullOrEmpty
            } else {
                $Result.ProcessId            | Should -Not -BeNullOrEmpty
                $Result.ProcessPath          | Should -Not -BeNullOrEmpty
                $Result.ProcessCommandLine   | Should -Not -BeNullOrEmpty
            }
            
            $Result.TestSampleContent    | Should -Not -BeNullOrEmpty
        } -TestCases @(
            @{ Method = 'PowerShell' },
            @{ Method = 'RegExeCommandLine' },
            @{ Method = 'WMI' }
        )

        It 'should set a Binary registry value for an existing registry value using the following method: <Method>' -Tag 'Technique', 'T1112' {
            # First, ensure that the key doesn't exist
            Remove-Item -Path "Registry::HKEY_CURRENT_USER\$RegistryKeyPath" -Force -ErrorAction Ignore

            # Ensure that the key and the value exist prior to the overwrite
            $null = New-Item -Path 'Registry::HKEY_CURRENT_USER\AtomicTestHarnesses' -Name 'T1112' -ErrorAction Stop
            Set-ItemProperty -Path 'Registry::HKEY_CURRENT_USER\AtomicTestHarnesses\T1112' -Name $ValueName -Type String -Value 'Hello' -ErrorAction Stop

            $Result = Set-ATHRegistry -Method $Method -Hive HKCU -KeyPath $RegistryKeyPath -ValueName $ValueName -ValueBinary @(1,2,3) -Force -ErrorAction Stop

            $Result | Should -Not -BeNullOrEmpty

            $Result.TechniqueID          | Should -BeExactly $ExpectedTechniqueID
            $Result.TestSuccess          | Should -BeTrue
            $Result.Method               | Should -BeExactly $Method
            $Result.SetKeyOnly           | Should -BeFalse
            $Result.KeyPath              | Should -BeExactly "HKEY_CURRENT_USER\$RegistryKeyPath"
            $Result.ValueName            | Should -BeExactly $ValueName
            $Result.ValueType            | Should -BeExactly 'Binary'
            $Result.ValueContent -is ([Byte[]]) | Should -BeTrue
            $Result.ValueContent.Count   | Should -Be 3
            $Result.ValueContent[0]      | Should -Be 1
            $Result.ValueContent[1]      | Should -Be 2
            $Result.ValueContent[2]      | Should -Be 3
            $Result.PreviousValueType    | Should -BeExactly 'String'
            $Result.PreviousValueContent | Should -BeExactly 'Hello'

            if ($Method -eq 'WMI') {
                $Result.ProcessId            | Should -BeNullOrEmpty
                $Result.ProcessPath          | Should -BeNullOrEmpty
                $Result.ProcessCommandLine   | Should -BeNullOrEmpty
            } else {
                $Result.ProcessId            | Should -Not -BeNullOrEmpty
                $Result.ProcessPath          | Should -Not -BeNullOrEmpty
                $Result.ProcessCommandLine   | Should -Not -BeNullOrEmpty
            }
            
            $Result.TestSampleContent    | Should -Not -BeNullOrEmpty
        } -TestCases @(
            @{ Method = 'PowerShell' },
            @{ Method = 'RegExeCommandLine' },
            @{ Method = 'WMI' }
        )

        It 'should set a DWord registry value for an existing registry value using the following method: <Method>' -Tag 'Technique', 'T1112' {
            # First, ensure that the key doesn't exist
            Remove-Item -Path "Registry::HKEY_CURRENT_USER\$RegistryKeyPath" -Force -ErrorAction Ignore

            # Ensure that the key and the value exist prior to the overwrite
            $null = New-Item -Path 'Registry::HKEY_CURRENT_USER\AtomicTestHarnesses' -Name 'T1112' -ErrorAction Stop
            Set-ItemProperty -Path 'Registry::HKEY_CURRENT_USER\AtomicTestHarnesses\T1112' -Name $ValueName -Type String -Value 'Hello' -ErrorAction Stop

            $Result = Set-ATHRegistry -Method $Method -Hive HKCU -KeyPath $RegistryKeyPath -ValueName $ValueName -ValueDword 4 -Force -ErrorAction Stop

            $Result | Should -Not -BeNullOrEmpty

            $Result.TechniqueID          | Should -BeExactly $ExpectedTechniqueID
            $Result.TestSuccess          | Should -BeTrue
            $Result.Method               | Should -BeExactly $Method
            $Result.SetKeyOnly           | Should -BeFalse
            $Result.KeyPath              | Should -BeExactly "HKEY_CURRENT_USER\$RegistryKeyPath"
            $Result.ValueName            | Should -BeExactly $ValueName
            $Result.ValueType            | Should -BeExactly 'DWord'
            $Result.ValueContent         | Should -Be 4
            $Result.PreviousValueType    | Should -BeExactly 'String'
            $Result.PreviousValueContent | Should -BeExactly 'Hello'

            if ($Method -eq 'WMI') {
                $Result.ProcessId            | Should -BeNullOrEmpty
                $Result.ProcessPath          | Should -BeNullOrEmpty
                $Result.ProcessCommandLine   | Should -BeNullOrEmpty
            } else {
                $Result.ProcessId            | Should -Not -BeNullOrEmpty
                $Result.ProcessPath          | Should -Not -BeNullOrEmpty
                $Result.ProcessCommandLine   | Should -Not -BeNullOrEmpty
            }
            
            $Result.TestSampleContent    | Should -Not -BeNullOrEmpty
        } -TestCases @(
            @{ Method = 'PowerShell' },
            @{ Method = 'RegExeCommandLine' },
            @{ Method = 'WMI' },
            @{ Method = 'VBScriptWscriptShellRegWrite' },
            @{ Method = 'JScriptWscriptShellRegWrite' }
        )

        It 'should set a QWord registry value for an existing registry value using the following method: <Method>' -Tag 'Technique', 'T1112' {
            # First, ensure that the key doesn't exist
            Remove-Item -Path "Registry::HKEY_CURRENT_USER\$RegistryKeyPath" -Force -ErrorAction Ignore

            # Ensure that the key and the value exist prior to the overwrite
            $null = New-Item -Path 'Registry::HKEY_CURRENT_USER\AtomicTestHarnesses' -Name 'T1112' -ErrorAction Stop
            Set-ItemProperty -Path 'Registry::HKEY_CURRENT_USER\AtomicTestHarnesses\T1112' -Name $ValueName -Type String -Value 'Hello' -ErrorAction Stop

            $Result = Set-ATHRegistry -Method $Method -Hive HKCU -KeyPath $RegistryKeyPath -ValueName $ValueName -ValueQword 4 -Force -ErrorAction Stop

            $Result | Should -Not -BeNullOrEmpty

            $Result.TechniqueID          | Should -BeExactly $ExpectedTechniqueID
            $Result.TestSuccess          | Should -BeTrue
            $Result.Method               | Should -BeExactly $Method
            $Result.SetKeyOnly           | Should -BeFalse
            $Result.KeyPath              | Should -BeExactly "HKEY_CURRENT_USER\$RegistryKeyPath"
            $Result.ValueName            | Should -BeExactly $ValueName
            $Result.ValueType            | Should -BeExactly 'QWord'
            $Result.ValueContent         | Should -Be 4
            $Result.PreviousValueType    | Should -BeExactly 'String'
            $Result.PreviousValueContent | Should -BeExactly 'Hello'

            if ($Method -eq 'WMI') {
                $Result.ProcessId            | Should -BeNullOrEmpty
                $Result.ProcessPath          | Should -BeNullOrEmpty
                $Result.ProcessCommandLine   | Should -BeNullOrEmpty
            } else {
                $Result.ProcessId            | Should -Not -BeNullOrEmpty
                $Result.ProcessPath          | Should -Not -BeNullOrEmpty
                $Result.ProcessCommandLine   | Should -Not -BeNullOrEmpty
            }
            
            $Result.TestSampleContent    | Should -Not -BeNullOrEmpty
        } -TestCases @(
            @{ Method = 'PowerShell' },
            @{ Method = 'RegExeCommandLine' },
            @{ Method = 'WMI' }
        )

        It 'should set String content for the "(Default)" registry value using the following method: <Method>' -Tag 'Technique', 'T1112' {
            # First, ensure that the key doesn't exist
            Remove-Item -Path "Registry::HKEY_CURRENT_USER\$RegistryKeyPath" -Force -ErrorAction Ignore

            $Result = Set-ATHRegistry -Method $Method -Hive HKCU -KeyPath $RegistryKeyPath -ValueName '(Default)' -ValueString 'Hello' -ErrorAction Stop

            $Result | Should -Not -BeNullOrEmpty

            $Result.TechniqueID          | Should -BeExactly $ExpectedTechniqueID
            $Result.TestSuccess          | Should -BeTrue
            $Result.Method               | Should -BeExactly $Method
            $Result.SetKeyOnly           | Should -BeFalse
            $Result.KeyPath              | Should -BeExactly "HKEY_CURRENT_USER\$RegistryKeyPath"
            $Result.ValueName            | Should -BeExactly '(Default)'
            $Result.ValueType            | Should -BeExactly 'String'
            $Result.ValueContent         | Should -Be 'Hello'
            $Result.PreviousValueType    | Should -BeNullOrEmpty
            $Result.PreviousValueContent | Should -BeNullOrEmpty

            if ($Method -eq 'WMI') {
                $Result.ProcessId            | Should -BeNullOrEmpty
                $Result.ProcessPath          | Should -BeNullOrEmpty
                $Result.ProcessCommandLine   | Should -BeNullOrEmpty
            } else {
                $Result.ProcessId            | Should -Not -BeNullOrEmpty
                $Result.ProcessPath          | Should -Not -BeNullOrEmpty
                $Result.ProcessCommandLine   | Should -Not -BeNullOrEmpty
            }
            
            $Result.TestSampleContent    | Should -Not -BeNullOrEmpty
        } -TestCases @(
            @{ Method = 'PowerShell' },
            @{ Method = 'RegExeCommandLine' },
            @{ Method = 'WMI' },
            @{ Method = 'VBScriptWscriptShellRegWrite' },
            @{ Method = 'JScriptWscriptShellRegWrite' }
        )
    }
}