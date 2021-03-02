Set-StrictMode -Version Latest

$TestScriptRoot = Split-Path $MyInvocation.MyCommand.Path -Parent
$ModuleRoot = Resolve-Path "$TestScriptRoot\..\..\"
$ModuleManifest = "$ModuleRoot\AtomicTestHarnesses.psd1"

Remove-Module [A]tomicTestHarnesses
Import-Module $ModuleManifest -Force -ErrorAction Stop

Describe 'Invoke-ATHCompiledHelp' {
    BeforeAll {
        $Help = Get-Help -Name Invoke-ATHCompiledHelp -Full
    
        $ExpectedTechniqueID = $null

        if ($Help.Synopsis.Split("`r`n")[-1] -match '^(?-i:Technique ID: )(?<TechniqueID>\S+) (?<TechniqueDescription>\(.+\))$') {
            $ExpectedTechniqueID = $Matches['TechniqueID']
        }
    }

    Context 'Validating error conditions' -Tag 'Unit', 'T1218.001' {
        BeforeEach {
            Get-Process -Name hh -ErrorAction SilentlyContinue | Stop-Process -Force
        }

        It 'hh.exe execution should not execute notepad.exe' -Tag 'Unit', 'T1218.001' {
            { Invoke-ATHCompiledHelp -HHFilePath "$Env:windir\System32\notepad.exe" -ErrorAction Stop } | Should -Throw
        }

        It 'should not run test when a non-existent CHM path is specified' -Tag 'Unit', 'T1218.001' {
            $BogusPath = 'C:\dsdfsiuhsdrfsawgfds'

            Test-Path -Path $BogusPath -PathType Container | Should -BeFalse

            { Invoke-ATHCompiledHelp -CHMFilePath $BogusPath -ErrorAction Stop } | Should -Throw
        }

        It "should not write to a directory that it does not have write access to: $Env:SystemDrive\" -Tag 'Unit', 'T1218.001' {
            { Invoke-ATHCompiledHelp -CHMFilePath "$Env:SystemDrive\Test.chm" -ErrorAction Stop } | Should -Throw
        }

        It 'should indicate that the CHM runner process failed to start' -Tag 'Unit', 'T1218.001' {
            Mock Invoke-CimMethod { return @{ ReturnValue = 1 } }

            { Invoke-ATHCompiledHelp -ErrorAction Stop } | Should -Throw
        }

        It 'should indicate that the CHM child process failed to launch' -Tag 'Unit', 'T1218.001' {
            Mock Wait-Event { return $null }

            { Invoke-ATHCompiledHelp -ErrorAction Stop } | Should -Throw

            Start-Sleep -Seconds 1

            Get-Process -Name hh -ErrorAction SilentlyContinue | Stop-Process -Force

            $Result = Invoke-ATHCompiledHelp -ErrorAction SilentlyContinue

            Should -Invoke Wait-Event -Times 2

            $Result.TechniqueID                   | Should -BeExactly $ExpectedTechniqueID
            $Result.TestSuccess                   | Should -BeNullOrEmpty
            $Result.TestGuid                      | Should -Not -BeNullOrEmpty
            $Result.ExecutionType                 | Should -Not -BeNullOrEmpty
            $Result.ScriptEngine                  | Should -Not -BeNullOrEmpty
            $Result.CHMFilePath                   | Should -Not -BeNullOrEmpty
            $Result.CHMFileHashSHA256             | Should -Not -BeNullOrEmpty
            $Result.RunnerFilePath                | Should -Not -BeNullOrEmpty
            $Result.RunnerProcessId               | Should -Not -BeNullOrEmpty
            $Result.RunnerCommandLine             | Should -Not -BeNullOrEmpty
            $Result.RunnerChildProcessId          | Should -BeNullOrEmpty
            $Result.RunnerChildProcessCommandLine | Should -BeNullOrEmpty
        }

        AfterEach {
            Start-Sleep -Seconds 1

            Get-Process -Name hh -ErrorAction SilentlyContinue | Stop-Process -Force
        }
    }

    Context 'Expected artifacts and behaviors when exercising the attack technique' -Tag 'Technique', 'T1218.001' {
        BeforeAll {
            $Script:AlternateHHPath = "$env:windir\Temp\notepad.exe"

            Copy-Item -Path $env:windir\hh.exe -Destination $Script:AlternateHHPath

            $Script:FixedTestGuid = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
            $Script:ExpectedCHMHash = 'F9FCCC38771ACEC6EC2FD0042DC4417F7BCDDE3D95FE4864D086E6641CA23CF8'
            $Script:AlternateCHMFileName = 'Foo.chm'
        }

        It 'should execute the default help topic (UseAlternateCHMName: <UseAlternateCHMName>, UseAlternateHHPath: <UseAlternateHHPath>, InfoTechStorageHandler: <InfoTechStorageHandler>)' -Tag 'Technique', 'T1218.001' {
            $Arguments = @{}

            if ($UseAlternateCHMName) {
                $ExpectedFileName = $AlternateCHMFileName

                $Arguments['CHMFilePath'] = $ExpectedFileName
            } else {
                $ExpectedFileName = 'Test.chm'
            }

            if ($UseAlternateHHPath) {
                $ExpectedHHFileName = $AlternateHHPath.Split('\')[-1]

                $Arguments['HHFilePath'] = $AlternateHHPath
            } else {
                $ExpectedHHFileName = 'hh.exe'
            }

            if ($InfoTechStorageHandler) { $Arguments['InfoTechStorageHandler'] = $InfoTechStorageHandler }

            $Result = Invoke-ATHCompiledHelp -TestGuid $FixedTestGuid @Arguments

            $Result | Should -Not -BeNullOrEmpty

            $Result.TechniqueID                   | Should -BeExactly $ExpectedTechniqueID
            $Result.TestSuccess                   | Should -BeTrue
            $Result.TestGuid                      | Should -BeExactly $FixedTestGuid
            $Result.ExecutionType                 | Should -BeExactly 'ShortcutCommandDefault'
            $Result.ScriptEngine                  | Should -BeExactly 'None'
            $Result.CHMFilePath                   | Should -Not -BeNullOrEmpty
            $Result.CHMFilePath.EndsWith($ExpectedFileName) | Should -BeTrue
            $Result.CHMFileHashSHA256             | Should -BeExactly $ExpectedCHMHash
            $Result.RunnerFilePath                | Should -Not -BeNullOrEmpty
            $Result.RunnerFilePath.EndsWith($ExpectedHHFileName) | Should -BeTrue
            $Result.RunnerProcessId               | Should -Not -BeNullOrEmpty
            $Result.RunnerCommandLine             | Should -Not -BeNullOrEmpty
            if ($InfoTechStorageHandler) {
                $Result.RunnerCommandLine         | Should -Match "`"$($InfoTechStorageHandler):" # The storage handler should be present in the command-line
            }
            $Result.RunnerChildProcessId          | Should -Not -BeNullOrEmpty
            $Result.RunnerChildProcessCommandLine | Should -Match $FixedTestGuid

            $Result
        } -TestCases @(
            @{ UseAlternateCHMName = $False; UseAlternateHHPath = $False; InfoTechStorageHandler = $null },
            @{ UseAlternateCHMName = $True;  UseAlternateHHPath = $False; InfoTechStorageHandler = $null },
            @{ UseAlternateCHMName = $False; UseAlternateHHPath = $True;  InfoTechStorageHandler = $null },
            @{ UseAlternateCHMName = $True;  UseAlternateHHPath = $True;  InfoTechStorageHandler = $null },
            @{ UseAlternateCHMName = $False; UseAlternateHHPath = $False; InfoTechStorageHandler = 'its' },
            @{ UseAlternateCHMName = $True;  UseAlternateHHPath = $False; InfoTechStorageHandler = 'its' },
            @{ UseAlternateCHMName = $False; UseAlternateHHPath = $True;  InfoTechStorageHandler = 'its' },
            @{ UseAlternateCHMName = $True;  UseAlternateHHPath = $True;  InfoTechStorageHandler = 'its' },
            @{ UseAlternateCHMName = $False; UseAlternateHHPath = $False; InfoTechStorageHandler = 'ms-its' },
            @{ UseAlternateCHMName = $True;  UseAlternateHHPath = $False; InfoTechStorageHandler = 'ms-its' },
            @{ UseAlternateCHMName = $False; UseAlternateHHPath = $True;  InfoTechStorageHandler = 'ms-its' },
            @{ UseAlternateCHMName = $True;  UseAlternateHHPath = $True;  InfoTechStorageHandler = 'ms-its' },
            @{ UseAlternateCHMName = $False; UseAlternateHHPath = $False; InfoTechStorageHandler = 'mk:@MSITStore' },
            @{ UseAlternateCHMName = $True;  UseAlternateHHPath = $False; InfoTechStorageHandler = 'mk:@MSITStore' },
            @{ UseAlternateCHMName = $False; UseAlternateHHPath = $True;  InfoTechStorageHandler = 'mk:@MSITStore' },
            @{ UseAlternateCHMName = $True;  UseAlternateHHPath = $True;  InfoTechStorageHandler = 'mk:@MSITStore' }
        )

        It 'should simulate a CHM doubleclick (UseAlternateCHMName: <UseAlternateCHMName>)' -Tag 'Technique', 'T1218.001' {
            $Arguments = @{}

            if ($UseAlternateCHMName) {
                $ExpectedFileName = $AlternateCHMFileName

                $Arguments['CHMFilePath'] = $ExpectedFileName
            } else {
                $ExpectedFileName = 'Test.chm'
            }

            $Result = Invoke-ATHCompiledHelp -SimulateUserDoubleClick -TestGuid $FixedTestGuid @Arguments

            $Result | Should -Not -BeNullOrEmpty

            $Result.TechniqueID                   | Should -BeExactly $ExpectedTechniqueID
            $Result.TestSuccess                   | Should -BeTrue
            $Result.TestGuid                      | Should -BeExactly $FixedTestGuid
            $Result.ExecutionType                 | Should -BeExactly 'ShortcutCommandDoubleClick'
            $Result.ScriptEngine                  | Should -BeExactly 'None'
            $Result.CHMFilePath                   | Should -Not -BeNullOrEmpty
            $Result.CHMFilePath.EndsWith($ExpectedFileName) | Should -BeTrue
            $Result.CHMFileHashSHA256             | Should -BeExactly $ExpectedCHMHash
            $Result.RunnerFilePath                | Should -Not -BeNullOrEmpty
            $Result.RunnerFilePath.EndsWith('hh.exe') | Should -BeTrue
            $Result.RunnerProcessId               | Should -Not -BeNullOrEmpty
            $Result.RunnerCommandLine             | Should -Not -BeNullOrEmpty
            $Result.RunnerChildProcessId          | Should -Not -BeNullOrEmpty
            $Result.RunnerChildProcessCommandLine | Should -Match $FixedTestGuid

            $Result
        } -TestCases @(
            @{ UseAlternateCHMName = $False },
            @{ UseAlternateCHMName = $True }
        )

        It 'should execute WSH script code via specification of specific help topics (UseAlternateCHMName: <UseAlternateCHMName>, UseAlternateHHPath: <UseAlternateHHPath>, InfoTechStorageHandler: <InfoTechStorageHandler>, TopicExtension: <TopicExtension>, ScriptEngine: <ScriptEngine>)' -Tag 'Technique', 'T1218.001' {
            $Arguments = @{}

            if ($UseAlternateCHMName) {
                $ExpectedFileName = $AlternateCHMFileName

                $Arguments['CHMFilePath'] = $ExpectedFileName
            } else {
                $ExpectedFileName = 'Test.chm'
            }

            if ($UseAlternateHHPath) {
                $ExpectedHHFileName = $AlternateHHPath.Split('\')[-1]

                $Arguments['HHFilePath'] = $AlternateHHPath
            } else {
                $ExpectedHHFileName = 'hh.exe'
            }

            $Result = Invoke-ATHCompiledHelp -ScriptEngine $ScriptEngine -InfoTechStorageHandler $InfoTechStorageHandler -TopicExtension $TopicExtension -TestGuid $FixedTestGuid @Arguments

            $Result | Should -Not -BeNullOrEmpty

            $Result.TechniqueID                   | Should -BeExactly $ExpectedTechniqueID
            $Result.TestSuccess                   | Should -BeTrue
            $Result.TestGuid                      | Should -BeExactly $FixedTestGuid
            $Result.ExecutionType                 | Should -BeExactly 'WSHScriptTopic'
            $Result.ScriptEngine                  | Should -BeExactly $ScriptEngine
            $Result.CHMFilePath                   | Should -Not -BeNullOrEmpty
            $Result.CHMFilePath.EndsWith($ExpectedFileName) | Should -BeTrue
            $Result.CHMFileHashSHA256             | Should -BeExactly $ExpectedCHMHash
            $Result.RunnerFilePath                | Should -Not -BeNullOrEmpty
            $Result.RunnerFilePath.EndsWith($ExpectedHHFileName) | Should -BeTrue
            $Result.RunnerProcessId               | Should -Not -BeNullOrEmpty
            $Result.RunnerCommandLine             | Should -Match "`"$($InfoTechStorageHandler):.*::/TEMPLATE" # The storage handler should be present in the command-line
            $Result.RunnerChildProcessId          | Should -Not -BeNullOrEmpty
            $Result.RunnerChildProcessCommandLine | Should -Match $FixedTestGuid

            $Result
        } -TestCases @(
            @{ UseAlternateCHMName = $False; UseAlternateHHPath = $False; InfoTechStorageHandler = 'its'; TopicExtension = 'htm';  ScriptEngine = 'JScript' },
            @{ UseAlternateCHMName = $False; UseAlternateHHPath = $True;  InfoTechStorageHandler = 'its'; TopicExtension = 'htm';  ScriptEngine = 'JScript' },
            @{ UseAlternateCHMName = $True;  UseAlternateHHPath = $False; InfoTechStorageHandler = 'its'; TopicExtension = 'htm';  ScriptEngine = 'JScript' },
            @{ UseAlternateCHMName = $True;  UseAlternateHHPath = $True;  InfoTechStorageHandler = 'its'; TopicExtension = 'htm';  ScriptEngine = 'JScript' },
            @{ UseAlternateCHMName = $False; UseAlternateHHPath = $False; InfoTechStorageHandler = 'its'; TopicExtension = 'html'; ScriptEngine = 'JScript' },
            @{ UseAlternateCHMName = $False; UseAlternateHHPath = $True;  InfoTechStorageHandler = 'its'; TopicExtension = 'html'; ScriptEngine = 'JScript' },
            @{ UseAlternateCHMName = $True;  UseAlternateHHPath = $False; InfoTechStorageHandler = 'its'; TopicExtension = 'html'; ScriptEngine = 'JScript' },
            @{ UseAlternateCHMName = $True;  UseAlternateHHPath = $True;  InfoTechStorageHandler = 'its'; TopicExtension = 'html'; ScriptEngine = 'JScript' },
            @{ UseAlternateCHMName = $False; UseAlternateHHPath = $False; InfoTechStorageHandler = 'ms-its'; TopicExtension = 'htm';  ScriptEngine = 'JScript' },
            @{ UseAlternateCHMName = $False; UseAlternateHHPath = $True;  InfoTechStorageHandler = 'ms-its'; TopicExtension = 'htm';  ScriptEngine = 'JScript' },
            @{ UseAlternateCHMName = $True;  UseAlternateHHPath = $False; InfoTechStorageHandler = 'ms-its'; TopicExtension = 'htm';  ScriptEngine = 'JScript' },
            @{ UseAlternateCHMName = $True;  UseAlternateHHPath = $True;  InfoTechStorageHandler = 'ms-its'; TopicExtension = 'htm';  ScriptEngine = 'JScript' },
            @{ UseAlternateCHMName = $False; UseAlternateHHPath = $False; InfoTechStorageHandler = 'ms-its'; TopicExtension = 'html'; ScriptEngine = 'JScript' },
            @{ UseAlternateCHMName = $False; UseAlternateHHPath = $True;  InfoTechStorageHandler = 'ms-its'; TopicExtension = 'html'; ScriptEngine = 'JScript' },
            @{ UseAlternateCHMName = $True;  UseAlternateHHPath = $False; InfoTechStorageHandler = 'ms-its'; TopicExtension = 'html'; ScriptEngine = 'JScript' },
            @{ UseAlternateCHMName = $True;  UseAlternateHHPath = $True;  InfoTechStorageHandler = 'ms-its'; TopicExtension = 'html'; ScriptEngine = 'JScript' },
            @{ UseAlternateCHMName = $False; UseAlternateHHPath = $False; InfoTechStorageHandler = 'mk:@MSITStore'; TopicExtension = 'htm';  ScriptEngine = 'JScript' },
            @{ UseAlternateCHMName = $False; UseAlternateHHPath = $True;  InfoTechStorageHandler = 'mk:@MSITStore'; TopicExtension = 'htm';  ScriptEngine = 'JScript' },
            @{ UseAlternateCHMName = $True;  UseAlternateHHPath = $False; InfoTechStorageHandler = 'mk:@MSITStore'; TopicExtension = 'htm';  ScriptEngine = 'JScript' },
            @{ UseAlternateCHMName = $True;  UseAlternateHHPath = $True;  InfoTechStorageHandler = 'mk:@MSITStore'; TopicExtension = 'htm';  ScriptEngine = 'JScript' },
            @{ UseAlternateCHMName = $False; UseAlternateHHPath = $False; InfoTechStorageHandler = 'mk:@MSITStore'; TopicExtension = 'html'; ScriptEngine = 'JScript' },
            @{ UseAlternateCHMName = $False; UseAlternateHHPath = $True;  InfoTechStorageHandler = 'mk:@MSITStore'; TopicExtension = 'html'; ScriptEngine = 'JScript' },
            @{ UseAlternateCHMName = $True;  UseAlternateHHPath = $False; InfoTechStorageHandler = 'mk:@MSITStore'; TopicExtension = 'html'; ScriptEngine = 'JScript' },
            @{ UseAlternateCHMName = $True;  UseAlternateHHPath = $True;  InfoTechStorageHandler = 'mk:@MSITStore'; TopicExtension = 'html'; ScriptEngine = 'JScript' },

            @{ UseAlternateCHMName = $False; UseAlternateHHPath = $False; InfoTechStorageHandler = 'its'; TopicExtension = 'htm';  ScriptEngine = 'JScript.Compact' },
            @{ UseAlternateCHMName = $False; UseAlternateHHPath = $True;  InfoTechStorageHandler = 'its'; TopicExtension = 'htm';  ScriptEngine = 'JScript.Compact' },
            @{ UseAlternateCHMName = $True;  UseAlternateHHPath = $False; InfoTechStorageHandler = 'its'; TopicExtension = 'htm';  ScriptEngine = 'JScript.Compact' },
            @{ UseAlternateCHMName = $True;  UseAlternateHHPath = $True;  InfoTechStorageHandler = 'its'; TopicExtension = 'htm';  ScriptEngine = 'JScript.Compact' },
            @{ UseAlternateCHMName = $False; UseAlternateHHPath = $False; InfoTechStorageHandler = 'its'; TopicExtension = 'html'; ScriptEngine = 'JScript.Compact' },
            @{ UseAlternateCHMName = $False; UseAlternateHHPath = $True;  InfoTechStorageHandler = 'its'; TopicExtension = 'html'; ScriptEngine = 'JScript.Compact' },
            @{ UseAlternateCHMName = $True;  UseAlternateHHPath = $False; InfoTechStorageHandler = 'its'; TopicExtension = 'html'; ScriptEngine = 'JScript.Compact' },
            @{ UseAlternateCHMName = $True;  UseAlternateHHPath = $True;  InfoTechStorageHandler = 'its'; TopicExtension = 'html'; ScriptEngine = 'JScript.Compact' },
            @{ UseAlternateCHMName = $False; UseAlternateHHPath = $False; InfoTechStorageHandler = 'ms-its'; TopicExtension = 'htm';  ScriptEngine = 'JScript.Compact' },
            @{ UseAlternateCHMName = $False; UseAlternateHHPath = $True;  InfoTechStorageHandler = 'ms-its'; TopicExtension = 'htm';  ScriptEngine = 'JScript.Compact' },
            @{ UseAlternateCHMName = $True;  UseAlternateHHPath = $False; InfoTechStorageHandler = 'ms-its'; TopicExtension = 'htm';  ScriptEngine = 'JScript.Compact' },
            @{ UseAlternateCHMName = $True;  UseAlternateHHPath = $True;  InfoTechStorageHandler = 'ms-its'; TopicExtension = 'htm';  ScriptEngine = 'JScript.Compact' },
            @{ UseAlternateCHMName = $False; UseAlternateHHPath = $False; InfoTechStorageHandler = 'ms-its'; TopicExtension = 'html'; ScriptEngine = 'JScript.Compact' },
            @{ UseAlternateCHMName = $False; UseAlternateHHPath = $True;  InfoTechStorageHandler = 'ms-its'; TopicExtension = 'html'; ScriptEngine = 'JScript.Compact' },
            @{ UseAlternateCHMName = $True;  UseAlternateHHPath = $False; InfoTechStorageHandler = 'ms-its'; TopicExtension = 'html'; ScriptEngine = 'JScript.Compact' },
            @{ UseAlternateCHMName = $True;  UseAlternateHHPath = $True;  InfoTechStorageHandler = 'ms-its'; TopicExtension = 'html'; ScriptEngine = 'JScript.Compact' },
            @{ UseAlternateCHMName = $False; UseAlternateHHPath = $False; InfoTechStorageHandler = 'mk:@MSITStore'; TopicExtension = 'htm';  ScriptEngine = 'JScript.Compact' },
            @{ UseAlternateCHMName = $False; UseAlternateHHPath = $True;  InfoTechStorageHandler = 'mk:@MSITStore'; TopicExtension = 'htm';  ScriptEngine = 'JScript.Compact' },
            @{ UseAlternateCHMName = $True;  UseAlternateHHPath = $False; InfoTechStorageHandler = 'mk:@MSITStore'; TopicExtension = 'htm';  ScriptEngine = 'JScript.Compact' },
            @{ UseAlternateCHMName = $True;  UseAlternateHHPath = $True;  InfoTechStorageHandler = 'mk:@MSITStore'; TopicExtension = 'htm';  ScriptEngine = 'JScript.Compact' },
            @{ UseAlternateCHMName = $False; UseAlternateHHPath = $False; InfoTechStorageHandler = 'mk:@MSITStore'; TopicExtension = 'html'; ScriptEngine = 'JScript.Compact' },
            @{ UseAlternateCHMName = $False; UseAlternateHHPath = $True;  InfoTechStorageHandler = 'mk:@MSITStore'; TopicExtension = 'html'; ScriptEngine = 'JScript.Compact' },
            @{ UseAlternateCHMName = $True;  UseAlternateHHPath = $False; InfoTechStorageHandler = 'mk:@MSITStore'; TopicExtension = 'html'; ScriptEngine = 'JScript.Compact' },
            @{ UseAlternateCHMName = $True;  UseAlternateHHPath = $True;  InfoTechStorageHandler = 'mk:@MSITStore'; TopicExtension = 'html'; ScriptEngine = 'JScript.Compact' },

            @{ UseAlternateCHMName = $False; UseAlternateHHPath = $False; InfoTechStorageHandler = 'its'; TopicExtension = 'htm';  ScriptEngine = 'JScript.Encode' },
            @{ UseAlternateCHMName = $False; UseAlternateHHPath = $True;  InfoTechStorageHandler = 'its'; TopicExtension = 'htm';  ScriptEngine = 'JScript.Encode' },
            @{ UseAlternateCHMName = $True;  UseAlternateHHPath = $False; InfoTechStorageHandler = 'its'; TopicExtension = 'htm';  ScriptEngine = 'JScript.Encode' },
            @{ UseAlternateCHMName = $True;  UseAlternateHHPath = $True;  InfoTechStorageHandler = 'its'; TopicExtension = 'htm';  ScriptEngine = 'JScript.Encode' },
            @{ UseAlternateCHMName = $False; UseAlternateHHPath = $False; InfoTechStorageHandler = 'its'; TopicExtension = 'html'; ScriptEngine = 'JScript.Encode' },
            @{ UseAlternateCHMName = $False; UseAlternateHHPath = $True;  InfoTechStorageHandler = 'its'; TopicExtension = 'html'; ScriptEngine = 'JScript.Encode' },
            @{ UseAlternateCHMName = $True;  UseAlternateHHPath = $False; InfoTechStorageHandler = 'its'; TopicExtension = 'html'; ScriptEngine = 'JScript.Encode' },
            @{ UseAlternateCHMName = $True;  UseAlternateHHPath = $True;  InfoTechStorageHandler = 'its'; TopicExtension = 'html'; ScriptEngine = 'JScript.Encode' },
            @{ UseAlternateCHMName = $False; UseAlternateHHPath = $False; InfoTechStorageHandler = 'ms-its'; TopicExtension = 'htm';  ScriptEngine = 'JScript.Encode' },
            @{ UseAlternateCHMName = $False; UseAlternateHHPath = $True;  InfoTechStorageHandler = 'ms-its'; TopicExtension = 'htm';  ScriptEngine = 'JScript.Encode' },
            @{ UseAlternateCHMName = $True;  UseAlternateHHPath = $False; InfoTechStorageHandler = 'ms-its'; TopicExtension = 'htm';  ScriptEngine = 'JScript.Encode' },
            @{ UseAlternateCHMName = $True;  UseAlternateHHPath = $True;  InfoTechStorageHandler = 'ms-its'; TopicExtension = 'htm';  ScriptEngine = 'JScript.Encode' },
            @{ UseAlternateCHMName = $False; UseAlternateHHPath = $False; InfoTechStorageHandler = 'ms-its'; TopicExtension = 'html'; ScriptEngine = 'JScript.Encode' },
            @{ UseAlternateCHMName = $False; UseAlternateHHPath = $True;  InfoTechStorageHandler = 'ms-its'; TopicExtension = 'html'; ScriptEngine = 'JScript.Encode' },
            @{ UseAlternateCHMName = $True;  UseAlternateHHPath = $False; InfoTechStorageHandler = 'ms-its'; TopicExtension = 'html'; ScriptEngine = 'JScript.Encode' },
            @{ UseAlternateCHMName = $True;  UseAlternateHHPath = $True;  InfoTechStorageHandler = 'ms-its'; TopicExtension = 'html'; ScriptEngine = 'JScript.Encode' },
            @{ UseAlternateCHMName = $False; UseAlternateHHPath = $False; InfoTechStorageHandler = 'mk:@MSITStore'; TopicExtension = 'htm';  ScriptEngine = 'JScript.Encode' },
            @{ UseAlternateCHMName = $False; UseAlternateHHPath = $True;  InfoTechStorageHandler = 'mk:@MSITStore'; TopicExtension = 'htm';  ScriptEngine = 'JScript.Encode' },
            @{ UseAlternateCHMName = $True;  UseAlternateHHPath = $False; InfoTechStorageHandler = 'mk:@MSITStore'; TopicExtension = 'htm';  ScriptEngine = 'JScript.Encode' },
            @{ UseAlternateCHMName = $True;  UseAlternateHHPath = $True;  InfoTechStorageHandler = 'mk:@MSITStore'; TopicExtension = 'htm';  ScriptEngine = 'JScript.Encode' },
            @{ UseAlternateCHMName = $False; UseAlternateHHPath = $False; InfoTechStorageHandler = 'mk:@MSITStore'; TopicExtension = 'html'; ScriptEngine = 'JScript.Encode' },
            @{ UseAlternateCHMName = $False; UseAlternateHHPath = $True;  InfoTechStorageHandler = 'mk:@MSITStore'; TopicExtension = 'html'; ScriptEngine = 'JScript.Encode' },
            @{ UseAlternateCHMName = $True;  UseAlternateHHPath = $False; InfoTechStorageHandler = 'mk:@MSITStore'; TopicExtension = 'html'; ScriptEngine = 'JScript.Encode' },
            @{ UseAlternateCHMName = $True;  UseAlternateHHPath = $True;  InfoTechStorageHandler = 'mk:@MSITStore'; TopicExtension = 'html'; ScriptEngine = 'JScript.Encode' },

            @{ UseAlternateCHMName = $False; UseAlternateHHPath = $False; InfoTechStorageHandler = 'its'; TopicExtension = 'htm';  ScriptEngine = 'VBScript' },
            @{ UseAlternateCHMName = $False; UseAlternateHHPath = $True;  InfoTechStorageHandler = 'its'; TopicExtension = 'htm';  ScriptEngine = 'VBScript' },
            @{ UseAlternateCHMName = $True;  UseAlternateHHPath = $False; InfoTechStorageHandler = 'its'; TopicExtension = 'htm';  ScriptEngine = 'VBScript' },
            @{ UseAlternateCHMName = $True;  UseAlternateHHPath = $True;  InfoTechStorageHandler = 'its'; TopicExtension = 'htm';  ScriptEngine = 'VBScript' },
            @{ UseAlternateCHMName = $False; UseAlternateHHPath = $False; InfoTechStorageHandler = 'its'; TopicExtension = 'html'; ScriptEngine = 'VBScript' },
            @{ UseAlternateCHMName = $False; UseAlternateHHPath = $True;  InfoTechStorageHandler = 'its'; TopicExtension = 'html'; ScriptEngine = 'VBScript' },
            @{ UseAlternateCHMName = $True;  UseAlternateHHPath = $False; InfoTechStorageHandler = 'its'; TopicExtension = 'html'; ScriptEngine = 'VBScript' },
            @{ UseAlternateCHMName = $True;  UseAlternateHHPath = $True;  InfoTechStorageHandler = 'its'; TopicExtension = 'html'; ScriptEngine = 'VBScript' },
            @{ UseAlternateCHMName = $False; UseAlternateHHPath = $False; InfoTechStorageHandler = 'ms-its'; TopicExtension = 'htm';  ScriptEngine = 'VBScript' },
            @{ UseAlternateCHMName = $False; UseAlternateHHPath = $True;  InfoTechStorageHandler = 'ms-its'; TopicExtension = 'htm';  ScriptEngine = 'VBScript' },
            @{ UseAlternateCHMName = $True;  UseAlternateHHPath = $False; InfoTechStorageHandler = 'ms-its'; TopicExtension = 'htm';  ScriptEngine = 'VBScript' },
            @{ UseAlternateCHMName = $True;  UseAlternateHHPath = $True;  InfoTechStorageHandler = 'ms-its'; TopicExtension = 'htm';  ScriptEngine = 'VBScript' },
            @{ UseAlternateCHMName = $False; UseAlternateHHPath = $False; InfoTechStorageHandler = 'ms-its'; TopicExtension = 'html'; ScriptEngine = 'VBScript' },
            @{ UseAlternateCHMName = $False; UseAlternateHHPath = $True;  InfoTechStorageHandler = 'ms-its'; TopicExtension = 'html'; ScriptEngine = 'VBScript' },
            @{ UseAlternateCHMName = $True;  UseAlternateHHPath = $False; InfoTechStorageHandler = 'ms-its'; TopicExtension = 'html'; ScriptEngine = 'VBScript' },
            @{ UseAlternateCHMName = $True;  UseAlternateHHPath = $True;  InfoTechStorageHandler = 'ms-its'; TopicExtension = 'html'; ScriptEngine = 'VBScript' },
            @{ UseAlternateCHMName = $False; UseAlternateHHPath = $False; InfoTechStorageHandler = 'mk:@MSITStore'; TopicExtension = 'htm';  ScriptEngine = 'VBScript' },
            @{ UseAlternateCHMName = $False; UseAlternateHHPath = $True;  InfoTechStorageHandler = 'mk:@MSITStore'; TopicExtension = 'htm';  ScriptEngine = 'VBScript' },
            @{ UseAlternateCHMName = $True;  UseAlternateHHPath = $False; InfoTechStorageHandler = 'mk:@MSITStore'; TopicExtension = 'htm';  ScriptEngine = 'VBScript' },
            @{ UseAlternateCHMName = $True;  UseAlternateHHPath = $True;  InfoTechStorageHandler = 'mk:@MSITStore'; TopicExtension = 'htm';  ScriptEngine = 'VBScript' },
            @{ UseAlternateCHMName = $False; UseAlternateHHPath = $False; InfoTechStorageHandler = 'mk:@MSITStore'; TopicExtension = 'html'; ScriptEngine = 'VBScript' },
            @{ UseAlternateCHMName = $False; UseAlternateHHPath = $True;  InfoTechStorageHandler = 'mk:@MSITStore'; TopicExtension = 'html'; ScriptEngine = 'VBScript' },
            @{ UseAlternateCHMName = $True;  UseAlternateHHPath = $False; InfoTechStorageHandler = 'mk:@MSITStore'; TopicExtension = 'html'; ScriptEngine = 'VBScript' },
            @{ UseAlternateCHMName = $True;  UseAlternateHHPath = $True;  InfoTechStorageHandler = 'mk:@MSITStore'; TopicExtension = 'html'; ScriptEngine = 'VBScript' },

            @{ UseAlternateCHMName = $False; UseAlternateHHPath = $False; InfoTechStorageHandler = 'its'; TopicExtension = 'htm';  ScriptEngine = 'VBScript.Encode' },
            @{ UseAlternateCHMName = $False; UseAlternateHHPath = $True;  InfoTechStorageHandler = 'its'; TopicExtension = 'htm';  ScriptEngine = 'VBScript.Encode' },
            @{ UseAlternateCHMName = $True;  UseAlternateHHPath = $False; InfoTechStorageHandler = 'its'; TopicExtension = 'htm';  ScriptEngine = 'VBScript.Encode' },
            @{ UseAlternateCHMName = $True;  UseAlternateHHPath = $True;  InfoTechStorageHandler = 'its'; TopicExtension = 'htm';  ScriptEngine = 'VBScript.Encode' },
            @{ UseAlternateCHMName = $False; UseAlternateHHPath = $False; InfoTechStorageHandler = 'its'; TopicExtension = 'html'; ScriptEngine = 'VBScript.Encode' },
            @{ UseAlternateCHMName = $False; UseAlternateHHPath = $True;  InfoTechStorageHandler = 'its'; TopicExtension = 'html'; ScriptEngine = 'VBScript.Encode' },
            @{ UseAlternateCHMName = $True;  UseAlternateHHPath = $False; InfoTechStorageHandler = 'its'; TopicExtension = 'html'; ScriptEngine = 'VBScript.Encode' },
            @{ UseAlternateCHMName = $True;  UseAlternateHHPath = $True;  InfoTechStorageHandler = 'its'; TopicExtension = 'html'; ScriptEngine = 'VBScript.Encode' },
            @{ UseAlternateCHMName = $False; UseAlternateHHPath = $False; InfoTechStorageHandler = 'ms-its'; TopicExtension = 'htm';  ScriptEngine = 'VBScript.Encode' },
            @{ UseAlternateCHMName = $False; UseAlternateHHPath = $True;  InfoTechStorageHandler = 'ms-its'; TopicExtension = 'htm';  ScriptEngine = 'VBScript.Encode' },
            @{ UseAlternateCHMName = $True;  UseAlternateHHPath = $False; InfoTechStorageHandler = 'ms-its'; TopicExtension = 'htm';  ScriptEngine = 'VBScript.Encode' },
            @{ UseAlternateCHMName = $True;  UseAlternateHHPath = $True;  InfoTechStorageHandler = 'ms-its'; TopicExtension = 'htm';  ScriptEngine = 'VBScript.Encode' },
            @{ UseAlternateCHMName = $False; UseAlternateHHPath = $False; InfoTechStorageHandler = 'ms-its'; TopicExtension = 'html'; ScriptEngine = 'VBScript.Encode' },
            @{ UseAlternateCHMName = $False; UseAlternateHHPath = $True;  InfoTechStorageHandler = 'ms-its'; TopicExtension = 'html'; ScriptEngine = 'VBScript.Encode' },
            @{ UseAlternateCHMName = $True;  UseAlternateHHPath = $False; InfoTechStorageHandler = 'ms-its'; TopicExtension = 'html'; ScriptEngine = 'VBScript.Encode' },
            @{ UseAlternateCHMName = $True;  UseAlternateHHPath = $True;  InfoTechStorageHandler = 'ms-its'; TopicExtension = 'html'; ScriptEngine = 'VBScript.Encode' },
            @{ UseAlternateCHMName = $False; UseAlternateHHPath = $False; InfoTechStorageHandler = 'mk:@MSITStore'; TopicExtension = 'htm';  ScriptEngine = 'VBScript.Encode' },
            @{ UseAlternateCHMName = $False; UseAlternateHHPath = $True;  InfoTechStorageHandler = 'mk:@MSITStore'; TopicExtension = 'htm';  ScriptEngine = 'VBScript.Encode' },
            @{ UseAlternateCHMName = $True;  UseAlternateHHPath = $False; InfoTechStorageHandler = 'mk:@MSITStore'; TopicExtension = 'htm';  ScriptEngine = 'VBScript.Encode' },
            @{ UseAlternateCHMName = $True;  UseAlternateHHPath = $True;  InfoTechStorageHandler = 'mk:@MSITStore'; TopicExtension = 'htm';  ScriptEngine = 'VBScript.Encode' },
            @{ UseAlternateCHMName = $False; UseAlternateHHPath = $False; InfoTechStorageHandler = 'mk:@MSITStore'; TopicExtension = 'html'; ScriptEngine = 'VBScript.Encode' },
            @{ UseAlternateCHMName = $False; UseAlternateHHPath = $True;  InfoTechStorageHandler = 'mk:@MSITStore'; TopicExtension = 'html'; ScriptEngine = 'VBScript.Encode' },
            @{ UseAlternateCHMName = $True;  UseAlternateHHPath = $False; InfoTechStorageHandler = 'mk:@MSITStore'; TopicExtension = 'html'; ScriptEngine = 'VBScript.Encode' },
            @{ UseAlternateCHMName = $True;  UseAlternateHHPath = $True;  InfoTechStorageHandler = 'mk:@MSITStore'; TopicExtension = 'html'; ScriptEngine = 'VBScript.Encode' }
        )

        It 'should execute a Shortcut command via specification of specific help topics (UseAlternateCHMName: <UseAlternateCHMName>, UseAlternateHHPath: <UseAlternateHHPath>, InfoTechStorageHandler: <InfoTechStorageHandler>, TopicExtension: <TopicExtension>)' -Tag 'Technique', 'T1218.001' {
            $Arguments = @{}

            if ($UseAlternateCHMName) {
                $ExpectedFileName = $AlternateCHMFileName

                $Arguments['CHMFilePath'] = $ExpectedFileName
            } else {
                $ExpectedFileName = 'Test.chm'
            }

            if ($UseAlternateHHPath) {
                $ExpectedHHFileName = $AlternateHHPath.Split('\')[-1]

                $Arguments['HHFilePath'] = $AlternateHHPath
            } else {
                $ExpectedHHFileName = 'hh.exe'
            }

            $Result = Invoke-ATHCompiledHelp -ExecuteShortcutCommand -InfoTechStorageHandler $InfoTechStorageHandler -TopicExtension $TopicExtension -TestGuid $FixedTestGuid @Arguments

            $Result | Should -Not -BeNullOrEmpty

            $Result.TechniqueID                   | Should -BeExactly $ExpectedTechniqueID
            $Result.TestSuccess                   | Should -BeTrue
            $Result.TestGuid                      | Should -BeExactly $FixedTestGuid
            $Result.ExecutionType                 | Should -BeExactly 'ShortcutCommandTopic'
            $Result.ScriptEngine                  | Should -BeExactly 'None'
            $Result.CHMFilePath                   | Should -Not -BeNullOrEmpty
            $Result.CHMFilePath.EndsWith($ExpectedFileName) | Should -BeTrue
            $Result.CHMFileHashSHA256             | Should -BeExactly $ExpectedCHMHash
            $Result.RunnerFilePath                | Should -Not -BeNullOrEmpty
            $Result.RunnerFilePath.EndsWith($ExpectedHHFileName) | Should -BeTrue
            $Result.RunnerProcessId               | Should -Not -BeNullOrEmpty
            $Result.RunnerCommandLine             | Should -Match "`"$($InfoTechStorageHandler):.*::/TEMPLATE" # The storage handler should be present in the command-line
            $Result.RunnerChildProcessId          | Should -Not -BeNullOrEmpty
            $Result.RunnerChildProcessCommandLine | Should -Match $FixedTestGuid

            $Result
        } -TestCases @(
            @{ UseAlternateCHMName = $False; UseAlternateHHPath = $False; InfoTechStorageHandler = 'its'; TopicExtension = 'htm' },
            @{ UseAlternateCHMName = $False; UseAlternateHHPath = $True;  InfoTechStorageHandler = 'its'; TopicExtension = 'htm' },
            @{ UseAlternateCHMName = $True;  UseAlternateHHPath = $False; InfoTechStorageHandler = 'its'; TopicExtension = 'htm' },
            @{ UseAlternateCHMName = $True;  UseAlternateHHPath = $True;  InfoTechStorageHandler = 'its'; TopicExtension = 'htm' },
            @{ UseAlternateCHMName = $False; UseAlternateHHPath = $False; InfoTechStorageHandler = 'its'; TopicExtension = 'html' },
            @{ UseAlternateCHMName = $False; UseAlternateHHPath = $True;  InfoTechStorageHandler = 'its'; TopicExtension = 'html' },
            @{ UseAlternateCHMName = $True;  UseAlternateHHPath = $False; InfoTechStorageHandler = 'its'; TopicExtension = 'html' },
            @{ UseAlternateCHMName = $True;  UseAlternateHHPath = $True;  InfoTechStorageHandler = 'its'; TopicExtension = 'html' },
            @{ UseAlternateCHMName = $False; UseAlternateHHPath = $False; InfoTechStorageHandler = 'ms-its'; TopicExtension = 'htm' },
            @{ UseAlternateCHMName = $False; UseAlternateHHPath = $True;  InfoTechStorageHandler = 'ms-its'; TopicExtension = 'htm' },
            @{ UseAlternateCHMName = $True;  UseAlternateHHPath = $False; InfoTechStorageHandler = 'ms-its'; TopicExtension = 'htm' },
            @{ UseAlternateCHMName = $True;  UseAlternateHHPath = $True;  InfoTechStorageHandler = 'ms-its'; TopicExtension = 'htm' },
            @{ UseAlternateCHMName = $False; UseAlternateHHPath = $False; InfoTechStorageHandler = 'ms-its'; TopicExtension = 'html' },
            @{ UseAlternateCHMName = $False; UseAlternateHHPath = $True;  InfoTechStorageHandler = 'ms-its'; TopicExtension = 'html' },
            @{ UseAlternateCHMName = $True;  UseAlternateHHPath = $False; InfoTechStorageHandler = 'ms-its'; TopicExtension = 'html' },
            @{ UseAlternateCHMName = $True;  UseAlternateHHPath = $True;  InfoTechStorageHandler = 'ms-its'; TopicExtension = 'html' },
            @{ UseAlternateCHMName = $False; UseAlternateHHPath = $False; InfoTechStorageHandler = 'mk:@MSITStore'; TopicExtension = 'htm' },
            @{ UseAlternateCHMName = $False; UseAlternateHHPath = $True;  InfoTechStorageHandler = 'mk:@MSITStore'; TopicExtension = 'htm' },
            @{ UseAlternateCHMName = $True;  UseAlternateHHPath = $False; InfoTechStorageHandler = 'mk:@MSITStore'; TopicExtension = 'htm' },
            @{ UseAlternateCHMName = $True;  UseAlternateHHPath = $True;  InfoTechStorageHandler = 'mk:@MSITStore'; TopicExtension = 'htm' },
            @{ UseAlternateCHMName = $False; UseAlternateHHPath = $False; InfoTechStorageHandler = 'mk:@MSITStore'; TopicExtension = 'html' },
            @{ UseAlternateCHMName = $False; UseAlternateHHPath = $True;  InfoTechStorageHandler = 'mk:@MSITStore'; TopicExtension = 'html' },
            @{ UseAlternateCHMName = $True;  UseAlternateHHPath = $False; InfoTechStorageHandler = 'mk:@MSITStore'; TopicExtension = 'html' },
            @{ UseAlternateCHMName = $True;  UseAlternateHHPath = $True;  InfoTechStorageHandler = 'mk:@MSITStore'; TopicExtension = 'html' }
        )

        AfterEach {
            Stop-Process -Id $Result.RunnerChildProcessId -Force -ErrorAction SilentlyContinue
            Stop-Process -Id $Result.RunnerProcessId -Force -ErrorAction SilentlyContinue

            # Give handle to hh.exe time to be released
            Start-Sleep -Seconds 1
        }

        AfterAll {
            Start-Sleep -Seconds 2 # Give time for any handles to notepad.exe to be released.
            Remove-Item -Path $env:windir\Temp\notepad.exe -Force -ErrorAction SilentlyContinue
        }
    }
}