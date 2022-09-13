Set-StrictMode -Version Latest

$TestScriptRoot = Split-Path $MyInvocation.MyCommand.Path -Parent
$ModuleRoot = Resolve-Path "$TestScriptRoot\..\..\..\"
$ModuleManifest = "$ModuleRoot\AtomicTestHarnesses.psd1"

Remove-Module [A]tomicTestHarnesses
Import-Module $ModuleManifest -Force -ErrorAction Stop

Describe 'Invoke-ATHCORProfiler' {
    BeforeAll {
        $Help = Get-Help -Name Invoke-ATHCORProfiler -Full
    
        $ExpectedTechniqueID = $null

        if ($Help.Synopsis.Split("`r`n")[-1] -match '^(?-i:Technique ID: )(?<TechniqueID>\S+) (?<TechniqueDescription>\(.+\))$') {
            $ExpectedTechniqueID = $Matches['TechniqueID']
        }
    }

    Context 'Validating error conditions' -Tag 'Unit', 'T1574.012' {
        It 'should not accept malformed test guids' -Tag 'Unit', 'T1574.012' {
            $BogusTestGuid = 'asdfasdfasdfasdfasdfaasdf'

            { Invoke-ATHCORProfiler -TestGuid $BogusTestGuid } | Should -Throw
        }

        It 'should not accept malformed Profiler CLSIDs with registered profilers' -Tag 'Unit', 'T1574.012' {
            $BogusProfilerCLSID = 'asdfasdfasdfasdfasdfasdf'

            {  Invoke-ATHCORProfiler -RegisteredProfilerScope User -ProfilerCLSID $BogusProfilerCLSID } | Should -Throw
        }

        It 'should not accept process scoped registered profilers' -Tag 'Unit', 'T1574.012' {
            { Invoke-ATHCORProfiler -RegisteredProfilerScope Process } | Should -Throw
        }

        It 'should not accept a profiler path in a non-existant directory'  -Tag 'Unit', 'T1574.012' {
            $BogusPath = 'C:\dsdfsiuhsdrfsawgfds\sdlfksdjflksdj'

            Test-Path -Path $BogusPath -PathType Container -ErrorAction SilentlyContinue | Should -BeFalse

            { Invoke-ATHCORProfiler -ProfilerPath $BogusPath -ErrorAction Stop } | Should -Throw
        }
    }

    Context 'Expected artifacts and behaviors when exercising the attack technique' -Tag 'Technique', 'T1574.012' {
        BeforeAll {
            $FixedTestGuid = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
        }

        It 'should execute without any arguments' -Tag 'Technique', 'T1574.012' {
            $Result = Invoke-ATHCORProfiler -Force

            $Result | Should -Not -BeNullOrEmpty

            $Result.TechniqueID                                 | Should  -BeExactly $ExpectedTechniqueID
            $Result.TestSuccess                                 | Should  -BeTrue
            $Result.TestGuid                                    | Should  -Not -BeNullOrEmpty
            $Result.ProfilerScope                               | Should  -BeExactly 'User'
            $Result.ProfilerType                                | Should  -BeExactly 'RegistrationFree'
            $Result.ProfilerCLSID                               | Should  -Not -BeNullOrEmpty
            $Result.ProfilerDllPath                             | Should  -Match 'Profiler.dll'
            $Result.ProfilerDllFileSHA256Hash                   | Should  -Not -BeNullOrEmpty
            $Result.TargetProcessId                             | Should  -Not -BeNullOrEmpty
            $Result.TargetProcessPath                           | Should  -Match 'powershell.exe'
            $Result.TargetProcessCommandLine                    | Should  -Match 'powershell.exe'
            $Result.ChildProcessId                              | Should  -Not -BeNullOrEmpty
            $Result.ChildProcessCommandLine                     | Should  -Not -BeNullOrEmpty
            $Result.RegisteredProfilerRegistryCOMClassValueName | Should  -BeNullOrEmpty
            $Result.RegisteredProfilerRegistryCOMClassNameValue | Should  -BeNullOrEmpty
            $Result.CorEnableProfilingEnvVarRegistrySubKey.EndsWith('Environment') | Should -BeTrue
            $Result.CorEnableProfilingEnvVarRegistryValueName   | Should  -BeExactly 'COR_ENABLE_PROFILING'
            $Result.CorEnableProfilingEnvVarRegistryNameValue   | Should  -BeExactly 1
            $Result.CorProfilerEnvVarRegistrySubKey.EndsWith('Environment')        | Should -BeTrue
            $Result.CorProfilerEnvVarRegistryValueName          | Should  -BeExactly 'COR_PROFILER'
            $Result.CorProfilerEnvVarRegistryNameValue          | Should  -BeExactly $Result.ProfilerCLSID
            $Result.CorProfilerPathEnvVarRegistrySubKey.EndsWith('Environment')    | Should -BeTrue
            $Result.CorProfilerPathEnvVarRegistryValueName      | Should  -BeExactly 'COR_PROFILER_PATH'
            $Result.CorProfilerPathEnvVarRegistryNameValue      | Should  -Match 'Profiler.dll'

            $Result
        }

        It 'should simulate registered execution ( RegisteredProfilerScope: <RegisteredProfilerScope>)' {
            if (($RegisteredProfilerScope -eq 'Machine') -and (-not (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))) {
                Set-ItResult -Skipped -Because 'This test requires an elevated instance of PowerShell.'
            } else {
                $Result =  Invoke-ATHCORProfiler -RegisteredProfilerScope $RegisteredProfilerScope -ProfilerCLSID $FixedTestGuid -Force -TestGuid $FixedTestGuid
                $Result | Should -Not -BeNullOrEmpty

                $Result.TechniqueID                                 | Should  -BeExactly $ExpectedTechniqueID
                $Result.TestSuccess                                 | Should  -BeTrue
                $Result.TestGuid                                    | Should  -BeExactly $FixedTestGuid
                $Result.ProfilerScope                               | Should  -BeExactly $RegisteredProfilerScope
                $Result.ProfilerType                                | Should  -BeExactly 'Registered'
                $Result.ProfilerCLSID                               | Should  -BeExactly "{$FixedTestGuid}"
                $Result.ProfilerDllPath                             | Should  -Match 'Profiler.dll'
                $Result.ProfilerDllFileSHA256Hash                   | Should  -Not -BeNullOrEmpty
                $Result.TargetProcessId                             | Should  -Not -BeNullOrEmpty
                $Result.TargetProcessPath                           | Should  -Match 'powershell.exe'
                $Result.TargetProcessCommandLine                    | Should  -Match 'powershell.exe'
                $Result.ChildProcessId                              | Should  -Not -BeNullOrEmpty
                $Result.ChildProcessCommandLine                     | Should  -Not -BeNullOrEmpty
                $Result.RegisteredProfilerRegistryCOMClassValueName.EndsWith('InprocServer32') | Should  -BeTrue
                $Result.RegisteredProfilerRegistryCOMClassNameValue.EndsWith('Profiler.dll') | Should  -BeTrue
                $Result.CorEnableProfilingEnvVarRegistrySubKey.EndsWith('Environment') | Should -BeTrue
                $Result.CorEnableProfilingEnvVarRegistryValueName   | Should  -BeExactly 'COR_ENABLE_PROFILING'
                $Result.CorEnableProfilingEnvVarRegistryNameValue   | Should  -BeExactly 1
                $Result.CorProfilerEnvVarRegistrySubKey.EndsWith('Environment')        | Should -BeTrue
                $Result.CorProfilerEnvVarRegistryValueName          | Should  -BeExactly 'COR_PROFILER'
                $Result.CorProfilerEnvVarRegistryNameValue          | Should  -BeExactly "{$FixedTestGuid}"
                $Result.CorProfilerPathEnvVarRegistrySubKey.EndsWith('Environment')    | Should -BeTrue
                $Result.CorProfilerPathEnvVarRegistryValueName      | Should  -BeExactly 'COR_PROFILER_PATH'
                $Result.CorProfilerPathEnvVarRegistryNameValue      | Should  -Match 'Profiler.dll'

                $Result
            }
        } -TestCases @(
            @{ RegisteredProfilerScope = 'Machine' },
            @{ RegisteredProfilerScope = 'User' }
        )

        It 'should simulate registration free execution which produce environment variable artifacts in the registry (RegistrationFreeProfilerScope: <RegistrationFreeProfilerScope>)' {
            if (($RegistrationFreeProfilerScope -eq 'Machine') -and (-not (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))) {
                Set-ItResult -Skipped -Because 'This test requires an elevated instance of PowerShell.'
            } else {
                $Result =  Invoke-ATHCORProfiler -RegistrationFreeProfilerScope $RegistrationFreeProfilerScope -ProfilerCLSID $FixedTestGuid -Force -TestGuid $FixedTestGuid
                $Result | Should -Not -BeNullOrEmpty
    
                $Result.TechniqueID                                 | Should  -BeExactly $ExpectedTechniqueID
                $Result.TestSuccess                                 | Should  -BeTrue
                $Result.TestGuid                                    | Should  -BeExactly $FixedTestGuid
                $Result.ProfilerScope                               | Should  -BeExactly $RegistrationFreeProfilerScope
                $Result.ProfilerType                                | Should  -BeExactly 'RegistrationFree'
                $Result.ProfilerCLSID                               | Should  -BeExactly "{$FixedTestGuid}"
                $Result.ProfilerDllPath                             | Should  -Match 'Profiler.dll'
                $Result.ProfilerDllFileSHA256Hash                   | Should  -Not -BeNullOrEmpty
                $Result.TargetProcessId                             | Should  -Not -BeNullOrEmpty
                $Result.TargetProcessPath                           | Should  -Match 'powershell.exe'
                $Result.TargetProcessCommandLine                    | Should  -Match 'powershell.exe'
                $Result.ChildProcessId                              | Should  -Not -BeNullOrEmpty
                $Result.ChildProcessCommandLine                     | Should  -Not -BeNullOrEmpty
                $Result.RegisteredProfilerRegistryCOMClassValueName | Should  -BeNullOrEmpty
                $Result.RegisteredProfilerRegistryCOMClassNameValue | Should  -BeNullOrEmpty
                $Result.CorEnableProfilingEnvVarRegistrySubKey.EndsWith('Environment') | Should -BeTrue
                $Result.CorEnableProfilingEnvVarRegistryValueName   | Should  -BeExactly 'COR_ENABLE_PROFILING'
                $Result.CorEnableProfilingEnvVarRegistryNameValue   | Should  -BeExactly 1
                $Result.CorProfilerEnvVarRegistrySubKey.EndsWith('Environment')        | Should -BeTrue
                $Result.CorProfilerEnvVarRegistryValueName          | Should  -BeExactly 'COR_PROFILER'
                $Result.CorProfilerEnvVarRegistryNameValue          | Should  -BeExactly "{$FixedTestGuid}"
                $Result.CorProfilerPathEnvVarRegistrySubKey.EndsWith('Environment')    | Should -BeTrue
                $Result.CorProfilerPathEnvVarRegistryValueName      | Should  -BeExactly 'COR_PROFILER_PATH'
                $Result.CorProfilerPathEnvVarRegistryNameValue      | Should  -Match 'Profiler.dll'
    
                $Result
            }
        } -TestCases @(
            @{ RegistrationFreeProfilerScope = 'Machine' },
            @{ RegistrationFreeProfilerScope = 'User' }
        )

        It 'should simulate registration free Process scoped execution (RegistrationFreeProfilerScope: <RegistrationFreeProfilerScope>)' {
            $Result =  Invoke-ATHCORProfiler -RegistrationFreeProfilerScope $RegistrationFreeProfilerScope -ProfilerCLSID $FixedTestGuid -Force -TestGuid $FixedTestGuid
            $Result | Should -Not -BeNullOrEmpty
    
            $Result.TechniqueID                                 | Should  -BeExactly $ExpectedTechniqueID
            $Result.TestSuccess                                 | Should  -BeTrue
            $Result.TestGuid                                    | Should  -BeExactly $FixedTestGuid
            $Result.ProfilerScope                               | Should  -BeExactly $RegistrationFreeProfilerScope
            $Result.ProfilerType                                | Should  -BeExactly 'RegistrationFree'
            $Result.ProfilerCLSID                               | Should  -BeExactly "{$FixedTestGuid}"
            $Result.ProfilerDllPath                             | Should  -Match 'Profiler.dll'
            $Result.ProfilerDllFileSHA256Hash                   | Should  -Not -BeNullOrEmpty
            $Result.TargetProcessId                             | Should  -Not -BeNullOrEmpty
            $Result.TargetProcessPath                           | Should  -Match 'powershell.exe'
            $Result.TargetProcessCommandLine                    | Should  -Match 'powershell.exe'
            $Result.ChildProcessId                              | Should  -Not -BeNullOrEmpty
            $Result.ChildProcessCommandLine                     | Should  -Not -BeNullOrEmpty
            $Result.RegisteredProfilerRegistryCOMClassValueName | Should  -BeNullOrEmpty
            $Result.RegisteredProfilerRegistryCOMClassNameValue | Should  -BeNullOrEmpty
            $Result.CorEnableProfilingEnvVarRegistrySubKey      | Should  -BeNullOrEmpty
            $Result.CorEnableProfilingEnvVarRegistryValueName   | Should  -BeNullOrEmpty
            $Result.CorEnableProfilingEnvVarRegistryNameValue   | Should  -BeNullOrEmpty
            $Result.CorProfilerEnvVarRegistrySubKey             | Should  -BeNullOrEmpty
            $Result.CorProfilerEnvVarRegistryValueName          | Should  -BeNullOrEmpty
            $Result.CorProfilerEnvVarRegistryNameValue          | Should  -BeNullOrEmpty
            $Result.CorProfilerPathEnvVarRegistrySubKey         | Should  -BeNullOrEmpty
            $Result.CorProfilerPathEnvVarRegistryValueName      | Should  -BeNullOrEmpty
            $Result.CorProfilerPathEnvVarRegistryNameValue      | Should  -BeNullOrEmpty
    
            $Result
        } -TestCases @(
            @{ RegistrationFreeProfilerScope = 'Process' }
        )
    }
}
