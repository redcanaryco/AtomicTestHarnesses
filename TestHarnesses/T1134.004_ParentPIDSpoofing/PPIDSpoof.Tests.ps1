Set-StrictMode -Version Latest

$TestScriptRoot = Split-Path $MyInvocation.MyCommand.Path -Parent
$ModuleRoot = Resolve-Path "$TestScriptRoot\..\..\"
$ModuleManifest = "$ModuleRoot\AtomicTestHarnesses.psd1"

Remove-Module [A]tomicTestHarnesses
Import-Module $ModuleManifest -Force -ErrorAction Stop

Describe 'Start-ATHProcessUnderSpecificParent' {
    BeforeAll {
        $Help = Get-Help -Name Start-ATHProcessUnderSpecificParent -Full
    
        $ExpectedTechniqueID = $null

        if ($Help.Synopsis.Split("`r`n")[-1] -match '^(?-i:Technique ID: )(?<TechniqueID>\S+) (?<TechniqueDescription>\(.+\))$') {
            $ExpectedTechniqueID = $Matches['TechniqueID']
        }

        $FixedTestGuid = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
    }
    
    Context 'Validating error conditions' -Tag 'Unit', 'T1134.004' {
        It 'should fail to validate a non-existent executable path.' -Tag 'Unit', 'T1134.004' {
            { Start-ATHProcessUnderSpecificParent -FilePath sdkfljhsdfjfrsdsdg.exe -CommandLine sdkfjhsdfkjds -ParentId $PID -ErrorAction Stop } | Should -Throw
        }

        It 'should fail to spawn from a non-existent process' -Tag 'Unit', 'T1134.004' {
            { Start-ATHProcessUnderSpecificParent -ParentId ([Int]::MinValue) -ErrorAction Stop } | Should -Throw
        }

        It 'should throw an exception if it fails to obtain child process information' -Tag 'Unit', 'T1134.004' {
            Mock Get-CimInstance { return $null } -ParameterFilter { $Property.Count -eq 4 }

            { Start-ATHProcessUnderSpecificParent -ParentId $PID -ErrorAction Stop } | Should -Throw

            Should -Invoke Get-CimInstance -Times 1
        }

        It 'should throw an exception if it fails to obtain parent process information' -Tag 'Unit', 'T1134.004' {
            Mock Get-CimInstance { return $null } -ParameterFilter { $Property.Count -eq 3 }

            { Start-ATHProcessUnderSpecificParent -ParentId $PID -ErrorAction Stop } | Should -Throw

            Should -Invoke Get-CimInstance -Times 1
        }
    }

    Context 'Expected artifacts and behaviors when exercising the attack technique' -Tag 'Technique', 'T1134.004' {
        It 'should execute as a child process of explorer.exe' -Tag 'Technique', 'T1134.004' {
            $Result = Get-Process -Name explorer | Select-Object -First 1 | Start-ATHProcessUnderSpecificParent -TestGuid $FixedTestGuid

            $Result | Should -Not -BeNullOrEmpty

            $Result.TechniqueID              | Should -BeExactly $ExpectedTechniqueID
            $Result.TestSuccess              | Should -BeTrue
            $Result.TestGuid                 | Should -BeExactly $FixedTestGuid
            $Result.ProcessId                | Should -Not -BeNullOrEmpty
            $Result.ProcessPath              | Should -Match 'powershell.exe'
            $Result.ProcessCommandLine       | Should -MatchExactly "$($FixedTestGuid)`$"
            $Result.ParentProcessId          | Should -Not -BeNullOrEmpty
            $Result.ParentProcessPath        | Should -Match 'explorer.exe'
            $Result.ParentProcessCommandLine | Should -Match 'explorer.exe'
            $Result.SpoofingProcessId          | Should -BeExactly $PID
            $Result.SpoofingProcessPath        | Should -Not -BeNullOrEmpty
            $Result.SpoofingProcessCommandLine | Should -Not -BeNullOrEmpty

            $Result
        }

        It 'should execute as a child process of the current PowerShell process' -Tag 'Technique', 'T1134.004' {
            $Result = Start-ATHProcessUnderSpecificParent -ParentId $PID -TestGuid $FixedTestGuid

            $Result | Should -Not -BeNullOrEmpty

            $CurrentProcessInfo = Get-CimInstance -ClassName Win32_Process -Property CommandLine, ExecutablePath -Filter "ProcessId = $PID" -ErrorAction Stop

            $Result.TechniqueID              | Should -BeExactly $ExpectedTechniqueID
            $Result.TestSuccess              | Should -BeTrue
            $Result.TestGuid                 | Should -BeExactly $FixedTestGuid
            $Result.ProcessId                | Should -Not -BeNullOrEmpty
            $Result.ProcessPath              | Should -Match 'powershell.exe'
            $Result.ProcessCommandLine       | Should -MatchExactly "$($FixedTestGuid)`$"
            $Result.ParentProcessId          | Should -Be $PID
            $Result.ParentProcessPath        | Should -BeExactly $CurrentProcessInfo.ExecutablePath
            $Result.ParentProcessCommandLine | Should -BeExactly $CurrentProcessInfo.CommandLine
            $Result.SpoofingProcessId          | Should -BeExactly $PID
            $Result.SpoofingProcessPath        | Should -Not -BeNullOrEmpty
            $Result.SpoofingProcessCommandLine | Should -Not -BeNullOrEmpty

            $Result
        }

        It 'should spawn a child process from a newly created notepad.exe process' -Tag 'Technique', 'T1134.004' {
            $Result = Start-Process -FilePath $Env:windir\System32\notepad.exe -PassThru -ErrorAction Stop |
                Start-ATHProcessUnderSpecificParent -FilePath powershell.exe -CommandLine '-Command Write-Host foo'

            $Result | Should -Not -BeNullOrEmpty

            $Result.TechniqueID              | Should -BeExactly $ExpectedTechniqueID
            $Result.TestSuccess              | Should -BeTrue
            $Result.TestGuid                 | Should -BeNullOrEmpty
            $Result.ProcessId                | Should -Not -BeNullOrEmpty
            $Result.ProcessPath              | Should -Match 'powershell.exe$'
            $Result.ProcessCommandLine       | Should -MatchExactly 'Write-Host foo$'
            $Result.ParentProcessId          | Should -Not -BeNullOrEmpty
            $Result.ParentProcessPath        | Should -Match 'notepad.exe'
            $Result.ParentProcessCommandLine | Should -Match 'notepad.exe'
            $Result.SpoofingProcessId          | Should -BeExactly $PID
            $Result.SpoofingProcessPath        | Should -Not -BeNullOrEmpty
            $Result.SpoofingProcessCommandLine | Should -Not -BeNullOrEmpty

            $Result

            # Kill the spawned notepad.exe process
            Stop-Process -Id $Result.ParentProcessId
        }
    }
}