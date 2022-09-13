Set-StrictMode -Version Latest

$TestScriptRoot = Split-Path $MyInvocation.MyCommand.Path -Parent
$ModuleRoot = Resolve-Path "$TestScriptRoot\..\..\..\"
$ModuleManifest = "$ModuleRoot\AtomicTestHarnesses.psd1"

Remove-Module [A]tomicTestHarnesses
Import-Module $ModuleManifest -Force -ErrorAction Stop

Describe 'Invoke-ATHInjectedThread' {
    BeforeAll {
        $Help = Get-Help -Name Invoke-ATHInjectedThread -Full

        $ExpectedTechniqueID = $null

        if ($Help.Synopsis.Split("`r`n")[-1] -match '^(?-i:Technique ID: )(?<TechniqueID>\S+) (?<TechniqueDescription>\(.+\))$') {
            $ExpectedTechniqueID = $Matches['TechniqueID']
        }
    }

    Context 'Validating error conditions' -Tag 'Unit', 'T1055.002' {
        It 'should execute custom position-independent code' -Tag 'Unit', 'T1055.002' {
            $Result = Invoke-ATHInjectedThread -PositionIndependentCodeBytes @(0x90, 0x90, 0x90, 0xC3) # NOP, NOP, NOP, RET

            $Result | Should -Not -BeNullOrEmpty

            $Result.TechniqueID                   | Should -BeExactly $ExpectedTechniqueID
            $Result.TestSuccess                   | Should -BeNullOrEmpty
            $Result.TestGuid                      | Should -Not -BeNullOrEmpty
            $Result.InjectedCodeBytes             | Should -Not -BeNullOrEmpty
            $Result.InjectedCodeHash              | Should -BeExactly '97E3BFAD17932F638A894351239CA24CB76467E080C5B268307547D36366FE10'
            $Result.SourceProcessId               | Should -Be $PID
            $Result.SourceExecutablePath          | Should -Not -BeNullOrEmpty
            $Result.SourceCommandLine             | Should -Not -BeNullOrEmpty
            $Result.TargetProcessId               | Should -Not -BeNullOrEmpty
            $Result.TargetExecutablePath          | Should -Match 'notepad\.exe$'
            $Result.TargetCommandLine             | Should -BeExactly 'notepad.exe'
            $Result.TargetProcessAccess           | Should -BeExactly 'PROCESS_CREATE_THREAD, PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE, PROCESS_QUERY_INFORMATION'
            $Result.TargetProcessAccessValue      | Should -Be 1082
            $Result.TargetBaseAddressHex          | Should -Match '^[0-9A-F]{16}$'
            $Result.TargetAllocationPageProtect   | Should -BeExactly 'PAGE_EXECUTE_READWRITE'
            $Result.TargetAllocationPageProtectValue | Should -Be 64
            $Result.TargetThreadId                | Should -Not -BeNullOrEmpty
            $Result.TargetChildProcessId          | Should -BeNullOrEmpty
            $Result.TargetChildProcessCommandLine | Should -BeNullOrEmpty
        }

        It 'should inject into itself (the current process)' -Tag 'Unit', 'T1055.002' {
            $Result = Invoke-ATHInjectedThread -ProcessId $PID

            $Result | Should -Not -BeNullOrEmpty

            $Result.TechniqueID                   | Should -BeExactly $ExpectedTechniqueID
            $Result.TestSuccess                   | Should -BeTrue
            $Result.TestGuid                      | Should -Not -BeNullOrEmpty
            $Result.InjectedCodeBytes             | Should -Not -BeNullOrEmpty
            $Result.InjectedCodeHash              | Should -Not -BeNullOrEmpty
            $Result.SourceProcessId               | Should -Be $PID
            $Result.SourceExecutablePath          | Should -BeExactly $Result.TargetExecutablePath
            $Result.SourceCommandLine             | Should -BeExactly $Result.TargetCommandLine
            $Result.TargetProcessId               | Should -Be $PID
            $Result.TargetExecutablePath          | Should -Not -BeNullOrEmpty
            $Result.TargetCommandLine             | Should -Not -BeNullOrEmpty
            $Result.TargetProcessAccess           | Should -BeExactly 'PROCESS_CREATE_THREAD, PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE, PROCESS_QUERY_INFORMATION'
            $Result.TargetProcessAccessValue      | Should -Be 1082
            $Result.TargetBaseAddressHex          | Should -Match '^[0-9A-F]{16}$'
            $Result.TargetAllocationPageProtect   | Should -BeExactly 'PAGE_EXECUTE_READWRITE'
            $Result.TargetAllocationPageProtectValue | Should -Be 64
            $Result.TargetThreadId                | Should -Not -BeNullOrEmpty
            $Result.TargetChildProcessId          | Should -Not -BeNullOrEmpty
            $Result.TargetChildProcessCommandLine | Should -Not -BeNullOrEmpty
        }

        It 'should not inject into a non-existant process ID' -Tag 'Unit', 'T1055.002' {
            { Invoke-ATHInjectedThread -ProcessId 1 -ErrorAction Stop } | Should -Throw
        }

        It 'should not accept an empty array of position-independent code' -Tag 'Unit', 'T1055.002' {
            { Invoke-ATHInjectedThread -PositionIndependentCodeBytes @() -ErrorAction Stop } | Should -Throw
        }

        It 'should fail to inject when the template notepad.exe target fails to launch' -Tag 'Unit', 'T1055.002' {
             Mock Invoke-CimMethod { return @{ ReturnValue = 1 } }

            { Invoke-ATHInjectedThread -ErrorAction Stop } | Should -Throw
        }

        It 'should not have access to inject into the System process' -Tag 'Unit', 'T1055.002' {
            { Invoke-ATHInjectedThread -ProcessId 4 -ErrorAction Stop } | Should -Throw
        }

        It 'should not inject into a 32-bit process' -Tag 'Unit', 'T1055.002' {
            $Wow64Notepad = Start-Process -FilePath $Env:windir\SysWOW64\notepad.exe -WindowStyle Hidden -PassThru

            { $Wow64Notepad | Invoke-ATHInjectedThread -ErrorAction Stop } | Should -Throw

            $Wow64Notepad | Stop-Process -Force
        }

        It 'should indicate that the powershell.exe child process failed to launch' -Tag 'Unit', 'T1055.002' {
            Mock Wait-Event { return $null }

            { Invoke-ATHInjectedThread -ErrorAction Stop } | Should -Throw
        }
    }

    Context 'Expected artifacts and behaviors when exercising the attack technique' -Tag 'Technique', 'T1055.002' {
        BeforeAll {
            $Script:FixedTestGuid = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'

            $Script:TargetNotepadProc = Start-Process -FilePath $Env:windir\System32\notepad.exe -WindowStyle Hidden -PassThru
        }

        It 'should inject into a process (IsRWXMemory: <IsRWXMemory>, MinimumProcessAccess: <MinimumProcessAccess>, InjectIntoSpecificProcess: <InjectIntoSpecificProcess>)' -Tag 'Technique', 'T1055.002' {
            $Arguments = @{}

            if ($IsRWXMemory) {
                $ExpectedPageProtection      = 'PAGE_EXECUTE_READWRITE'
                $ExpectedPageProtectionValue = 64

                $Arguments['MemoryProtectionType'] = 'ReadWriteExecute'
            } else {
                $ExpectedPageProtection = 'PAGE_EXECUTE_READ'
                $ExpectedPageProtectionValue = 32

                $Arguments['MemoryProtectionType'] = 'ReadExecute'
            }

            if ($MinimumProcessAccess) {
                $ExpectedProcessAccess      = 'PROCESS_CREATE_THREAD, PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE, PROCESS_QUERY_INFORMATION'
                $ExpectedProcessAccessValue = 1082

                $Arguments['ProcessAccessType'] = 'MinimumAccess'
            } else {
                $ExpectedProcessAccess      = 'PROCESS_ALL_ACCESS'
                $ExpectedProcessAccessValue = 2097151

                $Arguments['ProcessAccessType'] = 'AllAccess'
            }

            if ($InjectIntoSpecificProcess) {
                $ExpectedProcessId = $TargetNotepadProc.Id

                $Arguments['ProcessId'] = $TargetNotepadProc.Id
            } else {
                $ExpectedProcessId = $null
            }

            $Result = Invoke-ATHInjectedThread -TestGuid $FixedTestGuid @Arguments

            $Result | Should -Not -BeNullOrEmpty

            $Result.TechniqueID                   | Should -BeExactly $ExpectedTechniqueID
            $Result.TestSuccess                   | Should -BeTrue
            $Result.TestGuid                      | Should -BeExactly $FixedTestGuid
            $Result.InjectedCodeBytes             | Should -Not -BeNullOrEmpty
            $Result.InjectedCodeHash              | Should -Not -BeNullOrEmpty
            $Result.SourceProcessId               | Should -Be $PID
            $Result.SourceExecutablePath          | Should -Not -BeNullOrEmpty
            $Result.SourceCommandLine             | Should -Not -BeNullOrEmpty

            if ($InjectIntoSpecificProcess) {
                $Result.TargetProcessId           | Should -Be $ExpectedProcessId
            } else {
                $Result.TargetProcessId           | Should -Not -BeNullOrEmpty
            }

            $Result.TargetExecutablePath          | Should -Match 'notepad\.exe'
            $Result.TargetCommandLine             | Should -Match 'notepad\.exe'
            $Result.TargetProcessAccess           | Should -BeExactly $ExpectedProcessAccess
            $Result.TargetProcessAccessHex        | Should -BeExactly $ExpectedProcessAccessHex
            $Result.TargetBaseAddressHex          | Should -Match '^[0-9A-F]{16}$'
            $Result.TargetAllocationPageProtect   | Should -BeExactly $ExpectedPageProtection
            $Result.TargetAllocationPageProtectValue | Should -Be $ExpectedPageProtectionValue
            $Result.TargetThreadId                | Should -Not -BeNullOrEmpty
            $Result.TargetChildProcessId          | Should -Not -BeNullOrEmpty
            $Result.TargetChildProcessCommandLine | Should -Match $FixedTestGuid
        } -TestCases @(
            @{ IsRWXMemory = $False; MinimumProcessAccess = $False; InjectIntoSpecificProcess = $False },
            @{ IsRWXMemory = $True;  MinimumProcessAccess = $False; InjectIntoSpecificProcess = $False },
            @{ IsRWXMemory = $False; MinimumProcessAccess = $True;  InjectIntoSpecificProcess = $False },
            @{ IsRWXMemory = $True;  MinimumProcessAccess = $True;  InjectIntoSpecificProcess = $False },
            @{ IsRWXMemory = $False; MinimumProcessAccess = $False; InjectIntoSpecificProcess = $True  },
            @{ IsRWXMemory = $True;  MinimumProcessAccess = $False; InjectIntoSpecificProcess = $True  },
            @{ IsRWXMemory = $False; MinimumProcessAccess = $True;  InjectIntoSpecificProcess = $True  },
            @{ IsRWXMemory = $True;  MinimumProcessAccess = $True;  InjectIntoSpecificProcess = $True  }
        )

        AfterAll {
            $Script:TargetNotepadProc | Stop-Process -Force
        }
    }
}
