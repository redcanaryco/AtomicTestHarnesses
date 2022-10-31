Set-StrictMode -Version Latest

$TestScriptRoot = Split-Path $MyInvocation.MyCommand.Path -Parent
$ModuleRoot = Resolve-Path "$TestScriptRoot\..\..\..\"
$ModuleManifest = "$ModuleRoot\AtomicTestHarnesses.psd1"

Remove-Module [A]tomicTestHarnesses
Import-Module $ModuleManifest -Force -ErrorAction Stop

Describe 'Get-ATHDriverService' {
    BeforeAll {
        $Help = Get-Help -Name Get-ATHDriverService -Full
    
        $ExpectedTechniqueID = $null

        if ($Help.Synopsis.Split("`r`n")[-1] -match '^(?-i:Technique ID: )(?<TechniqueID>\S+) (?<TechniqueDescription>\(.+\))$') {
            $ExpectedTechniqueID = $Matches['TechniqueID']
        }
    }

    Context 'Validating error conditions' -Tag 'Unit', 'T1543.003' {
        It 'should return detailed, contextual information for a running driver service based on the service name' {
            $ServiceName = 'cdrom'

            $Result = Get-ATHDriverService -ServiceName $ServiceName -ErrorAction Stop

            $Result | Should -Not -BeNullOrEmpty

            $Result.TechniqueID                   | Should -BeExactly $ExpectedTechniqueID
            $Result.ServiceName                   | Should -Be $ServiceName
            $Result.ServiceDisplayName            | Should -Not -BeNullOrEmpty
            $Result.ServiceStartMode              | Should -Not -BeNullOrEmpty
            $Result.ServiceState                  | Should -Not -BeNullOrEmpty
            $Result.ServiceType                   | Should -BeExactly 'Kernel Driver'
            $Result.ServiceRegistryKey            | Should -Be "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\$ServiceName"
            $Result.DriverPathFormatted           | Should -Match '^[A-Z]:\\'
            $Result.DriverPathFormatted.EndsWith('cdrom.sys')   | Should -BeTrue
            $Result.DriverPathUnformatted.EndsWith('cdrom.sys') | Should -BeTrue
            $Result.DriverFileHashSHA256          | Should -Not -BeNullOrEmpty
            $Result.LoadedImageBaseAddress        | Should -Not -BeNullOrEmpty
            $Result.LoadedImageSize               | Should -Not -BeNullOrEmpty
            $Result.LoadCount                     | Should -BeGreaterThan 0
        }

        It 'should throw an error when a non-existent service name is supplied' {
            { Get-ATHDriverService -ServiceName ' ' -ErrorAction Stop } | Should -Throw
        }

        It 'should return detailed, contextual information for a running driver service when a driver filename is supplied' {
            $DriverFilename = 'cdrom.sys'

            $Result = Get-ATHDriverService -LoadedDriverFileName $DriverFilename -ErrorAction Stop

            $Result | Should -Not -BeNullOrEmpty

            $Result.TechniqueID                   | Should -BeExactly $ExpectedTechniqueID
            $Result.ServiceName                   | Should -Not -BeNullOrEmpty
            $Result.ServiceDisplayName            | Should -Not -BeNullOrEmpty
            $Result.ServiceStartMode              | Should -Not -BeNullOrEmpty
            $Result.ServiceState                  | Should -Not -BeNullOrEmpty
            $Result.ServiceType                   | Should -BeExactly 'Kernel Driver'
            $Result.ServiceRegistryKey            | Should -Not -BeNullOrEmpty
            $Result.DriverPathFormatted           | Should -Match '^[A-Z]:\\'
            $Result.DriverPathFormatted.EndsWith($DriverFilename)   | Should -BeTrue
            $Result.DriverPathUnformatted.EndsWith($DriverFilename) | Should -BeTrue
            $Result.DriverFileHashSHA256          | Should -Not -BeNullOrEmpty
            $Result.LoadedImageBaseAddress        | Should -Not -BeNullOrEmpty
            $Result.LoadedImageSize               | Should -Not -BeNullOrEmpty
            $Result.LoadCount                     | Should -BeGreaterThan 0
        }

        It 'should not return output when a non-existent driver path is supplied' {
            $Result = Get-ATHDriverService -LoadedDriverFileName ' ' -ErrorAction Stop | Should -BeNullOrEmpty

            $Result | Should -BeNullOrEmpty
        }
    }
}


Describe 'Remove-ATHDriverService' {
    BeforeAll {
        $Help = Get-Help -Name Get-ATHDriverService -Full
    
        $ExpectedTechniqueID = $null

        if ($Help.Synopsis.Split("`r`n")[-1] -match '^(?-i:Technique ID: )(?<TechniqueID>\S+) (?<TechniqueDescription>\(.+\))$') {
            $ExpectedTechniqueID = $Matches['TechniqueID']
        }
    }

    Context 'Validating error conditions' -Tag 'Unit', 'T1543.003' {
        It 'should throw an error when a non-existent service name is supplied' {
            { Remove-ATHDriverService -ServiceName ' ' -ErrorAction Stop } | Should -Throw
        }
    }
}
