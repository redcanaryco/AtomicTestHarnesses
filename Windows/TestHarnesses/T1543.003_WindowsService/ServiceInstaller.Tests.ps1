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

Describe 'New-ATHService' {
    BeforeAll {
        $Help = Get-Help -Name New-ATHService -Full
    
        $ExpectedTechniqueID = $null

        if ($Help.Synopsis.Split("`r`n")[-1] -match '^(?-i:Technique ID: )(?<TechniqueID>\S+) (?<TechniqueDescription>\(.+\))$') {
            $ExpectedTechniqueID = $Matches['TechniqueID']
        }
    }

    Context 'Validating error conditions' -Tag 'Unit', 'T1543.003' {
        It 'should create a Win32OwnProcess service called ATHService successfully via sc.exe' {
            $ServiceName = 'ATHService'

            $Result = New-ATHService -ServiceName $ServiceName -DisplayName $ServiceName -DeleteServiceBinary

            $Result | Should -Not -BeNullOrEmpty

            $Result.TechniqueID                   | Should -BeExactly $ExpectedTechniqueID
            $Result.TestSuccess                   | Should -Be $true
            $Result.ServiceName                   | Should -Be $ServiceName
            $Result.ServiceDisplayName            | Should -Be $ServiceName
            $Result.ServiceStartMode              | Should -Be 3
            $Result.ServiceState                  | Should -Be 'Stopped'
            $Result.ServiceType                   | Should -Be 16
            $Result.ServiceRegistryKey            | Should -Be "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\$ServiceName"
            $Result.ServiceImagePath              | Should -Not -BeNullOrEmpty
            $Result.DriverPathFormatted           | Should -be $null
            $Result.DriverPathUnformatted         | Should -be $null
            $Result.DriverFileHashSHA256          | Should -be $null
            $Result.LoadedImageBaseAddress        | Should -be $null
            $Result.LoadedImageSize               | Should -be $null
            $Result.LoadCount                     | Should -be $null

        }

        It 'should create a Win32OwnProcess service called WMIATHService successfully via WMI' {
            $ServiceName = 'WMIATHService'

            $Result = New-ATHService -ServiceName $ServiceName -DisplayName $ServiceName -Variant WMI -DeleteServiceBinary

            $Result | Should -Not -BeNullOrEmpty

            $Result.TechniqueID                   | Should -BeExactly $ExpectedTechniqueID
            $Result.TestSuccess                   | Should -Be $true
            $Result.ServiceName                   | Should -Be $ServiceName
            $Result.ServiceDisplayName            | Should -Be $ServiceName
            $Result.ServiceStartMode              | Should -Be 3
            $Result.ServiceState                  | Should -Be 'Stopped'
            $Result.ServiceType                   | Should -Be 16
            $Result.ServiceRegistryKey            | Should -Be "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\$ServiceName"
            $Result.ServiceImagePath              | Should -Not -BeNullOrEmpty
            $Result.DriverPathFormatted           | Should -be $null
            $Result.DriverPathUnformatted         | Should -be $null
            $Result.DriverFileHashSHA256          | Should -be $null
            $Result.LoadedImageBaseAddress        | Should -be $null
            $Result.LoadedImageSize               | Should -be $null
            $Result.LoadCount                     | Should -be $null

        }

        It 'should create a Win32ShareProcess service called Win32ATHService successfully via Win32 API CreateService' {
            $ServiceName = 'Win32ATHService'

            $Result = New-ATHService -ServiceName $ServiceName -DisplayName $ServiceName -ServiceType Win32ShareProcess -Variant Win32 -DeleteServiceBinary

            $Result | Should -Not -BeNullOrEmpty

            $Result.TechniqueID                   | Should -BeExactly $ExpectedTechniqueID
            $Result.TestSuccess                   | Should -Be $true
            $Result.ServiceName                   | Should -Be $ServiceName
            $Result.ServiceDisplayName            | Should -Be $ServiceName
            $Result.ServiceStartMode              | Should -Be 3
            $Result.ServiceState                  | Should -Be 'Stopped'
            $Result.ServiceType                   | Should -Be 32
            $Result.ServiceRegistryKey            | Should -Be "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\$ServiceName"
            $Result.ServiceImagePath              | Should -Not -BeNullOrEmpty
            $Result.DriverPathFormatted           | Should -be $null
            $Result.DriverPathUnformatted         | Should -be $null
            $Result.DriverFileHashSHA256          | Should -be $null
            $Result.LoadedImageBaseAddress        | Should -be $null
            $Result.LoadedImageSize               | Should -be $null
            $Result.LoadCount                     | Should -be $null

        }

        It 'should create a service called RegATHService successfully via manual Registry' {
            $ServiceName = 'RegATHService'

            $Result = New-ATHService -ServiceName $ServiceName -DisplayName $ServiceName -FilePath 'C:\Windows\System32\cmd.exe' -Variant Registry

            $Result | Should -Not -BeNullOrEmpty

            $Result.TechniqueID                   | Should -BeExactly $ExpectedTechniqueID
            $Result.TestSuccess                   | Should -Be $true
            $Result.ServiceName                   | Should -Be $ServiceName
            $Result.ServiceDisplayName            | Should -Be $ServiceName
            $Result.ServiceStartMode              | Should -Be 3
            $Result.ServiceState                  | Should -Be 'Stopped'
            $Result.ServiceType                   | Should -Be 16
            $Result.ServiceRegistryKey            | Should -Be "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\$ServiceName"
            $Result.ServiceImagePath              | Should -Not -BeNullOrEmpty
            $Result.DriverPathFormatted           | Should -be $null
            $Result.DriverPathUnformatted         | Should -be $null
            $Result.DriverFileHashSHA256          | Should -be $null
            $Result.LoadedImageBaseAddress        | Should -be $null
            $Result.LoadedImageSize               | Should -be $null
            $Result.LoadCount                     | Should -be $null

        }



    }
}
Describe 'Remove-ATHService' {
    BeforeAll {
        $Help = Get-Help -Name Remove-ATHService -Full
    
        $ExpectedTechniqueID = $null

        if ($Help.Synopsis.Split("`r`n")[-1] -match '^(?-i:Technique ID: )(?<TechniqueID>\S+) (?<TechniqueDescription>\(.+\))$') {
            $ExpectedTechniqueID = $Matches['TechniqueID']
        }
    }

    Context 'Validating error conditions' -Tag 'Unit', 'T1543.003' {
        It 'should remove ATHService' { 
                $Result =  Remove-ATHService -ServiceName ATHService

                $Result | Should -Not -BeNullOrEmpty

                $Result.TechniqueID     | Should -BeExactly $ExpectedTechniqueID
                $Result.ServiceRemoved   | Should -Be $true
                $Result.ServiceName     | Should -Be 'ATHService'
            } 

        It 'should remove WMIATHService' {
                $Result =  Remove-ATHService -ServiceName WMIATHService

                $Result | Should -Not -BeNullOrEmpty

                $Result.TechniqueID     | Should -BeExactly $ExpectedTechniqueID
                $Result.ServiceRemoved   | Should -Be $true
                $Result.ServiceName     | Should -Be 'WMIATHService'
            
        }

        It 'should remove Win32ATHService' {
                $Result =  Remove-ATHService -ServiceName Win32ATHService

                $Result | Should -Not -BeNullOrEmpty

                $Result.TechniqueID     | Should -BeExactly $ExpectedTechniqueID
                $Result.ServiceRemoved   | Should -Be $true
                $Result.ServiceName     | Should -Be 'Win32ATHService'
        }

        It 'should remove RegATHService via manual registry removal' {
                $Result =  Remove-ATHService -ServiceName RegATHService -RegistryRemove
                $Global:foo = $Result
                $Result | Should -Not -BeNullOrEmpty

                $Result.TechniqueID     | Should -BeExactly $ExpectedTechniqueID
                $Result.ServiceRemoved   | Should -Be $true
                $Result.ServiceName     | Should -Be 'RegATHService'
        }
    }
}