Set-StrictMode -Version Latest

$TestScriptRoot = Split-Path $MyInvocation.MyCommand.Path -Parent
$ModuleRoot = Resolve-Path "$TestScriptRoot\..\..\..\"
$ModuleManifest = "$ModuleRoot\AtomicTestHarnesses.psd1"

Remove-Module [A]tomicTestHarnesses
Import-Module $ModuleManifest -Force -ErrorAction Stop

Describe 'New-ATHPortableExecutableRunner' {
    BeforeAll {
        $Help = Get-Help -Name New-ATHPortableExecutableRunner -Full

        $ExpectedTechniqueID = $null

        if ($Help.Synopsis.Split("`r`n")[-1] -match '^(?-i:Technique ID: )(?<TechniqueID>\S+) (?<TechniqueDescription>\(.+\))$') {
            $ExpectedTechniqueID = $Matches['TechniqueID']
        }
    }

    Context 'Expected artifacts and behaviors when exercising the attack technique' -Tag 'Technique', 'T1204.002' {
        BeforeAll {
            $Script:FixedTestGuid = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'

            $Script:DefaultDllFilename = 'test.dll'
            $Script:DefaultExeFilename = 'test.exe'
        }

        It 'generate an EXE file with only the -FilePath argument' -Tag 'Technique', 'T1204.002' {
            $Result = New-ATHPortableExecutableRunner -FilePath $DefaultExeFilename -TestGuid $FixedTestGuid

            $Result | Should -Not -BeNullOrEmpty

            $Result.TechniqueID                       | Should -BeExactly $ExpectedTechniqueID
            $Result.TestGuid                          | Should -BeExactly $FixedTestGuid
            $Result.PEFilePath                        | Should -Not -BeNullOrEmpty
            Split-Path -Path $Result.PEFilePath -Leaf | Should -BeExactly $DefaultExeFilename
            $Result.PEType                            | Should -BeExactly 'Exe'
            $Result.PEHashMD5                         | Should -Not -BeNullOrEmpty
            $Result.PEHashSHA1                        | Should -Not -BeNullOrEmpty
            $Result.PEHashSHA256                      | Should -Not -BeNullOrEmpty
            $Result.EmbeddedScriptblock.ToString()    | Should -BeExactly "powershell.exe --% -nop -Command Write-Host $FixedTestGuid; Start-Sleep -Seconds 5; exit"
            $Result.DllExportFunction                 | Should -BeNullOrEmpty
            $Result.DllExportOrdinal                  | Should -BeNullOrEmpty
            $Result.VersionInfoResourcePresent        | Should -BeFalse
            $Result.OriginalFilename                  | Should -BeNullOrEmpty
            $Result.InternalName                      | Should -BeNullOrEmpty
            $Result.CompanyName                       | Should -BeNullOrEmpty
            $Result.FileDescription                   | Should -BeNullOrEmpty
            $Result.ProductVersion                    | Should -BeNullOrEmpty
            $Result.ProductName                       | Should -BeNullOrEmpty
            $Result.IsSigned                          | Should -BeFalse
            $Result.CertSigner                        | Should -BeNullOrEmpty
            $Result.CertThumbprint                    | Should -BeNullOrEmpty
            $Result.CertSerialNumber                  | Should -BeNullOrEmpty
            $Result.CertCreation                      | Should -BeNullOrEmpty
            $Result.CertExpiration                    | Should -BeNullOrEmpty
            $Result.CertIssuer                        | Should -BeNullOrEmpty
            $Result.CertIssuerThumbprint              | Should -BeNullOrEmpty
            $Result.TempResFilePath.EndsWith('test.res') | Should -BeTrue
            $Result.TempILFilePath.EndsWith('test.il')   | Should -BeTrue
        }

        It 'generate an DLL file with only the -FilePath argument' -Tag 'Technique', 'T1204.002' {
            $Result = New-ATHPortableExecutableRunner -FilePath $DefaultDllFilename -Dll -TestGuid $FixedTestGuid

            $Result | Should -Not -BeNullOrEmpty

            $Result.TechniqueID                       | Should -BeExactly $ExpectedTechniqueID
            $Result.TestGuid                          | Should -BeExactly $FixedTestGuid
            $Result.PEFilePath                        | Should -Not -BeNullOrEmpty
            Split-Path -Path $Result.PEFilePath -Leaf | Should -BeExactly $DefaultDllFilename
            $Result.PEType                            | Should -BeExactly 'Dll'
            $Result.PEHashMD5                         | Should -Not -BeNullOrEmpty
            $Result.PEHashSHA1                        | Should -Not -BeNullOrEmpty
            $Result.PEHashSHA256                      | Should -Not -BeNullOrEmpty
            $Result.EmbeddedScriptblock.ToString()    | Should -BeExactly "powershell.exe --% -nop -Command Write-Host $FixedTestGuid; Start-Sleep -Seconds 5; exit"
            $Result.DllExportFunction                 | Should -BeExactly 'RunMe'
            $Result.DllExportOrdinal                  | Should -Be 1
            $Result.VersionInfoResourcePresent        | Should -BeFalse
            $Result.OriginalFilename                  | Should -BeNullOrEmpty
            $Result.InternalName                      | Should -BeNullOrEmpty
            $Result.CompanyName                       | Should -BeNullOrEmpty
            $Result.FileDescription                   | Should -BeNullOrEmpty
            $Result.ProductVersion                    | Should -BeNullOrEmpty
            $Result.ProductName                       | Should -BeNullOrEmpty
            $Result.IsSigned                          | Should -BeFalse
            $Result.CertSigner                        | Should -BeNullOrEmpty
            $Result.CertThumbprint                    | Should -BeNullOrEmpty
            $Result.CertSerialNumber                  | Should -BeNullOrEmpty
            $Result.CertCreation                      | Should -BeNullOrEmpty
            $Result.CertExpiration                    | Should -BeNullOrEmpty
            $Result.CertIssuer                        | Should -BeNullOrEmpty
            $Result.CertIssuerThumbprint              | Should -BeNullOrEmpty
            $Result.TempResFilePath.EndsWith('test.res') | Should -BeTrue
            $Result.TempILFilePath.EndsWith('test.il')   | Should -BeTrue
        }

        It 'clone kernel32.dll version info and signature attributes' -Tag 'Technique', 'T1204.002' {
            $FileInfo = Get-Item -Path "$Env:windir\System32\kernel32.dll"

            $Result = $FileInfo | New-ATHPortableExecutableRunner -FilePath $DefaultDllFilename -Dll -SignFile -TestGuid $FixedTestGuid

            $Result | Should -Not -BeNullOrEmpty

            $Result.TechniqueID                       | Should -BeExactly $ExpectedTechniqueID
            $Result.TestGuid                          | Should -BeExactly $FixedTestGuid
            $Result.PEFilePath                        | Should -Not -BeNullOrEmpty
            Split-Path -Path $Result.PEFilePath -Leaf | Should -BeExactly $DefaultDllFilename
            $Result.PEType                            | Should -BeExactly 'Dll'
            $Result.PEHashMD5                         | Should -Not -BeNullOrEmpty
            $Result.PEHashSHA1                        | Should -Not -BeNullOrEmpty
            $Result.PEHashSHA256                      | Should -Not -BeNullOrEmpty
            $Result.EmbeddedScriptblock.ToString()    | Should -BeExactly "powershell.exe --% -nop -Command Write-Host $FixedTestGuid; Start-Sleep -Seconds 5; exit"
            $Result.DllExportFunction                 | Should -BeExactly 'RunMe'
            $Result.DllExportOrdinal                  | Should -Be 1
            $Result.VersionInfoResourcePresent        | Should -BeTrue
            $Result.OriginalFilename                  | Should -BeExactly $FileInfo.VersionInfo.OriginalFilename
            $Result.InternalName                      | Should -BeExactly $FileInfo.VersionInfo.InternalName
            $Result.CompanyName                       | Should -BeExactly $FileInfo.VersionInfo.CompanyName
            $Result.FileDescription                   | Should -BeExactly $FileInfo.VersionInfo.FileDescription
            $Result.ProductVersion                    | Should -BeExactly $FileInfo.VersionInfo.ProductVersion
            $Result.ProductName                       | Should -BeExactly $FileInfo.VersionInfo.ProductName
            $Result.IsSigned                          | Should -BeTrue
            $Result.CertSigner                        | Should -Not -BeNullOrEmpty
            $Result.CertThumbprint                    | Should -Not -BeNullOrEmpty
            $Result.CertSerialNumber                  | Should -Not -BeNullOrEmpty
            $Result.CertCreation                      | Should -Not -BeNullOrEmpty
            $Result.CertExpiration                    | Should -Not -BeNullOrEmpty
            $Result.CertIssuer                        | Should -Not -BeNullOrEmpty
            $Result.CertIssuerThumbprint              | Should -Not -BeNullOrEmpty
            $Result.TempResFilePath.EndsWith('test.res') | Should -BeTrue
            $Result.TempILFilePath.EndsWith('test.il')   | Should -BeTrue
        }

        It 'launch the default embedded scriptblock from an EXE' -Tag 'Technique', 'T1204.002' {
            $Result = New-ATHPortableExecutableRunner -FilePath $DefaultExeFilename

            $Result | Should -Not -BeNullOrEmpty

            $WMIEventQuery = "SELECT * FROM __InstanceCreationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_Process' AND TargetInstance.Name = 'powershell.exe' AND TargetInstance.CommandLine LIKE '%$($Result.TestGuid)%'"

            $null = Register-CimIndicationEvent -SourceIdentifier 'ProcessSpawned' -Query $WMIEventQuery -Action {
                $SpawnedProcInfo = [PSCustomObject] @{
                    ProcessId = $EventArgs.NewEvent.TargetInstance.ProcessId
                    ProcessCommandLine = $EventArgs.NewEvent.TargetInstance.CommandLine
                }

                New-Event -SourceIdentifier 'ChildProcSpawned' -MessageData $SpawnedProcInfo

                Stop-Process -Id $EventArgs.NewEvent.TargetInstance.ProcessId -Force
            }

            Start-Process -FilePath $Result.PEFilePath

            $ChildProcSpawnedEvent = Wait-Event -SourceIdentifier 'ChildProcSpawned' -Timeout 10
            $ChildProcInfo = $null

            $ExpectedChildProcSpawned = $False

            if ($ChildProcSpawnedEvent) {
                $ExpectedChildProcSpawned = $True
                $ChildProcSpawnedEvent | Remove-Event
            }

            Unregister-Event -SourceIdentifier 'ProcessSpawned'

            $ExpectedChildProcSpawned | Should -BeTrue
        }

        It 'launch the default embedded scriptblock from an DLL' -Tag 'Technique', 'T1204.002' {
            $Result = New-ATHPortableExecutableRunner -FilePath $DefaultDllFilename -Dll

            $Result | Should -Not -BeNullOrEmpty

            $WMIEventQuery = "SELECT * FROM __InstanceCreationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_Process' AND TargetInstance.Name = 'powershell.exe' AND TargetInstance.CommandLine LIKE '%$($Result.TestGuid)%'"

            $null = Register-CimIndicationEvent -SourceIdentifier 'ProcessSpawned' -Query $WMIEventQuery -Action {
                $SpawnedProcInfo = [PSCustomObject] @{
                    ProcessId = $EventArgs.NewEvent.TargetInstance.ProcessId
                    ProcessCommandLine = $EventArgs.NewEvent.TargetInstance.CommandLine
                }

                New-Event -SourceIdentifier 'ChildProcSpawned' -MessageData $SpawnedProcInfo

                Stop-Process -Id $EventArgs.NewEvent.TargetInstance.ProcessId -Force
            }

            Start-Process -FilePath "$Env:windir\System32\rundll32.exe" -ArgumentList "$($Result.PEFilePath),RunMe"

            $ChildProcSpawnedEvent = Wait-Event -SourceIdentifier 'ChildProcSpawned' -Timeout 10
            $ChildProcInfo = $null

            $ExpectedChildProcSpawned = $False

            if ($ChildProcSpawnedEvent) {
                $ExpectedChildProcSpawned = $True
                $ChildProcSpawnedEvent | Remove-Event
            }

            Unregister-Event -SourceIdentifier 'ProcessSpawned'

            $ExpectedChildProcSpawned | Should -BeTrue
        }
    }
}