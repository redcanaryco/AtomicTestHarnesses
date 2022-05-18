@{

# Script module or binary module file associated with this manifest.
RootModule = 'AtomicTestHarnesses.psm1'

# Version number of this module.
ModuleVersion = '1.9.0.0'

# ID used to uniquely identify this module
GUID = '195a1637-d4a4-4cb3-8d80-5b5d4e3e930a'

# Author of this module
Author = 'Mike Haag, Jesse Brown, Matt Graeber, Jonathan Johnson'

# Company or vendor of this module
CompanyName = 'Red Canary, Inc.'

# Copyright statement for this module
Copyright = '2021 Red Canary, Inc. All rights reserved.'

# Description of the functionality provided by this module
Description = 'A module to facilitate the testing of attack techniques and their corresponding procedures.'

# Minimum version of the Windows PowerShell engine required by this module
PowerShellVersion = '5.0'

# Assemblies that must be loaded prior to importing this module
RequiredAssemblies = @('TestHarnesses\T1218.007_Msiexec\Dependencies\Microsoft.Deployment.WindowsInstaller.dll')

# Functions to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no functions to export.
FunctionsToExport = 'Get-ATHDriverService',
                    'Get-ATHMSI',
                    'Invoke-ATHHTMLApplication',
                    'Invoke-ATHCompiledHelp',
                    'Invoke-ATHCORProfiler',
                    'Invoke-ATHCreateProcessWithToken',
                    'Invoke-ATHInjectedThread',
                    'Invoke-ATHMSBuild',
                    'Invoke-ATHRemoteFXvGPUDisablementCommand',
                    'Invoke-ATHTokenImpersonation',
                    'New-ATHDriverService',
                    'Invoke-ATHMSI',
                    'New-ATHMSI',
                    'Out-ATHPowerShellCommandLineParameter',
                    'Remove-ATHDriverService',
                    'Start-ATHProcessHerpaderp',
                    'Start-ATHProcessUnderSpecificParent'
                    

# Private data to pass to the module specified in RootModule/ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
PrivateData = @{

    PSData = @{

        # Tags applied to this module. These help with module discovery in online galleries.
        Tags = @('Security', 'Defense')

        # A URL to the license for this module.
        LicenseUri = 'https://github.com/redcanaryco/AtomicTestHarnesses/blob/master/LICENSE'

        # A URL to the main website for this project.
        ProjectUri = 'https://github.com/redcanaryco/AtomicTestHarnesses'

        # ReleaseNotes of this module
        ReleaseNotes = @'

1.9.0
-----
Added: 
* New-ATHMSI
* Get-ATHMSI
* Invoke-ATHMSI

1.8.0
-----
Added: 
* Invoke-ATHTokenImpersonation
* Invoke-ATHCreateProcessWithToken

1.7.0
-----
Added:
* New-ATHDriverService
* Get-ATHDriverService
* Remove-ATHDriverService

1.6.0
-----
Added:
* Invoke-ATHCorProfiler

1.5.0
-----
Added:
* Invoke-ATHInjectedThread

1.4.0
-----
Added:
* Invoke-ATHMSBuild

Improvements:
* Invoke-ATHCompiledHelp was returning the wrong MITRE technique ID. Thanks, Mike Haag (@M_haggis) for pointing out the issue and supplying the fix!
* Invoke-ATHCompiledHelp Pester tests were extracting the incorrect MITRE technique ID.

1.3.0
-----
Added:
* Start-ATHProcessHerpaderp

1.2.0
-----
Added:
* Invoke-ATHRemoteFXvGPUDisablementCommand

1.1.1
-----
Added:
* Out-ATHPowerShellCommandLineParameter

Improvements:
* Added tags to each individual Pester test so that tags are surfaced when Invoke-Pester is run with -PassThru.
* Tweaked an error handler in Start-ATHProcessUnderSpecificParent to have less aggressive handling logic.

1.0.0
-----
Added:
* Invoke-ATHHTMLApplication
* Invoke-ATHCompiledHelp
* Start-ATHProcessUnderSpecificParent
'@

    } # End of PSData hashtable

} # End of PrivateData hashtable

}

