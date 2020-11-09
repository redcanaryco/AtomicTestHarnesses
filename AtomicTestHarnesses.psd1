@{

# Script module or binary module file associated with this manifest.
RootModule = 'AtomicTestHarnesses.psm1'

# Version number of this module.
ModuleVersion = '1.1.1.0'

# ID used to uniquely identify this module
GUID = '195a1637-d4a4-4cb3-8d80-5b5d4e3e930a'

# Author of this module
Author = 'Mike Haag, Jesse Brown, Matt Graeber'

# Company or vendor of this module
CompanyName = 'Red Canary, Inc.'

# Copyright statement for this module
Copyright = '2020 Red Canary, Inc. All rights reserved.'

# Description of the functionality provided by this module
Description = 'A module to facilitate the testing of attack techniques and their corresponding procedures.'

# Minimum version of the Windows PowerShell engine required by this module
PowerShellVersion = '5.0'

# Functions to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no functions to export.
FunctionsToExport = 'Invoke-ATHHTMLApplication',
                    'Invoke-ATHCompiledHelp',
                    'Out-ATHPowerShellCommandLineParameter',
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

