if (-not ('AtomicTestHarnesses_T1543_003.ProcessNativeMethods' -as [Type])) {
    $TypeDef = @'
using System;
using System.Runtime.InteropServices;

namespace AtomicTestHarnesses_T1543_003 {
    public struct UNICODE_STRING
	{
		public short  Length;
		public short  MaximumLength;
		public IntPtr Buffer;
	}

    [Flags]
    public enum SC_MANAGER {
        AllAccess        = 0xF003F,
        Connect          = 0x0001,
        CreateService    = 0x0002,
        EnumerateService = 0x0004,
        Lock             = 0x0008,
        QueryLockStatus  = 0x0010,
        ModifyBootConfig = 0x0020
    }

    [Flags]
    public enum SERVICE {
        AllAccess           = 0xF01FF,
        Delete              = 0x10000,
        QueryConfig         = 0x0001,
        ChangeConfig        = 0x0002,
        QueryStatus         = 0x0004,
        EnumerateDependents = 0x0008,
        Start               = 0x0010,
        Stop                = 0x0020,
        PauseContinue       = 0x0040,
        Interrogate         = 0x0080,
        UserDefinedControl  = 0x0100
    }

    [Flags]
    public enum SERVICE_START {
        BootStart   = 0x0000,
        SystemStart = 0x0001,
        AutoStart   = 0x0002,
        DemandStart = 0x0003,
        Disabled    = 0x0004
    }

    [StructLayout(LayoutKind.Sequential, Pack = 2, CharSet = CharSet.Ansi)]
    public struct SYSTEM_MODULE {
        public uint Reserved1;
        public uint Reserved2;
        public UInt64 ImageBaseAddress;
        public uint ImageSize;
        public uint Flags;
        public ushort Index;
        public ushort Rank;
        public ushort LoadCount;
        public ushort NameOffset;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
        public string Name;
    }

    public class ProcessNativeMethods {
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
		public static extern IntPtr CreateService(IntPtr hService, string serviceName, string displayName, int access, int serviceType, int startType, int errorControl, string binaryPath, string loadOrderGroup, IntPtr pTagId, string dependencies, string servicesStartName, string password);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
		public static extern IntPtr OpenSCManager(string machineName, string databaseName, int access);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
		public static extern bool CloseServiceHandle(IntPtr hService);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
		public static extern bool DeleteService(IntPtr hService);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
		public static extern IntPtr OpenService(IntPtr hService, string serviceName, int access);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
		public static extern bool StartService(IntPtr hService, int dwNumServiceArgs, IntPtr lpServiceArgVectors);

        [DllImport("ntdll.dll", CharSet = CharSet.Unicode)]
		public static extern void RtlInitUnicodeString(ref UNICODE_STRING DestinationString, String SourceString);

        [DllImport("ntdll.dll")]
		public static extern int NtQuerySystemInformation(int SystemInformationClass, IntPtr SystemInformation, uint SystemInformationLength, ref uint ReturnLength);

        [DllImport("ntdll.dll")]
		public static extern int NtUnloadDriver(ref UNICODE_STRING DriverServiceName);
    }
}
'@

    Add-Type -TypeDefinition $TypeDef -ErrorAction Stop
}

# Helper function. Do not export.
function New-UnicodeString {
    param (
        [Parameter(Mandatory, Position = 0)]
        [ValidateNotNull()]
        $String
    )

    $UnicodeString = New-Object -TypeName AtomicTestHarnesses_T1543_003.UNICODE_STRING

    [AtomicTestHarnesses_T1543_003.ProcessNativeMethods]::RtlInitUnicodeString([Ref] $UnicodeString, $String)

    return $UnicodeString
}

# Helper function. Do not export.
# The purpose of this helper function is to normalize the inconsistent driver path strings.
# There may be some corner cases that were not considered here in which case, they can be easily added.
filter ConvertFrom-UnformattedDriverPath {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [String]
        [ValidateNotNullOrEmpty()]
        $DriverPathString
    )

    switch -Regex ($DriverPathString) {
        '^System32\\' {
            $FormattedPath = "$($Env:windir)\$DriverPathString"
        }

        '^\\\?\?\\[A-Z]{1}:\\' {
            $FormattedPath = $DriverPathString.Substring(4)
        }

        '^\\SystemRoot\\' {
            $FormattedPath = "$($env:SystemRoot)\$($DriverPathString.Substring(12))"
        }

        default {
            # Consider the path as-is. This may represent an unaccounted for corner case or a standard path - i.e. in the form of "drive-letter:\path\to\driver.sys"
            $FormattedPath = $DriverPathString
        }
    }

    $FormattedPath
}

# Helper function. Do not export.
# This function is a wrapper for NtQuerySystemInformation to retrieve loaded driver information.
function Get-LoadedDriver {
    [CmdletBinding()]
    Param ()

    if ([IntPtr]::Size -eq 4) {
        # 32-bit could be supported but this test harness does not require it.
        Write-Error 'Enumerating loaded drivers is only supported in a 64-bit process.'

        return
    }

    $ModuleInfo64BitStructSize = 296

    $SystemModuleInformation = 0x0B

    [UInt32] $ReturnLength = 0

    $Result = [AtomicTestHarnesses_T1543_003.ProcessNativeMethods]::NtQuerySystemInformation($SystemModuleInformation, [IntPtr]::Zero, 0, [ref] $ReturnLength)

    if ($Result -ne 0xC0000004) { # STATUS_INFO_LENGTH_MISMATCH
        Write-Error "NtQuerySystemInformation encountered an unexpected error. Error code: 0x$($Result.ToString('X8'))"

        return
    }

    $SysModuleInfoPtr = [Runtime.InteropServices.Marshal]::AllocHGlobal($ReturnLength)

    [UInt32] $ReturnLength2 = 0

    $Result = [AtomicTestHarnesses_T1543_003.ProcessNativeMethods]::NtQuerySystemInformation($SystemModuleInformation, $SysModuleInfoPtr, $ReturnLength, [ref] $ReturnLength2)

    if ($Result -ne 0) {
        [Runtime.InteropServices.Marshal]::FreeHGlobal($SysModuleInfoPtr)

        Write-Error "NtQuerySystemInformation encountered an unexpected error. Error code: 0x$($Result.ToString('X8'))"

        return
    }

    $ModuleCount = [Runtime.InteropServices.Marshal]::ReadInt32($SysModuleInfoPtr)

    $ModuleInfoPtr = [IntPtr]::Add($SysModuleInfoPtr, 0x10)

    $ModuleInformation = 1..$ModuleCount | ForEach-Object {
        [Runtime.InteropServices.Marshal]::PtrToStructure($ModuleInfoPtr, [Type][AtomicTestHarnesses_T1543_003.SYSTEM_MODULE])
        $ModuleInfoPtr = [IntPtr]::Add($ModuleInfoPtr, $ModuleInfo64BitStructSize)
    }

    [Runtime.InteropServices.Marshal]::FreeHGlobal($SysModuleInfoPtr)

    $ModuleInformation
}

filter Get-ATHDriverService {
<#
.SYNOPSIS

Retrieves information about an installed and/or loaded driver service.

Technique ID: T1543.003 (Create or Modify System Process: Windows Service)

.DESCRIPTION

Get-ATHDriverService retrieves information about a registered driver service with optional loaded driver context. This function can be used to validate the installation and loaded status of existing services or validate the installation of a new driver service.

Get-ATHDriverService permits a user to specify either a specific service name to query or the filename of a driver that it suspected to be loaded.

Get-ATHDriverService does not comprise an attack technique so it has no need to implement the standardized TestSuccess and TestGuid output fields.

.PARAMETER ServiceName

Specifies a service name to query that corresponds to a driver-specific service.

.PARAMETER LoadedDriverFileName

Specifies the filename of a driver that is suspected to be loaded. Get-ATHDriverService will return all loaded drivers that match the specified filename and attempt to identify its corresponding installed service.

.INPUTS

System.ServiceProcess.ServiceController

Get-ATHDriverService accepts the output of Get-Service.

Microsoft.Management.Infrastructure.CimInstance#root/cimv2/Win32_SystemDriver

Get-ATHDriverService accepts the output of a Win32_SystemDriver WMI object via Get-CimInstance.

.OUTPUTS

PSObject

Outputs an object consisting of relevant execution details. The following object properties may be populated:

* TechniqueID - Specifies the relevant MITRE ATT&CK Technique ID.
* ServiceName - Specifies the name of the installed service. This field may not be populated if a driver is loaded that does not have a corresponding service.
* ServiceDisplayName - Specifies the display name of the installed service. This field may not be populated if a driver is loaded that does not have a corresponding service.
* ServiceStartMode - Specifies the name of the installed service. The following start modes may be returned: Boot, System, Auto, Manual, Disabled. This field may not be populated if a driver is loaded that does not have a corresponding service.
* ServiceState - Specifies the current state of the installed service. The following states may be returned: Stopped, Start Pending, Stop Pending, Running, Continue Pending, Pause Pending, Paused, Unknown. This field may not be populated if a driver is loaded that does not have a corresponding service.
* ServiceType - Specifies the type of installed service. The following types may be returned: Kernel Driver, File System Driver, Unknown. This field may not be populated if a driver is loaded that does not have a corresponding service.
* ServiceRegistryKey - Specifies the registry key path of the installed service. This field may not be populated if a driver is loaded that does not have a corresponding service.
* DriverPathFormatted - The full path to the driver formatted as driver-letter:\path\to\driver.sys
* DriverPathUnformatted - The full, unformatted driver path. Driver paths are not standardized and can be interpreted in several ways.
* LoadedImageBaseAddress - The loaded kernel virtual base address of the driver. This field may not be populated if the driver is not currently loaded.
* LoadedImageSize - The image size of the driver mapped in memory. This field may not be populated if the driver is not currently loaded.
* LoadCount - The number of times the driver has been loaded in kernel memory. This field may not be populated if the driver is not currently loaded.

.EXAMPLE

Get-ATHDriverService -ServiceName Beep

.EXAMPLE

Get-ATHDriverService -LoadedDriverFileName cdrom.sys
#>
    [CmdletBinding(DefaultParameterSetName = 'ServiceName')]
    param(
        [Parameter(Mandatory, ParameterSetName = 'ServiceName', ValueFromPipelineByPropertyName)]
        [String]
        [ValidateLength(0,256)]
        [Alias('Name')]
        $ServiceName,

        [Parameter(Mandatory, ParameterSetName = 'FileName')]
        [String]
        [ValidateNotNullOrEmpty()]
        $LoadedDriverFileName
    )

    $LoadedDrivers = Get-LoadedDriver

    $DriverServiceHashtable = @{}

    # Prepopulate a hashtable consisting of driver service names with their corresponding image paths.
    (Get-Item HKLM:\SYSTEM\CurrentControlSet\Services\).GetSubKeyNames() | ForEach-Object {
        $ServiceInformation = try { [PSCustomObject] @{
            Type = (Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$_" -Name Type)
            ImagePath = (Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$_" -Name ImagePath)
        } } catch {}

        if ($ServiceInformation -and (($ServiceInformation.Type -eq 1) -or ($ServiceInformation.Type -eq 2))) {
            $DriverServiceHashtable[$_] = ConvertFrom-UnformattedDriverPath -DriverPathString $ServiceInformation.ImagePath
        }
    }

    switch ($PSCmdlet.ParameterSetName) {
        'ServiceName' {
            $ServiceWMIInstance = Get-CimInstance Win32_SystemDriver -Filter "Name = '$ServiceName'" | Select-Object -First 1

            if (-not $ServiceWMIInstance) {
                # Attempt to resolve the driver path directly via the registry.
                $ServiceType = Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName" -Name Type -ErrorAction Stop

                if (-not (($ServiceType -eq 1) -or ($ServiceType -eq 2))) {
                    Write-Error "The specified service is not a driver service. Service name: $ServiceName"

                    return
                }

                $ImagePath = Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName" -Name ImagePath -ErrorAction Stop

                $UnformattedDriverPath = $ImagePath
                $ResolvedDriverPath = ConvertFrom-UnformattedDriverPath -DriverPathString $ImagePath
            } else {
                $UnformattedDriverPath = $ServiceWMIInstance.PathName
                $ResolvedDriverPath = ConvertFrom-UnformattedDriverPath -DriverPathString $ServiceWMIInstance.PathName
            }

            $ResolvedDriverHash = Get-FileHash -Path $ResolvedDriverPath -Algorithm SHA256 | Select-Object -ExpandProperty Hash

            # Attempt to find the first matching loaded driver based on the resolved service image path
            $MatchingLoadedDriver = $LoadedDrivers | ForEach-Object {
                if ($ResolvedDriverPath -eq (ConvertFrom-UnformattedDriverPath -DriverPathString $_.Name)) { $_ }
            } | Select-Object -First 1

            if ($MatchingLoadedDriver) {
                [PSCustomObject] @{
                    TechniqueID        = 'T1543.003'
                    ServiceName        = $ServiceWMIInstance.Name
                    ServiceDisplayName = $ServiceWMIInstance.Description
                    ServiceStartMode   = $ServiceWMIInstance.StartMode
                    ServiceState       = $ServiceWMIInstance.State
                    ServiceType        = $ServiceWMIInstance.ServiceType
                    ServiceRegistryKey = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\$ServiceName"
                    DriverPathFormatted    = $ResolvedDriverPath
                    DriverPathUnformatted  = $MatchingLoadedDriver.Name
                    DriverFileHashSHA256   = $ResolvedDriverHash
                    LoadedImageBaseAddress = $MatchingLoadedDriver.ImageBaseAddress
                    LoadedImageSize        = $MatchingLoadedDriver.ImageSize
                    LoadCount              = $MatchingLoadedDriver.LoadCount
                }
            } else {
                # No corresponding loaded driver was found
                [PSCustomObject] @{
                    TechniqueID        = 'T1543.003'
                    ServiceName        = $ServiceWMIInstance.Name
                    ServiceDisplayName = $ServiceWMIInstance.Description
                    ServiceStartMode   = $ServiceWMIInstance.StartMode
                    ServiceState       = $ServiceWMIInstance.State
                    ServiceType        = $ServiceWMIInstance.ServiceType
                    ServiceRegistryKey = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\$ServiceName"
                    DriverPathFormatted    = $ResolvedDriverPath
                    DriverPathUnformatted  = $UnformattedDriverPath
                    DriverFileHashSHA256   = $ResolvedDriverHash
                    LoadedImageBaseAddress = $null
                    LoadedImageSize        = $null
                    LoadCount              = $null
                }
            }
        }

        'FileName' {
            $LoadedDrivers | Where-Object { $_.Name.ToLower().EndsWith($LoadedDriverFileName.ToLower()) } | ForEach-Object {
                $ResolvedDriverPath = ConvertFrom-UnformattedDriverPath -DriverPathString $_.Name

                $ResolvedDriverHash = Get-FileHash -Path $ResolvedDriverPath -Algorithm SHA256 | Select-Object -ExpandProperty Hash

                # For each loaded driver, attempt to resolve any services that correspond to the driver image path
                $MatchingServices = foreach ($ServiceName in $DriverServiceHashtable.Keys) {
                    if ($DriverServiceHashtable[$ServiceName] -eq $ResolvedDriverPath) {
                        $ServiceName
                    }
                }

                if ($MatchingServices) {
                    foreach ($MatchingServiceName in $MatchingServices) {
                        $ServiceWMIInstance = Get-CimInstance -ClassName Win32_SystemDriver -Filter "Name = '$MatchingServiceName'"

                        [PSCustomObject] @{
                            TechniqueID        = 'T1543.003'
                            ServiceName        = $MatchingServiceName
                            ServiceDisplayName = $ServiceWMIInstance.Description
                            ServiceStartMode   = $ServiceWMIInstance.StartMode
                            ServiceState       = $ServiceWMIInstance.State
                            ServiceType        = $ServiceWMIInstance.ServiceType
                            ServiceRegistryKey = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\$MatchingServiceName"
                            DriverPathFormatted    = $ResolvedDriverPath
                            DriverPathUnformatted  = $_.Name
                            DriverFileHashSHA256   = $ResolvedDriverHash
                            LoadedImageBaseAddress = $_.ImageBaseAddress
                            LoadedImageSize        = $_.ImageSize
                            LoadCount              = $_.LoadCount
                        }
                    }
                } else {
                    # No corresponding service was found.
                    [PSCustomObject] @{
                        TechniqueID        = 'T1543.003'
                        ServiceName        = $null
                        ServiceDisplayName = $null
                        ServiceStartMode   = $null
                        ServiceState       = $null
                        ServiceType        = $null
                        ServiceRegistryKey = $null
                        DriverPathFormatted    = $ResolvedDriverPath
                        DriverPathUnformatted  = $_.Name
                        DriverFileHashSHA256   = $ResolvedDriverHash
                        LoadedImageBaseAddress = $_.ImageBaseAddress
                        LoadedImageSize        = $_.ImageSize
                        LoadCount              = $_.LoadCount
                    }
                }
            }
        }
    }
}

function Remove-ATHService {
<#
.SYNOPSIS

Uninstall a driver service and optionally unload the corresponding loaded driver.

Technique ID: T1543.003 (Create or Modify System Process: Windows Service)

.DESCRIPTION

Remove-ATHDriverService uninstalls a driver service and optionally unloads the corresponding loaded driver.

.PARAMETER ServiceName

Specifies the service name of the driver service to uninstall.

.PARAMETER Unload

Explicitly unload the loaded driver by calling NtUnloadDriver.

.INPUTS

System.ServiceProcess.ServiceController

Remove-ATHDriverService accepts the output of Get-Service.

Microsoft.Management.Infrastructure.CimInstance#root/cimv2/Win32_SystemDriver

Remove-ATHDriverService accepts the output of a Win32_SystemDriver WMI object via Get-CimInstance.

.OUTPUTS

PSObject

Outputs an object consisting of relevant uninstallation details. The following object properties may be populated:

* TechniqueID - Specifies the relevant MITRE ATT&CK Technique ID.
* ServiceRemoved - Indicates True if the service was successfully removed.
* ServiceName - Specifies the name of the uninstalled service.

.EXAMPLE

Remove-ATHDriverService -ServiceName TestDriverService

.EXAMPLE

Remove-ATHDriverService -ServiceName TestDriverService -Unload
#>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [String]
        [ValidateLength(0,256)]
        [Alias('Name')]
        $ServiceName,

        [Switch]
        $DriverUnload, 

        [Switch]
        $RegistryRemove
    )

    
    if($RegistryRemove){

        $null = Remove-Item HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName

        [PSCustomObject] @{
            TechniqueID = 'T1543.003'
            ServiceRemoved = $True
            ServiceName = $ServiceName
        }
    }
    else{
        if ($DriverUnload) {
            $DriverServiceInstance = Get-CimInstance -ClassName Win32_SystemDriver -Filter "Name = '$ServiceName'"

            if (-not $DriverServiceInstance) {
                Write-Error "The `"$ServiceName`" service is not a registered driver service."

                return
            }
            $ServiceNameString = New-UnicodeString -String $ServiceName

            $UnloadResult = [AtomicTestHarnesses_T1543_003.ProcessNativeMethods]::NtUnloadDriver([Ref] $ServiceNameString)

            if ($UnloadResult) {
                Write-Error "The driver corresponding to the `"$ServiceName`" service failed to unload. ErrorCode: 0x$($UnloadResult.ToString('X8'))"
            }
        }

        Write-Verbose 'Requesting service control manager handle with SC_MANAGER_CONNECT access.'

        # Get a handle to the service control manager requesting the minimum possible access to create a service: SC_MANAGER_CONNECT (0x0001)
        $SCHandle = [AtomicTestHarnesses_T1543_003.ProcessNativeMethods]::OpenSCManager(
            $null,                                              # lpMachineName
            'ServicesActive',                                   # lpDatabaseName
            [AtomicTestHarnesses_T1543_003.SC_MANAGER]::Connect # dwDesiredAccess
        );$LastError = [ComponentModel.Win32Exception][Runtime.InteropServices.Marshal]::GetLastWin32Error()

        if ($SCHandle -eq ([IntPtr]::Zero)) {
            # Failed to open a handle to the service control manager

            Write-Error "Failed to obtain a service control manager handle with SC_MANAGER_CONNECT access. Reason: $($LastError.Message) (ErrorCode: 0x$($LastError.NativeErrorCode.ToString('X8')))"

            return
        }

        Write-Verbose 'Requesting service handle with DELETE access.'

        $ServiceHandle = [AtomicTestHarnesses_T1543_003.ProcessNativeMethods]::OpenService(
            $SCHandle,                                        # hSCManager
            $ServiceName,                                     # lpServiceName
            ([AtomicTestHarnesses_T1543_003.SERVICE]::Delete) # dwDesiredAccess
        );$LastError = [ComponentModel.Win32Exception][Runtime.InteropServices.Marshal]::GetLastWin32Error()

        if ($ServiceHandle -eq ([IntPtr]::Zero)) {
            # Close the service control manager handle
            $null = [AtomicTestHarnesses_T1543_003.ProcessNativeMethods]::CloseServiceHandle($SCHandle)

            Write-Error "Failed to obtain a service handle with DELETE access. Reason: $($LastError.Message) (ErrorCode: 0x$($LastError.NativeErrorCode.ToString('X8')))"

            return
        }

        Write-Verbose 'Deleting the service.'

        $DeletionResult = [AtomicTestHarnesses_T1543_003.ProcessNativeMethods]::DeleteService(
            $ServiceHandle
        );$LastError = [ComponentModel.Win32Exception][Runtime.InteropServices.Marshal]::GetLastWin32Error()

        if ($False -eq $DeletionResult) {
            # Close the service handle
            $null = [AtomicTestHarnesses_T1543_003.ProcessNativeMethods]::CloseServiceHandle($ServiceHandle)

            # Close the service control manager handle
            $null = [AtomicTestHarnesses_T1543_003.ProcessNativeMethods]::CloseServiceHandle($SCHandle)

            Write-Error "Failed to delete the service. Reason: $($LastError.Message) (ErrorCode: 0x$($LastError.NativeErrorCode.ToString('X8')))"

            return
        }

        Write-Verbose 'Service was successfully deleted.'

        [PSCustomObject] @{
            TechniqueID = 'T1543.003'
            ServiceRemoved = $True
            ServiceName = $ServiceName
        }
    }
}


function New-ATHService {
<#
.SYNOPSIS

Installs a driver as a service.

Technique ID: T1543.003 (Create or Modify System Process: Windows Service)

.DESCRIPTION

New-ATHDriverService installs a driver as a service and optionally loads it.

.PARAMETER ServiceName

Specifies the name of the service to be created.

.PARAMETER DisplayName

Specifies the description of the service to be created.

.PARAMETER StartType

Specifies how the driver service should start. Supported options are: BootStart, SystemStart, AutoStart, DemandStart, Disabled. If -StartType is not specified, AutoStart is used as the default option.

.PARAMETER ServiceType

Specifies the type of driver service to install: KernelDriver or FileSystemDriver. If -ServiceType is not specified, KernelDriver is used as the default option.

.PARAMETER FilePath

Specifies the path to the service binary.

.PARAMETER StartService

Indicates that the service is to be started immediately after installation.

.OUTPUTS

PSObject

Outputs an object consisting of relevant execution details. The following object properties may be populated:

* TechniqueID - Specifies the relevant MITRE ATT&CK Technique ID.
* ServiceName - Specifies the name of the installed service. This field may not be populated if a driver is loaded that does not have a corresponding service.
* ServiceDisplayName - Specifies the display name of the installed service. This field may not be populated if a driver is loaded that does not have a corresponding service.
* ServiceStartMode - Specifies the name of the installed service. The following start modes may be returned: Boot, System, Auto, Manual, Disabled. This field may not be populated if a driver is loaded that does not have a corresponding service.
* ServiceState - Specifies the current state of the installed service. The following states may be returned: Stopped, Start Pending, Stop Pending, Running, Continue Pending, Pause Pending, Paused, Unknown. This field may not be populated if a driver is loaded that does not have a corresponding service.
* ServiceType - Specifies the type of installed service. The following types may be returned: Kernel Driver, File System Driver, Unknown. This field may not be populated if a driver is loaded that does not have a corresponding service.
* ServiceRegistryKey - Specifies the registry key path of the installed service. This field may not be populated if a driver is loaded that does not have a corresponding service.
* DriverPathFormatted - The full path to the driver formatted as driver-letter:\path\to\driver.sys
* DriverPathUnformatted - The full, unformatted driver path. Driver paths are not standardized and can be interpreted in several ways.
* LoadedImageBaseAddress - The loaded kernel virtual base address of the driver. This field may not be populated if the driver is not currently loaded.
* LoadedImageSize - The image size of the driver mapped in memory. This field may not be populated if the driver is not currently loaded.
* LoadCount - The number of times the driver has been loaded in kernel memory. This field may not be populated if the driver is not currently loaded.

.EXAMPLE

New-ATHDriverService -ServiceName phymem -DisplayName 'Does driver stuff' -FilePath phymem64.sys -StartService
#>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [String]
        [ValidateLength(0,256)]
        $ServiceName,

        [Parameter(Mandatory)]
        [String]
        [ValidateLength(0,256)]
        $DisplayName,

        [string]
        [ValidateSet('sc.exe', 'WMI', 'Win32', 'Registry')]
        $Variant = 'sc.exe',

        [String]
        [ValidateSet('BootStart', 'SystemStart', 'AutoStart', 'DemandStart', 'Disabled')]
        $StartType = 'AutoStart',

        [String]
        [ValidateSet('KernelDriver', 'FileSystemDriver', 'Win32OwnProcess', 'Win32ShareProcess')]
        $ServiceType = 'KernelDriver',

        [Parameter(Mandatory)]
        [String]
        [ValidateScript({Test-Path -Path $_ -PathType Leaf})]
        $FilePath,

        [Switch]
        $StartService
    )

    $ServicesRegKey = 'HKLM:\SYSTEM\CurrentControlSet\Services'
    $NewServiceRegKey = Join-Path -Path $ServicesRegKey -ChildPath $ServiceName
    $ServiceRegistryKey = $null
    $TestCommand = $MyInvocation

    # Resolve the full service binary path
    $ServiceBinPath = Resolve-Path -Path $FilePath -ErrorAction Stop

    Write-Verbose "Requesting service control manager handle with SC_MANAGER_CONNECT access."

    switch($Variant) {
       'sc.exe'{
        #Updating values to match: https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/sc-create
           switch($ServiceType){
                'KernelDriver' {$service='kernel'}
                'FileSystemDriver'{$service='filesys'}
                'Win32OwnProcess'{$service='own'}
                'Win32ShareProcess'{$service='share'}
                }
            switch($StartType){
                'AutoStart'{$start = 'auto'}
                'BootStart'{$start = 'boot'}
                'SystemStart'{$start = 'system'}
                'DemandStart'{$start = 'demand'}
                'Disabled'{$start = 'disabled'}
            }

       $null = sc.exe create $ServiceName binpath= $FilePath start= $start displayname= $DisplayName type= $service

       if ($StartService) {
        $null = sc.exe start $ServiceName
    }

       }

       'WMI'{
        #Updating values to match: https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/create-method-in-class-win32-service
        switch ($ServiceType) {
                'KernelDriver'      { $ServiceTypeValue = 1}
                'FileSystemDriver'  { $ServiceTypeValue = 2}
                'Win32OwnProcess'   { $ServiceTypeValue = 16}
                'Win32ShareProcess' { $ServiceTypeValue = 32}
            }
            switch($StartType){
                'AutoStart'{$start = 'Automatic'}
                'BootStart'{$start = 'Boot'}
                'SystemStart'{$start = 'System'}
                'DemandStart'{$start = 'Manual'}
                'Disabled'{$start = 'Disabled'}
            }
       $ResultWMI = Invoke-CimMethod -ClassName Win32_Service -MethodName Create -Arguments @{Name= $ServiceName; DisplayName= $DisplayName; PathName= $FilePath; StartMode= $start; ServiceType = ([Byte] $ServiceTypeValue)}
       if($ResultWMI.ReturnValue -ne 0){
        Write-Error "Service failed to create via WMI. Error code: $($ResultWMI.ReturnValue)"
       }
       if ($StartService) {
        $Service = (Get-WmiObject -Class Win32_Service -Filter "Name='$($ServiceName)'").InvokeMethod("StartService",$null)
        }
    }

       'Registry'{
        switch ($ServiceType) {
            'KernelDriver'      { $ServiceTypeValue = 1}
            'FileSystemDriver'  { $ServiceTypeValue = 2}
            'Win32OwnProcess'   { $ServiceTypeValue = 16}
            'Win32ShareProcess' { $ServiceTypeValue = 32}
        }
        switch($StartType){
            'AutoStart'{$start = 2}
            'BootStart'{$start = 0}
            'SystemStart'{$start = 1}
            'DemandStart'{$start = 3}
            'Disabled'{$start = 4}
        }
        $null = reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\$ServiceName 
        $null = reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\$ServiceName /v ImagePath /d $FilePath /t REG_EXPAND_SZ 
        $null = reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\$ServiceName /v ErrorControl /d 1 /t REG_DWORD 
        $null = reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\$ServiceName /v ObjectName /d 'LocalSystem' /t REG_SZ 
        $null = reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\$ServiceName /v DisplayName /d $DisplayName /t REG_SZ 
        $null = reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\$ServiceName /v Start /d $start /t REG_DWORD 
        $null = reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\$ServiceName /v Type /d $ServiceTypeValue /t REG_DWORD 
        if ($StartService) {
            Write-Error "Can't start service until computer is rebooted"
        }
    }   
        
       'Win32' { 
            # Get a handle to the service control manager requesting the minimum possible access to create a service: SC_MANAGER_CREATE_SERVICE (0x0002)
            $SCHandle = [AtomicTestHarnesses_T1543_003.ProcessNativeMethods]::OpenSCManager(
                $null,                                                    # lpMachineName
                'ServicesActive',                                         # lpDatabaseName
                [AtomicTestHarnesses_T1543_003.SC_MANAGER] 'CreateService, Connect' # dwDesiredAccess
            );$LastError = [ComponentModel.Win32Exception][Runtime.InteropServices.Marshal]::GetLastWin32Error()

            if ($SCHandle -eq ([IntPtr]::Zero)) {
                # Failed to open a handle to the service control manager

                Write-Error "Failed to obtain a service control manager handle with SC_MANAGER_CREATE_SERVICE access. Reason: $($LastError.Message) (ErrorCode: 0x$($LastError.NativeErrorCode.ToString('X8')))"

                return
            }

            Write-Verbose 'Creating service.'

            switch ($ServiceType) {
                'KernelDriver'      { $ServiceTypeValue = 1; $lpServiceStartName = $null }
                'FileSystemDriver'  { $ServiceTypeValue = 2; $lpServiceStartName = $null }
                'Win32OwnProcess'   { $ServiceTypeValue = 16; $lpServiceStartName = 'NT AUTHORITY\SYSTEM' }
                'Win32ShareProcess' { $ServiceTypeValue = 32; $lpServiceStartName = 'NT AUTHORITY\SYSTEM' }
            }


            $ServiceHandle = [AtomicTestHarnesses_T1543_003.ProcessNativeMethods]::CreateService(
                $SCHandle,                                                      # hSCManager
                $ServiceName,                                                   # lpServiceName
                $DisplayName,                                                   # lpDisplayName
                ([AtomicTestHarnesses_T1543_003.SERVICE]::AllAccess),           # dwDesiredAccess
                $ServiceTypeValue,                                              # dwServiceType
                ($StartType -as [AtomicTestHarnesses_T1543_003.SERVICE_START]), # dwStartType
                0x0001,                                                         # dwErrorControl - SERVICE_ERROR_NORMAL
                $ServiceBinPath,                                           # lpBinaryPathName
                $null,                                                          # lpLoadOrderGroup
                ([IntPtr]::Zero),                                               # lpdwTagId
                $null,                                                          # lpDependencies
                $lpServiceStartName,                                            # lpServiceStartName
                $null                                                           # lpPassword
            );$LastError = [ComponentModel.Win32Exception][Runtime.InteropServices.Marshal]::GetLastWin32Error()

            if ($ServiceHandle -eq ([IntPtr]::Zero)) {
                # Close the service control manager handle
                $null = [AtomicTestHarnesses_T1543_003.ProcessNativeMethods]::CloseServiceHandle($SCHandle)

                Write-Error "Failed to create service. Reason: $($LastError.Message) (ErrorCode: 0x$($LastError.NativeErrorCode.ToString('X8')))"

                return
            }

            Write-Verbose 'Successfully created the service.'

            # Only supply registry key context in the case that the service was successfully created.
            if (Test-Path -Path $NewServiceRegKey -PathType Container) {
                $ServiceRegistryKey = $NewServiceRegKey
            }

            # Calling CreateService will create an empty "ObjectName" value which will cause StartService to fail with an error code of 0x4db (WIN32: 1243 ERROR_SERVICE_NOT_FOUND) - "The specified service does not exist."
            # Explicitly deleting the "ObjectName" value will resolve this issue.
            if($null -eq $lpServiceStartName){
                Remove-ItemProperty -Path $ServiceRegistryKey -Name ObjectName -ErrorAction Ignore 
            }

            if ($StartService) {
                Write-Verbose 'Attempting to start the service'

                $StartServiceResult = [AtomicTestHarnesses_T1543_003.ProcessNativeMethods]::StartService(
                    $ServiceHandle, # hService
                    0,              # dwNumServiceArgs
                    [IntPtr]::Zero  # lpServiceArgVectors
                );$LastError = [ComponentModel.Win32Exception][Runtime.InteropServices.Marshal]::GetLastWin32Error()

                if ($StartServiceResult -eq $False) {
                    # Close the service handle
                    $null = [AtomicTestHarnesses_T1543_003.ProcessNativeMethods]::CloseServiceHandle($ServiceHandle)

                    # Close the service control manager handle
                    $null = [AtomicTestHarnesses_T1543_003.ProcessNativeMethods]::CloseServiceHandle($SCHandle)

                    Write-Error "Failed to start service. Reason: $($LastError.Message) (ErrorCode: 0x$($LastError.NativeErrorCode.ToString('X8')))"

                    return
                }
            }
             # Close the service handle
            $null = [AtomicTestHarnesses_T1543_003.ProcessNativeMethods]::CloseServiceHandle($ServiceHandle)

            # Close the service control manager handle
            $null = [AtomicTestHarnesses_T1543_003.ProcessNativeMethods]::CloseServiceHandle($SCHandle)
           }
    }

    if (($ServiceType -eq  'KernelDriver') -or ($ServiceType -eq 'FileSystemDriver')){
        Get-ATHDriverService -ServiceName $ServiceName
    }
    else{
        $ServiceInfo = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName\ -ErrorAction Ignore
        if ($null -ne $ServiceInfo){
            $TestSuccess = $true
            $ServiceWMIInstance = Get-CimInstance Win32_Service -Filter "Name = '$ServiceName'" | Select-Object -First 1
            if($null -eq $ServiceWMIInstance){
                $ServiceState = 'Stopped'
            }
            else{
                $ServiceState = $ServiceWMIInstance.State
            }
        }
        else{
            $TestSuccess = $false
        }
    
    [PSCustomObject] @{
        TechniqueID        = 'T1543.003'
        TestSuccess        = $TestSuccess
        TestCommand        = $TestCommand.Line
        ServiceName        = $ServiceName
        ServiceDisplayName = $ServiceInfo.DisplayName
        ServiceStartType   = $ServiceInfo.Start
        ServiceType        = $ServiceInfo.Type
        ServiceState       = $ServiceState
        ServiceImagePath   = $ServiceInfo.ImagePath
        ServiceUser        = $ServiceInfo.ObjectName
    }
}

}