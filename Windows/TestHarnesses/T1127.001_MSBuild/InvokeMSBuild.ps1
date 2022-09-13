function Invoke-ATHMSBuild {
<#
.SYNOPSIS

MSBuild execution harness for the purposes of validating detection coverage.

Technique ID: T1127.001 (Trusted Developer Utilities Proxy Execution: MSBuild)

.DESCRIPTION

Invoke-ATHMSBuild automates the execution of .NET code using MSBuild for the purposes of validating detection coverage.

.PARAMETER ProjectFilePath

Specifies the full path of the MSBuild project file that is written to disk. If not specified, "test.proj" will be written to the current directory. With the exception of supplying -NoCLIProjectFile, the project file can have any file extension or no extension.

.PARAMETER MSBuildFilePath

Specifies an alternate path to MSBuild. MSBuild can execute from any directory with any filename and extension. If not specified, the default MSBuild path is used based on the .NET framework runtime used by the running PowerShell process.

.PARAMETER Language

Specifies the language of the embedded .NET code in the MSbuild project file. By default, MSbuild supports inline C#, VB.Net, and JScript.NET. The following language specifiations are supported in the project XML:

* cs, c#, csharp (All of which imply C# code)
* vb, vbs, visualbasic, vbscript (All of which imply VB.Net code)
* js, jscript, javascript (All of which imply JScript.Net code)

.PARAMETER NoCLIProjectFile

Specifies that MSbuild should execute without supplying a project file at the command line. If no project file is supplied at the command line, MSBuild will execute the first project file that ends with "proj" in the current directory. -NoCLIProjectFile will only work if there are no previous *proj files in the current directory so ensure that the current directory does not contain any *proj files prior to supplying the -NoCLIProjectFile switch.

.PARAMETER TargetName

Specifies the target name in the MSbuild project file. This can be any value. If not specified, "TestTarget" is used as the default.

.PARAMETER TaskName

Specifies the task name in the MSbuild project file. This can be any value. If not specified, "TestTask" is used as the default.

.PARAMETER UsePropertyFunctions

As an alternative to supplying inline .NET code that is compiled and executed, MSBuild Property Functions allow a developer to supply XML parameters consisting of embedded .NET code that is interpreted and executed on the fly without compilation. Specifying -UsePropertyFunctions will prompt Invoke-ATHMSBuild to use Property Functions as an alternative to embedded .NET source code.

.PARAMETER PropertyName

Specifies the XML property name to use in the MSbuild project file. This can be any value. If not specified, "TestProperty" is used as the default.

.PARAMETER UseCustomTaskFactory

Specifies that a custom task factory assembly will be dropped and used to execute code rather than embedding executable code within the project file.

.PARAMETER TaskFactoryName

Specifies the task factory name in the MSbuild project file. This can be any value. If not specified, "TestTaskFactory" is used as the default.

.PARAMETER UseCustomLogger

Specifies that a custom logger assembly will be dropped and used to execute code rather than embedding executable code within the project file.

.PARAMETER UseUnregisterAssemblyTask

Specifies that an assembly that implements a custom assembly registration method will be dropped and used to execute code rather than embedding executable code within the project file.

.PARAMETER CustomEngineDllPath

Specifies the full path of the MSBuild custom engine/logger assembly that is written to disk. If not specified, "CustomEngine.dll" will be written to the current directory.

.PARAMETER ProjectFileContent

Specifies custom MSbuild project XML content. Supplying custom content overrides default behavior where a template project is generated dynamically.

.PARAMETER TestGuid

Optionally, specify a test GUID value to use to override the generated test GUID behavior.

.OUTPUTS

PSObject

Outputs an object consisting of relevant execution details. The following object properties may be populated:

* TechniqueID - Specifies the relevant MITRE ATT&CK Technique ID.
* TestSuccess - Will be set to True if it was determined that the MSBuild project contents successfully executed. This will not be set to True if -ProjectFileContent was supplied.
* TestGuid - Specifies the test GUID that was used for the test. This property will not be populated when -ProjectFileContent is specified.
* ExecutionType - Indicates how the MSBuild project file was executed: InlineSourceCode, PropertyFunctions, CustomLogger, CustomTaskFactory, CustomUnregisterFunction, CustomProjectFileContent
* ProjectFilePath - Specifies the full path of the MSBuild project file that was written to disk.
* ProjectFileHashSHA256 - Specifies the SHA256 hash of the MSBuild project file that was written to disk.
* ProjectContents - Specifies the contents of the MSBuild project file that was written to disk.
* CustomEnginePath - If -UseCustomTaskFactory or -UseCustomLogger is supplied, this specifies the full path of the custom task factory or logger assembly DLL that was written to disk. Otherwise, this property is empty.
* CustomEngineHashSHA256 - If -UseCustomTaskFactory or -UseCustomLogger is supplied, this specifies the SHA256 of the custom task factory or logger assembly DLL that was written to disk. Otherwise, this property is empty.
* RunnerFilePath - Specifies the full path of MSBuild runner.
* RunnerProcessId - Specifies the process ID of MSBuild runner.
* RunnerCommandLine - Specifies the commandline of MSBuild runner.
* RunnerChildProcessId - Specifies the process ID of process that was executed as the result of the MSBuild project content executing. This property will not be populated if user-supplied project content is supplied via -ProjectFileContent.
* RunnerChildProcessCommandLine - Specifies the commandline of process that was executed as the result of the HTA content executing. This property will not be populated if user-supplied project content is supplied via -ProjectFileContent.

.EXAMPLE

Invoke-ATHMSBuild

.EXAMPLE

Invoke-ATHMSBuild -ProjectFilePath test.txt

Drops and executes the MSBuild project file from the specified path/filename.

.EXAMPLE

Invoke-ATHMSBuild -NoCLIProjectFile

Drops a .proj file to the current directory and executes it without supplying any command-line arguments to MSBuild.

.EXAMPLE

Copy-Item -Path C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe -Destination foo.txt
Invoke-ATHMSBuild -MSBuildFilePath foo.txt

Copies MSBuild to a local directory, rename it, and execute .NET code with it.

.EXAMPLE

Invoke-ATHMSBuild -Language javascript

Specifies JScript.NET as an alternative .NET language with which to compile and execute.

.EXAMPLE

Invoke-ATHMSBuild -TargetName Foo -TaskName Bar

Populating the generated project file XML with non-default target and task names.

.EXAMPLE

Invoke-ATHMSBuild -UsePropertyFunctions

Using property functions as an alternative to compiling and executing inline .NET code.

.EXAMPLE

Invoke-ATHMSBuild -UseCustomTaskFactory

Proxying custom execution through a custom task factory assembly as an alternative to compiling and executing inline .NET code.

.EXAMPLE

Invoke-ATHMSBuild -UseCustomLogger

Proxying custom execution through a custom logger assembly as an alternative to compiling and executing inline .NET code.

.EXAMPLE

Invoke-ATHMSBuild -UseUnregisterAssemblyTask

Proxying custom execution through a custom assembly unregistration function as an alternative to compiling and executing inline .NET code.

.EXAMPLE

$CustomProjectContent = @'
<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <Target Name="TestTarget">
    <TestTask />
  </Target>
  <UsingTask TaskName="TestTask" TaskFactory="CodeTaskFactory" AssemblyFile="C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Microsoft.Build.Tasks.v4.0.dll" >
    <Task>
      <Code Language="cs">
        <![CDATA[
        System.Diagnostics.ProcessStartInfo startInfo = new System.Diagnostics.ProcessStartInfo("powershell.exe", "-nop -Command Write-Host Foo; Start-Sleep -Seconds 2; exit");
        startInfo.UseShellExecute = false;
        startInfo.WindowStyle = System.Diagnostics.ProcessWindowStyle.Hidden;
        System.Diagnostics.Process.Start(startInfo);
        ]]>
      </Code>
    </Task>
  </UsingTask>
</Project>
'@

Invoke-ATHMSBuild -ProjectFileContent $CustomProjectContent

Executes custom MSBuild project content rather than using a generated template project file.
#>

    [CmdletBinding(DefaultParameterSetName = 'InlineSourceCode')]
    param (
        [Parameter(Mandatory, ParameterSetName = 'CustomProjectFileContents')]
        [String]
        [ValidateNotNullOrEmpty()]
        $ProjectFileContent,

        [Parameter(ParameterSetName = 'InlineSourceCode')]
        [Parameter(ParameterSetName = 'CustomTaskFactory')]
        [Parameter(ParameterSetName = 'CustomLogger')]
        [Parameter(ParameterSetName = 'CustomUnregisterFunction')]
        [Parameter(ParameterSetName = 'PropertyFunctions')]
        [Parameter(ParameterSetName = 'CustomProjectFileContents')]
        [String]
        [ValidateNotNullOrEmpty()]
        $ProjectFilePath = 'test.proj',

        [Parameter(ParameterSetName = 'InlineSourceCode')]
        [Parameter(ParameterSetName = 'CustomTaskFactory')]
        [Parameter(ParameterSetName = 'CustomLogger')]
        [Parameter(ParameterSetName = 'CustomUnregisterFunction')]
        [Parameter(ParameterSetName = 'PropertyFunctions')]
        [Parameter(ParameterSetName = 'CustomProjectFileContents')]
        [Switch]
        $NoCLIProjectFile,

        [Parameter(ParameterSetName = 'InlineSourceCode')]
        [Parameter(ParameterSetName = 'CustomTaskFactory')]
        [Parameter(ParameterSetName = 'CustomLogger')]
        [Parameter(ParameterSetName = 'CustomUnregisterFunction')]
        [Parameter(ParameterSetName = 'PropertyFunctions')]
        [Parameter(ParameterSetName = 'CustomProjectFileContents')]
        [String]
        [ValidateNotNullOrEmpty()]
        $MSBuildFilePath = "$([Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory())MSBuild.exe",

        [Parameter(ParameterSetName = 'InlineSourceCode')]
        [String]
        [ValidateSet('cs', 'c#', 'csharp', 'vb', 'vbs', 'visualbasic', 'vbscript', 'js', 'jscript', 'javascript')]
        $Language = 'cs',

        [Parameter(Mandatory, ParameterSetName = 'PropertyFunctions')]
        [Switch]
        $UsePropertyFunctions,

        [Parameter(ParameterSetName = 'PropertyFunctions')]
        [String]
        [ValidateNotNullOrEmpty()]
        $PropertyName = 'TestProperty',

        [Parameter(ParameterSetName = 'InlineSourceCode')]
        [Parameter(ParameterSetName = 'CustomTaskFactory')]
        [Parameter(ParameterSetName = 'CustomLogger')]
        [Parameter(ParameterSetName = 'CustomUnregisterFunction')]
        [Parameter(ParameterSetName = 'PropertyFunctions')]
        [String]
        [ValidateNotNullOrEmpty()]
        $TargetName = 'TestTarget',

        [Parameter(ParameterSetName = 'InlineSourceCode')]
        [Parameter(ParameterSetName = 'CustomTaskFactory')]
        [Parameter(ParameterSetName = 'CustomLogger')]
        [Parameter(ParameterSetName = 'PropertyFunctions')]
        [String]
        [ValidateNotNullOrEmpty()]
        $TaskName = 'TestTask',

        [Parameter(ParameterSetName = 'CustomTaskFactory')]
        [String]
        [ValidateNotNullOrEmpty()]
        $TaskFactoryName = 'TestTaskFactory',

        [Parameter(Mandatory, ParameterSetName = 'CustomTaskFactory')]
        [Switch]
        $UseCustomTaskFactory,

        [Parameter(Mandatory, ParameterSetName = 'CustomLogger')]
        [Switch]
        $UseCustomLogger,

        [Parameter(Mandatory, ParameterSetName = 'CustomUnregisterFunction')]
        [Switch]
        $UseUnregisterAssemblyTask,

        [Parameter(ParameterSetName = 'CustomTaskFactory')]
        [Parameter(ParameterSetName = 'CustomLogger')]
        [Parameter(ParameterSetName = 'CustomUnregisterFunction')]
        [String]
        [ValidateNotNullOrEmpty()]
        $CustomEngineDllPath = 'CustomEngine.dll',

        [Parameter(ParameterSetName = 'InlineSourceCode')]
        [Parameter(ParameterSetName = 'CustomTaskFactory')]
        [Parameter(ParameterSetName = 'CustomLogger')]
        [Parameter(ParameterSetName = 'CustomUnregisterFunction')]
        [Parameter(ParameterSetName = 'PropertyFunctions')]
        [Parameter(ParameterSetName = 'CustomProjectFileContents')]
        [Guid]
        $TestGuid = (New-Guid)
    )

    $CustomEngineDllHash    = $null
    $MSBuildCommandLine     = $null
    $MSBuildTaskExecuted    = $null
    $MSBuildProcessId       = $null
    $ProcessWMICommandLine  = $null
    $ParentProcessPath      = $null
    $SpawnedProcCommandLine = $null
    $SpawnedProcProcessId   = $null
    $ExecutionType          = $null
    $TestGuidToUse          = $TestGuid

    $MSBuildFullPath = Resolve-Path -Path $MSBuildFilePath -ErrorAction Stop

    # Validate that the MSBuild supplied is actually MSBuild.
    $MSBuildFileInfo = Get-Item -Path $MSBuildFullPath -ErrorAction Stop

    if ($MSBuildFileInfo.VersionInfo.OriginalFilename -ne 'MSBuild.exe') {
        Write-Error "The MSBuild executable supplied is not MSBuild.exe: $MSBuildFullPath"

        return
    }

    $ParentDir = Split-Path -Path $ProjectFilePath -Parent
    $FileName = Split-Path -Path $ProjectFilePath -Leaf

    if (($ParentDir -eq '') -or ($ParentDir -eq '.')) {
        $ParentDir = $PWD.Path
    }

    if (!(Test-Path -Path $ParentDir -PathType Container)) {
        Write-Error "The following directory does not exist: $ParentDir"
        return
    }

    $FullProjectPath = Join-Path -Path $ParentDir -ChildPath $FileName

    $ParentEngineDir = Split-Path -Path $CustomEngineDllPath -Parent
    $EngineFileName = Split-Path -Path $CustomEngineDllPath -Leaf

    if (($ParentEngineDir -eq '') -or ($ParentEngineDir -eq '.')) {
        $ParentEngineDir = $PWD.Path
    }

    if (!(Test-Path -Path $ParentEngineDir -PathType Container)) {
        Write-Error "The following directory does not exist: $ParentEngineDir"
        return
    }

    $FullCustomEnginePath = Join-Path -Path $ParentEngineDir -ChildPath $EngineFileName

    $MSBuildCommandLine = "`"$MSBuildFullPath`""

    if ($NoCLIProjectFile) {
        if (!$FileName.ToLower().EndsWith('proj')) {
            Write-Error "When not specifying a project file at the command-line, the project file on disk must end with a *proj extension."
            return
        }

        $ProjFileCount = Get-ChildItem -Path $ParentDir\*proj -File | Measure-Object | Select-Object -ExpandProperty Count

        if ($ProjFileCount -gt 1) {
            Write-Error "There cannot be more than one *proj file in $ParentDir. The following files were found: $((Get-ChildItem -Path $ParentDir\*proj | Select-Object -ExpandProperty Name) -join ', '). Either delete the files or create a new directory that doesn't have any *proj files in it."
            return
        }
    }

    $TypeDef = @"
using System;
using System.Diagnostics;
using System.Collections.Generic;
using Microsoft.Build.Framework;
using Microsoft.Build.Utilities;
using System.Runtime.InteropServices;

namespace AtomicTestHarnesses {
    public class MyAssemblyRegistration {
        [ComUnregisterFunction]
        public static void UnregisterFunction(Type t) {
            ProcessStartInfo startInfo = new ProcessStartInfo("powershell.exe", "-nop -Command Write-Host $TestGuid; Start-Sleep -Seconds 2; exit");
            startInfo.UseShellExecute = false;

            Process.Start(startInfo);
        }
    }

    public class MyLogger : Logger {
        public override void Initialize(IEventSource eventSource) {
            eventSource.MessageRaised += new BuildMessageEventHandler(eventSource_MessageRaised);
        }

        void eventSource_MessageRaised(object sender, BuildMessageEventArgs e)
        {
            Guid testGuid;

            if ((e.SenderName == "Message") && Guid.TryParse(e.Message, out testGuid)) {
                Console.WriteLine("Message test: " + testGuid);

                ProcessStartInfo startInfo = new ProcessStartInfo("powershell.exe", "-nop -Command Write-Host " + testGuid + "; Start-Sleep -Seconds 2; exit");
                startInfo.UseShellExecute = false;
                startInfo.WindowStyle = ProcessWindowStyle.Hidden;

                Process.Start(startInfo);
            }
        }
    }

    public class MyTask : ITask {
        private IBuildEngine buildEngine;

		private ITaskHost hostObject;

        public IBuildEngine BuildEngine {
	        get {
		        return this.buildEngine;
	        }

	        set {
		        this.buildEngine = value;
	        }
        }

        public ITaskHost HostObject {
	        get {
		        return this.hostObject;
	        }

	        set {
		        this.hostObject = value;
	        }
        }

        public bool Execute() {
            return true;
        }
    }

    public class $TaskFactoryName : ITaskFactory {
        private IDictionary<string, TaskPropertyInfo> taskParameterTypeInfo;

        public string FactoryName {
            get {
				return "Custom Task Factory";
            }
        }

        public Type TaskType {
            get {
                return typeof(MyTask);
            }

            set {}
        }

        public TaskPropertyInfo[] GetTaskParameters() {
            TaskPropertyInfo[] array = new TaskPropertyInfo[this.taskParameterTypeInfo.Count];

			this.taskParameterTypeInfo.Values.CopyTo(array, 0);

			return array;
        }

        public bool Initialize(string taskName, IDictionary<string, TaskPropertyInfo> taskParameters, string taskElementContents, IBuildEngine taskFactoryLoggingHost) {
            Console.WriteLine("Task contents: " + taskElementContents);

            ProcessStartInfo startInfo = new ProcessStartInfo("powershell.exe", "-nop -Command Write-Host " + taskElementContents + "; Start-Sleep -Seconds 2; exit");
            startInfo.UseShellExecute = false;
            startInfo.WindowStyle = ProcessWindowStyle.Hidden;

            Process.Start(startInfo);

            this.taskParameterTypeInfo = taskParameters;

            return true;
        }

        public ITask CreateTask(IBuildEngine loggingHost)
        {
            MyTask task = new MyTask();

            return task;
        }

        public void CleanupTask(ITask task) {

        }
    }
}
"@

    switch ($PSCmdlet.ParameterSetName) {
        'InlineSourceCode' {
            $ExecutionType = 'InlineSourceCode'
            $FullCustomEnginePath = $null

            $ProjectTemplate = @"
<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <Target Name="$TargetName">
    <$TaskName />
  </Target>
  <UsingTask TaskName="$TaskName" TaskFactory="CodeTaskFactory" AssemblyFile="$([Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory())Microsoft.Build.Tasks.v4.0.dll" >
    <Task>
      <Code Language="$Language">
        <![CDATA[
        REPLACEME
        ]]>
      </Code>
    </Task>
  </UsingTask>
</Project>
"@

            $ProjectTemplateJScript = @"
<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <Target Name="$TargetName">
    <$TaskName />
  </Target>
  <UsingTask TaskName="$TaskName" TaskFactory="CodeTaskFactory" AssemblyFile="$([Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory())Microsoft.Build.Tasks.v4.0.dll" >
    <Task>
      <Reference Include="System" />
      <Code Language="$Language">
        <![CDATA[
        REPLACEME
        ]]>
      </Code>
    </Task>
  </UsingTask>
</Project>
"@

            $CSharpCode = @"
System.Diagnostics.ProcessStartInfo startInfo = new System.Diagnostics.ProcessStartInfo("powershell.exe", "-nop -Command Write-Host $($TestGuid); Start-Sleep -Seconds 2; exit");
        startInfo.UseShellExecute = false;
        startInfo.WindowStyle = System.Diagnostics.ProcessWindowStyle.Hidden;
        System.Diagnostics.Process.Start(startInfo);
"@

            $VBDotNetCode = @"
Dim startInfo As New System.Diagnostics.ProcessStartInfo
        startInfo.FileName = "powershell.exe"
        startInfo.Arguments = "-nop -Command Write-Host $($TestGuid); Start-Sleep -Seconds 2; exit"
        startInfo.UseShellExecute = False
        startInfo.WindowStyle = System.Diagnostics.ProcessWindowStyle.Hidden

        System.Diagnostics.Process.Start(startInfo)
"@

            $JScriptDotNetCode = @"
var startInfo;
        startInfo = new System.Diagnostics.ProcessStartInfo("powershell.exe", "-nop -Command Write-Host $($TestGuid); Start-Sleep -Seconds 2; exit");
        startInfo.UseShellExecute = false;
        startInfo.WindowStyle = System.Diagnostics.ProcessWindowStyle.Hidden;

        System.Diagnostics.Process.Start(startInfo);
"@

            switch ($Language) {
                'cs'          { $ProcRunnerCode = $CSharpCode }
                'c#'          { $ProcRunnerCode = $CSharpCode }
                'csharp'      { $ProcRunnerCode = $CSharpCode }
                'vb'          { $ProcRunnerCode = $VBDotNetCode }
                'vbs'         { $ProcRunnerCode = $VBDotNetCode <# Despite the naming, VB.Net is interpreted #> }
                'visualbasic' { $ProcRunnerCode = $VBDotNetCode }
                'vbscript'    { $ProcRunnerCode = $VBDotNetCode <# Despite the naming, VB.Net is interpreted #> }
                'js'          { $ProcRunnerCode = $JScriptDotNetCode; $ProjectTemplate = $ProjectTemplateJScript }
                'jscript'     { $ProcRunnerCode = $JScriptDotNetCode; $ProjectTemplate = $ProjectTemplateJScript }
                'javascript'  { $ProcRunnerCode = $JScriptDotNetCode; $ProjectTemplate = $ProjectTemplateJScript }
            }

            $ProjectTemplate = $ProjectTemplate.Replace('REPLACEME', $ProcRunnerCode)
        }

        'CustomProjectFileContents' {
            $ExecutionType = 'CustomProjectFileContent'
            $FullCustomEnginePath = $null
            $TestGuidToUse = $null

            $ProjectTemplate = $ProjectFileContent
        }

        'PropertyFunctions' {
            $ExecutionType = 'PropertyFunctions'
            $FullCustomEnginePath = $null

            $ProjectTemplate = @"
<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <Target Name="$TargetName">
  <PropertyGroup>
    <$PropertyName>`$([System.Diagnostics.Process]::Start("powershell.exe", "-nop -Command Write-Host $($TestGuid); Start-Sleep -Seconds 2; exit"))</$PropertyName>
  </PropertyGroup>
  </Target>
</Project>
"@
        }

        'CustomUnregisterFunction' {
            $ExecutionType = 'CustomUnregisterFunction'

            Add-Type -TypeDefinition $TypeDef -ReferencedAssemblies "$([Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory())Microsoft.Build.Framework.dll", "$([Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory())Microsoft.Build.Utilities.v4.0.dll" -OutputAssembly $FullCustomEnginePath -ErrorAction Stop

            $CustomEngineDllHash = Get-FileHash -Path $FullCustomEnginePath | Select-Object -ExpandProperty Hash

            $ProjectTemplate = @"
<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <Target Name="$TargetName">
    <UnregisterAssembly Assemblies="$FullCustomEnginePath" />
  </Target>
</Project>
"@
        }

        'CustomLogger' {
            $ExecutionType = 'CustomLogger'

            Add-Type -TypeDefinition $TypeDef -ReferencedAssemblies "$([Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory())Microsoft.Build.Framework.dll", "$([Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory())Microsoft.Build.Utilities.v4.0.dll" -OutputAssembly $FullCustomEnginePath -ErrorAction Stop

            $CustomEngineDllHash = Get-FileHash -Path $FullCustomEnginePath | Select-Object -ExpandProperty Hash

            $ProjectTemplate = @"
<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <Target Name="$TargetName">
    <Message Text="$TestGuid" />
  </Target>
</Project>
"@

            $MSBuildCommandLine += " /logger:$FullCustomEnginePath"
        }

        'CustomTaskFactory' {
            $ExecutionType = 'CustomTaskFactory'

            Add-Type -TypeDefinition $TypeDef -ReferencedAssemblies "$([Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory())Microsoft.Build.Framework.dll", "$([Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory())Microsoft.Build.Utilities.v4.0.dll" -OutputAssembly $FullCustomEnginePath -ErrorAction Stop

            $CustomEngineDllHash = Get-FileHash -Path $FullCustomEnginePath | Select-Object -ExpandProperty Hash

            $ProjectTemplate = @"
<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <Target Name="$TargetName">
    <$TaskName />
  </Target>
  <UsingTask TaskName="$TaskName" TaskFactory="$TaskFactoryName" AssemblyFile="$FullCustomEnginePath" >
    <Task>$TestGuid</Task>
  </UsingTask>
</Project>
"@
        }
    }

    Out-File -FilePath $FullProjectPath -InputObject $ProjectTemplate -Force

    $ProjectHash = Get-FileHash -Path $FullProjectPath -Algorithm SHA256 | Select-Object -ExpandProperty Hash

    if (-not $NoCLIProjectFile) {
        $MSBuildCommandLine += " $($FullProjectPath)"
    }

    # Only run the following if non-custom project content is supplied (i.e. -ProjectFileContent is not supplied)
    if ($ExecutionType -ne 'CustomProjectFileContent') {
        # Remove any stale events
        Get-Event -SourceIdentifier 'ChildProcSpawned' -ErrorAction SilentlyContinue | Remove-Event
        Get-EventSubscriber -SourceIdentifier 'ProcessSpawned' -ErrorAction SilentlyContinue | Unregister-Event

        # Trigger an event any time powershell.exe has $TestGuid in the command line.
        # This event should correspond to the mshta or rundll process that launched it.
        $WMIEventQuery = "SELECT * FROM __InstanceCreationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_Process' AND TargetInstance.Name = 'powershell.exe' AND TargetInstance.CommandLine LIKE '%$($TestGuid)%'"

        Write-Verbose "Registering MSBuild.exe child process creation WMI event using the following WMI event query: $WMIEventQuery"

        $null = Register-CimIndicationEvent -SourceIdentifier 'ProcessSpawned' -Query $WMIEventQuery -Action {
            $SpawnedProcInfo = [PSCustomObject] @{
                ProcessId = $EventArgs.NewEvent.TargetInstance.ProcessId
                ProcessCommandLine = $EventArgs.NewEvent.TargetInstance.CommandLine
            }

            New-Event -SourceIdentifier 'ChildProcSpawned' -MessageData $SpawnedProcInfo

            Stop-Process -Id $EventArgs.NewEvent.TargetInstance.ProcessId
        }
    }

    $ProcessStartup = New-CimInstance -ClassName Win32_ProcessStartup -ClientOnly
    $ProcessStartupInstance = Get-CimInstance -InputObject $ProcessStartup
    $ProcessStartupInstance.ShowWindow = [UInt16] 0 # Hide the window

    if ($UsePropertyFunctions) {
        # Set %MSBUILDENABLEALLPROPERTYFUNCTIONS% in the child MSBuild process so that property function restrictions are lifted.
        [String[]] $AllEnvVars = (Get-ChildItem Env:\* | ForEach-Object { "$($_.Name)=$($_.Value)" }) + 'MSBUILDENABLEALLPROPERTYFUNCTIONS=1'

        $ProcessStartupInstance.EnvironmentVariables = $AllEnvVars
    }

    $ProcStartResult = Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{ CommandLine = $MSBuildCommandLine; CurrentDirectory = $PWD.Path; ProcessStartupInformation = $ProcessStartupInstance }

    if ($ProcStartResult.ReturnValue -eq 0) {
        $MSBuildProcessId = $ProcStartResult.ProcessId

        if ($ExecutionType -eq 'CustomProjectFileContent') {
            # When custom task XML is supplied, there may be a race condition where process information cannot be retrieved.
            $ParentProcessPath = $MSBuildFullPath
            $ProcessWMICommandLine = $MSBuildCommandLine
        } else {
            # Retrieval via WMI is a more authoritative source
            $ParentProcess = Get-CimInstance -ClassName 'Win32_Process' -Filter "ProcessId = $MSBuildProcessId" -Property 'CommandLine', 'ExecutablePath'

            $ParentProcessPath = $ParentProcess.ExecutablePath
            $ProcessWMICommandLine = $ParentProcess.CommandLine
        }
    } else {
        Write-Error "MSbuild process failed to start."
    }

    if ($ExecutionType -ne 'CustomProjectFileContent') {
        $ChildProcSpawnedEvent = Wait-Event -SourceIdentifier 'ChildProcSpawned' -Timeout 10
        $ChildProcInfo = $null

        if ($ChildProcSpawnedEvent) {
            $MSBuildTaskExecuted = $True

            $ChildProcInfo = $ChildProcSpawnedEvent.MessageData

            $SpawnedProcCommandLine = $ChildProcInfo.ProcessCommandLine
            $SpawnedProcProcessId   = $ChildProcInfo.ProcessId

            $ChildProcSpawnedEvent | Remove-Event
        } else {
            Write-Error "MSBuild child process was not spawned."
        }

        # Cleanup
        Unregister-Event -SourceIdentifier 'ProcessSpawned'
    }

    [PSCustomObject] @{
        TechniqueID = 'T1127.001'
        TestSuccess = $MSBuildTaskExecuted
        TestGuid = $TestGuidToUse
        ExecutionType = $ExecutionType
        ProjectFilePath = $FullProjectPath
        ProjectFileHashSHA256 = $ProjectHash
        ProjectContents = $ProjectTemplate
        CustomEnginePath = $FullCustomEnginePath
        CustomEngineHashSHA256 = $CustomEngineDllHash
        RunnerFilePath = $ParentProcessPath
        RunnerProcessId = $MSBuildProcessId
        RunnerCommandLine = $ProcessWMICommandLine
        RunnerChildProcessId = $SpawnedProcProcessId
        RunnerChildProcessCommandLine = $SpawnedProcCommandLine
    }
}