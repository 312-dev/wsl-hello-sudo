# Windows Hello bridge, PowerShell edition.
#
# Functionally identical to WindowsHelloBridge.exe, but executed by the
# Microsoft-signed powershell.exe so that Windows Smart App Control permits it.
# SAC blocks unsigned locally-built executables regardless of what they do, and
# once enforced it cannot be re-enabled after being switched off, so shipping no
# unsigned binary at all is preferable to weakening the machine.
#
# This changes nothing about the security model. The PAM module still verifies an
# RSA signature produced by a TPM-held private key against a root-owned public
# key, so a tampered copy of this script can no more forge an authentication than
# a tampered .exe could.
#
#   authenticator <key_name>   reads challenge bytes on stdin, writes raw
#                              signature bytes to stdout after a Hello gesture
#   creator <key_name>         creates a credential, writes <key_name>.pem to cwd
#
# Exit codes match the Rust implementation's FailureReason::to_code().

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)][ValidateSet('authenticator', 'creator')]
    [string]$Mode,
    [Parameter(Mandatory = $true, Position = 1)]
    [string]$KeyName
)

$ErrorActionPreference = 'Stop'

# Exit codes, mirroring win_hello_bridge/src/error.rs. 174 is skipped there so the
# numbers line up with KeyCredentialStatus.
$EXIT_NOT_SUPPORTED   = 170
$EXIT_EXISTS          = 171
$EXIT_NOT_FOUND       = 172
$EXIT_DEVICE_LOCKED   = 173
$EXIT_UNKNOWN         = 175
$EXIT_USER_CANCELLED  = 176
$EXIT_PREFERS_PASSWD  = 177
$EXIT_OTHER           = 178

# Diagnostics must never touch stdout: in authenticator mode stdout is the raw
# signature channel and a stray character corrupts it.
function Write-Diag([string]$Message) { [Console]::Error.WriteLine($Message) }

function Get-StatusExitCode([string]$Status) {
    switch ($Status) {
        'Success'                { 0 }
        'CredentialAlreadyExists' { $EXIT_EXISTS }
        'NotFound'               { $EXIT_NOT_FOUND }
        'SecurityDeviceLocked'   { $EXIT_DEVICE_LOCKED }
        'UnknownError'           { $EXIT_UNKNOWN }
        'UserCanceled'           { $EXIT_USER_CANCELLED }
        'UserPrefersPassword'    { $EXIT_PREFERS_PASSWD }
        default                  { $EXIT_OTHER }
    }
}

try {
    Add-Type -AssemblyName System.Runtime.WindowsRuntime

    $asTaskGeneric = ([System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object {
        $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and
        $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1'
    })[0]

    function Await($Operation, $ResultType) {
        $netTask = $asTaskGeneric.MakeGenericMethod($ResultType).Invoke($null, @($Operation))
        $netTask.Wait(-1) | Out-Null
        $netTask.Result
    }

    # Windows silently refuses SetForegroundWindow to any process that does not
    # already own the foreground, and PAM launches this one from a context that
    # never does. The reliable workaround is to synthesise a key event (which
    # grants foreground rights to the caller) and to attach our input queue to
    # the current foreground thread so its rights apply to us too.
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

public static class WslHelloWindow
{
    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    static extern IntPtr FindWindow(string lpClassName, string lpWindowName);
    [DllImport("user32.dll")]
    static extern IntPtr GetForegroundWindow();
    [DllImport("user32.dll")]
    static extern bool SetForegroundWindow(IntPtr hWnd);
    [DllImport("user32.dll")]
    static extern bool BringWindowToTop(IntPtr hWnd);
    [DllImport("user32.dll")]
    static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
    [DllImport("user32.dll")]
    static extern void SwitchToThisWindow(IntPtr hWnd, bool fAltTab);
    [DllImport("user32.dll")]
    static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);
    [DllImport("kernel32.dll")]
    static extern uint GetCurrentThreadId();
    [DllImport("user32.dll")]
    static extern bool AttachThreadInput(uint idAttach, uint idAttachTo, bool fAttach);
    [DllImport("user32.dll")]
    static extern void keybd_event(byte bVk, byte bScan, uint dwFlags, UIntPtr dwExtraInfo);

    const byte VK_MENU = 0x12;          // ALT
    const uint KEYEVENTF_KEYUP = 0x2;
    const int SW_SHOW = 5;
    const int SW_RESTORE = 9;

    public static IntPtr FindHelloDialog()
    {
        return FindWindow("Credential Dialog Xaml Host", null);
    }

    public static void ForceForeground(IntPtr hWnd)
    {
        if (hWnd == IntPtr.Zero) return;

        // A synthesised keypress makes this process the last to send input,
        // which is one of the conditions that lifts the foreground lock.
        keybd_event(VK_MENU, 0, 0, UIntPtr.Zero);
        keybd_event(VK_MENU, 0, KEYEVENTF_KEYUP, UIntPtr.Zero);

        uint fgPid;
        uint fgThread = GetWindowThreadProcessId(GetForegroundWindow(), out fgPid);
        uint thisThread = GetCurrentThreadId();

        bool attached = (fgThread != 0 && fgThread != thisThread)
                        && AttachThreadInput(thisThread, fgThread, true);
        try
        {
            ShowWindow(hWnd, SW_SHOW);
            ShowWindow(hWnd, SW_RESTORE);
            BringWindowToTop(hWnd);
            SetForegroundWindow(hWnd);
            SwitchToThisWindow(hWnd, true);
        }
        finally
        {
            if (attached) AttachThreadInput(thisThread, fgThread, false);
        }
    }
}
'@

    # Windows raises the Hello prompt behind whatever has focus, which on a
    # PAM-triggered sudo is usually nothing the user is looking at. Poll the
    # pending operation instead of blocking, and pull the dialog forward once it
    # exists. Without this the prompt sits unnoticed until sudo times out.
    function Await-WithHelloFocus($Operation, $ResultType) {
        $netTask = $asTaskGeneric.MakeGenericMethod($ResultType).Invoke($null, @($Operation))
        # Retry a few times rather than once: the dialog can be created before it
        # is ready to take focus, and it occasionally loses it again right after.
        $attempts = 0
        while (-not $netTask.IsCompleted) {
            if ($attempts -lt 8) {
                $hwnd = [WslHelloWindow]::FindHelloDialog()
                if ($hwnd -ne [IntPtr]::Zero) {
                    [WslHelloWindow]::ForceForeground($hwnd)
                    $attempts++
                }
            }
            Start-Sleep -Milliseconds 250
        }
        $netTask.Result
    }

    [Windows.Security.Credentials.KeyCredentialManager, Windows.Security.Credentials, ContentType = WindowsRuntime] | Out-Null
    [Windows.Security.Cryptography.CryptographicBuffer, Windows.Security.Cryptography, ContentType = WindowsRuntime] | Out-Null
    $retrievalType = [Windows.Security.Credentials.KeyCredentialRetrievalResult]

    if ($Mode -eq 'creator') {
        # Probe first. On Windows 11 25H2, RequestCreateAsync(FailIfExists) throws
        # a raw NCrypt 0x80098044 instead of reporting CredentialAlreadyExists,
        # even for a name that has never existed. See creator.rs for the detail.
        $existing = Await ([Windows.Security.Credentials.KeyCredentialManager]::OpenAsync($KeyName)) $retrievalType

        if ($existing.Status -eq 'Success') {
            $credential = $existing.Credential
        } elseif ($existing.Status -eq 'NotFound') {
            [Windows.Security.Credentials.KeyCredentialCreationOption, Windows.Security.Credentials, ContentType = WindowsRuntime] | Out-Null
            $created = Await ([Windows.Security.Credentials.KeyCredentialManager]::RequestCreateAsync(
                $KeyName, [Windows.Security.Credentials.KeyCredentialCreationOption]::ReplaceExisting)) $retrievalType
            if ($created.Status -ne 'Success') {
                Write-Diag "Error: credential creation failed ($($created.Status))"
                exit (Get-StatusExitCode $created.Status)
            }
            $credential = $created.Credential
        } else {
            Write-Diag "Error: $($existing.Status)"
            exit (Get-StatusExitCode $existing.Status)
        }

        $publicKey = $credential.RetrievePublicKeyWithDefaultBlobType()
        $base64 = [Windows.Security.Cryptography.CryptographicBuffer]::EncodeToBase64String($publicKey)

        # RFC 7468 requires the body wrapped at 64 columns; strict PEM parsers
        # (RustCrypto's pem-rfc7468) reject a single long line.
        $sb = [System.Text.StringBuilder]::new()
        [void]$sb.AppendLine('-----BEGIN PUBLIC KEY-----')
        for ($i = 0; $i -lt $base64.Length; $i += 64) {
            [void]$sb.AppendLine($base64.Substring($i, [Math]::Min(64, $base64.Length - $i)))
        }
        [void]$sb.AppendLine('-----END PUBLIC KEY-----')

        $outFile = Join-Path (Get-Location).Path "$KeyName.pem"
        [System.IO.File]::WriteAllText($outFile, $sb.ToString())
        Write-Diag "Done. The public credential key is written in '$outFile'"
        exit 0
    }

    # authenticator mode
    $stdin = [Console]::OpenStandardInput()
    $buffer = [System.IO.MemoryStream]::new()
    $stdin.CopyTo($buffer)
    $challenge = $buffer.ToArray()

    if ($challenge.Length -eq 0) {
        Write-Diag 'Error: empty challenge on stdin'
        exit $EXIT_OTHER
    }

    $opened = Await ([Windows.Security.Credentials.KeyCredentialManager]::OpenAsync($KeyName)) $retrievalType
    if ($opened.Status -ne 'Success') {
        Write-Diag "Error: cannot open credential '$KeyName' ($($opened.Status))"
        exit (Get-StatusExitCode $opened.Status)
    }

    # CryptographicBuffer::CreateFromByteArray hands PowerShell 5.1 a bare
    # __ComObject that it cannot convert back to IBuffer for the next call.
    # AsBuffer/ToArray are .NET extension methods and project correctly.
    $data = [System.Runtime.InteropServices.WindowsRuntime.WindowsRuntimeBufferExtensions]::AsBuffer($challenge)

    # This is the call that raises the Windows Hello prompt.
    $signResult = Await-WithHelloFocus ($opened.Credential.RequestSignAsync($data)) `
                                       ([Windows.Security.Credentials.KeyCredentialOperationResult])

    if ($signResult.Status -ne 'Success') {
        Write-Diag "Error: signing failed ($($signResult.Status))"
        exit (Get-StatusExitCode $signResult.Status)
    }

    # RequestSignAsync hands back the signature as a __ComObject, so PowerShell's
    # own overload resolution cannot match ToArray(IBuffer). Invoking the method
    # by reflection makes the runtime QueryInterface the COM object to IBuffer.
    $toArray = [System.Runtime.InteropServices.WindowsRuntime.WindowsRuntimeBufferExtensions].GetMethods() |
        Where-Object { $_.Name -eq 'ToArray' -and $_.GetParameters().Count -eq 1 } |
        Select-Object -First 1
    $signature = $toArray.Invoke($null, @($signResult.Result))

    $stdout = [Console]::OpenStandardOutput()
    $stdout.Write($signature, 0, $signature.Length)
    $stdout.Flush()
    exit 0
}
catch {
    $inner = $_.Exception
    while ($inner.InnerException) { $inner = $inner.InnerException }
    Write-Diag ("Error: 0x{0:X8} {1}" -f $inner.HResult, $inner.Message)
    exit $EXIT_OTHER
}
