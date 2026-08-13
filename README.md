# WSL Hello sudo

> ### About this fork
>
> A maintained fork of [nullpo-head/WSL-Hello-sudo](https://github.com/nullpo-head/WSL-Hello-sudo)
> (MIT, (c) 2017 Takaya Saeki). Upstream's last commit was December 2021 and it no
> longer builds a working install on current Windows. This fork exists because the
> original stopped working on Windows 11 24H2/25H2, and because a module that sits
> in the `sudo` auth path deserves tests, a small dependency tree, and a supply
> chain you can verify.
>
> **Fixed here**
>
> - **Windows 11 25H2 broke key creation.** `KeyCredentialManager::RequestCreateAsync`
>   with `KeyCredentialCreationOption::FailIfExists` now throws a raw NCrypt error
>   `0x80098044` instead of returning the documented `CredentialAlreadyExists`
>   status, and it does so even for a key name that has never existed. Because the
>   error propagates before the status is inspected, upstream's fallback branch is
>   unreachable and installation fails with an empty `Error:` message. This fork
>   probes with `OpenAsync` and only creates when the credential is truly absent.
> - **RFC 7468 compliance.** The bridge emitted the public key as a single
>   unwrapped base64 line. OpenSSL tolerated it; strict parsers do not. The bridge
>   now wraps at 64 columns and the PAM module normalises existing keys, so no
>   re-enrolment is needed.
>
> **Smart App Control**
>
> On Windows 11 with Smart App Control enforced, `WindowsHelloBridge.exe` will not
> run at all: SAC blocks unsigned locally-built executables as a class, reporting
> "An Application Control policy has blocked this file" (CodeIntegrity events 3077
> and 3033). Turning SAC off is irreversible without reinstalling Windows, so this
> fork ships `powershell_bridge/WindowsHelloBridge.ps1` instead, executed by the
> Microsoft-signed `powershell.exe`. Point the config at it with the new
> `authenticator_script` key; the executable path still works where SAC is off.
>
> This costs nothing in security. The trust anchor was always the root-owned
> public key, never the bridge binary's integrity, so a tampered script can no
> more forge a TPM signature than a tampered `.exe` could.
>
> **Hardened here**
>
> - **OpenSSL removed from the auth path.** It was vendored and statically linked
>   (~10MB of C) to perform exactly one RSA PKCS#1 v1.5 / SHA-256 signature
>   verification. Replaced with RustCrypto (`rsa`, `sha2`). The module went from
>   9.98MB to ~600KB with no C in the build.
> - **Nonce from the OS CSPRNG.** `uuid 0.5` -> `rand 0.3` (both long unmaintained)
>   replaced with `getrandom` and a 256-bit nonce. This nonce is the only thing
>   preventing replay of an observed signature.
> - **Tests, where there were none.** Upstream could not have any: vendored bindgen
>   output contained `&(*(0 as *const T))` layout assertions that modern rustc
>   rejects as UB, so `cargo test` failed to compile. Those generated blocks are
>   gone and the verifier now has tests proving it rejects replayed challenges,
>   wrong-key signatures and malformed input.
> - **Correct linkage.** `cdylib` with `extern "C"` entry points, rather than a
>   Rust-ABI `dylib` that happened to work.
> - **Supply chain.** All GitHub Actions pinned to commit SHAs, `cargo-deny` gating
>   licences/advisories/sources, a daily advisory scan, and release artifacts
>   published with build provenance you can check with `gh attestation verify`.
>   `deny.toml` explicitly bans OpenSSL from ever returning to the tree.

"WSL Hello sudo" is a Linux PAM module and companion Windows CLI apps that realize `sudo` by
biometric login of [Windows Hello](https://www.microsoft.com/en-us/windows/windows-hello) on Windows Subsystem for Linux (WSL).  
This PAM module allows you to authenticate `sudo` via face recognition, fingerprint authentication, and of couse machine-local PIN.
It runs in both WSL and WSL 2.

Both the Linux PAM module and Windows CLI app are written in Rust.
Please use it at your own risk. There is no warranty.

![demo](https://github.com/nullpo-head/WSL-Hello-sudo/blob/master/demo.gif)

"WSL Hello sudo" actually does __not__ modify your `sudo` command at all. It is a Linux PAM module.  
PAM, _Plaggable Authentication Module_, is a UNIX's module system that provides user authentication mechanisms to applications such as `sudo` or `su`. "WSL Hello sudo" is such a PAM module that lets applications use Windows Hello.

## Installation and Configuration

### Installation

The installation process is very simple.  
Please download the latest release package from GitHub Release and unpack it.  
Run `install.sh` inside the directory, and follow the instruction of `install.sh`

```ShellSession
$ wget http://github.com/nullpo-head/WSL-Hello-sudo/releases/latest/download/release.tar.gz
$ tar xvf release.tar.gz
$ cd release
$ ./install.sh
```

Although you don't have to care about the detailed installation process,  
`install.sh` does following things.

1. Copy a small Windows CLI app that launches Windows Hello to `C:\Users\your_account\pam_wsl_hello` (default location)  
2. Install a PAM module to your WSL system.
3. Create config files in `/etc/pam_wsl_hello/`
4. Create a pam-configs entry in `/usr/share/pam-configs/` for automatic PAM configuration
5. Create `uninstall.sh`

### Configuration

"WSL Hello sudo" is not a fork of `sudo` but a PAM module. You have to adjust the PAM configuration to make it effective.

#### Automatic configuration
On Ubuntu, you can use `sudo pam-auth-update` to show a list of installed PAM authentication modules, and select the ones you want to use for authentication (which will also affect sudo etc.)

The install scripts will install the required configuration. If you're not using the install script, you can copy the pam-config file from the release tarball to `/usr/share/pam-configs/`.

#### Manual configuration

If for some reason you do not want to use automatic configuration, you can configure `/etc/pam.d/sudo` manually.
I strongly recommend to set password of root first so that you can switch to it by `su`, in case you make some typo in the config of `sudo`.  
Add `auth sufficient pam_wsl_hello.so` to the top line of your `/etc/pam.d/sudo` like the following example  

```
#%PAM-1.0

auth       sufficient pam_wsl_hello.so
session    required   pam_env.so readenv=1 user_readenv=0
session    required   pam_env.so readenv=1 envfile=/etc/default/locale user_readenv=0
@include common-auth
@include common-account
@include common-session-noninteractive
```
Even if you fail to authenticate via Windows Hello, `sudo` moves on to the regular password authentication by this setting with `sufficient`.  

Other applications that authenticate users such as `su` can also utilize Windows Hello by this module.  
Even so, __I strongly recommend you to make either `sudo` or `su` free from this module to prevent from being locked out__

## Troubleshooting

### Windows Hello window appears in background.

The Windows Hello dialog sometimes appears in background.
In some cases, it even fails to recognize your face with some weird error message.
It seems a bug of Windows API. In that case, restarting Windows a couple of times might solve the problem.

### "Windows Hello is not invoked! `sudo` just prompts password!"

Maybe some error is happening. Unfortunately, `sudo` suppresses error messages from PAM modules.  
To debug "WSL Hello sudo", make it effective for `su` instead of `sudo`. `su` shows error messages from PAM modules,
so you can see what is going on.

For your information, the setting for `su` will be like the example below.
I will show only relevant two lines.
```
auth       sufficient pam_rootok.so
auth       sufficient pam_wsl_hello.so  
```

## Build

Both the Linux PAM module and the Windows CLI apps of "WSL Hello sudo" are written in Rust.
So, only `cargo` is required to build it.

To build "WSL Hello sudo", make sure you're in WSL and then just run `make`.

```ShellSession
$ git clone https://github.com/nullpo-head/WSL-Hello-sudo.git
$ cd WSL-Hello-sudo
$ make
```

## Internals

Windows Hello maintains RSA key-pairs for each Windows user in its TPM hardware, and tells success of authentication by signing given contents by the private key.
To utilize its API, "WSL Hello sudo" contains small Windows CLI apps that return public key and signed signature of given content.
On the other hand, the PAM module of "WSL Hello sudo" remembers the public keys of each Windows user who corresponds to each Linux user.
So, the PAM module authenticates the given Linux user by the following process.

0. The PAM module is launched by `sudo` and receives a Linux user to be authenticated
1. The PAM module launches the companion Windows app and sends a random value via WSL's interop bridge
2. The companion Windows app invokes Windows Hello
3. Windows Hello makes a signature of the given input by the private key of the current Windows user
4. The companion Windows app returns the signature
5. The PAM module verifies the signature by the public key of the Windows user who corresponds to the given Linux user.
