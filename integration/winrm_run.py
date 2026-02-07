import argparse
import os
import sys


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--endpoint", required=True, help="e.g. http://host:5985/wsman")
    p.add_argument("--user", required=True)
    p.add_argument("--password", required=True)
    p.add_argument("--repo-dir", default="", help=r"e.g. C:\src\trustinstall (optional)")
    p.add_argument(
        "--repo-zip-url",
        default="",
        help="HTTP URL to a zip of the repo to run tests from (optional)",
    )
    p.add_argument(
        "--module",
        default="",
        help="go test target, e.g. github.com/LubyRuffy/trustinstall@main (optional)",
    )
    p.add_argument(
        "--goproxy",
        default="",
        help="GOPROXY override for the Windows VM (optional)",
    )
    p.add_argument(
        "--gosumdb",
        default="",
        help="GOSUMDB override for the Windows VM (optional)",
    )
    args = p.parse_args()

    try:
        import winrm  # type: ignore
    except Exception as e:
        print("pywinrm not installed:", e, file=sys.stderr)
        return 2

    # NTLM over HTTP (5985). This is for local/private networks only.
    s = winrm.Session(
        args.endpoint,
        auth=(args.user, args.password),
        transport="ntlm",
        server_cert_validation="ignore",
    )

    # PowerShell single-quoted string escaping: double the quote.
    repo_dir = (args.repo_dir or "").replace("'", "''")
    repo_zip_url = (args.repo_zip_url or "").strip().replace("'", "''")
    module = (args.module or "").strip() or os.environ.get(
        "TRUSTINSTALL_WINDOWS_MODULE_REF", ""
    ).strip()
    if not module:
        module = "github.com/LubyRuffy/trustinstall@main"
    module = module.replace("'", "''")
    goproxy = (args.goproxy or "").strip().replace("'", "''")
    gosumdb = (args.gosumdb or "").strip().replace("'", "''")

    ps_script = "\n".join(
        [
            "$ErrorActionPreference = 'Stop'",
            "$ProgressPreference = 'SilentlyContinue'",
            f"$repoDir = '{repo_dir}'",
            f"$repoZipUrl = '{repo_zip_url}'",
            f"$target = '{module}'",
            f"$goproxy = '{goproxy}'",
            f"$gosumdb = '{gosumdb}'",
            "if ($goproxy) {",
            "  $env:GOPROXY = $goproxy",
            "} elseif (-not $env:GOPROXY) {",
            "  $env:GOPROXY = 'https://proxy.golang.com.cn,https://goproxy.cn,https://goproxy.io,direct'",
            "}",
            "if ($gosumdb) {",
            "  $env:GOSUMDB = $gosumdb",
            "} elseif (-not $env:GOSUMDB) {",
            "  $env:GOSUMDB = 'sum.golang.google.cn'",
            "}",
            # Prefer an existing Go install at C:\go even if PATH is not configured.
            '$env:PATH = "C:\\go\\bin;" + $env:PATH',
            # Ensure Go exists; download matching arch zip if missing.
            "if (-not (Get-Command go -ErrorAction SilentlyContinue)) {",
            "  $arch = $env:PROCESSOR_ARCHITECTURE",
            "  $goarch = 'amd64'",
            "  if ($arch -match 'ARM64') { $goarch = 'arm64' }",
            "  $ver = '1.25.5'",
            '  $zip = "go$ver.windows-$goarch.zip"',
            '  $url = "https://go.dev/dl/$zip"',
            '  $out = "C:\\Temp\\$zip"',
            "  New-Item -ItemType Directory -Force -Path C:\\Temp | Out-Null",
            "  if (Get-Command curl.exe -ErrorAction SilentlyContinue) {",
            "    curl.exe -L $url -o $out --max-time 600",
            "  } else {",
            "    Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $out",
            "  }",
            "  if (Test-Path C:\\go) { Remove-Item -Recurse -Force C:\\go }",
            "  Expand-Archive -Force -Path $out -DestinationPath C:\\",
            "}",
            # If repoDir is missing, but we have a zip URL, pull the zip from host and use it.
            "if ((-not $repoDir) -or (-not (Test-Path -LiteralPath $repoDir))) {",
            "  if ($repoZipUrl) {",
            "    $zipPath = 'C:\\Temp\\trustinstall-src.zip'",
            "    New-Item -ItemType Directory -Force -Path C:\\Temp | Out-Null",
            "    if (Get-Command curl.exe -ErrorAction SilentlyContinue) {",
            "      curl.exe -L $repoZipUrl -o $zipPath --max-time 600",
            "    } else {",
            "      Invoke-WebRequest -UseBasicParsing -Uri $repoZipUrl -OutFile $zipPath",
            "    }",
            "    $extractDir = Join-Path C:\\Temp ('trustinstall-src-' + [guid]::NewGuid().ToString('N'))",
            "    New-Item -ItemType Directory -Force -Path $extractDir | Out-Null",
            "    Expand-Archive -Force -Path $zipPath -DestinationPath $extractDir",
            "    $repoDir = $extractDir",
            "  }",
            "}",
            'Write-Output \"[trustinstall-winrm-it] go version:\"',
            "go version",
            'Write-Output \"[trustinstall-winrm-it] running windows_integration tests...\"',
            "if ($repoDir -and (Test-Path -LiteralPath $repoDir)) {",
            "  Set-Location -LiteralPath $repoDir",
            "  go test ./... -tags windows_integration -run TestWindowsInstallUninstall_SystemTrust -count=1 -v",
            "} else {",
            "  Write-Output '[trustinstall-winrm-it] ERROR: no repo-dir and no repo-zip-url provided'",
            "  exit 2",
            "}",
        ]
    )

    r = s.run_ps(ps_script)
    # Always print output for the caller to capture.
    if r.std_out:
        sys.stdout.write(r.std_out.decode("utf-8", errors="replace"))
    if r.std_err:
        sys.stderr.write(r.std_err.decode("utf-8", errors="replace"))

    return int(r.status_code or 0)


if __name__ == "__main__":
    raise SystemExit(main())
