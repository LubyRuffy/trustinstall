import argparse
import sys


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--endpoint", required=True, help="e.g. http://host:5985/wsman")
    p.add_argument("--user", required=True)
    p.add_argument("--password", required=True)
    p.add_argument("--repo-dir", required=True, help=r"e.g. C:\src\trustinstall")
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

    ps_script = "\n".join(
        [
            "$ErrorActionPreference = 'Stop'",
            f"Set-Location -LiteralPath '{args.repo_dir.replace(\"'\", \"''\")}'",
            'Write-Output \"[trustinstall-winrm-it] go version:\"',
            "go version",
            'Write-Output \"[trustinstall-winrm-it] running windows_integration tests...\"',
            "go test ./... -tags windows_integration -run TestWindowsInstallUninstall_SystemTrust -count=1 -v",
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

