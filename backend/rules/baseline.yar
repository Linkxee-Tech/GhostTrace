rule Suspicious_PowerShell_Execution
{
    meta:
        description = "Detects suspicious PowerShell execution strings"
        author = "GhostTrace"
    strings:
        $ps1 = "powershell"
        $iex = "Invoke-Expression"
        $enc = "-enc"
    condition:
        2 of ($*)
}

rule Suspicious_Command_Artifacts
{
    meta:
        description = "Detects common suspicious command artifacts"
        author = "GhostTrace"
    strings:
        $cmd = "cmd.exe"
        $curl = "curl"
        $wget = "wget"
        $base64 = "base64"
    condition:
        2 of ($*)
}
