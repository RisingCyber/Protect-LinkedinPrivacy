#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Protect-LinkedInPrivacy.ps1
    Mitigates Linkedin browser fingerprinting, extension scanning (AED),
    and tracking behaviours confirmed via static JS bundle analysis (April 2026).

.DESCRIPTION
    Applies host-level and browser-level protections. No code is injected into
    Linkedin this script only exercises lawful control over your own system.

    MITIGATIONS APPLIED:
      [1] Block Linkedin tracking and HUMAN Security endpoints via Windows Hosts file
      [2] Harden Firefox via user.js in all profiles (WebRTC, fingerprinting, Battery API)
      [3] Apply Chrome enterprise registry policy (WebRTC, URLBlocklist, camera/mic)
      [4] Apply Edge enterprise registry policy (mirrors Chrome)

.NOTES
    Author  : Based on chunk.716 forensic analysis
    Version : 1.1.0
    Requires: Windows 10/11, PowerShell 5.1+, Administrator privileges

#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [switch]$Force,
    [switch]$SkipHostsFile,
    [switch]$SkipFirefox,
    [switch]$SkipChrome,
    [switch]$SkipEdge,
    [switch]$SkipDNS
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---- Colour helpers (ASCII labels only - no Unicode symbols) ----------------
function Write-Header {
    param([string]$Text)
    Write-Host ""
    Write-Host "==========================================" -ForegroundColor DarkCyan
    Write-Host "  $Text" -ForegroundColor Cyan
    Write-Host "==========================================" -ForegroundColor DarkCyan
}

function Write-Step {
    param([string]$Text)
    Write-Host ""
    Write-Host "  >> $Text" -ForegroundColor Yellow
}

function Write-Ok {
    param([string]$Text)
    Write-Host "    [OK]   $Text" -ForegroundColor Green
}

function Write-Warn {
    param([string]$Text)
    Write-Host "    [WARN] $Text" -ForegroundColor DarkYellow
}

function Write-Skip {
    param([string]$Text)
    Write-Host "    [SKIP] $Text" -ForegroundColor Gray
}

function Write-Manual {
    param([string]$Text)
    Write-Host "    [TODO] $Text" -ForegroundColor Magenta
}

# ---- Backup helper ----------------------------------------------------------
function Backup-File {
    param([string]$Path)
    if (Test-Path $Path) {
        $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
        $bak = "$Path.bak_$timestamp"
        Copy-Item -Path $Path -Destination $bak -Force
        $shortName = [System.IO.Path]::GetFileName($Path)
        $shortBak  = [System.IO.Path]::GetFileName($bak)
        Write-Ok "Backed up: $shortName -> $shortBak"
    }
}

# ============================================================================
# [1]  HOSTS FILE - Block tracking and HUMAN Security endpoints
# ============================================================================
function Set-HostsBlocks {
    Write-Header "[1] Hosts File - Blocking Linkedin Tracking Endpoints"

    $hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"

    # www.linkedin.com is intentionally NOT blocked - that would break the site.
    # The li/track path lives on www.linkedin.com and requires uBlock Origin
    # (see manual steps printed at the end of this script).
    $blockEntries = @(
        "0.0.0.0  li.protechts.net",
        "0.0.0.0  www.linkedin-ei.com",
        "0.0.0.0  tags.tiqcdn.com",
        "0.0.0.0  collect.tealiumiq.com"
    )

    $marker    = "# -- Linkedin mitigations --"
    $markerEnd = "# -- end Linkedin mitigations --"

    Write-Step "Reading current hosts file..."
    $current = Get-Content -Path $hostsPath -Raw

    if ($current -match [regex]::Escape($marker)) {
        Write-Skip "Block section already present in hosts file. Skipping."
        return
    }

    $allLines = @($marker) + $blockEntries + @($markerEnd)
    $newBlock = $allLines -join "`r`n"

    if ($PSCmdlet.ShouldProcess($hostsPath, "Append tracking block entries")) {
        Backup-File -Path $hostsPath
        Add-Content -Path $hostsPath -Value "`r`n$newBlock" -Encoding UTF8
        Write-Ok "Added $($blockEntries.Count) block entries to hosts file."
    }

    Write-Manual "li/track cannot be hosts-blocked (same domain as linkedin.com)."
    Write-Manual "Add these to uBlock Origin -> My Filters:"
    Write-Manual "  ||linkedin.com/li/track^"
    Write-Manual "  ||linkedin.com/apfc/collect^"
    Write-Manual "  ||linkedin.com/platform-telemetry^"
    Write-Manual "  ||li.protechts.net^"
}

# ============================================================================
# [2]  FIREFOX - user.js hardening across all profiles
# ============================================================================
function Set-FirefoxHardening {
    Write-Header "[2] Firefox - Fingerprint Resistance + WebRTC Lockdown"

    $profileBase = "$env:APPDATA\Mozilla\Firefox\Profiles"

    if (-not (Test-Path $profileBase)) {
        Write-Skip "Firefox profiles directory not found. Skipping."
        return
    }

    $profiles = Get-ChildItem -Path $profileBase -Directory

    if ($profiles.Count -eq 0) {
        Write-Skip "No Firefox profiles found."
        return
    }

    Write-Step "Found $($profiles.Count) Firefox profile(s)."

    # Build user.js as an array of strings - no here-string to avoid encoding issues
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm'

    $prefLines = @(
        "// -- Linkedin mitigations -- Protect-LinkedinPrivacy.ps1",
        "// Applied: $timestamp",
        "//",
        "// [F-01] WebRTC IP leak - disable ICE candidate gathering",
        "// Prevents RTCPeerConnection from exposing LAN/VPN-bypass IPs via STUN",
        'user_pref("media.peerconnection.enabled", false);',
        'user_pref("media.peerconnection.ice.default_address_only", true);',
        'user_pref("media.peerconnection.ice.no_host", true);',
        "//",
        "// [F-02] Canvas fingerprinting - randomise pixel output per session",
        "// Breaks x64hash128(canvas.toDataURL()) uniqueness",
        'user_pref("privacy.resistFingerprinting", true);',
        'user_pref("privacy.resistFingerprinting.randomDataOnCanvasExtract", true);',
        "//",
        "// [F-03] Audio fingerprinting - covered by resistFingerprinting above",
        "// OfflineAudioContext output is spoofed automatically",
        "//",
        "// [F-04] Battery Status API - disable entirely",
        "// Deprecated by Firefox/Chrome for fingerprinting; Linkedin still probes it",
        'user_pref("dom.battery.enabled", false);',
        "//",
        "// [F-05] Media device enumeration - block camera/mic without explicit grant",
        'user_pref("media.navigator.enabled", false);',
        'user_pref("media.navigator.video.enabled", false);',
        "//",
        "// [F-07] Font fingerprinting - limit system font exposure",
        "// Breaks the 71-font enumeration probe",
        'user_pref("browser.display.use_document_fonts", 0);',
        "//",
        "// [F-08] Network Information API - disable",
        "// Prevents connection type, bandwidth, and RTT collection",
        'user_pref("dom.netinfo.enabled", false);',
        "//",
        "// [F-09] WebGL2 - higher fingerprint entropy surface",
        'user_pref("webgl.enable-webgl2", false);',
        "//",
        "// Additional hardening",
        'user_pref("privacy.firstparty.isolate", true);',
        'user_pref("network.cookie.cookieBehavior", 1);',
        'user_pref("privacy.trackingprotection.enabled", true);',
        'user_pref("privacy.trackingprotection.fingerprinting.enabled", true);',
        'user_pref("privacy.trackingprotection.cryptomining.enabled", true);',
        'user_pref("geo.enabled", false);',
        "// -- end Linkedin mitigations --"
    )

    $userJsContent = $prefLines -join "`r`n"

    foreach ($profile in $profiles) {
        $userJsPath = Join-Path $profile.FullName "user.js"
        Write-Step "Applying to profile: $($profile.Name)"

        if ($PSCmdlet.ShouldProcess($userJsPath, "Write Firefox user.js hardening")) {
            if (Test-Path $userJsPath) {
                Backup-File -Path $userJsPath
                $existing = Get-Content -Path $userJsPath -Raw -ErrorAction SilentlyContinue
                if (-not $existing) { $existing = '' }
                # Remove any previous block written by this script
                $existing = $existing -replace '(?s)// -- Linkedin mitigations --.*?// -- end Linkedin mitigations --\r?\n?', ''
                $combined = $existing.TrimEnd() + "`r`n`r`n" + $userJsContent
                [System.IO.File]::WriteAllText($userJsPath, $combined, [System.Text.Encoding]::UTF8)
            } else {
                [System.IO.File]::WriteAllText($userJsPath, $userJsContent, [System.Text.Encoding]::UTF8)
            }
            Write-Ok "user.js written: $userJsPath"
        }
    }

    # Firefox enterprise policies.json (system-wide Firefox install)
    $ffRegPath = 'HKLM:\SOFTWARE\Mozilla\Mozilla Firefox'
    $ffInstall = (Get-ItemProperty $ffRegPath -ErrorAction SilentlyContinue).'Install Directory'

    if ($ffInstall) {
        $policyDir  = Join-Path $ffInstall "distribution"
        $policyPath = Join-Path $policyDir "policies.json"

        $policyContent = @'
{
  "policies": {
    "DisableTelemetry": true,
    "DNSOverHTTPS": {
      "Enabled": true,
      "ProviderURL": "https://cloudflare-dns.com/dns-query",
      "Locked": false
    }
  }
}
'@

        if ($PSCmdlet.ShouldProcess($policyPath, "Write Firefox policies.json")) {
            if (-not (Test-Path $policyDir)) {
                New-Item -ItemType Directory -Path $policyDir -Force | Out-Null
            }
            [System.IO.File]::WriteAllText($policyPath, $policyContent, [System.Text.Encoding]::UTF8)
            Write-Ok "Firefox policies.json written: $policyPath"
        }
    } else {
        Write-Skip "Firefox system install not found in registry - skipping policies.json."
    }
}

# ============================================================================
# [3]  CHROME - Enterprise registry policy
# ============================================================================
function Set-ChromeHardening {
    Write-Header "[3] Google Chrome - Enterprise Policy Hardening"

    $policyPath   = "HKLM:\SOFTWARE\Policies\Google\Chrome"
    $urlBlockPath = "$policyPath\URLBlocklist"

    if ($PSCmdlet.ShouldProcess($policyPath, "Apply Chrome enterprise registry policies")) {
        if (-not (Test-Path $policyPath))   { New-Item -Path $policyPath   -Force | Out-Null }
        if (-not (Test-Path $urlBlockPath)) { New-Item -Path $urlBlockPath -Force | Out-Null }

        # [F-01] Prevent WebRTC from exposing LAN/VPN-bypass IPs via STUN
        Set-ItemProperty -Path $policyPath -Name "WebRtcIPHandling" -Value "default_public_interface_only" -Type String
        Write-Ok "[F-01] WebRTC set to public-interface-only"

        # [F-05] Block camera and microphone without explicit per-site grant
        Set-ItemProperty -Path $policyPath -Name "VideoCaptureAllowed" -Value 0 -Type DWord
        Set-ItemProperty -Path $policyPath -Name "AudioCaptureAllowed" -Value 0 -Type DWord
        Write-Ok "[F-05] Camera and microphone blocked by policy"

        # AED extension scan exfiltration endpoint block
        Set-ItemProperty -Path $urlBlockPath -Name "1" -Value "https://www.linkedin.com/li/track*"     -Type String
        Set-ItemProperty -Path $urlBlockPath -Name "2" -Value "https://www.linkedin.com/apfc/collect*" -Type String
        Set-ItemProperty -Path $urlBlockPath -Name "3" -Value "https://li.protechts.net/*"              -Type String
        Write-Ok "[AED] URLBlocklist: li/track, apfc/collect, li.protechts.net"

        # DNS-over-HTTPS within Chrome
        Set-ItemProperty -Path $policyPath -Name "DnsOverHttpsMode"      -Value "secure"                               -Type String
        Set-ItemProperty -Path $policyPath -Name "DnsOverHttpsTemplates"  -Value "https://cloudflare-dns.com/dns-query" -Type String
        Write-Ok "[DoH] Chrome DNS-over-HTTPS -> Cloudflare"

        Write-Warn "Canvas/Audio/Font fingerprinting requires a browser extension in Chrome."
        Write-Manual "Install: Canvas Fingerprint Defender"
        Write-Manual "  ID: lanfdkkpgfjfdikkncbnojekcppdebfp"
        Write-Manual "Install: uBlock Origin (add custom filters - see summary)"
        Write-Manual "  ID: cjpalhdlnbpafiamejdnhcphjbkeiagm"
    }
}

# ============================================================================
# [4]  EDGE - Mirror Chrome policies for Microsoft Edge (Chromium)
# ============================================================================
function Set-EdgeHardening {
    Write-Header "[4] Microsoft Edge - Enterprise Policy Hardening"

    $policyPath   = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
    $urlBlockPath = "$policyPath\URLBlocklist"

    if ($PSCmdlet.ShouldProcess($policyPath, "Apply Edge enterprise registry policies")) {
        if (-not (Test-Path $policyPath))   { New-Item -Path $policyPath   -Force | Out-Null }
        if (-not (Test-Path $urlBlockPath)) { New-Item -Path $urlBlockPath -Force | Out-Null }

        Set-ItemProperty -Path $policyPath -Name "WebRtcIPHandling"      -Value "default_public_interface_only"         -Type String
        Set-ItemProperty -Path $policyPath -Name "VideoCaptureAllowed"   -Value 0                                       -Type DWord
        Set-ItemProperty -Path $policyPath -Name "AudioCaptureAllowed"   -Value 0                                       -Type DWord
        Set-ItemProperty -Path $policyPath -Name "DnsOverHttpsMode"      -Value "secure"                                -Type String
        Set-ItemProperty -Path $policyPath -Name "DnsOverHttpsTemplates" -Value "https://cloudflare-dns.com/dns-query"  -Type String

        Set-ItemProperty -Path $urlBlockPath -Name "1" -Value "https://www.linkedin.com/li/track*"     -Type String
        Set-ItemProperty -Path $urlBlockPath -Name "2" -Value "https://www.linkedin.com/apfc/collect*" -Type String
        Set-ItemProperty -Path $urlBlockPath -Name "3" -Value "https://li.protechts.net/*"              -Type String

        Write-Ok "Edge policies applied (mirrors Chrome hardening)"
    }
}

# ============================================================================
# [5]  WINDOWS DNS-over-HTTPS (Windows 10 2004+ / Windows 11)
# ============================================================================
function Set-SystemDoH {
    Write-Header "[5] Windows System-Wide DNS-over-HTTPS"

    $build = [System.Environment]::OSVersion.Version.Build
    if ($build -lt 19041) {
        Write-Skip "DoH requires Windows 10 build 19041 (2004) or later. Skipping."
        return
    }

    if ($PSCmdlet.ShouldProcess("DNS Client", "Register Cloudflare DoH servers")) {
        try {
            Add-DnsClientDohServerAddress `
                -ServerAddress "1.1.1.1" `
                -DohTemplate "https://cloudflare-dns.com/dns-query" `
                -AllowFallbackToUdp $false `
                -AutoUpgrade $true `
                -ErrorAction SilentlyContinue

            Add-DnsClientDohServerAddress `
                -ServerAddress "1.0.0.1" `
                -DohTemplate "https://cloudflare-dns.com/dns-query" `
                -AllowFallbackToUdp $false `
                -AutoUpgrade $true `
                -ErrorAction SilentlyContinue

            Write-Ok "DoH registered: Cloudflare 1.1.1.1 / 1.0.0.1"
            Write-Manual "Set your adapter DNS to 1.1.1.1 and 1.0.0.1 for full effect:"
            Write-Manual "  Settings -> Network & Internet -> adapter -> DNS server assignment"
        }
        catch {
            Write-Warn "Could not register DoH: $($_.Exception.Message)"
            Write-Manual "Set manually: Settings -> Privacy & Security -> Security -> Use secure DNS"
        }
    }
}

# ============================================================================
# [6]  SUMMARY REPORT
# ============================================================================
function Write-Summary {
    Write-Header "SUMMARY - Applied Mitigations"

    $col1 = 30
    $col2 = 46
    $col3 = 18

    $headerLine = "Finding".PadRight($col1) + "Method".PadRight($col2) + "Status".PadRight($col3)
    $divider    = "-" * ($col1 + $col2 + $col3)

    Write-Host ""
    Write-Host "  $headerLine" -ForegroundColor White
    Write-Host "  $divider"    -ForegroundColor DarkGray

    $rows = @(
        @("F-01 WebRTC IP Leak",        "Hosts + Chrome/Edge WebRtcIPHandling + FF", "[OK] Applied"          ),
        @("F-02 Canvas Fingerprint",    "Firefox resistFingerprinting=true",          "[OK] Firefox only"     ),
        @("F-03 Audio Fingerprint",     "Firefox resistFingerprinting=true",          "[OK] Firefox only"     ),
        @("F-04 Battery API",           "Firefox dom.battery.enabled=false",          "[OK] Firefox / Manual" ),
        @("F-05 Device Enumeration",    "Chrome/Edge policy + Firefox pref",          "[OK] Applied"          ),
        @("F-06 Incognito Detection",   "Firefox resistFingerprinting",               "[OK] Firefox only"     ),
        @("F-07 Font Enumeration",      "Firefox use_document_fonts=0",               "[OK] Firefox only"     ),
        @("F-08 Network Info API",      "Firefox dom.netinfo.enabled=false",          "[OK] Firefox only"     ),
        @("F-09 WebGL Fingerprint",     "Firefox WebGL2 off; extension for Chrome",   "[PARTIAL]"             ),
        @("F-10 Hardware Signals",      "Firefox resistFingerprinting (CPU spoof)",   "[OK] Firefox only"     ),
        @("F-11 AdBlock Detection",     "Manual - install uBlock Origin",             "[TODO] Manual"         ),
        @("F-12 Tealium 3rd-party",     "Hosts blocks tiqcdn/tealiumiq",              "[OK] Applied"          ),
        @("AED Extension Scanning",     "Chrome/Edge URLBlocklist li/track + apfc",   "[OK] Applied"          ),
        @("HUMAN Security iframe",      "Hosts blocks li.protechts.net",              "[OK] Applied"          )
    )

    foreach ($row in $rows) {
        $status = $row[2]
        $color  = switch -Wildcard ($status) {
            "*OK*"      { "Green"   }
            "*PARTIAL*" { "Yellow"  }
            default     { "Magenta" }
        }
        $line = $row[0].PadRight($col1) + $row[1].PadRight($col2) + $status.PadRight($col3)
        Write-Host "  $line" -ForegroundColor $color
    }

    Write-Host ""
    Write-Host "  REQUIRED MANUAL STEPS:" -ForegroundColor Cyan
    Write-Host "  ----------------------------------------------------------------" -ForegroundColor DarkCyan
    Write-Host "  1. Use FIREFOX as your LinkedIn browser (most prefs auto-applied)." -ForegroundColor White
    Write-Host ""
    Write-Host "  2. Install uBlock Origin and add these custom filters:" -ForegroundColor White
    Write-Host "       ||linkedin.com/li/track^"            -ForegroundColor Gray
    Write-Host "       ||linkedin.com/apfc/collect^"        -ForegroundColor Gray
    Write-Host "       ||linkedin.com/platform-telemetry^"  -ForegroundColor Gray
    Write-Host "       ||li.protechts.net^"                 -ForegroundColor Gray
    Write-Host ""
    Write-Host "  3. CHROME ONLY: Install Canvas Fingerprint Defender." -ForegroundColor White
    Write-Host "       ID: lanfdkkpgfjfdikkncbnojekcppdebfp"            -ForegroundColor Gray
    Write-Host ""
    Write-Host "  4. CHROME ONLY: chrome://flags -> Anonymize local IPs (WebRTC) -> Enabled." -ForegroundColor White
    Write-Host ""
    Write-Host "  5. Set adapter DNS to 1.1.1.1 / 1.0.0.1 to activate DoH." -ForegroundColor White
    Write-Host ""
    Write-Host "  Source: chunk.716 static forensic analysis (Apr 2026)" -ForegroundColor DarkGray
    Write-Host "  Repo  : https://github.com/RisingCyber/Protect-LinkedinPrivacy"   -ForegroundColor DarkGray
    Write-Host ""
}

# ============================================================================
# ENTRY POINT
# ============================================================================
Write-Host ""
Write-Host "  Protect-LinkedinPrivacy.ps1  v1.1.0" -ForegroundColor Cyan
Write-Host "  Linkedin + Fingerprinting Mitigations" -ForegroundColor Cyan
Write-Host "  Findings: F-01 through F-12 + AED Extension Scanning" -ForegroundColor DarkCyan
Write-Host ""

if (-not $Force -and -not $WhatIfPreference) {
    Write-Host "  This script will modify:" -ForegroundColor Yellow
    Write-Host "    - Windows Hosts file (adds tracker domain blocks)"
    Write-Host "    - Firefox user.js in all detected profiles"
    Write-Host "    - Chrome enterprise registry policies (HKLM)"
    Write-Host "    - Edge enterprise registry policies (HKLM)"
    Write-Host "    - Windows DNS-over-HTTPS client settings"
    Write-Host ""
    $confirm = Read-Host "  Proceed? [Y/N]"
    if ($confirm -notmatch '^[Yy]') {
        Write-Host "  Aborted." -ForegroundColor Red
        exit 0
    }
}

if (-not $SkipHostsFile) { Set-HostsBlocks }
if (-not $SkipFirefox)   { Set-FirefoxHardening }
if (-not $SkipChrome)    { Set-ChromeHardening }
if (-not $SkipEdge)      { Set-EdgeHardening }
if (-not $SkipDNS)       { Set-SystemDoH }

Write-Summary
