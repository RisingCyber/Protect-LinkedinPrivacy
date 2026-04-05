.SYNOPSIS
    Protect-LinkeinPrivacy.ps1
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
      [5] Register system-wide DNS-over-HTTPS via Cloudflare

.RUN
powershell -ExecutionPolicy Bypass -File ./Protect-LinkedinPrivacy.ps1



##Manual Controls:

1-Use Firefox. 
Firefox with “privacy.resistFingerprinting = true” spoofs canvas, audio, hardware concurrency, screen resolution, and timezone. 
Breaking the core fingerprint which Chrome has no equivalent built-in.

2- Use uBlock Origin filters 
||linkedin.com/li/track^
||linkedin.com/*/telemetry/*
||linkedin.com/apfc/collect^
||li.protechts.net^

3-Block WebRTC IP leaks
In Firefox go to about:config
change
"media.peerconnection.enabled = false"
"dom.battery.enabled = false"
