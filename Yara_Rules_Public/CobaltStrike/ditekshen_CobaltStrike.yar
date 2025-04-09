rule MALWARE_Win_CobaltStrike {
    meta:
        author = "ditekSHen"
        description = "CobaltStrike payload"
    strings:
        $s1 = "%%IMPORT%%" fullword ascii
        $s2 = "www6.%x%x.%s" fullword ascii
        $s3 = "cdn.%x%x.%s" fullword ascii
        $s4 = "api.%x%x.%s" fullword ascii
        $s5 = "%s (admin)" fullword ascii
        $s6 = "could not spawn %s: %d" fullword ascii
        $s7 = "Could not kill %d: %d" fullword ascii
        $s8 = "Could not connect to pipe (%s): %d" fullword ascii
        $s9 = /%s\.\d[(%08x).]+\.%x%x\.%s/ ascii

        $pwsh1 = "IEX (New-Object Net.Webclient).DownloadString('http" ascii
        $pwsh2 = "powershell -nop -exec bypass -EncodedCommand \"%s\"" fullword ascii
    condition:
        uint16(0) == 0x5a4d and (5 of ($s*) or (all of ($pwsh*) and 2 of ($s*)) or (#s9 > 6 and 4 of them)) 
}

rule MALWARE_Win_UNKCobaltStrike {
    meta:
        author = "ditekSHen"
        description = "Detects unknown malware, potentially CobaltStrike related"
    strings:
        $s1 = "https://%hu.%hu.%hu.%hu:%u" ascii wide
        $s2 = "https://microsoft.com/telemetry/update.exe" ascii wide
        $s3 = "\\System32\\rundll32.exe" ascii wide
        $s4 = "api.opennicproject.org" ascii wide
        $s5 = "%s %s,%s %u" ascii wide
        $s6 = "User32.d?" ascii wide
        $s7 = "StrDupA" fullword ascii wide
        $s8 = "{6d4feed8-18fd-43eb-b5c4-696ad06fac1e}" ascii wide
        $s9 = "{ac41592a-3d21-46b7-8f21-24de30531656}" ascii wide
        $s10 = "bd526:3b.4e32.57c8.9g32.35ef41642767~" ascii wide
        $s11 = { 4b d3 91 49 a1 80 91 42 83 b6 33 28 36 6b 90 97 } // BITS
        $s12 = { 0d 4c e3 5c c9 0d 1f 4c 89 7c da a1 b7 8c ee 7c } // BITS
    condition:
        uint16(0) == 0x5a4d and 6 of them
}

