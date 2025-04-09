import "pe"

private rule Amadey
{
    meta:
        author = "kevoreilly"
        description = "Amadey Payload"
        cape_type = "Amadey Payload"
        hash = "988258716d5296c1323303e8fe4efd7f4642c87bfdbe970fe9a3bb3f410f70a4"
    strings:
        $decode1 = {8B D1 B8 FF FF FF 7F D1 EA 2B C2 3B C8 76 07 BB FF FF FF 7F EB 08 8D 04 0A 3B D8 0F 42 D8}
        $decode2 = {33 D2 8B 4D ?? 8B C7 F7 F6 8A 84 3B [4] 2A 44 0A 01 88 87 [4] 47 8B 45 ?? 8D 50 01}
        $decode3 = {8A 04 02 88 04 0F 41 8B 7D ?? 8D 42 01 3B CB 7C}
    condition:
        uint16(0) == 0x5A4D and 2 of them
}

private rule MALWARE_Win_Amadey {
    meta:
        author = "ditekSHen"
        description = "Amadey downloader payload"
    strings:
        $s1 = "_ZZ14aGetProgramDirvE11UsersDirRes" fullword ascii
        $s2 = "_libshell32_a" ascii
        $s3 = "_ShellExecuteExA@4" ascii
        $s4 = "aGetTempDirvE10TempDirRes" ascii
        $s5 = "aGetHostNamevE7InfoBuf" ascii
        $s6 = "aCreateProcessPc" ascii
        $s7 = "aGetHostNamev" ascii
        $s8 = "aGetSelfDestinationiE22aGetSelfDestinationRes" ascii
        $s9 = "aGetSelfPathvE15aGetSelfPathRes" ascii
        $s10 = "aResolveHostPcE15aResolveHostRes" ascii
        $s11 = "aUrlMonDownloadPcS" ascii
        $s12 = "aWinSockPostPcS_S_" ascii
        $s13 = "aCreateProcessPc" ascii

        $v1 = "hii^" fullword ascii
        $v2 = "plugins/" fullword ascii
        $v3 = "ProgramData\\" fullword ascii
        $v4 = "&unit=" fullword ascii
        $v5 = "runas" fullword ascii wide
        $v6 = "Microsoft Internet Explorer" fullword wide
        $v7 = "stoi argument" ascii

        $av1 = "AVAST Software" fullword ascii
        $av2 = "Avira" fullword ascii
        $av3 = "Kaspersky Lab" fullword ascii
        $av4 = "ESET" fullword ascii
        $av5 = "Panda Security" fullword ascii
        $av6 = "Doctor Web" fullword ascii
        $av7 = "360TotalSecurity" fullword ascii
        $av8 = "Bitdefender" fullword ascii
        $av9 = "Norton" fullword ascii
        $av10 = "Sophos" fullword ascii
        $av11 = "Comodo" fullword ascii

        $pdb1 = "Amadey\\Release\\Amadey.pdb" ascii wide
    condition:
        uint16(0) == 0x5a4d and (7 of ($s*) or (6 of ($v*) and 2 of ($av*)) or 1 of ($pdb*))
}

rule New_YaraRules_Amadey {
    meta:
        description = "new yara rules for amadey family malware"
        author = "ino"
        date = "April 2025"
    strings:
        $name = "string"
}