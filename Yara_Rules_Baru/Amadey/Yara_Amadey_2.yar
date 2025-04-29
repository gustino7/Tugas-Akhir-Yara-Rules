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

private rule file_0da5b00e8e941ac4be29830e6040cb5f {
    meta:
        description = "file 0da5b00e8e941ac4be29830e6040cb5f"
        author = "ino"
        date = "April 2025"
    strings:
        $x1 = "@GetVice@0" fullword ascii
        $x2 = "ProductVersions" fullword wide
        $x3 = "StringFileInform" fullword wide
        $x4 = "voygcuadage.exe" fullword wide
    condition:
        3 of them
}

private rule file_4506917f5cd8be78ec581d74085c21b75b17c2ede56f0af2dc38bc3f09e96caf {
    meta:
        description = "file 4506917f5cd8be78ec581d74085c21b75b17c2ede56f0af2dc38bc3f09e96caf"
        author = "ino"
        date = "April 2025"
    strings:
        $x1 = "DSystem\\CurrentControlSet\\Control\\Session Manager" fullword ascii
        $x2 = "Extract" fullword wide
        $x3 = "SeShutdownPrivilege" fullword ascii
        $x4 = ".rdata$brc" fullword ascii
        $x5 = "WEXTRACT" ascii wide
    condition:
        2 of them
}

private rule file_7970613a8bdc95bb97d4996d9302153feef816b64a6b1861045a2aec85dcdb8d {
    meta:
        description = "file 7970613a8bdc95bb97d4996d9302153feef816b64a6b1861045a2aec85dcdb8d"
        author = "ino"
        date = "April 2025"
    strings:
        $x1 = "?GetProcessWindowStation" fullword ascii
        $x2 = "C:\\halewupesi_xafidehusef\\57\\molaj\\yawavilunu-48\\goyu.pdb" fullword ascii
        $x3 = "Type Descriptor" fullword ascii
        $x4 = "AppPolicyGetProcessTerminationMethod" fullword ascii
    condition:
        2 of them
}

rule New_YaraRules_Amadey {
    meta:
        description = "new yara rules for amadey family malware"
        author = "ino"
        date = "April 2025"
    strings:
        // Suspicious string = p* or Similar string = l*
        $p1 = "C:\\tibosewodenak\\loxab\\bidujeguk\\zemiw\\3\\rap\\l.pdb" fullword ascii
        $p2 = "C:\\xeyes.pdb" fullword ascii
        $p3 = "C:\\horonu\\suyi\\xapum_foyozunehax-tubak80\\xo.pdb" fullword ascii 
        $p4 = "@GetFirstVice@0" fullword ascii 
        $p5 = "C:\\yokugu\\gemupocu tuhokanaye.pdb" fullword ascii
        $p6 = "xiSWl90.exe" fullword ascii
        $p7 = "xHRuL30.exe" fullword ascii
        $p8 = "v0017Qj.exe" fullword ascii
        $p9 = "tz9483.exe" fullword ascii
        $p10 = /za[0-9]{6}\.exe/ fullword ascii // membentuk pola za**.exe
        $p11 = /y[0-9]{2}\.exe/ fullword ascii // membentuk pola y**.exe
        $p12 = "constructor or from DllMain." fullword ascii
        $p14 = "D:\\Mktmp\\Amadey\\Release\\Amadey.pdb" fullword ascii
        $p15 = "api-ms-win-core-synch-l1-2-0.dll" fullword wide

        // obfuscated API Hashing
        $l1 = "LoadLibraryA" ascii
        $l2 = "GetProcAddress" ascii

    condition:
        uint16(0) == 0x5a4d
        and ((any of ($p*)) and (any of ($l*)))
        and 1 of (
            Amadey,
            MALWARE_Win_Amadey,
            file_0da5b00e8e941ac4be29830e6040cb5f,
            file_4506917f5cd8be78ec581d74085c21b75b17c2ede56f0af2dc38bc3f09e96caf,
            file_7970613a8bdc95bb97d4996d9302153feef816b64a6b1861045a2aec85dcdb8d
        )
        and filesize < 5000KB
}