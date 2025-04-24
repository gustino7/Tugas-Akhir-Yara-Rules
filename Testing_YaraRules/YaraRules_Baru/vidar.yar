import "pe"

private rule CAPE_Vidar {
    meta:
        author = "kevoreilly,rony"
        description = "Vidar Payload"
        cape_type = "Vidar Payload"
        packed = "0cff8404e73906f3a4932e145bf57fae7a0e66a7d7952416161a5d9bb9752fd8"
    strings:
        $decode = {FF 75 0C 8D 34 1F FF 15 ?? ?? ?? ?? 8B C8 33 D2 8B C7 F7 F1 8B 45 0C 8B 4D 08 8A 04 02 32 04 31 47 88 06 3B 7D 10 72 D8}
        $xor_dec = {0F B6 [0-5] C1 E? ?? 33 ?? 81 E? [0-5] 89 ?? 7C AF 06}
        $wallet = "*wallet*.dat" fullword ascii wide
        $s1 = "\"os_crypt\":{\"encrypted_key\":\"" fullword ascii wide
        $s2 = "screenshot.jpg" fullword ascii wide
        $s3 = "\\Local State" fullword ascii wide
        $s4 = "Content-Disposition: form-data; name=\"" fullword ascii wide
        $s5 = "CC\\%s_%s.txt" fullword ascii wide
        $s6 = "History\\%s_%s.txt" fullword ascii wide
        $s7 = "Autofill\\%s_%s.txt" fullword ascii wide
        $s8 = "Downloads\\%s_%s.txt" fullword ascii wide
    condition:
        uint16be(0) == 0x4d5a and 6 of them 
}

private rule elastic_Vidar_32fea8da {
    meta:
        author = "Elastic Security"
        id = "32fea8da-b381-459c-8bf4-696388b8edcc"
        fingerprint = "ebcced7b2924cc9cfe9ed5b5f84a8959e866a984f2b5b6e1ec5b1dd096960325"
        creation_date = "2023-05-04"
        last_modified = "2023-06-13"
        threat_name = "Windows.Trojan.Vidar"
        reference_sample = "6f5c24fc5af2085233c96159402cec9128100c221cb6cb0d1c005ced7225e211"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 4F 4B 58 20 57 65 62 33 20 57 61 6C 6C 65 74 }
        $a2 = { 8B E5 5D C3 5E B8 03 00 00 00 5B 8B E5 5D C3 5E B8 08 00 00 }
        $a3 = { 83 79 04 00 8B DE 74 08 8B 19 85 DB 74 62 03 D8 8B 03 85 C0 }
    condition:
        all of them
}

private rule elastic_Vidar_114258d5 {
    meta:
        author = "Elastic Security"
        id = "114258d5-f05e-46ac-914b-1a7f338ccf58"
        fingerprint = "9b4f7619e15398fcafc622af821907e4cf52964c55f6a447327738af26769934"
        creation_date = "2021-06-28"
        last_modified = "2021-08-23"
        threat_name = "Windows.Trojan.Vidar"
        reference_sample = "34c0cb6eaf2171d3ab9934fe3f962e4e5f5e8528c325abfe464d3c02e5f939ec"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "BinanceChainWallet" fullword
        $a2 = "*wallet*.dat" fullword
        $a3 = "SOFTWARE\\monero-project\\monero-core" fullword
        $b1 = "CC\\%s_%s.txt" fullword
        $b2 = "History\\%s_%s.txt" fullword
        $b3 = "Autofill\\%s_%s.txt" fullword
    condition:
        1 of ($a*) and 1 of ($b*)
}

private rule file_0c857501e3851072db666386136929c06bcf4c8d3160b41b7d82a3ce9afca1be {
    meta:
        description = "file 0c857501e3851072db666386136929c06bcf4c8d3160b41b7d82a3ce9afca1be"
        author = "ino"
        date = "April 2025"
    strings:
        $x1 = "RunpeX.Stub.Framework" fullword wide
        $x2 = "TaskKill" fullword wide
        $x3 = "GetMethodDescriptor" fullword wide
        $x4 = "zeroBits" fullword ascii
        $x5 = "VMEntry" fullword ascii
    condition:
        3 of them
}

private rule file_49a7f82743a038d7a570d5d5d8ecb92f369f0e6dbba6532674c4789f0daf9b31 {
    meta:
        description = "file 49a7f82743a038d7a570d5d5d8ecb92f369f0e6dbba6532674c4789f0daf9b31"
        author = "ino"
        date = "April 2025"
    strings:
        $x1 = "DigiCertTrusted" fullword ascii
        $x2 = "DigiCert Trusted G4 Code Signing" fullword ascii
        $x3 = "vector too long" fullword ascii
        $x4 = "api-ms-" fullword wide
        $x5 = ".data$rs" fullword ascii
    condition:
        3 of them
}

rule New_YaraRules_Vidar {
    meta:
        description = "new yara rules for Vidar family malware"
        author = "ino"
        date = "April 2025"
    strings:
        // Suspicious string = *s* or PEStudio Blacklist: strings = *p*
        $p1 = "GetResourceString" fullword wide
        $p2 = "GetProcessesByName" fullword ascii
        $p3 = "SendKeys" fullword ascii
        $p4 = "CurrentUser" fullword ascii
        $p5 = "CreateSubKey" fullword ascii
        $p6 = "LocalMachine" fullword ascii
        $p8 = "Reverse" fullword ascii
        $p9 = "MemoryStream" fullword ascii
        $p11 = "System.Security.Principal" fullword ascii
        $p12 = "Hashtable" fullword ascii
        $p13 = "Encoding" fullword ascii
        $p14 = "BeginInvoke" fullword ascii
        $p15 = "EndInvoke" fullword ascii
        $p16 = "Binder" fullword ascii
        $p17 = "Monitor" fullword ascii
        $p18 = "callback" fullword ascii
        $p19 = "wrong protocol type" fullword ascii
        $p20 = "connection already in progress" fullword ascii
        $p21 = "owner dead" fullword ascii
        $p22 = "network reset" fullword ascii
        $p23 = "network down" fullword ascii
        $p24 = "broken pipe" fullword ascii
        $p25 = "protocol error" fullword ascii
        $p26 = "permission denied" fullword ascii

        $s1 = "KoiVM.Runtime" fullword ascii // plugin for the ConfuserEx obfuscation tool
        $s2 = "DigiCert SHA2 Assured ID Code Signing CA" fullword ascii // manipulate certificate authority
        $s3 = "C:\\Windows\\System32\\cmd.exe" fullword ascii
        $s4 = "Select * From Win32_OperatingSystem" fullword wide

    condition:
        uint16(0) == 0x5a4d
        and ((5 of ($p*)) or (1 of ($s*)))
        and 1 of (
            CAPE_Vidar,
            elastic_Vidar_32fea8da,
            elastic_Vidar_114258d5,
            file_0c857501e3851072db666386136929c06bcf4c8d3160b41b7d82a3ce9afca1be,
            file_49a7f82743a038d7a570d5d5d8ecb92f369f0e6dbba6532674c4789f0daf9b31
        )
        and filesize < 5000KB
}