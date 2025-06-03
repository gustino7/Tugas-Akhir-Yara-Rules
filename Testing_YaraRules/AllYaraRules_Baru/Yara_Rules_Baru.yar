import "pe"

private rule AgentTeslaV3 {
    meta:
      author = "ditekshen"
      description = "AgentTeslaV3 infostealer payload"
      cape_type = "AgentTesla payload"
    strings:
        $s1 = "get_kbok" fullword ascii
        $s2 = "get_CHoo" fullword ascii
        $s3 = "set_passwordIsSet" fullword ascii
        $s4 = "get_enableLog" fullword ascii
        $s5 = "bot%telegramapi%" wide
        $s6 = "KillTorProcess" fullword ascii
        $s7 = "GetMozilla" ascii
        $s8 = "torbrowser" wide
        $s9 = "%chatid%" wide
        $s10 = "logins" fullword wide
        $s11 = "credential" fullword wide
        $s12 = "AccountConfiguration+" wide
        $s13 = "<a.+?href\\s*=\\s*([\"'])(?<href>.+?)\\1[^>]*>" fullword wide
        $s14 = "set_Lenght" fullword ascii
        $s15 = "get_Keys" fullword ascii
        $s16 = "set_AllowAutoRedirect" fullword ascii
        $s17 = "set_wtqQe" fullword ascii
        $s18 = "set_UseShellExecute" fullword ascii
        $s19 = "set_IsBodyHtml" fullword ascii
        $s20 = "set_FElvMn" fullword ascii
        $s21 = "set_RedirectStandardOutput" fullword ascii

        $g1 = "get_Clipboard" fullword ascii
        $g2 = "get_Keyboard" fullword ascii
        $g3 = "get_Password" fullword ascii
        $g4 = "get_CtrlKeyDown" fullword ascii
        $g5 = "get_ShiftKeyDown" fullword ascii
        $g6 = "get_AltKeyDown" fullword ascii

        $m1 = "yyyy-MM-dd hh-mm-ssCookieapplication/zipSCSC_.jpegScreenshotimage/jpeg/log.tmpKLKL_.html<html></html>Logtext/html[]Time" ascii
        $m2 = "%image/jpg:Zone.Identifier\\tmpG.tmp%urlkey%-f \\Data\\Tor\\torrcp=%PostURL%127.0.0.1POST+%2B" ascii
        $m3 = ">{CTRL}</font>Windows RDPcredentialpolicyblobrdgchrome{{{0}}}CopyToComputeHashsha512CopySystemDrive\\WScript.ShellRegReadg401" ascii
        $m4 = "%startupfolder%\\%insfolder%\\%insname%/\\%insfolder%\\Software\\Microsoft\\Windows\\CurrentVersion\\Run%insregname%SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\RunTruehttp" ascii
        $m5 = "\\WindowsLoad%ftphost%/%ftpuser%%ftppassword%STORLengthWriteCloseGetBytesOpera" ascii
    condition:
        (8 of ($s*) or (6 of ($s*) and 4 of ($g*))) or (2 of ($m*))
}

private rule file_14a388b154b55a25c66b1bfef9499b64 {
    meta:
        description = "file 14a388b154b55a25c66b1bfef9499b64"
        author = "ino"
        date = "March 2025"
    strings:
        $x1 = "@@DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD" ascii
        $x2 = "PUBLICMAP" fullword ascii
        $x3 = "GetEmptyTileCount" fullword ascii
        $x4 = "TurnAction_Spy" fullword ascii
        $x5 = "PRIVATEMAP" fullword ascii
        $x6 = "Operating system" fullword wide
        $x7 = "Logical processors" fullword wide
        $x8 = "My.Computer" fullword ascii
        $x9 = "ObjectProvider" fullword ascii
    condition:
        2 of them
}

private rule file_5b14a7366cf5dbea3386c6afbd25f012 {
    meta:
        description = "file 5b14a7366cf5dbea3386c6afbd25f012"
        author = "ino"
        date = "March 2025"
    strings:
        $x1 = "PasswordDialog" fullword ascii
        $x2 = "LabelPassword" fullword ascii
        $x3 = "Send_Remote_AT_Command" fullword ascii
        $x4 = "TargetPoint" fullword ascii
        $x5 = "SetHostAddress" fullword ascii
        $x6 = "VitualMode" fullword ascii
    condition:
        2 of them
}

private rule file_6802c9c481671ec10ee1178946a46c73 {
    meta:
        description = "file 6802c9c481671ec10ee1178946a46c73"
        author = "ino"
        date = "March 2025"
    strings:
        $x1 = "get_username" fullword ascii
        $x2 = "GuidMasterKey" fullword ascii
        $x3 = "get_LastAccessed" fullword ascii
    condition:
        2 of them
}

rule New_YaraRules_AgentTesla {
    meta:
        description = "new yara rules for agent tesla family malware"
        author = "ino"
        date = "March 2025"
    strings:
        // Agent Tesla secara umum dibuat dengan C#, ditandai dengan string:
        $dotnet1 = "mscoree.dll" ascii
        $dotnet2 = "mscorlib" ascii
        $dotnet3 = "#Strings" ascii
        $dotnet4 = { 5F 43 6F 72 [3] 4D 61 69 6E }

        // Suspicious string = p* or Similar string = l*
        $p1 = "CancellationTokenRegistrati.exe" fullword wide
        $p2 = "COMServerEnt.exe" fullword wide
        $p3 = "http://tempuri.org/SeguridadDS.xsd" fullword wide
        $p4 = "CREATE LOGIN [" fullword wide
        $p5 = "getMd5Hash" fullword ascii
        $p6 = "HostProtectionResour.exe" fullword wide
        $p7 = "get_txtPassword" fullword ascii
        $p8 = "RuntimeReflectionExtensio.exe" fullword wide
        $p9 = "ComRegisterFunctionAttribu.exe" fullword wide
        $p10 = "LIBFLA" fullword wide ascii
        $p11 = "4C4942464C41" wide // Encoded LIBFLA
        $p12 = "DomainCompressedSta.exe" fullword wide
        $p13 = "EncoderReplacementFallba.exe" fullword wide
        $p14 = "StaticIndexRangePartition" wide ascii
        $p15 = "get_txtServerPassword" fullword ascii
        $p16 = "get_UserXOrigin" fullword ascii
        $p17 = "GetPrivateProfileString" fullword ascii
        $p18 = "passwordIsSet" fullword ascii 
        $p19 = "AccountCredentialsModel" fullword ascii
        $p20 = "AccountConfiguration" fullword ascii
        $p21 = "org.jdownloader.settings.AccountSettings.accounts.ejs" fullword wide
        $p22 = "encryptedPassword" fullword wide
        $p23 = "syncpassword" fullword wide
        $p24 = "<br>Password: " fullword wide
        $p25 = "HTTP Password" fullword wide
        $p26 = "IExpando.Plug" fullword wide
        
        // String Matched
        $l1 = "_CorExeMain" ascii
        $l2 = "#GUID" ascii
        $l3 = "#Blob" ascii
        $l4 = "System.Diagnostics" ascii
        $l5 = "System.Reflection" ascii
        // Yara Rules publik
        $l6 = "SmtpClient" wide
        $l7 = "appdata" ascii wide
        $l8 = "OSFullName" ascii

    condition:
        uint16(0) == 0x5a4d 
        and (2 of ($dotnet*))
        and ((1 of ($p*)) and (5 of ($l*)))
        and 1 of (
            AgentTeslaV3,
            file_14a388b154b55a25c66b1bfef9499b64,
            file_5b14a7366cf5dbea3386c6afbd25f012,
            file_6802c9c481671ec10ee1178946a46c73
        )
        and filesize < 5000KB
}

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
        $p16 = "Command.com /c %s" ascii
        $p17 = "advapi32.dll" nocase ascii

        // String Matched
        $l1 = "CreateThread" ascii
        $l2 = "LoadLibraryA" ascii
        $l3 = "GetProcAddress" ascii
        $l4 = "WriteProcessMemory" ascii // possible shellcode inject
        $l5 = "RegCreateKeyExA" ascii
        $l6 = "RegSetValueExA" ascii
        $l7 = "CreateMutexA" ascii
        $l8 = "CallWindowProcA" ascii
        $l9 = "NtUnmapViewOfSection" ascii // possible injection code
        $l10 = "VirtualAlloc" ascii
        $l11 = "InternetOpenUrl" ascii // possible C2
        $l12 = ".?AV" ascii // antivirus
        $l13 = "schedule" ascii wide // schedule send to C2
        $l14 = "GetUserObjectInformation" ascii
        // Yara Rules publik
        $l15 = "CreateProcess" ascii
        $l16 = "ShellExecute" ascii
        // Command
        $l17 = "SHELL32.DLL" nocase wide ascii
        $l18 = "Kernel32.dll" nocase wide ascii
        $l19 = "setupapi.dll" ascii
        $l20 = "USER32.DLL" nocase ascii
        $l21 = "/C:<Cmd>" wide
        $l22 = "msdownld.tmp" ascii

    condition:
        uint16(0) == 0x5a4d
        and ((2 of ($p*)) and (7 of ($l*)))
        and 1 of (
            Amadey,
            MALWARE_Win_Amadey,
            file_0da5b00e8e941ac4be29830e6040cb5f,
            file_4506917f5cd8be78ec581d74085c21b75b17c2ede56f0af2dc38bc3f09e96caf,
            file_7970613a8bdc95bb97d4996d9302153feef816b64a6b1861045a2aec85dcdb8d
        )
        and filesize < 5000KB
}

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
        $x2 = "System.Security.Permissions.SecurityPermissionAttribute" ascii
        $x3 = "Kernel32.Dll" fullword wide
        $x4 = "GetMethodDescriptor" fullword wide
        $x5 = "System.Resources.ResourceReader" ascii
        $x6 = "PublicKeyToken=" ascii
    condition:
        2 of them
}

private rule file_49a7f82743a038d7a570d5d5d8ecb92f369f0e6dbba6532674c4789f0daf9b31 {
    meta:
        description = "file 49a7f82743a038d7a570d5d5d8ecb92f369f0e6dbba6532674c4789f0daf9b31"
        author = "ino"
        date = "April 2025"
    strings:
        $x1 = "DigiCertTrusted" ascii
        $x2 = "DigiCert Trusted" ascii
        $x3 = "DigiCertAssured" ascii
        $x4 = "AppPolicyGetProcessTerminationMethod" fullword ascii
        $x5 = "level='asInvoker'" ascii
    condition:
        2 of them
}

private rule file_532BC078A68683CE70CB765191A128FADEE2A23180B1A8E8A16B72F1A8EE291A {
    meta:
        description = "file 532BC078A68683CE70CB765191A128FADEE2A23180B1A8E8A16B72F1A8EE291A"
        author = "ino"
        date = "April 2025"
    strings:
        $x1 = "C:\\Windows\\System32\\cmd.exe" fullword ascii
        $x2 = "C:\\Users\\" fullword ascii
    condition:
        any of them
}

rule New_YaraRules_Vidar {
    meta:
        description = "new yara rules for Vidar family malware"
        author = "ino"
        date = "April 2025"
    strings:
        // Suspicious string = p* or Similar string = l*
        $p1 = "SQLDEPENDENCY" fullword ascii
        $p2 = "SQLCOMMAND" fullword ascii
        $p3 = "ENCRYPTIONKEY" ascii
        $p4 = "HOTCOMMAND" ascii
        $p5 = "SMIEVENTSINK" ascii
        $p6 = "WEBBROWSERENCRYPTION" ascii
        $p8 = "SQLCLIENTENCRYPTION" ascii
        $p9 = "NAMEHASHKEY" ascii
        $p11 = "kernelsoft.exe" fullword wide
        $p12 = "ExecuteSqlAndSetPassword" fullword ascii
        $p13 = "GetCommonLogger" fullword ascii
        $p14 = "get_LoggerActions" fullword ascii
        $p15 = "remoteClient" fullword ascii
        $p16 = "DigiCert Timestamp" ascii
        $p17 = "C:\\xampp\\htdocs\\Cryptor\\cc140f66929a41b198964842fc3a5bc0\\Loader\\qw\\Engine" fullword wide
        $p18 = "del C:\\ProgramData\\*.dll" fullword ascii
        $p19 = "pespy.dll" fullword wide
        $p20 = "Cookies\\%s_%s.txt" fullword ascii
        $p21 = "passwords.txt" fullword wide
        $p22 = "SELECT host, isHttpOnly, path, isSecure, expiry, name, value FROM moz_cookies" fullword ascii
        $p23 = "cookies.sqlite" fullword ascii
        $p24 = "\\Downloads\\%s_%s.txt" fullword ascii
        $p25 = "\\Autofill\\%s_%s.txt" fullword ascii
        $p26 = "\\History\\%s_%s.txt" fullword ascii
        $p27 = "Select * From Win32_OperatingSystem" fullword wide
        $p28 = "KoiVM.Runtime" fullword ascii // plugin for the ConfuserEx obfuscation tool
        $p29 = "DigiCert SHA2 Assured ID Code Signing CA" fullword ascii // manipulate certificate authority
        $p30 = "api-ms-win-appmodel-runtime-l1-1-2" fullword wide
        $p31 = "ADVAPI32" nocase ascii wide

        // Matched String
        $l1 = " KoiVM [{0}]" fullword wide
        $l2 = "SkipVerification" wide
        $l3 = "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\TaskKill" fullword wide
        $l4 = "AVbad_alloc" ascii
        // Yara Rules publik
        $l5 = "Disposition" ascii nocase
        $l6 = "wallet" ascii
        // Command
        $l7 = "KERNEL32.dll" nocase ascii wide
        $l8 = "ShellExecute" ascii

    condition:
        uint16(0) == 0x5a4d
        and ((3 of ($p*)) and (2 of ($l*)))
        and 1 of (
            CAPE_Vidar,
            elastic_Vidar_32fea8da,
            elastic_Vidar_114258d5,
            file_0c857501e3851072db666386136929c06bcf4c8d3160b41b7d82a3ce9afca1be,
            file_49a7f82743a038d7a570d5d5d8ecb92f369f0e6dbba6532674c4789f0daf9b31,
            file_532BC078A68683CE70CB765191A128FADEE2A23180B1A8E8A16B72F1A8EE291A
        )
        and filesize < 5000KB
}