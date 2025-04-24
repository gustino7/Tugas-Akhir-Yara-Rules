rule CAPE_agent_tesla
{
    meta:
        description = "Detecting HTML strings used by Agent Tesla malware"
        author = "Stormshield"
        version = "1.0"

    strings:
        $html_username    = "<br>UserName&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;: " wide ascii
        $html_pc_name     = "<br>PC&nbsp;Name&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;: " wide ascii
        $html_os_name     = "<br>OS&nbsp;Full&nbsp;Name&nbsp;&nbsp;: " wide ascii
        $html_os_platform = "<br>OS&nbsp;Platform&nbsp;&nbsp;&nbsp;: " wide ascii
        $html_clipboard   = "<br><span style=font-style:normal;text-decoration:none;text-transform:none;color:#FF0000;><strong>[clipboard]</strong></span>" wide ascii

    condition:
        3 of them
}

rule CAPE_AgentTesla
{
    meta:
        author = "kevoreilly"
        description = "AgentTesla Payload"
        cape_type = "AgentTesla Payload"
    strings:
        $string1 = "smtp" wide
        $string2 = "appdata" wide
        $string3 = "76487-337-8429955-22614" wide
        $string4 = "yyyy-MM-dd HH:mm:ss" wide
        //$string5 = "%site_username%" wide
        $string6 = "webpanel" wide
        $string7 = "<br>UserName&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;:" wide
        $string8 = "<br>IP Address&nbsp;&nbsp;:" wide

        $agt1 = "IELibrary.dll" ascii
        $agt2 = "C:\\Users\\Admin\\Desktop\\IELibrary\\IELibrary\\obj\\Debug\\IELibrary.pdb" ascii
        $agt3 = "GetSavedPasswords" ascii
        $agt4 = "GetSavedCookies" ascii
    condition:
        uint16(0) == 0x5A4D and (all of ($string*) or 3 of ($agt*))
}

rule CAPE_AgentTeslaV2 {
    meta:
        author = "ditekshen"
        description = "AgenetTesla Type 2 Keylogger payload"
        cape_type = "AgentTesla Payload"
    strings:
        $s1 = "get_kbHook" ascii
        $s2 = "GetPrivateProfileString" ascii
        $s3 = "get_OSFullName" ascii
        $s4 = "get_PasswordHash" ascii
        $s5 = "remove_Key" ascii
        $s6 = "FtpWebRequest" ascii
        $s7 = "logins" fullword wide
        $s8 = "keylog" fullword wide
        $s9 = "1.85 (Hash, version 2, native byte-order)" wide

        $cl1 = "Postbox" fullword ascii
        $cl2 = "BlackHawk" fullword ascii
        $cl3 = "WaterFox" fullword ascii
        $cl4 = "CyberFox" fullword ascii
        $cl5 = "IceDragon" fullword ascii
        $cl6 = "Thunderbird" fullword ascii
    condition:
        (uint16(0) == 0x5a4d and 6 of ($s*)) or (6 of ($s*) and 2 of ($cl*))
}

rule CAPE_AgentTeslaV3 {
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
        (uint16(0) == 0x5a4d and (8 of ($s*) or (6 of ($s*) and 4 of ($g*)))) or (2 of ($m*))
}

rule CAPE_AgentTeslaXor
{
    meta:
        author = "kevoreilly"
        description = "AgentTesla xor-based config decoding"
        cape_type = "AgentTesla Payload"
    strings:
        $decode = {06 91 06 61 20 [4] 61 D2 9C 06 17 58 0A 06 7E [4] 8E 69 FE 04 2D ?? 2A}
    condition:
        uint16(0) == 0x5A4D and any of them
}

rule CAPE_AgentTeslaV4
{
    meta:
        author = "kevoreilly"
        description = "AgentTesla Payload"
        cape_type = "AgentTesla Payload"
        packed = "7f8a95173e17256698324886bb138b7936b9e8c5b9ab8fffbfe01080f02f286c"
    strings:
        $decode1 = {(07|FE 0C 01 00) (07|FE 0C 01 00) 8E 69 (17|20 01 00 00 00) 63 8F ?? 00 00 01 25 47 (06|FE 0C 00 00) (1A|20 04 00 00 00) 58 4A D2 61 D2 52}
        $decode2 = {(07|FE 0C 01 00) (08|FE 0C 02 00) 8F ?? 00 00 01 25 47 (07|FE 0C 01 00) (11 07|FE 0C 07 00) 91 (06|FE 0C 00 00) (1A|20 04 00 00 00) 58 4A 61 D2 61 D2 52}
        $decode3 = {(07|FE 0C 01 00) (11 07|FE 0C 07 00) 8F ?? 00 00 01 25 47 (07|FE 0C 01 00) (08|FE 0C 02 00) 91 61 D2 52}
    condition:
        uint16(0) == 0x5A4D and all of them
}

rule CAPE_AgentTeslaV4JIT
{
    meta:
        author = "kevoreilly"
        description = "AgentTesla JIT-compiled native code"
        cape_type = "AgentTesla Payload"
        packed = "7f8a95173e17256698324886bb138b7936b9e8c5b9ab8fffbfe01080f02f286c"
    strings:
        $decode1 = {8B 01 8B 40 3C FF 50 10 8B C8 E8 [4] 89 45 CC B8 1A 00 00 00}
        $decode2 = {83 F8 18 75 2? 8B [2-5] D1 F8}
        $decode3 = {8D 4C 0? 08 0F B6 01 [0-3] 0F B6 5? 04 33 C2 88 01 B8 19 00 00 00}
    condition:
        2 of them
}

rule CAPE_AgentTeslaV5 {
    meta:
      author = "ClaudioWayne"
      description = "AgentTeslaV5 infostealer payload"
      cape_type = "AgentTesla payload"
      sample = "893f4dc8f8a1dcee05a0840988cf90bc93c1cda5b414f35a6adb5e9f40678ce9"
    strings:
        $template1 = "<br>User Name: " fullword wide
        $template2 = "<br>Username: " fullword wide
        $template3 = "<br>RAM: " fullword wide
        $template4 = "<br>Password: " fullword wide
        $template5 = "<br>OSFullName: " fullword wide
        $template6 = "<br><hr>Copied Text: <br>" fullword wide
        $template7 = "<br>CPU: " fullword wide
        $template8 = "<br>Computer Name: " fullword wide
        $template9 = "<br>Application: " fullword wide

        $chromium_browser1 = "Comodo\\Dragon\\User Data" fullword wide
        $chromium_browser2 = "Fenrir Inc\\Sleipnir5\\setting\\modules\\ChromiumViewer" fullword wide
        $chromium_browser3 = "Google\\Chrome\\User Data" fullword wide
        $chromium_browser4 = "Elements Browser\\User Data" fullword wide
        $chromium_browser5 = "Yandex\\YandexBrowser\\User Data" fullword wide
        $chromium_browser6 = "MapleStudio\\ChromePlus\\User Data" fullword wide

        $mozilla_browser1 = "\\Mozilla\\SeaMonkey\\" fullword wide
        $mozilla_browser2 = "\\K-Meleon\\" fullword wide
        $mozilla_browser3 = "\\NETGATE Technologies\\BlackHawk\\" fullword wide
        $mozilla_browser4 = "\\Thunderbird\\" fullword wide
        $mozilla_browser5 = "\\8pecxstudios\\Cyberfox\\" fullword wide
        $mozilla_browser6 = "360Chrome\\Chrome\\User Data" fullword wide
        $mozilla_browser7 = "\\Mozilla\\Firefox\\" fullword wide

        $database1 = "Berkelet DB" fullword wide
        $database2 = " 1.85 (Hash, version 2, native byte-order)" fullword wide
        $database3 = "00061561" fullword wide
        $database4 = "key4.db" fullword wide
        $database5 = "key3.db" fullword wide
        $database6 = "global-salt" fullword wide
        $database7 = "password-check" fullword wide

        $software1 = "\\FileZilla\\recentservers.xml" fullword wide
        $software2 = "\\VirtualStore\\Program Files (x86)\\FTP Commander\\Ftplist.txt" fullword wide
        $software3 = "\\The Bat!" fullword wide
        $software4 = "\\Apple Computer\\Preferences\\keychain.plist" fullword wide
        $software5 = "\\MySQL\\Workbench\\workbench_user_data.dat" fullword wide
        $software6 = "\\Trillian\\users\\global\\accounts.dat" fullword wide
        $software7 = "SOFTWARE\\Martin Prikryl\\WinSCP 2\\Sessions" fullword wide
        $software8 = "FTP Navigator\\Ftplist.txt" fullword wide
        $software9 = "NordVPN" fullword wide
        $software10 = "JDownloader 2.0\\cfg" fullword wide
    condition:
        uint16(0) == 0x5a4d and 4 of ($template*) and 3 of ($chromium_browser*) and 3 of ($mozilla_browser*) and 3 of ($database*) and 5 of ($software*)
}

rule Elastic_Windows_Trojan_AgentTesla_d3ac2b2f {
    meta:
        author = "Elastic Security"
        id = "d3ac2b2f-14fc-4851-8a57-41032e386aeb"
        fingerprint = "cbbb56fe6cd7277ae9595a10e05e2ce535a4e6bf205810be0bbce3a883b6f8bc"
        creation_date = "2021-03-22"
        last_modified = "2022-06-20"
        threat_name = "Windows.Trojan.AgentTesla"
        reference = "https://www.elastic.co/security-labs/attack-chain-leads-to-xworm-and-agenttesla"
        reference_sample = "65463161760af7ab85f5c475a0f7b1581234a1e714a2c5a555783bdd203f85f4"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "GetMozillaFromLogins" ascii fullword
        $a2 = "AccountConfiguration+username" wide fullword
        $a3 = "MailAccountConfiguration" ascii fullword
        $a4 = "KillTorProcess" ascii fullword
        $a5 = "SmtpAccountConfiguration" ascii fullword
        $a6 = "GetMozillaFromSQLite" ascii fullword
        $a7 = "Proxy-Agent: HToS5x" wide fullword
        $a8 = "set_BindingAccountConfiguration" ascii fullword
        $a9 = "doUsernamePasswordAuth" ascii fullword
        $a10 = "SafariDecryptor" ascii fullword
        $a11 = "get_securityProfile" ascii fullword
        $a12 = "get_useSeparateFolderTree" ascii fullword
        $a13 = "get_DnsResolver" ascii fullword
        $a14 = "get_archivingScope" ascii fullword
        $a15 = "get_providerName" ascii fullword
        $a16 = "get_ClipboardHook" ascii fullword
        $a17 = "get_priority" ascii fullword
        $a18 = "get_advancedParameters" ascii fullword
        $a19 = "get_disabledByRestriction" ascii fullword
        $a20 = "get_LastAccessed" ascii fullword
        $a21 = "get_avatarType" ascii fullword
        $a22 = "get_signaturePresets" ascii fullword
        $a23 = "get_enableLog" ascii fullword
        $a24 = "TelegramLog" ascii fullword
        $a25 = "generateKeyV75" ascii fullword
        $a26 = "set_accountName" ascii fullword
        $a27 = "set_InternalServerPort" ascii fullword
        $a28 = "set_bindingConfigurationUID" ascii fullword
        $a29 = "set_IdnAddress" ascii fullword
        $a30 = "set_GuidMasterKey" ascii fullword
        $a31 = "set_username" ascii fullword
        $a32 = "set_version" ascii fullword
        $a33 = "get_Clipboard" ascii fullword
        $a34 = "get_Keyboard" ascii fullword
        $a35 = "get_ShiftKeyDown" ascii fullword
        $a36 = "get_AltKeyDown" ascii fullword
        $a37 = "get_Password" ascii fullword
        $a38 = "get_PasswordHash" ascii fullword
        $a39 = "get_DefaultCredentials" ascii fullword
    condition:
        8 of ($a*)
}

rule Elastic_Windows_Trojan_AgentTesla_e577e17e {
    meta:
        author = "Elastic Security"
        id = "e577e17e-5c42-4431-8c2d-0c1153128226"
        fingerprint = "009cb27295a1aa0dde84d29ee49b8fa2e7a6cec75eccb7534fec3f5c89395a9d"
        creation_date = "2022-03-11"
        last_modified = "2022-04-12"
        threat_name = "Windows.Trojan.AgentTesla"
        reference = "https://www.elastic.co/security-labs/attack-chain-leads-to-xworm-and-agenttesla"
        reference_sample = "ed43ddb536e6c3f8513213cd6eb2e890b73e26d5543c0ba1deb2690b5c0385b6"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 20 4D 27 00 00 33 DB 19 0B 00 07 17 FE 01 2C 02 18 0B 00 07 }
    condition:
        all of them
}

rule Elastic_Windows_Trojan_AgentTesla_f2a90d14 {
    meta:
        author = "Elastic Security"
        id = "f2a90d14-7212-41a5-a2cd-a6a6dedce96e"
        fingerprint = "829c827069846ba1e1378aba8ee6cdc801631d769dc3dce15ccaacd4068a88a6"
        creation_date = "2022-03-11"
        last_modified = "2022-04-12"
        threat_name = "Windows.Trojan.AgentTesla"
        reference = "https://www.elastic.co/security-labs/attack-chain-leads-to-xworm-and-agenttesla"
        reference_sample = "ed43ddb536e6c3f8513213cd6eb2e890b73e26d5543c0ba1deb2690b5c0385b6"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 0B FE 01 2C 0B 07 16 7E 08 00 00 04 A2 1F 0C 0C 00 08 1F 09 FE 01 }
    condition:
        all of them
}

rule Elastic_Windows_Trojan_AgentTesla_a2d69e48 {
    meta:
        author = "Elastic Security"
        id = "a2d69e48-b114-4128-8c2f-6fabee49e152"
        fingerprint = "bd46dd911aadf8691516a77f3f4f040e6790f36647b5293050ecb8c25da31729"
        creation_date = "2023-05-01"
        last_modified = "2023-06-13"
        threat_name = "Windows.Trojan.AgentTesla"
        reference = "https://www.elastic.co/security-labs/attack-chain-leads-to-xworm-and-agenttesla"
        reference_sample = "edef51e59d10993155104d90fcd80175daa5ade63fec260e3272f17b237a6f44"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 00 03 08 08 10 08 10 18 09 00 04 08 18 08 10 08 10 18 0E 00 08 }
        $a2 = { 00 06 17 5F 16 FE 01 16 FE 01 2A 00 03 30 03 00 B1 00 00 00 }
    condition:
        all of them
}

rule Elastic_Windows_Trojan_AgentTesla_ebf431a8 {
    meta:
        author = "Elastic Security"
        id = "ebf431a8-45e8-416c-a355-4ac1db2d133a"
        fingerprint = "2d95dbe502421d862eee33ba819b41cb39cf77a44289f4de4a506cad22f3fddb"
        creation_date = "2023-12-01"
        last_modified = "2024-01-12"
        threat_name = "Windows.Trojan.AgentTesla"
        reference = "https://www.elastic.co/security-labs/attack-chain-leads-to-xworm-and-agenttesla"
        reference_sample = "0cb3051a80a0515ce715b71fdf64abebfb8c71b9814903cb9abcf16c0403f62b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "MozillaBrowserList"
        $a2 = "EnableScreenLogger"
        $a3 = "VaultGetItem_WIN7"
        $a4 = "PublicIpAddressGrab"
        $a5 = "EnableTorPanel"
        $a6 = "get_GuidMasterKey"
    condition:
        4 of them
}

rule InQuest_AgentTesla {
    meta:
        author = "InQuest Labs"
        source = "http://blog.inquest.net/blog/2018/05/22/field-notes-agent-tesla-open-directory/"
        created = "05/18/2018"
        TLP = "WHITE"
    strings:
        $s0 = "SecretId1" ascii
        $s1 = "#GUID" ascii
        $s2 = "#Strings" ascii
        $s3 = "#Blob" ascii
        $s4 = "get_URL" ascii
        $s5 = "set_URL" ascii
        $s6 = "DecryptIePassword" ascii
        $s8 = "GetURLHashString" ascii
        $s9 = "DoesURLMatchWithHash" ascii

        $f0 = "GetSavedPasswords" ascii
        $f1 = "IESecretHeader" ascii
        $f2 = "RecoveredBrowserAccount" ascii
        $f4 = "PasswordDerivedBytes" ascii
        $f5 = "get_ASCII" ascii
        $f6 = "get_ComputerName" ascii
        $f7 = "get_WebServices" ascii
        $f8 = "get_UserName" ascii
        $f9 = "get_OSFullName" ascii
        $f10 = "ComputerInfo" ascii
        $f11 = "set_Sendwebcam" ascii
        $f12 = "get_Clipboard" ascii
        $f13 = "get_TotalFreeSpace" ascii
        $f14 = "get_IsAttached" ascii

        $x0 = "IELibrary.dll" ascii wide
        $x1 = "webpanel" ascii wide nocase
        $x2 = "smtp" ascii wide nocase
        
        $v5 = "vmware" ascii wide nocase
        $v6 = "VirtualBox" ascii wide nocase
        $v7 = "vbox" ascii wide nocase
        $v9 = "avghookx.dll" ascii wide nocase

        $pdb = "IELibrary.pdb" ascii
    condition:
        (
            (
                5 of ($s*) or 
                7 of ($f*)
            ) and
            all of ($x*) and 
            all of ($v*) and
            $pdb
        )
}

rule jeFF0Falltrades_agent_tesla_2019 {
    meta:
        author = "jeFF0Falltrades"
        hash = "717f605727d21a930737e9f649d8cf5d12dbd1991531eaf68bb58990d3f57c05"

    strings:
        $appstr_1 = "Postbox" wide ascii nocase
        $appstr_2 = "Thunderbird" wide ascii nocase
        $appstr_3 = "SeaMonkey" wide ascii nocase
        $appstr_4 = "Flock" wide ascii nocase
        $appstr_5 = "BlackHawk" wide ascii nocase
        $appstr_6 = "CyberFox" wide ascii nocase
        $appstr_7 = "KMeleon" wide ascii nocase
        $appstr_8 = "IceCat" wide ascii nocase
        $appstr_9 = "PaleMoon" wide ascii nocase
        $appstr_10 = "IceDragon" wide ascii nocase
        // XOR sequence used in several decoding sequences in final payload
        $xor_seq = { FE 0C 0E 00 20 [4] 5A 20 [4] 61 } 

    condition:
        all of them and #xor_seq > 10
}

rule LastLine_Agent_Tesla {
     meta:
          author = "LastLine"
          reference = "https://www.lastline.com/labsblog/surge-of-agent-tesla-threat-report/"
     strings:
          $pass = "amp4Z0wpKzJ5Cg0GDT5sJD0sMw0IDAsaGQ1Afik6NwXr6rrSEQE=" fullword ascii wide nocase
          $salt = "aGQ1Afik6NampDT5sJEQE4Z0wpsMw0IDAD06rrSswXrKzJ5Cg0G=" fullword ascii wide nocase
 
     condition:
           uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and all of them
}

rule jattechhelplist_agenttesla_smtp_variant {

    meta:
        author = "J from THL <j@techhelplist.com> with thx to @Fumik0_ !!1!"
        date = "2018/2"
	reference1 = "https://www.virustotal.com/#/file/1198865bc928a7a4f7977aaa36af5a2b9d5a949328b89dd87c541758516ad417/detection"
	reference2 = "https://www.trendmicro.com/vinfo/us/threat-encyclopedia/malware/tspy_negasteal.a"
	reference3 = "Agent Tesla == negasteal -- @coldshell"
	version = 1
        maltype = "Stealer"
        filetype = "memory"

    strings:
		$a = "type={"
		$b = "hwid={"
		$c = "time={"
		$d = "pcname={"
		$e = "logdata={"
		$f = "screen={"
		$g = "ipadd={"
		$h = "webcam_link={"
		$i = "screen_link={"
		$j = "site_username={"
		$k = "[passwords]"

    condition:
        6 of them
}

rule Stormshield_Agenttesla
{
    meta:
        description = "Detecting HTML strings used by Agent Tesla malware"
        author = "Stormshield"
        reference = "https://thisissecurity.stormshield.com/2018/01/12/agent-tesla-campaign/"
        version = "1.0"

    strings:
        $html_username    = "<br>UserName&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;: " wide ascii
        $html_pc_name     = "<br>PC&nbsp;Name&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;: " wide ascii
        $html_os_name     = "<br>OS&nbsp;Full&nbsp;Name&nbsp;&nbsp;: " wide ascii
        $html_os_platform = "<br>OS&nbsp;Platform&nbsp;&nbsp;&nbsp;: " wide ascii
        $html_clipboard   = "<br><span style=font-style:normal;text-decoration:none;text-transform:none;color:#FF0000;><strong>[clipboard]</strong></span>" wide ascii

    condition:
        3 of them
}

private rule SUS_Exceptions_Jan24 {
    meta:
        description = "Detects unique exception strings from AgentTesla final payload in decompiled code and process memory"
        author = "Matt Green - @mgreen27"
        date = "2024-01-18"
        artifact = "Windows.Detection.Yara.Process"
        hash1 = "ebe2a77dab04458defd4d8f7760abda79a507ab0168d68a2930f9d7b1120127e"
        
    strings:
        $exception1 = "Unknow database format" wide fullword
        $exception2 = "Size of the SerializedPropertyStore is less than" wide
        $exception3 = "Version is not equal to " wide
        $exception4 = "Size of the StringName is less than 9" wide
        $exception5 = "Size of the StringName is not equal to " wide
        $exception6 = "Size of the NameSize is not equal to " wide

    condition:
        4 of ($exception*)
}

private rule SUS_Windows_Vault_Guids_Jan24 {
    meta:
        description = "Detects Windows Vault GUID strings observed in AgentTesla payload."
        author = "Matt Green - @mgreen27"
        date = "2024-01-18"
        artifact = "Windows.Detection.Yara.Process"
        hash1 = "ebe2a77dab04458defd4d8f7760abda79a507ab0168d68a2930f9d7b1120127e"
        
    strings:
        $s1 = "2F1A6504-0641-44CF-8BB5-3612D865F2E5" wide 	//Windows Secure Note
        $s2 = "3CCD5499-87A8-4B10-A215-608888DD3B55" wide 	//Windows Web Password Credential
        $s3 = "154E23D0-C644-4E6F-8CE6-5069272F999F" wide 	//Windows Credential Picker Protector
        $s4 = "4BF4C442-9B8A-41A0-B380-DD4A704DDB28" wide 	//Web Credentials
        $s5 = "77BC582B-F0A6-4E15-4E80-61736B6F3B29" wide 	//Windows Credentials
        $s6 = "E69D7838-91B5-4FC9-89D5-230D4D4CC2BC" wide 	//Windows Domain Certificate Credential
        $s7 = "3E0E35BE-1B77-43E7-B873-AED901B6275B" wide 	//Windows Domain Password Credential
        $s8 = "3C886FF3-2669-4AA2-A8FB-3F6759A77548" wide 	//Windows Extended Credential

    condition:
        all of them
}

private rule SUS_Browser_References_Jan24 {
    meta:
        description = "Detects unique strings observed in AgentTesla browser stealer module in decompiled code and process memory"
        author = "Matt Green - @mgreen27"
        date = "2024-01-18"
        artifact = "Windows.Detection.Yara.Process"
        hash1 = "ebe2a77dab04458defd4d8f7760abda79a507ab0168d68a2930f9d7b1120127e"
        
    strings:
        $browser01 = "7Star\\7Star\\User Data" wide
        $browser02 = "CocCoc\\Browser\\User Data" wide
        $browser03 = "Fenrir Inc\\Sleipnir5\\setting\\modules\\ChromiumViewer" wide
        $browser04 = "\\Thunderbird\\" wide
        $browser05 = "\\K-Meleon\\" wide
        $browser06 = "360Chrome\\Chrome\\User Data" wide
        $browser07 = "uCozMedia\\Uran\\User Data" wide
        $browser08 = "\\Mozilla\\SeaMonkey\\" wide
        $browser09 = "Orbitum\\User Data" wide
        $browser10 = "CentBrowser\\User Data" wide
        $browser11 = "Elements Browser\\User Data" wide
        $browser12 = "CatalinaGroup\\Citrio\\User Data" wide
        $browser13 = "Yandex\\YandexBrowser\\User Data" wide
        $browser14 = "liebao\\User Data" wide
        $browser15 = "Sputnik\\Sputnik\\User Data" wide
        $browser16 = "BraveSoftware\\Brave-Browser\\User Data" wide
        $browser17 = "Microsoft\\Edge\\User Data" wide
        $browser18 = "\\Comodo\\IceDragon\\" wide
        $browser19 = "\\Mozilla\\Firefox\\" wide
        $browser20 = "\\Waterfox\\" wide
        $browser21 = "Chromium\\User Data" wide
        $browser22 = "Iridium\\User Data" wide
        $browser23 = "Chedot\\User Data" wide
        $browser24 = "\\Mozilla\\icecat\\" wide
        $browser25 = "\\8pecxstudios\\Cyberfox\\" wide
        $browser26 = "\\Moonchild Productions\\Pale Moon\\" wide
        $browser27 = "\\Postbox\\" wide
        $browser28 = "Opera Browser" wide
        $browser29 = "Opera Software\\Opera Stable" wide
        $browser30 = "Amigo\\User Data" wide
        $browser31 = "\\Flock\\Browser\\" wide
        $browser32 = "MapleStudio\\ChromePlus\\User Data" wide
        $browser33 = "Comodo\\Dragon\\User Data" wide
        $browser34 = "Kometa\\User Data" wide
        $browser35 = "Coowon\\Coowon\\User Data" wide
        $browser36 = "\\NETGATE Technologies\\BlackHawk\\" wide
        $browser37 = "Google\\Chrome\\User Data" wide
        $browser38 = "Vivaldi\\User Data" wide
        $browser39 = "QIP Surf\\User Data" wide
        $browser40 = "Epic Privacy Browser\\User Data" wide
        $browser41 = "Torch\\User Data" wide

    condition:
        27 of ($browser*)
}

private rule SUS_Special_Key_References_Jan24 {
    meta:
        description = "Detects keyboard reference strings observed in AgentTesla in keyboard/clipboard hooking module."
        author = "Matt Green - @mgreen27"
        date = "2024-01-18"
        artifact = "Windows.Detection.Yara.Process"
        hash1 = "ebe2a77dab04458defd4d8f7760abda79a507ab0168d68a2930f9d7b1120127e"
        
    strings:
        $x1 = "_keyboardHook"
        $x2 = "_clipboardHook"
        $x3 = "EnableClipboardLogger"
        $x4 = "KeyloggerInterval"

        $key01 = "{Insert}" wide
        $key02 = "{HOME}" wide
        $key03 = "{PageDown}" wide
        $key04 = "{PageUp}" wide

        $key05 = "{ALT+F4}" wide
        $key06 = "{ALT+TAB}" wide
        
        $key07 = "{KEYDOWN}" wide
        $key08 = "{KEYUP}" wide
        $key00 = "{KEYLEFT}" wide
        $key10 = "{KEYRIGHT}" wide

        $key11 = "{CTRL}" wide
        $key12 = "{DEL}" wide
        $key13 = "{ENTER}" wide
        $key14 = "{TAB}" wide
        $key15 = "{Win}" wide
        $key16 = "{ESC}" wide

        $key17 = "{NumLock}" wide
        $key18 = "{CAPSLOCK}" wide
        $key19 = "{BACK}" wide
        $key20 = "{END}" wide

        $key21 = "{F1}" wide
        $key22 = "{F2}" wide
        $key23 = "{F3}" wide
        $key24 = "{F4}" wide
        $key25 = "{F5}" wide
        $key26 = "{F6}" wide
        $key27 = "{F7}" wide
        $key28 = "{F8}" wide
        $key29 = "{F9}" wide
        $key30 = "{F10}" wide
        $key31 = "{F11}" wide
        $key32 = "{F12}" wide

    condition:
        2 of ($x*) and 20 of ($key*)
}

private rule SUS_Application_References_Jan24 {
    meta:
        description = "Detects application reference strings observed in AgentTesla stealer payload."
        author = "Matt Green - @mgreen27"
        date = "2024-01-18"
        artifact = "Windows.Detection.Yara.Process"
        hash1 = "ebe2a77dab04458defd4d8f7760abda79a507ab0168d68a2930f9d7b1120127e"
        
    strings:
        $s01 = "\\Mailbird\\Store\\Store.db" wide
        $s02 = "Software\\Qualcomm\\Eudora\\CommandLine\\" wide
        $s03 = "\\.purple\\accounts.xml" wide //Pidgin
        $s04 = "\\Opera Mail\\Opera Mail\\wand.dat" wide
        $s05 = "UCBrowser\\" wide
        $s06 = "NordVPN" wide
        $s07 = "//setting[@name='Username']/value" wide // Nord
        $s08 = "\\FTPGetter\\servers.xml" wide
        $s09 = "\\FileZilla\\recentservers.xml" wide
        $s10 = "\\Program Files (x86)\\FTP Commander Deluxe\\Ftplist.txt" wide
        $s11 = "\\cftp\\Ftplist.txt" wide
        $s12 = "\\Program Files (x86)\\FTP Commander\\Ftplist.txt" wide
        $s13 = "Windows Mail App" wide
        $s14 = "COMPlus_legacyCorruptedStateExceptionsPolicy" wide
        $s15 = "Software\\Microsoft\\ActiveSync\\Partners" wide
        $s16 = "\\Pocomail\\accounts.ini" wide
        $s17 = "HKEY_CURRENT_USER\\Software\\Aerofox\\FoxmailPreview" wide	//Foxmail
        $s18 = "HKEY_CURRENT_USER\\Software\\Aerofox\\Foxmail\\V3.1" wide	//Foxmail
        $s19 = "\\Program Files\\Foxmail\\mail" wide	//Foxmail
        $s20 = "\\Program Files (x86)\\Foxmail\\mail" wide	//Foxmail
        $s21 = "\\Accounts\\Account.rec0" wide	//Foxmail
        $s22 = "\\Account.stg" wide	//Foxmail
        $s23 = /Software\\Microsoft\\Office\\\d{2}\.0\\Outlook\\Profiles/ wide 	//outlook
        $s24 = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows Messaging Subsystem\\Profiles" wide 	//outlook
        $s25 = "Software\\Microsoft\\Windows Messaging Subsystem\\Profiles\\9375CFF0413111d3B88A00104B2A6676" wide 	//outlook
        $s26 = "IMAP Password" wide 	//outlook
        $s27 = "POP3 Password" wide 	//outlook
        $s28 = "HTTP Password" wide 	//outlook
        $s29 = "SMTP Password" wide 	//outlook
        $s30 = "SOFTWARE\\Martin Prikryl\\WinSCP 2\\Sessions" wide
        $s31 = "Ipswitch\\WS_FTP\\Sites\\ws_ftp.ini" wide
        $s32 = "\\Common Files\\Apple\\Apple Application Support\\plutil.exe" wide
        $s33 = "\\Apple Computer\\Preferences\\keychain.plist" wide
        $s34 = " -convert xml1 -s -o \"" wide
        $s35 = "\\fixed_keychain.xml" wide
        $s36 = "\\Trillian\\users\\global\\accounts.dat" wide
        $s37 = "\\MySQL\\Workbench\\workbench_user_data.dat" wide
        $s38 = "Local Storage\\leveldb" wide 	//Discord
        $s39 = "discordcanary" wide
        $s40 = "discordptb" wide
        $s41 = "SmartFTP\\Client 2.0\\Favorites\\Quick Connect" wide
        $s42 = "\\FTP Navigator\\Ftplist.txt" wide
        $s43 = "\\Private Internet Access\\data" wide
        $s44 = "Software\\DownloadManager\\Passwords\\" wide
        $s45 = "Software\\IncrediMail\\Identities\\" wide
        $s46 = "Tencent\\QQBrowser\\User Data" wide
        $s47 = "\\Default\\EncryptedStorage" wide
        $s48 = "SOFTWARE\\FTPWare\\COREFTP\\Sites" wide
        $s49 = "\\Claws-mail" wide
        $s50 = "\\falkon\\profiles\\" wide
        $s51 = "SOFTWARE\\RealVNC\\WinVNC4" wide
        $s52 = "Software\\TightVNC\\Server" wide
        $s53 = "Software\\TigerVNC\\Server" wide
        $s54 = "Software\\TightVNC\\Server" wide
        $s55 = "SOFTWARE\\RealVNC\\vncserver" wide
        $s56 = "SOFTWARE\\Wow6432Node\\RealVNC\\WinVNC4" wide
        $s57 = "Software\\ORL\\WinVNC3" wide
        $s58 = "\\uvnc bvba\\UltraVNC\\ultravnc.ini" wide
        $s59 = "Dyn\\Updater\\config.dyndns" wide
        $s60 = "https://account.dyn.com/" wide fullword
        $s61 = "Dyn\\Updater\\daemon.cfg" wide
        $s62 = "Software\\A.V.M.\\Paltalk NG\\common_settings\\core\\users\\creds\\" wide
        $s63 = "\\Microsoft\\Credentials\\" wide
        $s64 = "\\Microsoft\\Protect\\" wide
        $s65 = "\\The Bat!" wide
        $s66 = "\\Account.CFN" wide
        $s67 = "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=" wide
        $s68 = "\\Psi+\\profiles" wide 
        $s69 = "Becky!" wide
        $s70 = "HKEY_CURRENT_USER\\Software\\RimArts\\B2\\Settings" wide
        $s71 = "\\Flock\\Browser\\" wide
        $s72 = "\\Default\\Login Data" wide 	//Opera
        $s73 = "JDownloader 2.0\\cfg" wide
        $s74 = "org.jdownloader.settings.AccountSettings.accounts.ejs" wide	//jdownloader
        $s75 = "jd.controlling.authentication.AuthenticationControllerSettings.list.ejs" wide	//jdownloader

    condition:
         40 of them
}


rule MattGreen_MAL_AgentTesla_Jan24 {
    meta:
        description = "Detects unique strings observed in AgentTesla payload in process memory using private rule references"
        author = "Matt Green - @mgreen27"
        date = "2024-01-18"
        artifact = "Windows.Detection.Yara.Process"
        hash1 = "ebe2a77dab04458defd4d8f7760abda79a507ab0168d68a2930f9d7b1120127e"
    strings:
        $dotnet1 = "mscoree.dll" ascii
        $dotnet2 = "mscorlib" ascii
        $dotnet3 = "#Strings" ascii
        $dotnet4 = { 5F 43 6F 72 [3] 4D 61 69 6E }

        $s01 = "https://api.ipify.org" wide fullword	// network
        $s02 = "https://api.telegram.org" wide	// network
        $s03 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:99.0) Gecko/20100101 Firefox/99.0" wide	// network
        $s04 = "multipart/form-data; boundary=" wide	// comms
        $s05 = "Content-Disposition: form-data; name=" wide // comms
        
        $s06 = "Berkelet DB" wide fullword // db access
        $s07 = " 1.85 (Hash, version 2, native byte-order)" wide fullword // Berkelet db access
        $s08 = "SQLite format 3" wide fullword // db access
        
        $s09 = ":Zone.Identifier" wide
        $s10 = "SELECT * FROM Win32_Processor" wide	// local discovery
        $s11 = "Win32_NetworkAdapterConfiguration" wide	// local discovery
        $s12 = "win32_processor" wide	// local discovery
        $s13 = "Win32_BaseBoard" wide	// local discovery

    condition:
        2 of ($dotnet*) and 5 of ($s*) and 
        3 of ( 
                SUS_Exceptions_Jan24, 
                SUS_Windows_Vault_Guids_Jan24, 
                SUS_Browser_References_Jan24, 
                SUS_Special_Key_References_Jan24,
                SUS_Application_References_Jan24
            )
}
