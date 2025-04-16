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
        $x1 = "@@DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD" ascii
        $x2 = "CancellationTokenRegistrati.exe" fullword wide // Typo
        $x3 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.R" ascii
        $x4 = "PRIVATEMAP" fullword ascii
        $x5 = "PUBLICMAP" fullword ascii
    condition:
        2 of them
}

private rule file_5b14a7366cf5dbea3386c6afbd25f012 {
    meta:
        description = "file 5b14a7366cf5dbea3386c6afbd25f012"
        author = "ino"
        date = "March 2025"
    strings:
        $x1 = "VitualMode" fullword ascii
        $x2 = "get_PasswordDialog" fullword ascii
        $x3 = "IEnumSTORECATEGO.exe" fullword wide
        $x4 = "Send_Remote_AT_Command" fullword ascii
        $x5 = "get_LabelPassword" fullword ascii
    condition:
        2 of them
}

private rule file_6802c9c481671ec10ee1178946a46c73 {
    meta:
        description = "file 6802c9c481671ec10ee1178946a46c73"
        author = "ino"
        date = "March 2025"
    strings:
        $x1 = "SmtpAccountConfiguration" ascii fullword
        $x2 = "set_BindingAccountConfiguration" ascii fullword
        $x3 = "MailAccountConfiguration" ascii fullword
        $x4 = "get_securityProfile" ascii fullword
        $x5 = "get_useSeparateFolderTree" ascii fullword
        $x6 = "get_DnsResolver" ascii fullword
        $x7 = "get_archivingScope" ascii fullword
        $x8 = "get_providerName" ascii fullword
        $x9 = "get_GuidMasterKey" ascii fullword
    condition:
        2 of them
}

private rule file_94491241e60bd744ff41c9f33cd39b02ee968cfce120720be9e8a849b8e39c0e {
    meta:
        description = "file 94491241e60bd744ff41c9f33cd39b02ee968cfce120720be9e8a849b8e39c0e"
        author = "ino"
        date = "March 2025"
    strings:
        $x1 = "MozillaBrowserList"
        $x2 = "EnableScreenLogger"
        $x3 = "VaultGetItem_WIN7"
        $x4 = "PublicIpAddressGrab"
        $x5 = "EnableTorPanel"
        $x6 = "get_GuidMasterKey"
        $x7 = "JDownloader 2.0\\cfg" fullword wide

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

        // Suspicious string = *s* or PEStudio Blacklist: strings = *p* or Similar string = *l*
        $p1 = "Hashtable" fullword ascii
        $p2 = "GetResourceString" fullword ascii
        $p3 = "CompareString" fullword ascii 
        $p4 = "GetProcesses" fullword ascii 
        $p5 = "Rijndael" fullword ascii 
        $p6 = "TripleDESCryptoServiceProvider" fullword ascii
        $p7 = "GetProcessesByName" fullword ascii
        $p8 = "PaddingMode" fullword ascii
        $p9 = "MD5CryptoServiceProvider" fullword ascii
        $p10 = "System.IO.Compression" fullword ascii
        $p11 = "CipherMode" fullword ascii
        $p12 = "DownloadFile" fullword ascii
        $p13 = "CreateDecryptor" fullword ascii
        $p14 = "Microsoft.VisualBasic" fullword ascii
        $p15 = "Listen" fullword ascii
        $p16 = "GetResponse" fullword ascii
        $p17 = "System.Net.Sockets" fullword ascii
        $p18 = "CreateObject" fullword ascii
        $p19 = "CurrentUser" fullword ascii
        $p20 = "Random" fullword ascii
        $p21 = "ComputeHash" fullword ascii
        $p22 = "System.Security.Cryptography" fullword ascii
        $p23 = "Reverse" fullword ascii
        $p24 = "LocalMachine" fullword ascii
        $p25 = "System.Security.Principal" fullword ascii
        $p26 = "MemoryStream" fullword ascii
        $p27 = "Connect" fullword ascii
        $p28 = "Console" fullword ascii
        $p29 = "EndInvoke" fullword ascii
        $p30 = "BeginInvoke" fullword ascii
        $p31 = "SMTP Password" fullword wide
        $p32 = "IMAP Password" fullword wide
        $p33 = "POP3 Password" fullword wide
        $p34 = "SmtpPassword" fullword wide
        $p35 = "Connected" fullword wide
        $p36 = "connecting" nocase ascii wide
        $p37 = "disconnect" nocase ascii wide

        $s1 = "4System.Web.Services.Protocols.SoapHttpClientProtocol" fullword ascii // SOAP (Simple Object Access Protocol)
        $s2 = { (63|43) 6F 6D 70 75 74 65 72 (4E|6E) 61 6D 65 } // C|computerN|name
        $s3 = "https://github.com" wide
        $s4 = "Operating system" wide
        
        $l1 = "ToString" ascii
        $l2 = "get_Length" ascii
        $l3 = "set_Enabled" ascii
        $l4 = "set_Name" ascii
        $l5 = "MoveNext" ascii
        $l6 = "GetType" ascii
        $l7 = "Collections" ascii
        $l8 = "get_Application" ascii
        $l9 = "get_Chars" ascii
        $l10 = "ContainsKey" ascii
        $l11 = "IDisposable" ascii

    condition:
        uint16(0) == 0x5a4d 
        and (2 of ($dotnet*)) 
        and ((5 of ($p*)) or (2 of ($s*)))
        and all of ($l*)
        and 1 of (
            AgentTeslaV3,
            file_14a388b154b55a25c66b1bfef9499b64,
            file_5b14a7366cf5dbea3386c6afbd25f012,
            file_6802c9c481671ec10ee1178946a46c73,
            file_94491241e60bd744ff41c9f33cd39b02ee968cfce120720be9e8a849b8e39c0e
        )
        and filesize < 5000KB
}