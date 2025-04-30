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
        
        $l1 = "000004b0" wide
        $l2 = "_CorExeMain" ascii
        $l3 = "#GUID" ascii
        $l4 = "#Blob" ascii
        $l5 = "<Module>" ascii
        $l6 = "RuntimeCompatibilityAttribute" ascii
        $l7 = "WrapNonExceptionThrows" ascii
        $l8 = "WinForms_SeeInnerException" wide
        $l9 = "WinForms_RecursiveFormCreate" wide
        $l10 = "Property can only be set to Nothing" wide
        $l11 = "Label" wide

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