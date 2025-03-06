import "pe"

private rule new_yara_agent_tesla {
    meta:
        description = "file 14a388b154b55a25c66b1bfef9499b64"
        author = "ino"
        date = "March 2025"
    strings:
        // Agent Tesla secara umum dibuat dengan C#, ditandai dengan string:
        $dotnet1 = "mscoree.dll" ascii
        $dotnet2 = "mscorlib" ascii
        $dotnet3 = "#Strings" ascii
        $dotnet4 = { 5F 43 6F 72 [3] 4D 61 69 6E }

        // File 14a388b154b55a25c66b1bfef9499b64
        $x1 = "@@DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD" ascii
        $x2 = "CancellationTokenRegistrati.exe" fullword wide // Typo
        $x3 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.R" ascii
        $x4 = "PRIVATEMAP" fullword ascii
        $x5 = "PUBLICMAP" fullword ascii

        // File 5b14a7366cf5dbea3386c6afbd25f012
        $x6 = "4System.Web.Services.Protocols.SoapHttpClientProtocol" fullword ascii
        $x7 = "VitualMode" fullword ascii
        $x8 = "get_PasswordDialog" fullword ascii
        $x9 = "IEnumSTORECATEGO.exe" fullword wide
        $x10 = "Send_Remote_AT_Command" fullword ascii

        // File 6802c9c481671ec10ee1178946a46c73
        $x11 = "SmtpAccountConfiguration" ascii fullword
        $x12 = "set_BindingAccountConfiguration" ascii fullword
        $x13 = "MailAccountConfiguration" ascii fullword
        $x14 = "get_securityProfile" ascii fullword
        $x15 = "get_useSeparateFolderTree" ascii fullword
        $x16 = "get_DnsResolver" ascii fullword
        $x17 = "get_archivingScope" ascii fullword
        $x18 = "get_providerName" ascii fullword
        $x19 = "get_GuidMasterKey" ascii fullword


        // Suspicious string
        $s1 = "4System.Web.Services.Protocols.SoapHttpClientProtocol" fullword ascii // SOAP (Simple Object Access Protocol)
        $s2 = { (63|43) 6F 6D 70 75 74 65 72 (4E|6E) 61 6D 65 } // C|computerN|name
        $s3 = "Hashtable" fullword ascii // PEStudio Blacklist string
        $s4 = "GetResourceString" fullword ascii // PEStudio Blacklist string
        $s5 = "https://github.com" wide
        $s6 = "Operating system" wide
        $s7 = "CompareString" fullword ascii 
        $s8 = "GetProcesses" fullword ascii 
        $s9 = "Rijndael" fullword ascii 
        $s10 = "TripleDESCryptoServiceProvider" fullword ascii /* PEStudio Blacklist: strings */
        $s11 = "GetProcessesByName" fullword ascii /* PEStudio Blacklist: strings */
        $s12 = "PaddingMode" fullword ascii /* PEStudio Blacklist: strings */
        $s13 = "MD5CryptoServiceProvider" fullword ascii /* PEStudio Blacklist: strings */
        $s14 = "System.IO.Compression" fullword ascii /* PEStudio Blacklist: strings */
        $s15 = "CipherMode" fullword ascii /* PEStudio Blacklist: strings */
        $s16 = "DownloadFile" fullword ascii /* PEStudio Blacklist: strings */
        $s17 = "CreateDecryptor" fullword ascii /* PEStudio Blacklist: strings */
        $s18 = "Microsoft.VisualBasic" fullword ascii /* PEStudio Blacklist: strings */
        $s19 = "Listen" fullword ascii /* PEStudio Blacklist: strings */
        $s20 = "GetResponse" fullword ascii /* PEStudio Blacklist: strings */
        $s21 = "System.Net.Sockets" fullword ascii /* PEStudio Blacklist: strings */
        $s22 = "CreateObject" fullword ascii /* PEStudio Blacklist: strings */
        $s23 = "CurrentUser" fullword ascii /* PEStudio Blacklist: strings */
        $s24 = "Random" fullword ascii /* PEStudio Blacklist: strings */
        $s25 = "ComputeHash" fullword ascii /* PEStudio Blacklist: strings */
        $s26 = "System.Security.Cryptography" fullword ascii /* PEStudio Blacklist: strings */
        $s27 = "Reverse" fullword ascii /* PEStudio Blacklist: strings */
        $s28 = "LocalMachine" fullword ascii /* PEStudio Blacklist: strings */
        $s29 = "System.Security.Principal" fullword ascii /* PEStudio Blacklist: strings */
        $s30 = "MemoryStream" fullword ascii /* PEStudio Blacklist: strings */
        $s31 = "Connect" fullword ascii /* PEStudio Blacklist: strings */
        $s32 = "Console" fullword ascii /* PEStudio Blacklist: strings */
        $s33 = "EndInvoke" fullword ascii /* PEStudio Blacklist: strings */
        $s34 = "BeginInvoke" fullword ascii /* PEStudio Blacklist: strings */
        
    condition:
        uint16(0) == 0x5a4d and
        2 of ($dotnet*) and 1 of ($x*)
        and 3 of ($s*) 
}