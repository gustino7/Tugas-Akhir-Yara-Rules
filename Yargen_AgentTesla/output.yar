/*
   YARA Rule Set
   Author: yarGen Rule Generator
   Date: 2025-02-26
   Identifier: Sample_Malware_AgentTesla
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

import "pe"

rule sig_14a388b154b55a25c66b1bfef9499b64 {
   meta:
      description = "Sample_Malware_AgentTesla - file 14a388b154b55a25c66b1bfef9499b64"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-02-26"
      hash1 = "cb414e417f8f3de9392dbc6a89421d1a8e95beabbbe387e11771567d63a7b227"
   strings:
      $x1 = "@@DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD" ascii
      $s2 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.R" ascii
      $s3 = "Alternatively, if you have a GitHub account, you may report this crash at https://github.com/jianmingyong/Pokemon-3D-Resource-Ma" wide
      $s4 = "CancellationTokenRegistrati.exe" fullword wide
      $s5 = "PUBLICMAP" fullword ascii /* base64 encoded string '=@K # ' */
      $s6 = "4System.Web.Services.Protocols.SoapHttpClientProtocol" fullword ascii
      $s7 = "EDDDDDDDDD" ascii /* reversed goodware string 'DDDDDDDDDE' */
      $s8 = "FDDDDDDDDD" ascii /* reversed goodware string 'DDDDDDDDDF' */
      $s9 = "GetEmptyTileCount" fullword ascii
      $s10 = "DDDG6ETDDDjIvGjDDDjNyDTDDDjIvGjDDDjNyDTDDDjIvGjDDDjNyDTDDDjIvGTDDDjIvGTDDDjIvGTDDDjIvGTDDDjIvGTDDDDKJGjDDDjIZETDDDDPGETDDDjHPDTD" ascii
      $s11 = "GetEmptyCoastalTileCount" fullword ascii
      $s12 = "Go to: http://pokemon3d.net/forum/threads/8234/ to report this crash there." fullword wide
      $s13 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/>" fullword ascii
      $s14 = "get_btnTurnAction_Spy" fullword ascii
      $s15 = "get_minesweeper" fullword ascii
      $s16 = "minesweeper" fullword wide
      $s17 = "qvqDNDDDT.pDJDDD3llDHDDDYvqDDDDDEDSRDDDDDLLRDDDDEDlIpLzNUDDDfDDDF\\DDMD}HDDjND\\DDDvMNZXDEGLDDZ\\lDu\\nNDrDDD;7edqkFDDTmrPzGdqkF" ascii
      $s18 = "WrDDDz<f[rDDD3GNDDDDRGFDDDDjjH|KNDDD<jFDDDz8jDDDD;ML};kEDHz7rLjEWrDDDH;f2DLDDLlEDHD8rDDDDvNLz<kLiDDDJfJRDDDDZDFDDXTo8jTHLPUD.ekE" ascii
      $s19 = "kEYeoU6f8QY]}YID7<p\\3kKgDjJgno5YiU[]}EDZVsIU7wXfzsJQk<JUL][WE<5gDPqet]IRVoWfs{HPFUnW{gIfTIJDTgpe6Lpg7YIU|][XHYpVHU6YXEDd3IJXv{Z" ascii
      $s20 = "nM6e6Q6fkEYeoU6f8QY]}Y4[3Y5fDL[\\rQH]|<5g}Q[\\T4Z]3Q[hWY5fY<IgogJDnY5]xIJdGUKhoU4[o]6ewYpfDTZ]q8Z\\rQHg7YJYiUJ]kEjfo{J]xIJV38Z]5" ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      1 of ($x*) and 4 of them
}

rule sig_94491241e60bd744ff41c9f33cd39b02ee968cfce120720be9e8a849b8e39c0e {
   meta:
      description = "Sample_Malware_AgentTesla - file 94491241e60bd744ff41c9f33cd39b02ee968cfce120720be9e8a849b8e39c0e"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-02-26"
      hash1 = "94491241e60bd744ff41c9f33cd39b02ee968cfce120720be9e8a849b8e39c0e"
   strings:
      $s1 = "org.jdownloader.settings.AccountSettings.accounts.ejs" fullword wide
      $s2 = "\\Trillian\\users\\global\\accounts.dat" fullword wide
      $s3 = "Software\\A.V.M.\\Paltalk NG\\common_settings\\core\\users\\creds\\" fullword wide
      // $s4 = "\\\"(hostname|encryptedPassword|encryptedUsername)\":\"(.*?)\"" fullword wide
      // $s5 = "SystemProcessorPerformanceInformation" fullword ascii
      // $s6 = "SmtpPassword" fullword wide
      // $s7 = "gnxLZ.exe" fullword wide
      // $s8 = "\\VirtualStore\\Program Files (x86)\\FTP Commander Deluxe\\Ftplist.txt" fullword wide
      $s9 = "\\Program Files (x86)\\FTP Commander Deluxe\\Ftplist.txt" fullword wide
      $s10 = "\\Program Files (x86)\\FTP Commander\\Ftplist.txt" fullword wide
      // $s11 = "\\VirtualStore\\Program Files (x86)\\FTP Commander\\Ftplist.txt" fullword wide
      $s12 = "SMTP Password" fullword wide
      // $s13 = "privateinternetaccess.com" fullword wide
      // $s14 = "paltalk.com" fullword wide
      // $s15 = "discord.com" fullword wide
      $s16 = "https://account.dyn.com/" fullword wide
      $s17 = "JDownloader 2.0" fullword wide // sama seperti s18
      $s18 = "JDownloader 2.0\\cfg" fullword wide
      // $s19 = "Internet Downloader Manager" fullword wide
      // $s20 = "PageExecuteReadWrite" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 700KB and
      8 of them
}

rule cff5f0bb2c9dc0d52591745ea43e9c7cd8dc46ea14c5a9996c72f76e7cdf7011 {
   meta:
      description = "Sample_Malware_AgentTesla - file cff5f0bb2c9dc0d52591745ea43e9c7cd8dc46ea14c5a9996c72f76e7cdf7011"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-02-26"
      hash1 = "cff5f0bb2c9dc0d52591745ea43e9c7cd8dc46ea14c5a9996c72f76e7cdf7011"
   strings:
      $s1 = "System.Security.Permissions.SecurityPermissionAttribute, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934" ascii
      $s2 = "PvG.exe" fullword wide
      $s3 = "get_TempDodgeBoost" fullword ascii
      $s4 = "get_TempBoost" fullword ascii
      $s5 = "get_TempCritBoost" fullword ascii
      $s6 = "get_TempInitBoost" fullword ascii
      $s7 = "get_TempDefenseBoost" fullword ascii
      $s8 = "get_TempAttackBoost" fullword ascii
      $s9 = "TempCritBoost" fullword ascii
      $s10 = "TempAttackBoost" fullword ascii
      $s11 = "set_TempBoost" fullword ascii
      $s12 = "TempBoost" fullword ascii
      $s13 = "set_TempAttackBoost" fullword ascii
      $s14 = "set_TempCritBoost" fullword ascii
      $s15 = "TempDodgeBoost" fullword ascii
      $s16 = "<TempDefenseBoost>k__BackingField" fullword ascii
      $s17 = "set_TempInitBoost" fullword ascii
      $s18 = "<TempDodgeBoost>k__BackingField" fullword ascii
      $s19 = "<TempCritBoost>k__BackingField" fullword ascii
      $s20 = "<TempAttackBoost>k__BackingField" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      8 of them
}

rule sig_5b14a7366cf5dbea3386c6afbd25f012 {
   meta:
      description = "Sample_Malware_AgentTesla - file 5b14a7366cf5dbea3386c6afbd25f012"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-02-26"
      hash1 = "f6ef92f6911bb14f5b8905f3964d21a9569c41c4e5367d0ee8aec59d54eb7024"
   strings:
      $s1 = "4System.Web.Services.Protocols.SoapHttpClientProtocol" fullword ascii
      $s2 = "IEnumSTORECATEGO.exe" fullword wide
      $s3 = "get_LabelPassword" fullword ascii
      $s4 = "get_PasswordDialog" fullword ascii
      $s5 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/>" fullword ascii
      $s6 = "Send_Remote_AT_Command" fullword ascii
      $s7 = "_TargetPoint" fullword ascii
      $s8 = "TargetPoint" fullword ascii
      $s9 = "get_TargetPoint" fullword ascii
      $s10 = "set_TargetPoint" fullword ascii
      $s11 = "VitualMode" fullword ascii /* base64 encoded string 'V+njS(u' */
      $s12 = "ControlSystemLibrary.BatteryDisplay.resources" fullword ascii
      $s13 = "GetPrivateProfileString" fullword ascii
      $s14 = "get_ComboBoxTipo" fullword ascii
      $s15 = "get_TextBoxNewPass2" fullword ascii
      $s16 = "get_UserXOrigin" fullword ascii
      $s17 = "_LabelPassword" fullword ascii
      $s18 = "get_ComboBoxTurnos" fullword ascii
      $s19 = "get_UserText" fullword ascii
      $s20 = "SetHostAddress" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule sig_6802c9c481671ec10ee1178946a46c73 {
   meta:
      description = "Sample_Malware_AgentTesla - file 6802c9c481671ec10ee1178946a46c73"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-02-26"
      hash1 = "e40736bc19f0008189f281f42cdfddf5bcf6a8c70a89e7bccd0aa0eb797edd22"
   strings:
      // $s1 = "hjzSoKEdezlRCIYwJFEAerVUZCdMcHUt.exe" fullword wide
      // $s2 = "https://www.theonionrouter.com/dist.torproject.org/torbrowser/9.5.3/tor-win32-0.4.3.6.zip" fullword wide
      // $s3 = "4System.Web.Services.Protocols.SoapHttpClientProtocol" fullword ascii
      // $s4 = "get_AccountCredentialsModel" fullword ascii
      // $s5 = "get_passwordIsSet" fullword ascii
      // $s6 = "get_templatePresets" fullword ascii
      // $s7 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/>" fullword ascii
      // $s8 = "get_BindingAccountConfiguration" fullword ascii
      $s9 = "SmtpAccountConfiguration" fullword ascii
      // $s10 = "get_AccountConfiguration" fullword ascii
      // $s11 = "get_IncludeInGlobalOperations" fullword ascii
      $s12 = "get_enableLog" fullword ascii
      // $s13 = "GetPrivateProfileString" fullword ascii
      // $s14 = "get_GuidMasterKey" fullword ascii
      // $s15 = "get_username" fullword ascii
      $s16 = "get_bindingConfigurationUID" fullword ascii
      // $s17 = "get_accountName" fullword ascii
      $s18 = "set_passwordIsSet" fullword ascii
      // $s19 = "set_AccountCredentialsModel" fullword ascii
      // $s20 = "get_InternalServerPort" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

/* Super Rules ------------------------------------------------------------- */

rule _94491241e60bd744ff41c9f33cd39b02ee968cfce120720be9e8a849b8e39c0e_6802c9c481671ec10ee1178946a46c73_0 {
   meta:
      description = "Sample_Malware_AgentTesla - from files 94491241e60bd744ff41c9f33cd39b02ee968cfce120720be9e8a849b8e39c0e, 6802c9c481671ec10ee1178946a46c73"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-02-26"
      hash1 = "94491241e60bd744ff41c9f33cd39b02ee968cfce120720be9e8a849b8e39c0e"
      hash2 = "e40736bc19f0008189f281f42cdfddf5bcf6a8c70a89e7bccd0aa0eb797edd22"
   strings:
      $s1 = "get_GuidMasterKey" fullword ascii
      $s2 = "get_username" fullword ascii
      $s3 = "get_LastAccessed" fullword ascii
      $s4 = "set_GuidMasterKey" fullword ascii
      $s5 = "set_username" fullword ascii
      $s6 = "get_Lenght" fullword ascii
      $s7 = "GetProcesses" fullword ascii /* Goodware String - occured 34 times */
      $s8 = "Rijndael" fullword ascii /* Goodware String - occured 36 times */
      $s9 = "TripleDESCryptoServiceProvider" fullword ascii /* Goodware String - occured 36 times */
      $s10 = "GetProcessesByName" fullword ascii /* Goodware String - occured 41 times */
      $s11 = "PaddingMode" fullword ascii /* Goodware String - occured 49 times */
      $s12 = "MD5CryptoServiceProvider" fullword ascii /* Goodware String - occured 50 times */
      $s13 = "CipherMode" fullword ascii /* Goodware String - occured 54 times */
      $s14 = "CreateDecryptor" fullword ascii /* Goodware String - occured 76 times */
      $s15 = "GetResponse" fullword ascii /* Goodware String - occured 124 times */
      $s16 = "CurrentUser" fullword ascii /* Goodware String - occured 204 times */
      $s17 = "ComputeHash" fullword ascii /* Goodware String - occured 226 times */
      $s18 = "System.Security.Cryptography" fullword ascii /* Goodware String - occured 305 times */
      $s19 = "Reverse" fullword ascii /* Goodware String - occured 338 times */
      $s20 = "LocalMachine" fullword ascii /* Goodware String - occured 353 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _14a388b154b55a25c66b1bfef9499b64_5b14a7366cf5dbea3386c6afbd25f012_1 {
   meta:
      description = "Sample_Malware_AgentTesla - from files 14a388b154b55a25c66b1bfef9499b64, 5b14a7366cf5dbea3386c6afbd25f012"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-02-26"
      hash1 = "cb414e417f8f3de9392dbc6a89421d1a8e95beabbbe387e11771567d63a7b227"
      hash2 = "f6ef92f6911bb14f5b8905f3964d21a9569c41c4e5367d0ee8aec59d54eb7024"
   strings:
      $s1 = "System.Windows.Forms.Form" fullword ascii
      $s2 = "DialogsLib" fullword ascii
      $s3 = "get_ParamArray0" fullword ascii
      $s4 = "get_ArrayAttribute" fullword ascii
      $s5 = "ThreadSafeObjectProvider`1" fullword ascii
      $s6 = "MyWebServices" fullword ascii
      $s7 = "m_ComputerObjectProvider" fullword ascii
      $s8 = "m_MyWebServicesObjectProvider" fullword ascii
      $s9 = "m_ThreadStaticValue" fullword ascii
      $s10 = "m_UserObjectProvider" fullword ascii
      $s11 = "Helplink" fullword ascii
      $s12 = "get_Label2" fullword ascii
      $s13 = "GetResourceString" fullword ascii /* Goodware String - occured 124 times */
      $s14 = "Hashtable" fullword ascii /* Goodware String - occured 645 times */
      $s15 = "DotsCell" fullword ascii
      $s16 = "MySettings" fullword ascii
      $s17 = "m_AppObjectProvider" fullword ascii
      $s18 = "MySettingsProperty" fullword ascii
      $s19 = "AutoPropertyValue" fullword ascii
      $s20 = "m_FormBeingCreated" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _14a388b154b55a25c66b1bfef9499b64_94491241e60bd744ff41c9f33cd39b02ee968cfce120720be9e8a849b8e39c0e_cff5f0bb2c9dc0d52591745ea_2 {
   meta:
      description = "Sample_Malware_AgentTesla - from files 14a388b154b55a25c66b1bfef9499b64, 94491241e60bd744ff41c9f33cd39b02ee968cfce120720be9e8a849b8e39c0e, cff5f0bb2c9dc0d52591745ea43e9c7cd8dc46ea14c5a9996c72f76e7cdf7011, 5b14a7366cf5dbea3386c6afbd25f012, 6802c9c481671ec10ee1178946a46c73"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-02-26"
      hash1 = "cb414e417f8f3de9392dbc6a89421d1a8e95beabbbe387e11771567d63a7b227"
      hash2 = "94491241e60bd744ff41c9f33cd39b02ee968cfce120720be9e8a849b8e39c0e"
      hash3 = "cff5f0bb2c9dc0d52591745ea43e9c7cd8dc46ea14c5a9996c72f76e7cdf7011"
      hash4 = "f6ef92f6911bb14f5b8905f3964d21a9569c41c4e5367d0ee8aec59d54eb7024"
      hash5 = "e40736bc19f0008189f281f42cdfddf5bcf6a8c70a89e7bccd0aa0eb797edd22"
   strings:
      $s1 = "Microsoft.VisualBasic" fullword ascii /* Goodware String - occured 98 times */
      $s2 = "Monitor" fullword ascii /* Goodware String - occured 1015 times */
      $s3 = "Remove" fullword ascii /* Goodware String - occured 1247 times */
      $s4 = "System.Runtime.CompilerServices" fullword ascii /* Goodware String - occured 1950 times */
      $s5 = "System.Reflection" fullword ascii /* Goodware String - occured 2186 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( all of them )
      ) or ( all of them )
}

rule _14a388b154b55a25c66b1bfef9499b64_5b14a7366cf5dbea3386c6afbd25f012_6802c9c481671ec10ee1178946a46c73_3 {
   meta:
      description = "Sample_Malware_AgentTesla - from files 14a388b154b55a25c66b1bfef9499b64, 5b14a7366cf5dbea3386c6afbd25f012, 6802c9c481671ec10ee1178946a46c73"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-02-26"
      hash1 = "cb414e417f8f3de9392dbc6a89421d1a8e95beabbbe387e11771567d63a7b227"
      hash2 = "f6ef92f6911bb14f5b8905f3964d21a9569c41c4e5367d0ee8aec59d54eb7024"
      hash3 = "e40736bc19f0008189f281f42cdfddf5bcf6a8c70a89e7bccd0aa0eb797edd22"
   strings:
      $s1 = "4System.Web.Services.Protocols.SoapHttpClientProtocol" fullword ascii
      $s2 = "MyTemplate" fullword ascii
      $s3 = "My.Computer" fullword ascii
      $s4 = "My.WebServices" fullword ascii
      $s5 = "CompareString" fullword ascii /* Goodware String - occured 28 times */
      $s6 = "Dispose__Instance__" fullword ascii
      $s7 = "My.User" fullword ascii
      $s8 = "Create__Instance__" fullword ascii
      $s9 = "get_Computer" fullword ascii /* Goodware String - occured 4 times */
      $s10 = "LateGet" fullword ascii /* Goodware String - occured 5 times */
      $s11 = "My.Application" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _14a388b154b55a25c66b1bfef9499b64_94491241e60bd744ff41c9f33cd39b02ee968cfce120720be9e8a849b8e39c0e_5b14a7366cf5dbea3386c6afb_4 {
   meta:
      description = "Sample_Malware_AgentTesla - from files 14a388b154b55a25c66b1bfef9499b64, 94491241e60bd744ff41c9f33cd39b02ee968cfce120720be9e8a849b8e39c0e, 5b14a7366cf5dbea3386c6afbd25f012, 6802c9c481671ec10ee1178946a46c73"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-02-26"
      hash1 = "cb414e417f8f3de9392dbc6a89421d1a8e95beabbbe387e11771567d63a7b227"
      hash2 = "94491241e60bd744ff41c9f33cd39b02ee968cfce120720be9e8a849b8e39c0e"
      hash3 = "f6ef92f6911bb14f5b8905f3964d21a9569c41c4e5367d0ee8aec59d54eb7024"
      hash4 = "e40736bc19f0008189f281f42cdfddf5bcf6a8c70a89e7bccd0aa0eb797edd22"
   strings:
      $s1 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/>" fullword ascii
      $s2 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" fullword ascii
      $s3 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" fullword ascii
      $s4 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" fullword ascii
      $s5 = "  </trustInfo>" fullword ascii
      $s6 = "      </requestedPrivileges>" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( all of them )
      ) or ( all of them )
}

