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
      $x1 = "@@DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD" ascii /* score: '38.00'*/
      $s2 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.R" ascii /* score: '27.00'*/
      $s3 = "Alternatively, if you have a GitHub account, you may report this crash at https://github.com/jianmingyong/Pokemon-3D-Resource-Ma" wide /* score: '23.00'*/
      $s4 = "CancellationTokenRegistrati.exe" fullword wide /* score: '21.00'*/
      $s5 = "PUBLICMAP" fullword ascii /* base64 encoded string '=@K # ' */ /* score: '19.50'*/
      $s6 = "4System.Web.Services.Protocols.SoapHttpClientProtocol" fullword ascii /* score: '19.00'*/
      $s7 = "EDDDDDDDDD" ascii /* reversed goodware string 'DDDDDDDDDE' */ /* score: '16.50'*/
      $s8 = "FDDDDDDDDD" ascii /* reversed goodware string 'DDDDDDDDDF' */ /* score: '16.50'*/
      $s9 = "GetEmptyCoastalTileCount" fullword ascii /* score: '16.00'*/
      $s10 = "DDDG6ETDDDjIvGjDDDjNyDTDDDjIvGjDDDjNyDTDDDjIvGjDDDjNyDTDDDjIvGTDDDjIvGTDDDjIvGTDDDjIvGTDDDjIvGTDDDDKJGjDDDjIZETDDDDPGETDDDjHPDTD" ascii /* score: '16.00'*/
      $s11 = "GetEmptyTileCount" fullword ascii /* score: '16.00'*/
      $s12 = "Go to: http://pokemon3d.net/forum/threads/8234/ to report this crash there." fullword wide /* score: '16.00'*/
      $s13 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/>" fullword ascii /* score: '15.00'*/
      $s14 = "get_btnTurnAction_Spy" fullword ascii /* score: '14.00'*/
      $s15 = "get_minesweeper" fullword ascii /* score: '14.00'*/
      $s16 = "minesweeper" fullword wide /* score: '13.00'*/
      $s17 = "kEYeoU6f8QY]}YID7<p\\3kKgDjJgno5YiU[]}EDZVsIU7wXfzsJQk<JUL][WE<5gDPqet]IRVoWfs{HPFUnW{gIfTIJDTgpe6Lpg7YIU|][XHYpVHU6YXEDd3IJXv{Z" ascii /* score: '12.00'*/
      $s18 = "WrDDDz<f[rDDD3GNDDDDRGFDDDDjjH|KNDDD<jFDDDz8jDDDD;ML};kEDHz7rLjEWrDDDH;f2DLDDLlEDHD8rDDDDvNLz<kLiDDDJfJRDDDDZDFDDXTo8jTHLPUD.ekE" ascii /* score: '12.00'*/
      $s19 = "qvqDNDDDT.pDJDDD3llDHDDDYvqDDDDDEDSRDDDDDLLRDDDDEDlIpLzNUDDDfDDDF\\DDMD}HDDjND\\DDDvMNZXDEGLDDZ\\lDu\\nNDrDDD;7edqkFDDTmrPzGdqkF" ascii /* score: '12.00'*/
      $s20 = "nM6e6Q6fkEYeoU6f8QY]}Y4[3Y5fDL[\\rQH]|<5g}Q[\\T4Z]3Q[hWY5fY<IgogJDnY5]xIJdGUKhoU4[o]6ewYpfDTZ]q8Z\\rQHg7YJYiUJ]kEjfo{J]xIJV38Z]5" ascii /* score: '12.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      1 of ($x*) and 4 of them
}

rule cff5f0bb2c9dc0d52591745ea43e9c7cd8dc46ea14c5a9996c72f76e7cdf7011 {
   meta:
      description = "Sample_Malware_AgentTesla - file cff5f0bb2c9dc0d52591745ea43e9c7cd8dc46ea14c5a9996c72f76e7cdf7011"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-02-26"
      hash1 = "cff5f0bb2c9dc0d52591745ea43e9c7cd8dc46ea14c5a9996c72f76e7cdf7011"
   strings:
      $s1 = "System.Security.Permissions.SecurityPermissionAttribute, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934" ascii /* score: '27.00'*/
      $s2 = "PvG.exe" fullword wide /* score: '19.00'*/
      $s3 = "get_TempDefenseBoost" fullword ascii /* score: '16.00'*/
      $s4 = "get_TempInitBoost" fullword ascii /* score: '16.00'*/
      $s5 = "get_TempBoost" fullword ascii /* score: '16.00'*/
      $s6 = "get_TempCritBoost" fullword ascii /* score: '16.00'*/
      $s7 = "get_TempDodgeBoost" fullword ascii /* score: '16.00'*/
      $s8 = "get_TempAttackBoost" fullword ascii /* score: '16.00'*/
      $s9 = "set_TempDodgeBoost" fullword ascii /* score: '11.00'*/
      $s10 = "TempCritBoost" fullword ascii /* score: '11.00'*/
      $s11 = "set_TempAttackBoost" fullword ascii /* score: '11.00'*/
      $s12 = "TempDefenseBoost" fullword ascii /* score: '11.00'*/
      $s13 = "TempInitBoost" fullword ascii /* score: '11.00'*/
      $s14 = "<TempCritBoost>k__BackingField" fullword ascii /* score: '11.00'*/
      $s15 = "set_TempBoost" fullword ascii /* score: '11.00'*/
      $s16 = "<TempDodgeBoost>k__BackingField" fullword ascii /* score: '11.00'*/
      $s17 = "<TempBoost>k__BackingField" fullword ascii /* score: '11.00'*/
      $s18 = "set_TempCritBoost" fullword ascii /* score: '11.00'*/
      $s19 = "<TempAttackBoost>k__BackingField" fullword ascii /* score: '11.00'*/
      $s20 = "TempBoost" fullword ascii /* score: '11.00'*/
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
      $s1 = "4System.Web.Services.Protocols.SoapHttpClientProtocol" fullword ascii /* score: '19.00'*/
      $s2 = "IEnumSTORECATEGO.exe" fullword wide /* score: '18.00'*/
      $s3 = "get_PasswordDialog" fullword ascii /* score: '17.00'*/
      $s4 = "get_LabelPassword" fullword ascii /* score: '17.00'*/
      $s5 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/>" fullword ascii /* score: '15.00'*/
      $s6 = "Send_Remote_AT_Command" fullword ascii /* score: '15.00'*/
      $s7 = "VitualMode" fullword ascii /* base64 encoded string 'V+njS(u' */ /* score: '14.00'*/
      $s8 = "get_TargetPoint" fullword ascii /* score: '14.00'*/
      $s9 = "TargetPoint" fullword ascii /* score: '14.00'*/
      $s10 = "_TargetPoint" fullword ascii /* score: '14.00'*/
      $s11 = "set_TargetPoint" fullword ascii /* score: '14.00'*/
      $s12 = "ControlSystemLibrary.BatteryDisplay.resources" fullword ascii /* score: '14.00'*/
      $s13 = "GetPrivateProfileString" fullword ascii /* score: '12.00'*/
      $s14 = "get_ComboBoxHoraInternet" fullword ascii /* score: '12.00'*/
      $s15 = "get_TextBoxPass" fullword ascii /* score: '12.00'*/
      $s16 = "get_ComboBoxSuc" fullword ascii /* score: '12.00'*/
      $s17 = "get_UserText" fullword ascii /* score: '12.00'*/
      $s18 = "Send_AT_Command" fullword ascii /* score: '12.00'*/
      $s19 = "COMMAND_STATUS_ENUM" fullword ascii /* score: '12.00'*/
      $s20 = "get_UserRotate" fullword ascii /* score: '12.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule sig_94491241e60bd744ff41c9f33cd39b02ee968cfce120720be9e8a849b8e39c0e {
   meta:
      description = "Sample_Malware_AgentTesla - file 94491241e60bd744ff41c9f33cd39b02ee968cfce120720be9e8a849b8e39c0e"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-02-26"
      hash1 = "94491241e60bd744ff41c9f33cd39b02ee968cfce120720be9e8a849b8e39c0e"
   strings:
      $s1 = "org.jdownloader.settings.AccountSettings.accounts.ejs" fullword wide /* score: '28.00'*/
      $s2 = "\\Trillian\\users\\global\\accounts.dat" fullword wide /* score: '26.00'*/
      $s3 = "Software\\A.V.M.\\Paltalk NG\\common_settings\\core\\users\\creds\\" fullword wide /* score: '23.00'*/
      $s4 = "\\\"(hostname|encryptedPassword|encryptedUsername)\":\"(.*?)\"" fullword wide /* score: '23.00'*/
      $s5 = "SmtpPassword" fullword wide /* PEStudio Blacklist: strings */ /* score: '22.00'*/
      $s6 = "SystemProcessorPerformanceInformation" fullword ascii /* score: '22.00'*/
      $s7 = "gnxLZ.exe" fullword wide /* score: '22.00'*/
      $s8 = "\\VirtualStore\\Program Files (x86)\\FTP Commander Deluxe\\Ftplist.txt" fullword wide /* score: '22.00'*/
      $s9 = "\\Program Files (x86)\\FTP Commander Deluxe\\Ftplist.txt" fullword wide /* score: '22.00'*/
      $s10 = "\\Program Files (x86)\\FTP Commander\\Ftplist.txt" fullword wide /* score: '22.00'*/
      $s11 = "\\VirtualStore\\Program Files (x86)\\FTP Commander\\Ftplist.txt" fullword wide /* score: '22.00'*/
      $s12 = "SMTP Password" fullword wide /* PEStudio Blacklist: strings */ /* score: '22.00'*/
      $s13 = "privateinternetaccess.com" fullword wide /* score: '21.00'*/
      $s14 = "paltalk.com" fullword wide /* score: '21.00'*/
      $s15 = "discord.com" fullword wide /* score: '21.00'*/
      $s16 = "https://account.dyn.com/" fullword wide /* score: '20.00'*/
      $s17 = "JDownloader 2.0" fullword wide /* score: '19.00'*/
      $s18 = "JDownloader 2.0\\cfg" fullword wide /* score: '19.00'*/
      $s19 = "Internet Downloader Manager" fullword wide /* score: '19.00'*/
      $s20 = "FileMapExecute" fullword ascii /* score: '18.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 700KB and
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
      $s1 = "hjzSoKEdezlRCIYwJFEAerVUZCdMcHUt.exe" fullword wide /* score: '22.00'*/
      $s2 = "https://www.theonionrouter.com/dist.torproject.org/torbrowser/9.5.3/tor-win32-0.4.3.6.zip" fullword wide /* score: '22.00'*/
      $s3 = "4System.Web.Services.Protocols.SoapHttpClientProtocol" fullword ascii /* score: '19.00'*/
      $s4 = "get_passwordIsSet" fullword ascii /* score: '17.00'*/
      $s5 = "get_AccountCredentialsModel" fullword ascii /* score: '17.00'*/
      $s6 = "get_templatePresets" fullword ascii /* score: '16.00'*/
      $s7 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/>" fullword ascii /* score: '15.00'*/
      $s8 = "SmtpAccountConfiguration" fullword ascii /* score: '15.00'*/
      $s9 = "get_BindingAccountConfiguration" fullword ascii /* score: '15.00'*/
      $s10 = "get_AccountConfiguration" fullword ascii /* score: '15.00'*/
      $s11 = "get_enableLog" fullword ascii /* score: '14.00'*/
      $s12 = "get_IncludeInGlobalOperations" fullword ascii /* score: '14.00'*/
      $s13 = "GetPrivateProfileString" fullword ascii /* score: '12.00'*/
      $s14 = "get_username" fullword ascii /* score: '12.00'*/
      $s15 = "get_GuidMasterKey" fullword ascii /* score: '12.00'*/
      $s16 = "set_AccountCredentialsModel" fullword ascii /* score: '12.00'*/
      $s17 = "get_accountName" fullword ascii /* score: '12.00'*/
      $s18 = "set_passwordIsSet" fullword ascii /* score: '12.00'*/
      $s19 = "get_InternalServerPort" fullword ascii /* score: '12.00'*/
      $s20 = "get_IdnAddress" fullword ascii /* score: '12.00'*/
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
      $s1 = "get_username" fullword ascii /* score: '12.00'*/
      $s2 = "get_GuidMasterKey" fullword ascii /* score: '12.00'*/
      $s3 = "get_LastAccessed" fullword ascii /* score: '9.00'*/
      $s4 = "set_username" fullword ascii /* score: '7.00'*/
      $s5 = "set_GuidMasterKey" fullword ascii /* score: '7.00'*/
      $s6 = "get_Lenght" fullword ascii /* score: '6.00'*/
      $s7 = "GetProcesses" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.97'*/ /* Goodware String - occured 34 times */
      $s8 = "TripleDESCryptoServiceProvider" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.96'*/ /* Goodware String - occured 36 times */
      $s9 = "Rijndael" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.96'*/ /* Goodware String - occured 36 times */
      $s10 = "GetProcessesByName" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.96'*/ /* Goodware String - occured 41 times */
      $s11 = "PaddingMode" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.95'*/ /* Goodware String - occured 49 times */
      $s12 = "MD5CryptoServiceProvider" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.95'*/ /* Goodware String - occured 50 times */
      $s13 = "CipherMode" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.95'*/ /* Goodware String - occured 54 times */
      $s14 = "CreateDecryptor" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.92'*/ /* Goodware String - occured 76 times */
      $s15 = "GetResponse" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.88'*/ /* Goodware String - occured 124 times */
      $s16 = "CurrentUser" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.80'*/ /* Goodware String - occured 204 times */
      $s17 = "ComputeHash" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.77'*/ /* Goodware String - occured 226 times */
      $s18 = "System.Security.Cryptography" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.70'*/ /* Goodware String - occured 305 times */
      $s19 = "Reverse" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.66'*/ /* Goodware String - occured 338 times */
      $s20 = "LocalMachine" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.65'*/ /* Goodware String - occured 353 times */
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
      $s1 = "System.Windows.Forms.Form" fullword ascii /* score: '10.00'*/
      $s2 = "DialogsLib" fullword ascii /* score: '9.00'*/
      $s3 = "get_ParamArray0" fullword ascii /* score: '9.00'*/
      $s4 = "get_ArrayAttribute" fullword ascii /* score: '9.00'*/
      $s5 = "ThreadSafeObjectProvider`1" fullword ascii /* score: '7.00'*/
      $s6 = "m_UserObjectProvider" fullword ascii /* score: '7.00'*/
      $s7 = "m_ComputerObjectProvider" fullword ascii /* score: '7.00'*/
      $s8 = "m_ThreadStaticValue" fullword ascii /* score: '7.00'*/
      $s9 = "m_MyWebServicesObjectProvider" fullword ascii /* score: '7.00'*/
      $s10 = "MyWebServices" fullword ascii /* score: '7.00'*/
      $s11 = "Helplink" fullword ascii /* score: '6.00'*/
      $s12 = "get_Label2" fullword ascii /* score: '6.00'*/
      $s13 = "GetResourceString" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.88'*/ /* Goodware String - occured 124 times */
      $s14 = "Hashtable" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.36'*/ /* Goodware String - occured 645 times */
      $s15 = "MyForms" fullword ascii /* score: '4.00'*/
      $s16 = "m_FormBeingCreated" fullword ascii /* score: '4.00'*/
      $s17 = "MySettingsProperty" fullword ascii /* score: '4.00'*/
      $s18 = "m_MyFormsObjectProvider" fullword ascii /* score: '4.00'*/
      $s19 = "set_Main" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s20 = "MyProject" fullword ascii /* score: '4.00'*/
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
      $s1 = "Microsoft.VisualBasic" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.90'*/ /* Goodware String - occured 98 times */
      $s2 = "Monitor" fullword ascii /* PEStudio Blacklist: strings */ /* score: '3.99'*/ /* Goodware String - occured 1015 times */
      $s3 = "Remove" fullword ascii /* PEStudio Blacklist: strings */ /* score: '3.75'*/ /* Goodware String - occured 1247 times */
      $s4 = "System.Runtime.CompilerServices" fullword ascii /* PEStudio Blacklist: strings */ /* score: '3.05'*/ /* Goodware String - occured 1950 times */
      $s5 = "System.Reflection" fullword ascii /* PEStudio Blacklist: strings */ /* score: '2.81'*/ /* Goodware String - occured 2186 times */
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
      $s1 = "4System.Web.Services.Protocols.SoapHttpClientProtocol" fullword ascii /* score: '19.00'*/
      $s2 = "MyTemplate" fullword ascii /* score: '11.00'*/
      $s3 = "My.Computer" fullword ascii /* score: '11.00'*/
      $s4 = "My.WebServices" fullword ascii /* score: '7.00'*/
      $s5 = "CompareString" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.97'*/ /* Goodware String - occured 28 times */
      $s6 = "Dispose__Instance__" fullword ascii /* score: '4.00'*/
      $s7 = "My.User" fullword ascii /* score: '4.00'*/
      $s8 = "Create__Instance__" fullword ascii /* score: '4.00'*/
      $s9 = "get_Computer" fullword ascii /* score: '1.00'*/ /* Goodware String - occured 4 times */
      $s10 = "My.Application" fullword ascii /* score: '0.00'*/
      $s11 = "LateGet" fullword ascii /* score: '0.00'*/ /* Goodware String - occured 5 times */
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
      $s1 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/>" fullword ascii /* score: '15.00'*/
      $s2 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" fullword ascii /* score: '11.00'*/
      $s3 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" fullword ascii /* score: '7.00'*/
      $s4 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" fullword ascii /* score: '5.00'*/
      $s5 = "  </trustInfo>" fullword ascii /* score: '4.00'*/
      $s6 = "      </requestedPrivileges>" fullword ascii /* score: '2.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( all of them )
      ) or ( all of them )
}

