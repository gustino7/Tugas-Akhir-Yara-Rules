rule CAPE_Amadey {
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

rule Ditekshen_MALWARE_Win_Amadey {
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

rule Elastic_Windows_Trojan_Amadey_7abb059b {
    meta:
        author = "Elastic Security"
        id = "7abb059b-4001-4eec-8185-1e0497e15062"
        fingerprint = "686ae7cf62941d7db051fa8c45f0f7a27440fa0fdc5f0919c9667dfeca46ca1f"
        creation_date = "2021-06-28"
        last_modified = "2021-08-23"
        threat_name = "Windows.Trojan.Amadey"
        reference_sample = "33e6b58ce9571ca7208d1c98610005acd439f3e37d2329dae8eb871a2c4c297e"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 18 83 78 14 10 72 02 8B 00 6A 01 6A 00 6A 00 6A 00 6A 00 56 }
    condition:
        all of them
}

rule Elastic_Windows_Trojan_Amadey_c4df8d4a {
    meta:
        author = "Elastic Security"
        id = "c4df8d4a-01f4-466f-8225-7c7f462b29e7"
        fingerprint = "4623c591ea465e23f041db77dc68ddfd45034a8bde0f20fd5fbcec060851200c"
        creation_date = "2021-06-28"
        last_modified = "2021-08-23"
        threat_name = "Windows.Trojan.Amadey"
        reference_sample = "9039d31d0bd88d0c15ee9074a84f8d14e13f5447439ba80dd759bf937ed20bf2"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "D:\\Mktmp\\NL1\\Release\\NL1.pdb" fullword
    condition:
        all of them
}

/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2019-01-30
   Identifier: amadey-botnet
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */

rule Hestat_del_task {
   meta:
      description = "amadey-botnet - file del_task.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2019-01-30"
      hash1 = "e58ce2a8fbc9ca9dc4fb34233b2d4a87fd155f03a320f0861fcde3b32eb057c5"
   strings:
      $s1 = "header( \"Location: login.php\" );" fullword ascii
      $s2 = "mysql_connect( $conf['dbhost'], $conf['dbuser'], $conf['dbpass'] ); " fullword ascii
      $s3 = "mysql_query( \"DELETE FROM tasks_exec WHERE task_id = '$id'\" );" fullword ascii
      $s4 = "echo \"Please login at root, observers cant delete task\"; " fullword ascii
      $s5 = "header( \"Refresh: 1; url = show_tasks.php\" );" fullword ascii
      $s6 = "include( \"header.php\" );" fullword ascii
      $s7 = "header( \"Location: \" . $_SERVER['HTTP_REFERER'] . \"\" );" fullword ascii
      $s8 = "if ( $_SESSION['Name'] == \"ROOT\" )  " fullword ascii
      $s9 = "include( \"cfg/config.php\" ); " fullword ascii
      $s10 = "if ( !is_numeric( $_GET['id'] ) ) " fullword ascii
      $s11 = "$id = strfix( $_GET['id'] );" fullword ascii
      $s12 = "if ( !( isset( $_SESSION['Name'] ) ) )" fullword ascii
      $s13 = "mysql_query( \"DELETE FROM tasks WHERE id = '$id' LIMIT 1\" );" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 2KB and
         ( 8 of them )
      ) or ( all of them )
}

rule Hestat_infected_01_29_19_amadey_botnet_header {
   meta:
      description = "amadey-botnet - file header.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2019-01-30"
      hash1 = "44227b5c4367fdedd1ae532fd00c57b9543b5261a68946a51f6ec11294bbb4fd"
   strings:
      $s1 = "<img src=\\\"images\\b6.png\\\"> <a href=\\\"login.php?logout=1\\\"><font color=\\\"#DDDDDD\\\">LOGOUT [\";" fullword ascii
      $s2 = "<td bgcolor=\\\"#FF0000\\\"><div align=\\\"center\\\"><img src=\\\"images\\logo_small.png\\\"></div></td>" fullword ascii
      $s3 = "<img src=\\\"images\\b1.png\\\"> <a href=\\\"statistic.php\\\"><font color=\\\"#DDDDDD\\\">STATISTIC</font></a>&nbsp; |&nbsp;" fullword ascii
      $s4 = "<img src=\\\"images\\b5.png\\\"> <a href=\\\"settings.php\\\"><font color=\\\"#DDDDDD\\\">SETTINGS</font></a>&nbsp; |&nbsp;" fullword ascii
      $s5 = "<img src=\\\"images\\b4.png\\\"> <a href=\\\"show_tasks.php\\\"><font color=\\\"#DDDDDD\\\">TASKS LIST</font></a>&nbsp; |&nbsp;" fullword ascii
      $s6 = "<meta http-equiv=\\\"Content-Type\\\" content=\\\"text/html; charset=windows-1251\\\">" fullword ascii
      $s7 = "<img src=\\\"images\\b5.png\\\"> <a href=\\\"settings.php\\\"><font color=\\\"#DDDDDD\\\">SETTINGS</font></a>" fullword ascii
      $s8 = "echo \"<table border=\\\"0\\\" width=\\\"100%\\\" cellspacing=\\\"0\\\" cellpadding=\\\"0\\\" bgcolor=\\\"#000000\\\">" fullword ascii
      $s9 = "echo \"<table border=\\\"0\\\" width=\\\"1000\\\" cellspacing=\\\"0\\\" cellpadding=\\\"0\\\" height=\\\"5\\\">" fullword ascii
      $s10 = "<link rel=\\\"stylesheet\\\" type=\\\"text/css\\\" href=\\\"f.st\\style.css\\\">" fullword ascii
      $s11 = "<table border=\\\"0\\\" width=\\\"1200\\\" cellspacing=\\\"0\\\" cellpadding=\\\"0\\\" height=\\\"100%\\\">" fullword ascii
      $s12 = "<td align=\\\"center\\\"><font color=\\\"#DDDDDD\\\" size=\\\"4\\\">" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 5KB and
         ( 8 of them )
      ) or ( all of them )
}

rule Hestat_infected_01_29_19_amadey_botnet_cfg_options {
   meta:
      description = "amadey-botnet - file options.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2019-01-30"
      hash1 = "5a478aa659d6e2137f9ff995437420c09ce8386d27b52a0cc52d8ae08b127a9e"
   strings:
      $s1 = "$options[\"show_hostname\"] = \"0\";" fullword ascii
      $s2 = "$options[\"show_username\"] = \"0\";" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 1KB and
         ( all of them )
      ) or ( all of them )
}

rule Hestat_show_units {
   meta:
      description = "amadey-botnet - file show_units.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2019-01-30"
      hash1 = "07905fbf257cacc7a9dd47381c9435f3366a472e3e6db998154a4e50c94223ed"
   strings:
      $s1 = "echo \"SQL connection filed, check host, name, login and password\";" fullword ascii
      $s2 = "<td><div align = center> <a href=\\\"show_units.php?sort=version\" . \"&f=\" . $_GET[\"f\"] . \"&show=\" . $_GET[\"show" fullword ascii
      $s3 = "echo \"&nbsp;<img src=\\\"images\\ic_11.png\\\"> \" . date( \"s\", ( time() - $row['online'] ) ) . \" sec\" ; " fullword ascii
      $s4 = "<td><div align = center> <a href=\\\"show_units.php?sort=ip\" . \"&f=\" . $_GET[\"f\"] . \"&show=\" . $_GET[\"show\"] . " fullword ascii
      $s5 = "<td><div align = center> <a href=\\\"show_units.php?sort=arch\" . \"&f=\" . $_GET[\"f\"] . \"&show=\" . $_GET[\"show\"] " fullword ascii
      $s6 = "<td><div align = center> <a href=\\\"show_units.php?sort=id\" . \"&f=\" . $_GET[\"f\"] . \"&show=\" . $_GET[\"show\"] . " fullword ascii
      $s7 = "<td><div align = center> <a href=\\\"show_units.php?sort=os\" . \"&f=\" . $_GET[\"f\"] . \"&show=\" . $_GET[\"show\"] . " fullword ascii
      $s8 = "<td><div align = center> <a href=\\\"show_units.php?sort=ar\" . \"&f=\" . $_GET[\"f\"] . \"&show=\" . $_GET[\"show\"] . " fullword ascii
      $s9 = "<td><div align = center> <a href=\\\"show_units.php?sort=online\" . \"&f=\" . $_GET[\"f\"] . \"&show=\" . $_GET[\"show\"" fullword ascii
      $s10 = "<td><div align = center> <a href=\\\"show_units.php?sort=reg\" . \"&f=\" . $_GET[\"f\"] . \"&show=\" . $_GET[\"show\"] ." fullword ascii
      $s11 = "$result = mysql_query( \"SELECT * FROM units WHERE online > \" . ( time() - 60 ) . \" ORDER BY $J DESC LIMIT $f, 100\" );" fullword ascii
      $s12 = "echo \"<td><div align = center> <a href=\\\"show_units.php?sort=pc\" . \"&f=\" . $_GET[\"f\"] . \"&show=\" . $_GET[\"" fullword ascii
      $s13 = "echo \"<td><div align = center> <a href=\\\"show_units.php?sort=av\" . \"&f=\" . $_GET[\"f\"] . \"&show=\" . $_GET[\"" fullword ascii
      $s14 = "echo \"<td><div align = center> <a href=\\\"show_units.php?sort=un\" . \"&f=\" . $_GET[\"f\"] . \"&show=\" . $_GET[\"" fullword ascii
      $s15 = "<td><div align = center> <a href=\\\"show_units.php?sort=country\" . \"&f=\" . $_GET[\"f\"] . \"&show=\" . $_GET[\"show" fullword ascii
      $s16 = "<td bgcolor = \" . $gb . \"><div align = left>\" . \"&nbsp;<img src=\\\"images\\ic_6.png\\\"> \" . $row['version'] . \"</div" fullword ascii
      $s17 = "header( \"Location: login.php\" );" fullword ascii
      $s18 = "if ( @mysql_connect( $conf['dbhost'], $conf['dbuser'], $conf['dbpass'] ) == false )" fullword ascii
      $s19 = "$all = mysql_query( \"SELECT * FROM units WHERE online > \" . ( time() - 60 ) );" fullword ascii
      $s20 = "<td bgcolor = \" . $gb . \"><div align = left>\" . \"&nbsp;<img src=\\\"images\\ic_8.png\\\"> \" . $row['os'] . \"</div></td" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 20KB and
         ( 8 of them )
      ) or ( all of them )
}

rule Hestat_edit_task {
   meta:
      description = "amadey-botnet - file edit_task.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2019-01-30"
      hash1 = "fb691c2e788044320bcf49811c45d7813e3fa62941ee5b9d4ebc05e53db9a0f4"
   strings:
      $x1 = "* Chosen country, * for any. <a href=\\\"images/task_example.png\\\" target=\\\"_blank\\\">Exampl" fullword ascii
      $s2 = "e</a>. <a href=\\\"f.st\\c.index.txt\\\" target=\\\"_blank\\\">Countries <b>index</b> table</a>." fullword ascii
      $s3 = "MakeTask( $_POST['path']  . \":::\" . $_POST['dllfunction'], \"0\", $_POST['filetype'], $_POST['autorun'], $_POST['count']" fullword ascii
      $s4 = "* Chosen country, * for any. <a href=\\\"images/task_example.png\\\" target=\\\"_blank\\\">Example</a>. <a href=\\\"f.st\\c.inde" ascii
      $s5 = "MakeTask( $_POST['path'], $_POST['run'], $_POST['filetype'], $_POST['autorun'], $_POST['count'], $_POST['unitid'], $_P" fullword ascii
      $s6 = "echo \"<meta http-equiv=\\\"refresh\\\" content=\\\"1; url=show_tasks.php\\\">\"; " fullword ascii
      $s7 = "* Startup options, <b>only for EXE</b>. Warning! Do not change this option if you don't know what it is." fullword ascii
      $s8 = "<form action=\\\"\" . basename( $_SERVER['SCRIPT_NAME'] ) . \"\\\" method=\\\"post\\\" name=\\\"form\\\">" fullword ascii
      $s9 = "header( \"Location: login.php\" );" fullword ascii
      $s10 = "* Startup options, <b>only for EXE</b>. Warning! Do not change this option if you don't k" fullword ascii
      $s11 = "mysql_query( \"UPDATE `tasks` SET `path` = '$url', `run` = '$run', `filetype` = '$filetype', `autorun` = '$autorun', `tlim" fullword ascii
      $s12 = "$sql = mysql_query( \"SELECT * FROM tasks WHERE id = '$id' LIMIT 1\" ) or die(mysql_error());" fullword ascii
      $s13 = "* Web URL, file will be saved with original name, expansion will be changed." fullword ascii
      $s14 = "mysql_connect($conf['dbhost'], $conf['dbuser'], $conf['dbpass'] ); " fullword ascii
      $s15 = "* Name of the calling function, <b>only for DLL</b>." fullword ascii
      $s16 = ", $_POST['unitid'], $_POST['country'], $_POST['id'], $_POST['ctlimit'] ); " fullword ascii
      $s17 = "function MakeTask( $url, $run, $filetype, $autorun, $limit, $units, $country, $id, $ctlimit ) " fullword ascii
      $s18 = "it` = '$limit', `path` = '$url', `units` = '$units', `country` = '$country' WHERE `id` = '\".$id.\"' LIMIT 1\" );" fullword ascii
      $s19 = "echo \"Please login at root, observers cant edit task\"; " fullword ascii
      $s20 = "<input name=\\\"dllfunction\\\" class=task value=\\\"\" . $dllfunction . \"\\\" style=\\\"float: left\\\">" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 30KB and
         ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule Hestat__home_hawk_infected_01_29_19_amadey_botnet_login {
   meta:
      description = "amadey-botnet - file login.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2019-01-30"
      hash1 = "25007daf60f075efd0c6ac57559e1045dcc72a2b1ac8fa5de5bcf47b8a63ef72"
   strings:
      $s1 = "<form action=\\\"login.php\\\" method=\\\"post\\\"> " fullword ascii
      $s2 = "if ( isset( $_POST[\"login\"]) && isset( $_POST[\"password\"] ) )" fullword ascii
      $s3 = "if ( ( $login == $conf[\"observer_login\"] ) && ( md5( $password ) == $conf[\"observer_password\"] ) )" fullword ascii
      $s4 = "if ( ( $login == $conf[\"login\"] ) && ( md5( $password ) == $conf[\"password\"] ) )" fullword ascii
      $s5 = "$login = $_POST[\"login\"];" fullword ascii
      $s6 = "header( \"Location: login.php\" );" fullword ascii
      $s7 = "<meta http-equiv=\\\"Content-Type\\\" content=\\\"text/html; charset=windows-1251\\\">" fullword ascii
      $s8 = "$password = $_POST[\"password\"];" fullword ascii
      $s9 = "@header( \"Refresh: 0; url = statistic.php\" );" fullword ascii
      $s10 = "if ( $_GET['logout'] == 1 ) " fullword ascii
      $s11 = "<table width=\\\"515\\\" height=\\\"481\\\" background=\\\"images\\bg_1.png\\\">" fullword ascii
      $s12 = "<link rel=\\\"stylesheet\\\" type=\\\"text/css\\\" href=\\\"f.st\\style.css\\\">" fullword ascii
      $s13 = "<input type=\\\"text\\\" class=task name=\\\"login\\\">" fullword ascii
      $s14 = "<input type=\\\"password\\\" class=task name=\\\"password\\\">" fullword ascii
      $s15 = "<font size = 1 color = #8d8c8c>default root: root/root</font>" fullword ascii
      $s16 = "<table border=\\\"0\\\" height=\\\"120\\\" cellpadding=\\\"0\\\" cellspacing=\\\"0\\\">" fullword ascii
      $s17 = "include( \"cfg/config.php\" );" fullword ascii
      $s18 = "$_SESSION[\"Name\"] = \"ROOT\";" fullword ascii
      $s19 = "<font size = 1 color = #8d8c8c>default obs: observer/observer</font>" fullword ascii
      $s20 = "<font size = 2>a2019 \\\"AMADEY\\\"</font>&nbsp;&nbsp;&nbsp;&nbsp;" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 20KB and
         ( 8 of them )
      ) or ( all of them )
}

rule Hestat_unitinfo {
   meta:
      description = "amadey-botnet - file unitinfo.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2019-01-30"
      hash1 = "d65a0cb6f9ac091e68aea1e8606263ac47ca7b38b59597905aa15cfcc513376e"
   strings:
      $x1 = "echo \"<tr><td bgcolor = \" . $gb . \">\" . \"&nbsp;<img src=\\\"images\\ic_8.png\\\"> \" . \"Operation system:\" . \"</td>\"; " fullword ascii
      $s2 = "echo \"<tr><td bgcolor = \" . $gb . \">\" . \"&nbsp;<img src=\\\"images\\ic_14.png\\\"> \" . \"Host name:\" . \"</td>\"; " fullword ascii
      $s3 = "echo \"<tr><td bgcolor = \" . $gb . \">\" . \"&nbsp;<img src=\\\"images\\ic_15.png\\\"> \" . \"User name:\" . \"</td>\"; " fullword ascii
      $s4 = "echo \"<tr><td bgcolor = \" . $gb . \">\" . \"&nbsp;<img src=\\\"images\\ic_12.png\\\"> \" . \"Last IP address:\" . \"</td>\"; " fullword ascii
      $s5 = "echo \"SQL connection filed, check host, name, login and password\";" fullword ascii
      $s6 = "echo \"<tr><td bgcolor = \" . $gb . \">\" . \"&nbsp;<img src=\\\"images\\ic_6.png\\\"> \" . \"Version:\" . \"</td>\"; " fullword ascii
      $s7 = "echo \"<tr><td bgcolor = \" . $gb . \">\" . \"&nbsp;<img src=\\\"images\\ic_10.png\\\"> \" . \"Access rights:\" . \"</td>\"; " fullword ascii
      $s8 = "echo \"<tr><td bgcolor = \" . $gb . \">\" . \"&nbsp;<img src=\\\"images\\ic_6.png\\\"> \" . \"Received tasks:\" . \"</td>\"; " fullword ascii
      $s9 = "echo \"<tr><td bgcolor = \" . $gb . \">\" . \"&nbsp;<img src=\\\"images\\ic_11.png\\\"> \" . \"Last seen:\" . \"</td>\"; " fullword ascii
      $s10 = "echo \"<tr><td bgcolor = \" . $gb . \">\" . \"&nbsp;<img src=\\\"images\\ic_av.png\\\"> \" . \"Antiviral kit:\" . \"</td>\"; " fullword ascii
      $s11 = "echo \"<tr><td bgcolor = \" . $gb . \">\" . \"&nbsp;<img src=\\\"images\\ic_13.png\\\"> \" . \"Country:\" . \"</td>\"; " fullword ascii
      $s12 = "$result = mysql_query( 'SELECT * FROM tasks_exec WHERE unitid = ' . $id );" fullword ascii
      $s13 = "header( \"Location: login.php\" );" fullword ascii
      $s14 = "if ( @mysql_connect( $conf['dbhost'], $conf['dbuser'], $conf['dbpass'] ) == false )" fullword ascii
      $s15 = "\"<td bgcolor = \" . $gb . \">\" . \"<div align = left>\" . \"<img src=\\\"images\\ic_3.png\\\"> \" . \"<a href=\\\"\" " fullword ascii
      $s16 = "echo \"<tr><td bgcolor = \" . $gb . \">\" . \"&nbsp;<img src=\\\"images\\ic_9.png\\\"> \" . \"Operation system architecture:\" ." ascii
      $s17 = "echo \"<tr><td bgcolor = \" . $gb . \">\" . \"&nbsp;<img src=\\\"images\\ic_9.png\\\"> \" . \"Operation system architecture:\" ." ascii
      $s18 = "\"<td bgcolor = \" . $gb . \">\" . \"<div align = left>&nbsp;<img src=\\\"images\\ic_1.png\\\"> \" . $r['id'] . \"" fullword ascii
      $s19 = "echo \"    <td width=200 bgcolor =\"  . $gb . \"><b>\" . GetUnitData( $i, 'version' ) . \"</b></td></tr>\";" fullword ascii
      $s20 = "@mysql_connect( $conf['dbhost'], $conf['dbuser'], $conf['dbpass'] );" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 20KB and
         ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule Hestat_infected_01_29_19_amadey_botnet_cfg_config {
   meta:
      description = "amadey-botnet - file config.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2019-01-30"
      hash1 = "e516cd50d498bce347853598d7855f87b28104413bee41cf413af0f294f845c6"
   strings:
      $s1 = "$conf[\"observer_password\"] = \"dfda0d32069b96bf6c4ea352feffd1b2\";" fullword ascii
      $s2 = "$conf[\"password\"] = \"63a9f0ea7bb98050796b649e85481845\";" fullword ascii
      $s3 = "$conf[\"observer_login\"] = \"observer\";" fullword ascii
      $s4 = "$conf[\"login\"] = \"root\";" fullword ascii
      $s5 = "$conf[\"dbhost\"] = \"localhost\";" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 1KB and
         ( all of them )
      ) or ( all of them )
}

rule Hestat_make_task {
   meta:
      description = "amadey-botnet - file make_task.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2019-01-30"
      hash1 = "87d952f000b19475ca7f9e815653746bc17c48cb69fbce19b8036fb4e731c770"
   strings:
      $x1 = "* Chosen country, * for any. <a href=\\\"images/task_example.png\\\" target=\\\"_blank\\\">Example<" fullword ascii
      $s2 = "MakeTask( $_POST['path']  . \":::\" . $_POST['dllfunction'], \"0\", $_POST['filetype'], $_POST['autorun'], $_POST['count']" fullword ascii
      $s3 = "/a>. <a href=\\\"f.st\\c.index.txt\\\" target=\\\"_blank\\\">Countries <b>index</b> table</a>." fullword ascii
      $s4 = "* Chosen country, * for any. <a href=\\\"images/task_example.png\\\" target=\\\"_blank\\\">Example</a>. <a href=\\\"f.st\\c.inde" ascii
      $s5 = "<input name=\\\"path\\\" class=task value=\\\"http://site.com/folder/exe.e\\\" style=\\\"float: left\\\" size=\\\"50\\\">" fullword ascii
      $s6 = "MakeTask( $_POST['path'], $_POST['run'], $_POST['filetype'], $_POST['autorun'], $_POST['count'], $_POST['unitid'], $_P" fullword ascii
      $s7 = "echo \"<meta http-equiv=\\\"refresh\\\" content=\\\"1; url=show_tasks.php\\\">\"; " fullword ascii
      $s8 = "* Startup options, <b>only for EXE</b>. Warning! Do not change this option if you don't know what it is." fullword ascii
      $s9 = "<form action=\\\"\" . basename( $_SERVER['SCRIPT_NAME'] ) . \"\\\" method=\\\"post\\\" name=\\\"form\\\">" fullword ascii
      $s10 = "header( \"Location: login.php\" );" fullword ascii
      $s11 = "* Startup options, <b>only for EXE</b>. Warning! Do not change this option if you don't kno" fullword ascii
      $s12 = "mysql_query( \"INSERT INTO tasks ( `path`, `run`, `filetype`, `autorun`, `tlimit`, `units`, `country` ) VALUES ( '$url', '$run" fullword ascii
      $s13 = "mysql_query( \"INSERT INTO tasks ( `id`, `path`, `run`, `filetype`, `autorun`, `tlimit`, `units`, `country` ) VALUES (  '10000" fullword ascii
      $s14 = "* Web URL, file will be saved with original name, expansion will be changed." fullword ascii
      $s15 = "mysql_connect( $conf['dbhost'], $conf['dbuser'], $conf['dbpass'] ); " fullword ascii
      $s16 = "* Name of the calling function, <b>only for DLL</b>." fullword ascii
      $s17 = "echo \"Please login at root, observers cant make task\"; " fullword ascii
      $s18 = "01', '$url', '$run', '$filetype', '$autorun', '$limit', '$units', '$country' )\" ); " fullword ascii
      $s19 = "MakeTask( $_POST['path']  . \":::\" . $_POST['dllfunction'], \"0\", $_POST['filetype'], $_POST['autorun'], $_POST['count'], $_PO" ascii
      $s20 = "<table border=\\\"0\\\" width=\\\"1000\\\" cellspacing=\\\"0\\\" cellpadding=\\\"0\\\" height=\\\"5\\\">" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 30KB and
         ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule Hestat_infected_01_29_19_amadey_botnet_f_st_style {
   meta:
      description = "amadey-botnet - file style.css"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2019-01-30"
      hash1 = "d38b01f2bc4f51954426964e89e540d5bc2ad91a0206451021e10db1ce02deb4"
   strings:
      $s1 = ": #242424;" fullword ascii /* hex encoded string '$$$' */
      $s2 = ": #3E3E3E;" fullword ascii /* hex encoded string '>>>' */
   condition:
      ( uint16(0) == 0x6f62 and
         filesize < 3KB and
         ( all of them )
      ) or ( all of them )
}

rule Hestat_show_tasks {
   meta:
      description = "amadey-botnet - file show_tasks.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2019-01-30"
      hash1 = "8a9bbd5e499be6a536df5704319bac256b900ca2902a9c9b3b5f51735506b1ad"
   strings:
      $s1 = "echo \"SQL connection filed, check host, name, login and password\";" fullword ascii
      $s2 = "header( \"Location: login.php\" );" fullword ascii
      $s3 = "if ( @mysql_connect( $conf['dbhost'], $conf['dbuser'], $conf['dbpass'] ) == false )" fullword ascii
      $s4 = "echo \"<td bgcolor = \" . $gb . \">\" . \"<img src=\\\"images\\ic_2.png\\\"> \" . $filetype . \"</td>\";" fullword ascii
      $s5 = "<td><div align = center>Download errors:</div></td> " fullword ascii
      $s6 = "\"  \" . \"<a href=\\\"del_task.php?id=\" . $id . \"\\\">[delete]</a> \" . \"</div></td>\";" fullword ascii
      $s7 = "$result = mysql_query( \"SELECT * FROM tasks ORDER BY id DESC\" );" fullword ascii
      $s8 = "<a href=\\\"make_task.php\\\"><img src=\\\"images\\ic_5.png\\\"> Add task</a>" fullword ascii
      $s9 = "echo \"<td bgcolor = \" . $gb . \"><div align = center>\" . $progress . \"%\" . \"</div></td>\";" fullword ascii
      $s10 = "include( \"header.php\" );" fullword ascii
      $s11 = "echo \"<td bgcolor = \" . $gb . \"><div align = center>\" . $success . \"%\" . \"</div></td>\";" fullword ascii
      $s12 = "$good = $row['exec'];" fullword ascii
      $s13 = "echo \"<td bgcolor = \" . $gb . \">\" . $autorun . \"</td>\";" fullword ascii
      $s14 = "echo \"<td bgcolor = \" . $gb . \"><div align = center>\" . $good . \"</div></td>\";" fullword ascii
      $s15 = "echo \"<td bgcolor = \" . $gb . \"><div align = center>\" . $l_err . \"</div></td>\";" fullword ascii
      $s16 = "echo \"<td bgcolor = \" . $gb . \"><div align = center>\" . $d_err . \"</div></td>\";" fullword ascii
      $s17 = "echo \"<td bgcolor = \" . $gb . \"><div align = center>\" . $needs . \"</div></td>\";" fullword ascii
      $s18 = "echo \"<td bgcolor = \" . $gb . \"><div align = center>\" . $units . \"</div></td>\";" fullword ascii
      $s19 = "echo \"<td bgcolor = \" . $gb . \"><div align = center>\" . $done . \"</div></td>\";" fullword ascii
      $s20 = "<table border=\\\"0\\\" width=\\\"1200\\\" cellspacing=\\\"0\\\" cellpadding=\\\"0\\\">" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 20KB and
         ( 8 of them )
      ) or ( all of them )
}

rule Hestat_statistic {
   meta:
      description = "amadey-botnet - file statistic.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2019-01-30"
      hash1 = "f64f7d52d4c08cc089f5f723de1489a247c9d5dd08f81da8d0b82cb63b31c4eb"
   strings:
      $s1 = "echo \"SQL connection filed, check host, name, login and password\";" fullword ascii
      $s2 = "echo \"<tr><td bgcolor = \". $gb . \">\" . \"&nbsp;<img src=\\\"images\\ic_6.png\\\"> \" . \"Units online:\" . \"</td>\"; " fullword ascii
      $s3 = "echo \"<tr><td bgcolor = \" . $gb . \">\" . \"&nbsp;<img src=\\\"images\\ic_6.png\\\"> \" . \"Active tasks:\" . \"</td>\"; " fullword ascii
      $s4 = "echo \"<td bgcolor = \" . $gb . \">\" . \"&nbsp;<img src=\\\"images\\ic_6.png\\\"> \" . \"New units on day:\" . \"</td>\"; " fullword ascii
      $s5 = "echo \"<tr><td bgcolor = \" . $gb . \">\" . \"&nbsp;<img src=\\\"images\\ic_6.png\\\"> \" . \"Units:\" . \"</td>\"; " fullword ascii
      $s6 = "echo \"<tr><td bgcolor = \" . $gb . \">\" . \"&nbsp;<img src=\\\"images\\ic_6.png\\\"> \" . \"Loads:\" . \"</td>\"; " fullword ascii
      $s7 = "header( \"Location: login.php\" );" fullword ascii
      $s8 = "if ( @mysql_connect( $conf['dbhost'], $conf['dbuser'], $conf['dbpass'] ) == false )" fullword ascii
      $s9 = "$result = mysql_query( 'SELECT * FROM units WHERE reg >' . ( time() - 86400 ) );" fullword ascii
      $s10 = "$result = mysql_query( 'SELECT * FROM units WHERE online > ' . ( time() - 604800 ) );" fullword ascii
      $s11 = "$result = mysql_query( 'SELECT * FROM units WHERE online > ' . ( time() - 60 ) );" fullword ascii
      $s12 = "$result =  mysql_query( 'SELECT * FROM units WHERE online > ' . ( time() - 86400 ) );" fullword ascii
      $s13 = "$result = mysql_query( 'SELECT * FROM units WHERE reg > ' . ( time() - 604800 ) );" fullword ascii
      $s14 = "mysql_connect( $conf[\"dbhost\"], $conf[\"dbuser\"], $conf[\"dbpass\"] );" fullword ascii
      $s15 = "$percent = aVersionUnitsCount( $row['version'] ) / ( GetUnitsCount() / 100 );" fullword ascii
      $s16 = "$result = mysql_query( 'SELECT * FROM units WHERE version = \"' . $version . '\"' );" fullword ascii
      $s17 = "echo \"   <td bgcolor = \" . $gb . \">\" . \"&nbsp;<img src=\\\"images\\ic_6.png\\\">&nbsp;\" . $row['version'] . \"</td>\"; " fullword ascii
      $s18 = "$res = mysql_query( \"SELECT SUM( error + error2 ) AS sum FROM tasks\" ); " fullword ascii
      $s19 = "@mysql_connect( $conf['dbhost'], $conf['dbuser'], $conf['dbpass'] );" fullword ascii
      $s20 = "mysql_connect( $conf['dbhost'], $conf['dbuser'], $conf['dbpass'] );" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 50KB and
         ( 8 of them )
      ) or ( all of them )
}

rule Hestat_infected_01_29_19_amadey_botnet_index {
   meta:
      description = "amadey-botnet - file index.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2019-01-30"
      hash1 = "2f6fc95474a13f99405a9fa327401e908a2bbe39865d8cb881418207faac63a4"
   strings:
      $s1 = "$sql = mysql_query( \"SELECT * FROM `tasks` WHERE `status`='1' AND `id` NOT IN ( SELECT `task_id` FROM `tasks_exec` WHERE " fullword ascii
      $s2 = "header( \"Refresh: 1; url = login.php\" );" fullword ascii
      $s3 = "mysql_query( \"INSERT `tasks_exec` VALUES ( null, '\" . $task['id'] . \"', '\" . $unit_id . \"', '1' )\" );" fullword ascii
      $s4 = "mysql_query( \"UPDATE `tasks` SET `loads`=`loads` + 1, `status`= IF (`loads` >= `tlimit` and `tlimit` <> 0 ,0 , `status` )  WH" fullword ascii
      $s5 = "IncreaseCount( $_POST[\"d1\"] , \"exec\" );" fullword ascii
      $s6 = "$geoip = geo_ip::getInstance( \"f.st/geo_ip.dat\" );" fullword ascii
      $s7 = "mysql_connect( $conf[\"dbhost\"], $conf[\"dbuser\"], $conf[\"dbpass\"] );" fullword ascii
      $s8 = "mysql_query( \"INSERT INTO units ( id, ip, first_ip, online, country, ar, arch, version, os, av, pc, un, reg ) VALUES (" fullword ascii
      $s9 = "echo \"<c>\" . GetTaskContent( $_POST[\"id\"] ) . \"<d>\";" fullword ascii
      $s10 = "`unitid`='\" . $unit_id . \"' AND `exec`='1' ) ORDER BY id ASC\" ); " fullword ascii
      $s11 = "mysql_query( \"UPDATE `tasks` SET `$type` = `$type` + 1 WHERE `id` = '\" . $taskid . \"' LIMIT 1\" );" fullword ascii
      $s12 = "elseif ( !empty( $_SERVER[\"HTTP_X_FORWARDED_FOR\"] ) ) " fullword ascii
      $s13 = "list( $id, $online ) = mysql_fetch_array( mysql_query( \"SELECT id, online FROM units WHERE id = '$bot_id' LIMIT 1\" ) );  " fullword ascii
      $s14 = "$res .= $task['id'] . $task['run'] . $task['filetype'] . $task['autorun'] . $task['path'] . \"#\";" fullword ascii
      $s15 = "function GetTaskContent( $unit_id ) " fullword ascii
      $s16 = "mysql_query( \"UPDATE units SET ip = '$bot_ip', online = '$time', country = '$country', ar = '$ar', arch = '$bi', versi" fullword ascii
      $s17 = "IncreaseCount( $_POST[\"e1\"] , \"error2\" );" fullword ascii
      $s18 = "IncreaseCount( $_POST[\"e0\"] , \"error\" );" fullword ascii
      $s19 = "$ip = $_SERVER[\"HTTP_X_FORWARDED_FOR\"];" fullword ascii
      $s20 = "return $geoip -> lookupCountryName( $ip );" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 20KB and
         ( 8 of them )
      ) or ( all of them )
}

rule Hestat_amadey_botnet_settings {
   meta:
      description = "amadey-botnet - file settings.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2019-01-30"
      hash1 = "25e3e53e418fa237a6620570acd55bf888c183623ae0991e89f773822c0fd862"
   strings:
      $x1 = "SaveConfig( $_POST[\"newlogin\"], $_POST[\"newpass\"], $_POST[\"oldpass\"], $_POST[\"obslogin\"], $_POST[\"obspass\"] );" fullword ascii
      $s2 = "$content = $content . $cr . $pr . \"\\$conf[\\\"observer_login\\\"]\" . $rn . \"\\\"\" . $ologin . \"\\\";\";" fullword ascii
      $s3 = "$content = $content . $cr . $pr . \"\\$conf[\\\"observer_login\\\"]\" . $rn . \"\\\"\" . $obslogin . \"\\\";\";" fullword ascii
      $s4 = "$content = $content . $cr . $pr . \"\\$conf[\\\"login\\\"]\" . $rn . \"\\\"\" . $clogin . \"\\\";\";" fullword ascii
      $s5 = "$content = $content . $cr . $pr . \"\\$conf[\\\"observer_password\\\"]\" . $rn . \"\\\"\" . md5( $obspass ) . \"\\\";\";" fullword ascii
      $s6 = "$content = $content . $cr . $pr . \"\\$conf[\\\"login\\\"]\" . $rn . \"\\\"\" . $newlogin . \"\\\";\";" fullword ascii
      $s7 = "SaveSQL( $_POST[\"sqlhost\"], $_POST[\"sqlname\"], $_POST[\"sqluser\"], $_POST[\"sqlpass\"], $_POST[\"oldpass\"] ); " fullword ascii
      $s8 = "$content = $content . $cr . $pr . \"\\$conf[\\\"password\\\"]\" . $rn . \"\\\"\" . md5( $newpass ) . \"\\\";\";" fullword ascii
      $s9 = "`unitid` varchar(16) NOT NULL, `exec` tinyint(1) NOT NULL DEFAULT '0', PRIMARY KEY (`id`), KEY `unitid` (`unitid`) ) ENGINE=MyI" fullword ascii
      $s10 = "$content = $content . $cr . $pr . \"\\$conf[\\\"observer_password\\\"]\" . $rn . \"\\\"\" . $opass . \"\\\";\";" fullword ascii
      $s11 = "$content = $content . $cr . $pr . \"\\$conf[\\\"password\\\"]\" . $rn . \"\\\"\" . $cpass . \"\\\";\";" fullword ascii
      $s12 = "function SaveConfig( $newlogin, $newpass, $oldpass, $obslogin, $obspass )" fullword ascii
      $s13 = "* Please enter observer login name." fullword ascii
      $s14 = "mysql_query( \"CREATE TABLE IF NOT EXISTS `tasks_exec` ( `id` int(11) NOT NULL AUTO_INCREMENT, `task_id` int(11) NOT NULL," fullword ascii
      $s15 = "&nbsp;<img src=\\\"images\\ic_2.png\\\">&nbsp;Change login data:" fullword ascii
      $s16 = "* Please enter new login name." fullword ascii
      $s17 = "echo \"<meta http-equiv=\\\"refresh\\\" content=\\\"1; url=settings.php\\\">\"; " fullword ascii
      $s18 = "<form action=\\\"\" . basename( $_SERVER['SCRIPT_NAME'] ) . \"\\\" method=\\\"post\\\" name=\\\"form\\\">" fullword ascii
      $s19 = "* Please enter observer password." fullword ascii
      $s20 = "* Please enter current CP password." fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 80KB and
         ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}