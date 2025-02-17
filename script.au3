#NoTrayIcon
#RequireAdmin
#Region
#AutoIt3Wrapper_Icon=Ressources\Icone.ico
#AutoIt3Wrapper_UseUpx=y
#AutoIt3Wrapper_Res_Fileversion=1.0.1.0
#AutoIt3Wrapper_Res_Language=1036
#AutoIt3Wrapper_Res_requestedExecutionLevel=requireAdministrator
#EndRegion
$CFRENAMED = RegRead ( "HKLM\Software\Microsoft\Windows\CurrentVersion\App Paths\combofix.exe" , "" )
If Not @error Then
	If StringInStr ( $CFRENAMED , "Combofix.exe" ) Then
		$CFRENAMED = ""
	EndIf
EndIf
Global $FILEPATHS [ 6 ] = [ @HomeDrive , @DesktopDir , @DesktopCommonDir , @UserProfileDir & "\Downloads" , @MyDocumentsDir & "\Téléchargements" , @MyDocumentsDir & "\Downloads" ]
Global $FILENAME [ 195 ] = [ "ad-fix*.*" , "Ad-R*.*" , "Addition*.txt" , "AdsFix*.*" , "AdwCleaner*.*" , "AHK_NavScan*.*" , "AntiZeroAccess*.*" , "AswMBR*.*" , "avenger*.*" , "avz4*.*" , "Blitzblank*.*" , "BFU*.*" , "Bootkit_remover*.*" , "BTFix*.*" , "BTKR*.*" , "catchme*.*" , "CFScript*.*" , "CKScanner*.*" , "Cleannavi*.*" , "CleanX-II*.*" , "CLRAV*.*" , "Combofix*.*" , "CSysFiles*.*" , "DaonolFix*.*" , "DeQuarantine*.*" , "DDO*.*" , "DDS*.*" , "DefenceInspector*.*" , "Defogger*.*" , "Deldomains*.*" , "DiagHelp*.*" , "Dial-a-fix*.*" , "drweb-cureit*.*" , "esetsmartinstaller*.*" , "exefix*.*" , "exehelper*.*" , "Extras????.txt" , "FindAWF*.*" , "FixerBro*.*" , "FixLog*.*" , "FixLop*.*" , "FixWalg*.*" , "Flash_disinfector*.*" , "ForceHide*.*" , "forcemove*.*" , "FoxScan*.*" , "FRST*.*" , "FSS*.*" , "FyK*.*" , "GetSystemInfo*.*" , "Gooredfix*.*" , "GrantPerms*.*" , "JRT*.*" , "HAMeb_Check*.*" , "haxfix*.*" , "HDDFix*.*" , "$HDDList*.*" , "HelpAsst_mebroot_fix*.*" , "hijackthis*.*" , "HJT*.*" , "HostsXpert*.*" , "info*.txt" , "JavaRa*.*" , "_kaf*.*" , "kaflog*.*" , "kill'em*.*" , "killafile*.*" , "Kenco*.*" , "KoobFix*.*" , "List'em*.*" , "List_Killem*.*" , "ListKill'em*.*" , "ListPart*.*" , "Load_TDSSKiller*.*" , "Log*.txt" , "LogonFix*.*" , "look2me-destroyer*.*" , "LopClean*.*" , "LopR*.*" , "LopS*.*" , "lopxp*.*" , "LSPFix*.*" , "maxlook*.*" , "mbr*.*" , "miniregtool*.*" , "minitoolbox*.*" , "mkv*.*" , "msncleaner*.*" , "msnfix*.*" , "myhosts*.*" , "myrights*.*" , "navilog1*.*" , "OneClick2RP*.*" , "Open-Config*.*" , "OTA*.exe" , "OTC*.exe" , "OTL*.txt" , "OTL*.exe" , "OTS*.exe" , "OTS*.txt" , "OTH*.exe" , "OTM*.exe" , "physicaldisk*.*" , "pca*.exe" , "PragmaFix*.*" , "Pre_diag*.*" , "Pre_Scan*.*" , "Pre_Script*.*" , "Prox*.exe" , "QooFix*.*" , "Quickdiag*.*" , "rapport_SX*.txt" , "rapport-WFR*.*" , "rapport.txt" , "RapportCHK*.*" , "rav.exe" , "RegistryTool*.*" , "RegLooks*.*" , "Reload_TDSSKiller*.*" , "RemAdvertisemen*.*" , "remover*.*" , "restorebfe*.*" , "result.txt" , "Report_*.*" , "RHosts*.*" , "rkill*.*" , "rkreport*.*" , "roguekiller*.*" , "Rooter*.*" , "RootRepeal*.*" , "RSIT*.*" , "RstAssociations*.*" , "RstHosts*.*" , "rustbfix*.*" , "SDFix*.*" , "Safebootkeyrepair*.*" , "Safeboot_repair*.*" , "sc-cleaner*.*" , "scan.txt" , "scanxp*.*" , "Script_*.*" , "SEAF*.*" , "Search.txt" , "SecurityCheck*.*" , "SecuScan*.*" , "ServicesRepair*.exe" , "Setup_Fix-Purge*.*" , "SetupMyRights*.*" , "Shortcut.txt" , "Shortcut_module*.*" , "Silent Runners*.*" , "SINO*.*" , "sitlog*.*" , "SmitFraudFix*.*" , "sreng*.*" , "ST_Fix*.*" , "Startup Programs*.*" , "supresstools*.*" , "SXCU*.exe" , "SystemLook*.*" , "TCleaner*.*" , "TmpSeaf*.*" , "TheKiller*.*" , "tdsskiller*.*" , "tdssq*.*" , "tfc*.*" , "ToolbarSD*.*" , "toolscleaner2*.*" , "toolsdiag*.*" , "Unhide*.*" , "USBFix*.*" , "virtumundobegone*.*" , "VundoFix*.*" , "WALG*.*" , "WareOut*.*" , "WGetIA*.*" , "WhyIGotInfected*.*" , "win32delfkil*.*" , "win32kdiag*.*" , "WinChk*.*" , "WinDelf*.*" , "WinFileReplace*.*" , "Winlogon*.*" , "Winsockxp*.*" , "WinUpdateFix*.*" , "WinUpdater*.*" , "WORT*.*" , "WUS_Fix*.*" , "WVCheck*.*" , "Yoog_Fix*.*" , "ZA-Scan*.*" , "Zeb-Restore*.*" , "ZHP*.*" , "Zoek*.*" , "ZSc*.*" ]
Global $FILESLIST [ 29 ] = [ @HomeDrive & "\log.txt" , @WindowsDir & "\grep.exe" , @WindowsDir & "\PEV.exe" , @WindowsDir & "\NIRCMD.exe" , @WindowsDir & "\MBR.exe" , @WindowsDir & "\SED.exe" , @WindowsDir & "\SWREG.exe" , @WindowsDir & "\SWSC.exe" , @WindowsDir & "\SWXCACLS.exe" , @WindowsDir & "\Zip.exe" , @WindowsDir & "MsnFix.txt" , @WindowsDir & "Look.bat" , @WindowsDir & "\system32\404Fix.exe" , @WindowsDir & "\system32\o4Patch.exe" , @WindowsDir & "\system32\VACFix.exe" , @WindowsDir & "\system32\VCCLSID.exe" , @WindowsDir & "\system32\IEDFix.exe" , @WindowsDir & "\system32\IEDFix.C.exe" , @WindowsDir & "\system32\Agent.OMZ.Fix.exe" , @WindowsDir & "\system32\WS2Fix.exe" , @WindowsDir & "\system32\Process.exe" , @WindowsDir & "\system32\Reboot.exe" , @WindowsDir & "\system32\RegDACL.exe" , @WindowsDir & "\system32\Restart.exe" , @WindowsDir & "\system32\SWReg.exe" , @WindowsDir & "\system32\SWSC.exe" , @WindowsDir & "\system32\SWXCacls.exe" , @WindowsDir & "\system32\SrchSTS.exe" , @WindowsDir & "\system32\Dumphive.exe" ]
Global $DIRLIST [ 85 ] = [ @HomeDrive & "\Qoobox" , @HomeDrive & "\JRT" , @HomeDrive & "\mbar" , @HomeDrive & "\Navilog1" , @HomeDrive & "\USBFix" , @HomeDrive & "\WORT" , @HomeDrive & "\FyK" , @HomeDrive & "\SDFix" , @HomeDrive & "\_OTL" , @HomeDrive & "\_OTM" , @HomeDrive & "\_OTS" , @HomeDrive & "\Toolbar SD" , @HomeDrive & "\Lop SD" , @HomeDrive & "\RSIT" , @HomeDrive & "\TDSSKiller" , @HomeDrive & "\_backupD" , @HomeDrive & "\Rooter$" , @HomeDrive & "\KoobFix" , @HomeDrive & "\YoogFix" , @HomeDrive & "\WGetIA" , @HomeDrive & "\WinFileReplace" , @HomeDrive & "\VundoFix Backups" , @HomeDrive & "\Sardu_2.0.4.3" , @HomeDrive & "\ST_Fix" , @HomeDrive & "\OTLPE_7" , @HomeDrive & "\Avenger" , @HomeDrive & "\MyHosts" , @HomeDrive & "\RustbFix" , @HomeDrive & "\SecuScan" , @HomeDrive & "\MSNCleaner" , @HomeDrive & "\pre_scan" , @HomeDrive & "\Combofix.{20D04FE0-3AEA-1069-A2D8-08002B30309D}" , @HomeDrive & "\32788R22FWJFW" , @HomeDrive & "\Combofix" , @HomeDrive & "\Fix-Purge" , @HomeDrive & "\LopSD$" , @HomeDrive & "\Scan" , @HomeDrive & "\ForceMove" , @HomeDrive & "\FRST" , @HomeDrive & "\zoek_backup" , @HomeDrive & "\ZHP" , @HomeDrive & "\Pre_Scan" , @HomeDrive & "\TDSSKiller_Quarantine" , @HomeDrive & "\Shortcut_Module" , @HomeDrive & "\AdwCleaner" , @HomeDrive & "\AdsFix" , @HomeDrive & "\Sitlog" , @HomeDrive & "\SecurityCheck" , @HomeDrive & "\QuickDiag" , @HomeDrive & "\HDDFix" , @HomeDrive & "\RegBackup" , @HomeDrive & "\FixerBro" , @UserProfileDir & "\Ad-Remover" , @UserProfileDir & "\SmitFraudFix" , @UserProfileDir & "\DoctorWeb" , @UserProfileDir & "\RK_Quarantine" , @UserProfileDir & "\Downloads\mbar" , @UserProfileDir & "\Downloads\FRST-OlderVersion" , @AppDataCommonDir & "\Open-Config" , @ProgramsCommonDir & "\FixLop" , @ProgramsCommonDir & "\List_Kill'em" , @ProgramsCommonDir & "\ZHP" , @ProgramsCommonDir & "\Hijackthis" , @ProgramsCommonDir & "\Fix-Purge" , @DesktopDir & "\GooredFix Backups" , @DesktopDir & "\DiagHelp" , @DesktopDir & "\Ad-Fix" , @DesktopDir & "\FRST-OlderVersion" , @DesktopDir & "\MsnFix" , @DesktopDir & "\rkill" , @DesktopDir & "\avz4" , @DesktopDir & "\mbar" , @DesktopDir & "\RK_Quarantine" , @ProgramFilesDir & "\Ad-Remover" , @ProgramFilesDir & "\FixLop" , @ProgramFilesDir & "\Navilog1" , @ProgramFilesDir & "\List_Kill'em" , @ProgramFilesDir & "\ZHPDiag" , @ProgramFilesDir & "\LopXp" , @ProgramFilesDir & "\SEAF" , @ProgramFilesDir & "\Trend Micro\Hijackthis" , @ProgramFilesDir & "\Hijackthis" , @WindowsDir & "\HaxFix" , @WindowsDir & "\Snack" , @TempDir & "\FindAWF" ]
Global $REGISTRYKEYS [ 54 ] = [ "HKCR\.L_K" , "HKCU\console_combofixbackup" , "HKCU\Software\pca" , "HKCU\Software\OldTimer Tools" , "HKCU\Software\Ad-Remover" , "HKCU\Software\g3n-h@ckm@n" , "HKCU\Software\Net-Worm.Win32.Kido removing too" , "HKCU\Software\USBFix" , "HKCU\Software\SEAF" , "HKCU\Software\Shortcut_Module" , "HKCU\Software\IDAVLab" , "HKCU\Software\TrendMicro\Hijackthis" , "HKCU\Software\AdsFix" , "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.cfxxe" , "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\MenuOrder\Start Menu2\Programs\List_Kill'em" , "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\MenuOrder\Start Menu2\Programs\FixLop" , "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\MenuOrder\Start Menu2\Programs\ZHP" , "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\MenuOrder\Start Menu2\Programs\HijackThis" , "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\MenuOrder\Start Menu2\Programs\Fix-Purge" , "HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\Ad-Remover" , "HKLM\SOFTWARE\pca" , "HKLM\SOFTWARE\OldTimer Tools" , "HKLM\SOFTWARE\Ad-Remover" , "HKLM\SOFTWARE\AdsFix" , "HKLM\SOFTWARE\AdwCleaner" , "HKLM\SOFTWARE\g3n-h@ckm@n" , "HKLM\SOFTWARE\USBFix" , "HKLM\SOFTWARE\SEAF" , "HKLM\SOFTWARE\IDAVLab" , "HKLM\SOFTWARE\Shortcut_Module" , "HKLM\SOFTWARE\Soeperman Enterprises Ltd." , "HKLM\SOFTWARE\Swearware" , "HKLM\SOFTWARE\Classes\.cfxxe" , "HKLM\SOFTWARE\Classes\cfxxefile" , "HKLM\SOFTWARE\TrendMicro\Hijackthis" , "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Ad-Remover" , "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Hijackthis" , "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\SEAF" , "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\USBFix" , "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\ZHPDiag_is1" , "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\FixLop_is1" , "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{List_Kill'em}_is1" , "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{3D8E9123-A7BA-4E66-8B66-AC46BFD13D9E}_is1" , "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{E88BA4E8-6B36-4D39-9499-C10B439819E1}_is1" , "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{01C25C02-A08E-49D7-BD37-9957E4A312DA}_is1" , "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\HijackThis.exe" , "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\combofix.exe" , "HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\Minimal\PEVSystemStart" , "HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\Minimal\procexp90.Sys" , "HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\Network\PEVSystemStart" , "HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\Network\procexp90.Sys" , "HKLM\SYSTEM\CurrentControlSet\Enum\Root\LEGACY_ASWMBR" , "HKLM\SYSTEM\CurrentControlSet\Enum\Root\LEGACY_DWPROT" , "HKLM\SYSTEM\CurrentControlSet\Services\aswMBR" ]
Global Const $WS_GROUP = 131072
Global Const $GUI_EVENT_CLOSE = + 4294967293
Global Const $GUI_CHECKED = 1
Global Const $GUI_DISABLE = 128
Global $OBJ_SR , $OBJ_WMI
Global $SYSTEMDRIVE = EnvGet ( "SystemDrive" ) & "\"
Func _SR_CREATERESTOREPOINT ( $STRDESCRIPTION )
	Local Const $MAX_DESC = 64
	Local Const $MAX_DESC_W = 256
	Local Const $BEGIN_SYSTEM_CHANGE = 100
	Local Const $MODIFY_SETTINGS = 12
	Local $_RESTOREPTINFO = DllStructCreate ( "DWORD dwEventType;DWORD dwRestorePtType;INT64 llSequenceNumber;WCHAR szDescription[" & $MAX_DESC_W & "]" )
	DllStructSetData ( $_RESTOREPTINFO , "dwEventType" , $BEGIN_SYSTEM_CHANGE )
	DllStructSetData ( $_RESTOREPTINFO , "dwRestorePtType" , $MODIFY_SETTINGS )
	DllStructSetData ( $_RESTOREPTINFO , "llSequenceNumber" , 0 )
	DllStructSetData ( $_RESTOREPTINFO , "szDescription" , $STRDESCRIPTION )
	Local $PRESTOREPTSPEC = DllStructGetPtr ( $_RESTOREPTINFO )
	Local $_SMGRSTATUS = DllStructCreate ( "UINT  nStatus;INT64 llSequenceNumber" )
	Local $PSMGRSTATUS = DllStructGetPtr ( $_SMGRSTATUS )
	Local $ARET = DllCall ( "SrClient.dll" , "BOOL" , "SRSetRestorePointW" , "ptr" , $PRESTOREPTSPEC , "ptr" , $PSMGRSTATUS )
	If @error Then Return 0
	Return $ARET [ 0 ]
EndFunc
Func _SR_ENUMRESTOREPOINTS ( )
	Local $ARET [ 1 ] [ 3 ] , $I = 0
	$ARET [ 0 ] [ 0 ] = 0
	If Not IsObj ( $OBJ_WMI ) Then $OBJ_WMI = ObjGet ( "winmgmts:root/default" )
	If Not IsObj ( $OBJ_WMI ) Then Return $ARET
	Local $RPSET = $OBJ_WMI .InstancesOf ( "SystemRestore" )
	If Not IsObj ( $RPSET ) Then Return $ARET
	For $RP In $RPSET
		$I += 1
		ReDim $ARET [ $I + 1 ] [ 3 ]
		$ARET [ $I ] [ 0 ] = $RP .SequenceNumber
		$ARET [ $I ] [ 1 ] = $RP .Description
		$ARET [ $I ] [ 2 ] = WMIDATESTRINGTODATE ( $RP .CreationTime )
	Next
	$ARET [ 0 ] [ 0 ] = $I
	Return $ARET
EndFunc
Func WMIDATESTRINGTODATE ( $DTMDATE )
	Return ( StringMid ( $DTMDATE , 5 , 2 ) & "/" & StringMid ( $DTMDATE , 7 , 2 ) & "/" & StringLeft ( $DTMDATE , 4 ) & " " & StringMid ( $DTMDATE , 9 , 2 ) & ":" & StringMid ( $DTMDATE , 11 , 2 ) & ":" & StringMid ( $DTMDATE , 13 , 2 ) )
EndFunc
Func _SR_REMOVEALLRESTOREPOINTS ( )
	Local $ARP = _SR_ENUMRESTOREPOINTS ( ) , $RET = 0
	For $I = 1 To $ARP [ 0 ] [ 0 ]
		$RET += _SR_REMOVERESTOREPOINT ( $ARP [ $I ] [ 0 ] )
	Next
	Return $RET
EndFunc
Func _SR_REMOVERESTOREPOINT ( $RPSEQNUMBER )
	Local $ARET = DllCall ( "SrClient.dll" , "DWORD" , "SRRemoveRestorePoint" , "DWORD" , $RPSEQNUMBER )
	If @error Then
		Return SetError ( 1 , 0 , 0 )
	ElseIf $ARET [ 0 ] = 0 Then
		Return 1
	Else
		Return SetError ( 1 , 0 , 0 )
	EndIf
EndFunc
Func _SR_ENABLE ( $DRIVEL = $SYSTEMDRIVE )
	If Not IsObj ( $OBJ_SR ) Then $OBJ_SR = ObjGet ( "winmgmts:{impersonationLevel=impersonate}!root/default:SystemRestore" )
	If Not IsObj ( $OBJ_SR ) Then Return 0
	If $OBJ_SR .Enable ( $DRIVEL ) = 0 Then Return 1
	Return 0
EndFunc
Global $H__ADVAPI32DLL = @SystemDir & "\Advapi32.dll"
Global $H__KERNEL32DLL = @SystemDir & "\Kernel32.dll"
Global $A__PRIV [ 4 ] [ 2 ]
Global Const $GENERIC_ALL = 268435456
Global Const $ACL_REVISION = 2
Global Enum $SE_UNKNOWN_OBJECT_TYPE = 0 , $SE_FILE_OBJECT , $SE_SERVICE , $SE_PRINTER , $SE_REGISTRY_KEY , $SE_LMSHARE , $SE_KERNEL_OBJECT , $SE_WINDOW_OBJECT , $SE_DS_OBJECT , $SE_DS_OBJECT_ALL , $SE_PROVIDER_DEFINED_OBJECT , $SE_WMIGUID_OBJECT , $SE_REGISTRY_WOW64_32KEY
Global Enum $NOT_USED_ACCESS = 0 , $GRANT_ACCESS , $SET_ACCESS , $DENY_ACCESS , $REVOKE_ACCESS , $SET_AUDIT_SUCCESS , $SET_AUDIT_FAILURE
Global $RESOURCESSTATE = 0
Func _INITIATEPERMISSIONRESOURCES ( )
	$H__ADVAPI32DLL = DllOpen ( @SystemDir & "\Advapi32.dll" )
	$H__KERNEL32DLL = DllOpen ( @SystemDir & "\Kernel32.dll" )
	$A__PRIV [ 0 ] [ 0 ] = "SeRestorePrivilege"
	$A__PRIV [ 0 ] [ 1 ] = 2
	$A__PRIV [ 1 ] [ 0 ] = "SeTakeOwnershipPrivilege"
	$A__PRIV [ 1 ] [ 1 ] = 2
	$A__PRIV [ 2 ] [ 0 ] = "SeDebugPrivilege"
	$A__PRIV [ 2 ] [ 1 ] = 2
	$A__PRIV [ 3 ] [ 0 ] = "SeSecurityPrivilege"
	$A__PRIV [ 3 ] [ 1 ] = 2
	$A__PREV = _SETPRIVILEGE ( $A__PRIV )
	$RESOURCESSTATE = 1
EndFunc
Func _SETPRIVILEGE ( $AVPRIVILEGE )
	Local $IDIM = UBound ( $AVPRIVILEGE , 0 ) , $AVPREVSTATE [ 1 ] [ 2 ]
	If Not ( $IDIM <= 2 And UBound ( $AVPRIVILEGE , $IDIM ) = 2 ) Then Return SetError ( 1300 , 0 , $AVPREVSTATE )
	If $IDIM = 1 Then
		Local $AVTEMP [ 1 ] [ 2 ]
		$AVTEMP [ 0 ] [ 0 ] = $AVPRIVILEGE [ 0 ]
		$AVTEMP [ 0 ] [ 1 ] = $AVPRIVILEGE [ 1 ]
		$AVPRIVILEGE = $AVTEMP
		$AVTEMP = 0
	EndIf
	Local $K , $TAGTP = "dword" , $ITOKENS = UBound ( $AVPRIVILEGE , 1 )
	Do
		$K += 1
		$TAGTP &= ";dword;long;dword"
	Until $K = $ITOKENS
	Local $TCURRSTATE , $TPREVSTATE , $PPREVSTATE , $TLUID , $AHGCP , $AVOPT , $AIGLE
	$TCURRSTATE = DllStructCreate ( $TAGTP )
	$TPREVSTATE = DllStructCreate ( $TAGTP )
	$PPREVSTATE = DllStructGetPtr ( $TPREVSTATE )
	$TLUID = DllStructCreate ( "dword;long" )
	DllStructSetData ( $TCURRSTATE , 1 , $ITOKENS )
	For $I = 0 To $ITOKENS + 4294967295
		DllCall ( $H__ADVAPI32DLL , "int" , "LookupPrivilegeValue" , "str" , "" , "str" , $AVPRIVILEGE [ $I ] [ 0 ] , "ptr" , DllStructGetPtr ( $TLUID ) )
		DllStructSetData ( $TCURRSTATE , 3 * $I + 2 , DllStructGetData ( $TLUID , 1 ) )
		DllStructSetData ( $TCURRSTATE , 3 * $I + 3 , DllStructGetData ( $TLUID , 2 ) )
		DllStructSetData ( $TCURRSTATE , 3 * $I + 4 , $AVPRIVILEGE [ $I ] [ 1 ] )
	Next
	$AHGCP = DllCall ( $H__KERNEL32DLL , "hwnd" , "GetCurrentProcess" )
	$AVOPT = DllCall ( $H__ADVAPI32DLL , "int" , "OpenProcessToken" , "hwnd" , $AHGCP [ 0 ] , "dword" , BitOR ( 32 , 8 ) , "hwnd*" , 0 )
	DllCall ( $H__ADVAPI32DLL , "int" , "AdjustTokenPrivileges" , "hwnd" , $AVOPT [ 3 ] , "int" , False , "ptr" , DllStructGetPtr ( $TCURRSTATE ) , "dword" , DllStructGetSize ( $TCURRSTATE ) , "ptr" , $PPREVSTATE , "dword*" , 0 )
	$AIGLE = DllCall ( $H__KERNEL32DLL , "dword" , "GetLastError" )
	DllCall ( $H__KERNEL32DLL , "int" , "CloseHandle" , "hwnd" , $AVOPT [ 3 ] )
	Local $ICOUNT = DllStructGetData ( $TPREVSTATE , 1 )
	If $ICOUNT > 0 Then
		Local $PLUID , $AVLPN , $TNAME , $AVPREVSTATE [ $ICOUNT ] [ 2 ]
		For $I = 0 To $ICOUNT + 4294967295
			$PLUID = $PPREVSTATE + 12 * $I + 4
			$AVLPN = DllCall ( $H__ADVAPI32DLL , "int" , "LookupPrivilegeName" , "str" , "" , "ptr" , $PLUID , "ptr" , 0 , "dword*" , 0 )
			$TNAME = DllStructCreate ( "char[" & $AVLPN [ 4 ] & "]" )
			DllCall ( $H__ADVAPI32DLL , "int" , "LookupPrivilegeName" , "str" , "" , "ptr" , $PLUID , "ptr" , DllStructGetPtr ( $TNAME ) , "dword*" , DllStructGetSize ( $TNAME ) )
			$AVPREVSTATE [ $I ] [ 0 ] = DllStructGetData ( $TNAME , 1 )
			$AVPREVSTATE [ $I ] [ 1 ] = DllStructGetData ( $TPREVSTATE , 3 * $I + 4 )
		Next
	EndIf
	Return SetError ( $AIGLE [ 0 ] , 0 , $AVPREVSTATE )
EndFunc
Func _GRANTALLACCESS ( $ONAME , $_SE_OBJECT_TYPE = $SE_FILE_OBJECT , $SETOWNER = "Administrators" , $RECURSE = 1 )
	Local $APERM [ 1 ] [ 3 ]
	$APERM [ 0 ] [ 0 ] = "Everyone"
	$APERM [ 0 ] [ 1 ] = 1
	$APERM [ 0 ] [ 2 ] = $GENERIC_ALL
	Return _SETOBJECTPERMISSIONS ( $ONAME , $APERM , $_SE_OBJECT_TYPE , $SETOWNER , 1 , $RECURSE )
EndFunc
Func _SETOBJECTPERMISSIONS ( $ONAME , $APERMISSIONS , $_SE_OBJECT_TYPE = $SE_FILE_OBJECT , $SETOWNER = "" , $CLEARDACL = 0 , $RECURSE = 0 , $INHERIT = 3 )
	If $RESOURCESSTATE = 0 Then _INITIATEPERMISSIONRESOURCES ( )
	If Not IsArray ( $APERMISSIONS ) Or UBound ( $APERMISSIONS , 2 ) < 3 Then Return SetError ( 1 , 0 , 0 )
	Local $DACL = _CREATEDACLFROMARRAY ( $APERMISSIONS , $INHERIT )
	Local $HASDENIEDACES = @extended
	Local $SECURITY_INFORMATION = 4 , $POWNER = 0
	If $SETOWNER <> "" Then
		If Not IsDllStruct ( $SETOWNER ) Then $SETOWNER = _GETSIDSTRUCT ( $SETOWNER )
		$POWNER = DllStructGetPtr ( $SETOWNER )
		If $POWNER And _ISVALIDSID ( $POWNER ) Then
			$SECURITY_INFORMATION = 5
		Else
			$POWNER = 0
		EndIf
	EndIf
	If Not IsPtr ( $ONAME ) And $_SE_OBJECT_TYPE = $SE_FILE_OBJECT Then
		Return _SETFILEOBJECTSECURITY ( $ONAME , $DACL , $POWNER , $CLEARDACL , $RECURSE , $HASDENIEDACES , $SECURITY_INFORMATION )
	ElseIf Not IsPtr ( $ONAME ) And $_SE_OBJECT_TYPE = $SE_REGISTRY_KEY Then
		Return _SETREGOBJECTSECURITY ( $ONAME , $DACL , $POWNER , $CLEARDACL , $RECURSE , $HASDENIEDACES , $SECURITY_INFORMATION )
	Else
		If $CLEARDACL Then _CLEAROBJECTDACL ( $ONAME , $_SE_OBJECT_TYPE )
		Return _SETOBJECTSECURITY ( $ONAME , $_SE_OBJECT_TYPE , $SECURITY_INFORMATION , $POWNER , 0 , $DACL , 0 )
	EndIf
EndFunc
Func _CREATEDACLFROMARRAY ( ByRef $APERMISSIONS , ByRef $INHERIT )
	Local $UB2 = UBound ( $APERMISSIONS , 2 )
	If Not IsArray ( $APERMISSIONS ) Or $UB2 < 3 Then Return SetError ( 1 , 0 , 0 )
	Local $UB = UBound ( $APERMISSIONS ) , $PSID [ $UB ] , $L = 0 , $_TRUSTEE_TYPE = 1
	Local $ACCESSMODE , $HASDENIEDACES = 0 , $ACALL
	Local $_EXPLICIT_ACCESS , $T_EXPLICIT_ACCESS = "DWORD;DWORD;DWORD;ptr;DWORD;DWORD;DWORD;ptr"
	For $I = 1 To $UB + 4294967295
		$T_EXPLICIT_ACCESS &= ";DWORD;DWORD;DWORD;ptr;DWORD;DWORD;DWORD;ptr"
	Next
	$_EXPLICIT_ACCESS = DllStructCreate ( $T_EXPLICIT_ACCESS )
	For $I = 0 To $UB + 4294967295
		If Not IsDllStruct ( $APERMISSIONS [ $I ] [ 0 ] ) Then $APERMISSIONS [ $I ] [ 0 ] = _GETSIDSTRUCT ( $APERMISSIONS [ $I ] [ 0 ] )
		$PSID [ $I ] = DllStructGetPtr ( $APERMISSIONS [ $I ] [ 0 ] )
		If Not _ISVALIDSID ( $PSID [ $I ] ) Then ContinueLoop
		DllStructSetData ( $_EXPLICIT_ACCESS , $L + 1 , $APERMISSIONS [ $I ] [ 2 ] )
		If $APERMISSIONS [ $I ] [ 1 ] = 0 Then
			$HASDENIEDACES = 1
			$ACCESSMODE = $DENY_ACCESS
		Else
			$ACCESSMODE = $SET_ACCESS
		EndIf
		If $UB2 > 3 Then $INHERIT = $APERMISSIONS [ $I ] [ 3 ]
		DllStructSetData ( $_EXPLICIT_ACCESS , $L + 2 , $ACCESSMODE )
		DllStructSetData ( $_EXPLICIT_ACCESS , $L + 3 , $INHERIT )
		DllStructSetData ( $_EXPLICIT_ACCESS , $L + 6 , 0 )
		$ACALL = DllCall ( $H__ADVAPI32DLL , "BOOL" , "LookupAccountSid" , "ptr" , 0 , "ptr" , $PSID [ $I ] , "ptr*" , 0 , "dword*" , 32 , "ptr*" , 0 , "dword*" , 32 , "dword*" , 0 )
		If Not @error Then $_TRUSTEE_TYPE = $ACALL [ 7 ]
		DllStructSetData ( $_EXPLICIT_ACCESS , $L + 7 , $_TRUSTEE_TYPE )
		DllStructSetData ( $_EXPLICIT_ACCESS , $L + 8 , $PSID [ $I ] )
		$L += 8
	Next
	Local $P_EXPLICIT_ACCESS = DllStructGetPtr ( $_EXPLICIT_ACCESS )
	$ACALL = DllCall ( $H__ADVAPI32DLL , "DWORD" , "SetEntriesInAcl" , "ULONG" , $UB , "ptr" , $P_EXPLICIT_ACCESS , "ptr" , 0 , "ptr*" , 0 )
	If @error Or $ACALL [ 0 ] Then Return SetError ( 1 , 0 , 0 )
	Return SetExtended ( $HASDENIEDACES , $ACALL [ 4 ] )
EndFunc
Func _GETSIDSTRUCT ( $ACCOUNTNAME )
	If $ACCOUNTNAME = "TrustedInstaller" Then $ACCOUNTNAME = "NT SERVICE\TrustedInstaller"
	If $ACCOUNTNAME = "Everyone" Then
		Return _STRINGSIDTOSID ( "S-1-1-0" )
	ElseIf $ACCOUNTNAME = "Authenticated Users" Then
		Return _STRINGSIDTOSID ( "S-1-5-11" )
	ElseIf $ACCOUNTNAME = "System" Then
		Return _STRINGSIDTOSID ( "S-1-5-18" )
	ElseIf $ACCOUNTNAME = "Administrators" Then
		Return _STRINGSIDTOSID ( "S-1-5-32-544" )
	ElseIf $ACCOUNTNAME = "Users" Then
		Return _STRINGSIDTOSID ( "S-1-5-32-545" )
	ElseIf $ACCOUNTNAME = "Guests" Then
		Return _STRINGSIDTOSID ( "S-1-5-32-546" )
	ElseIf $ACCOUNTNAME = "Power Users" Then
		Return _STRINGSIDTOSID ( "S-1-5-32-547" )
	ElseIf $ACCOUNTNAME = "Local Authority" Then
		Return _STRINGSIDTOSID ( "S-1-2" )
	ElseIf $ACCOUNTNAME = "Creator Owner" Then
		Return _STRINGSIDTOSID ( "S-1-3-0" )
	ElseIf $ACCOUNTNAME = "NT Authority" Then
		Return _STRINGSIDTOSID ( "S-1-5-1" )
	ElseIf $ACCOUNTNAME = "Restricted" Then
		Return _STRINGSIDTOSID ( "S-1-5-12" )
	ElseIf StringRegExp ( $ACCOUNTNAME , "\A(S-1-\d+(-\d+){0,5})\z" ) Then
		Return _STRINGSIDTOSID ( $ACCOUNTNAME )
	Else
		Local $SID = _LOOKUPACCOUNTNAME ( $ACCOUNTNAME )
		Return _STRINGSIDTOSID ( $SID )
	EndIf
EndFunc
Func _STRINGSIDTOSID ( $SSID )
	Local $ARESULT = DllCall ( $H__ADVAPI32DLL , "bool" , "ConvertStringSidToSidW" , "wstr" , $SSID , "ptr*" , 0 )
	If @error Then Return SetError ( @error , @extended , 0 )
	If Not $ARESULT [ 0 ] Then Return 0
	Local $ISIZE = _GETLENGTHSID ( $ARESULT [ 2 ] )
	Local $TBUFFER = DllStructCreate ( "byte Data[" & $ISIZE & "]" , $ARESULT [ 2 ] )
	Local $TSID = DllStructCreate ( "byte Data[" & $ISIZE & "]" )
	DllStructSetData ( $TSID , "Data" , DllStructGetData ( $TBUFFER , "Data" ) )
	DllCall ( $H__KERNEL32DLL , "ptr" , "LocalFree" , "ptr" , $ARESULT [ 2 ] )
	Return $TSID
EndFunc
Func _GETLENGTHSID ( $PSID )
	If Not _ISVALIDSID ( $PSID ) Then Return SetError ( + 4294967295 , 0 , "" )
	Local $ARESULT = DllCall ( $H__ADVAPI32DLL , "dword" , "GetLengthSid" , "ptr" , $PSID )
	If @error Then Return SetError ( @error , @extended , 0 )
	Return $ARESULT [ 0 ]
EndFunc
Func _LOOKUPACCOUNTNAME ( $SACCOUNT , $SSYSTEM = "" )
	Local $TDATA = DllStructCreate ( "byte SID[256]" )
	Local $PSID = DllStructGetPtr ( $TDATA , "SID" )
	Local $ARESULT = DllCall ( $H__ADVAPI32DLL , "bool" , "LookupAccountNameW" , "wstr" , $SSYSTEM , "wstr" , $SACCOUNT , "ptr" , $PSID , "dword*" , 256 , "wstr" , "" , "dword*" , 256 , "int*" , 0 )
	If @error Then Return SetError ( @error , @extended , 0 )
	If Not $ARESULT [ 0 ] Then Return 0
	Return _SIDTOSTRINGSID ( $PSID )
EndFunc
Func _SIDTOSTRINGSID ( $PSID )
	If Not _ISVALIDSID ( $PSID ) Then Return SetError ( + 4294967295 , 0 , "" )
	Local $ARESULT = DllCall ( $H__ADVAPI32DLL , "int" , "ConvertSidToStringSidW" , "ptr" , $PSID , "ptr*" , 0 )
	If @error Then Return SetError ( @error , @extended , "" )
	If Not $ARESULT [ 0 ] Then Return ""
	Local $TBUFFER = DllStructCreate ( "wchar Text[256]" , $ARESULT [ 2 ] )
	Local $SSID = DllStructGetData ( $TBUFFER , "Text" )
	DllCall ( $H__KERNEL32DLL , "ptr" , "LocalFree" , "ptr" , $ARESULT [ 2 ] )
	Return $SSID
EndFunc
Func _ISVALIDSID ( $PSID )
	Local $ARESULT = DllCall ( $H__ADVAPI32DLL , "bool" , "IsValidSid" , "ptr" , $PSID )
	If @error Then Return SetError ( @error , @extended , False )
	Return $ARESULT [ 0 ]
EndFunc
Func _SETFILEOBJECTSECURITY ( $ONAME , ByRef $DACL , ByRef $POWNER , ByRef $CLEARDACL , ByRef $RECURSE , ByRef $HASDENIEDACES , ByRef $SECURITY_INFORMATION )
	Local $RET , $NAME
	If Not $HASDENIEDACES Then
		If $CLEARDACL Then _CLEAROBJECTDACL ( $ONAME , $SE_FILE_OBJECT )
		$RET = _SETOBJECTSECURITY ( $ONAME , $SE_FILE_OBJECT , $SECURITY_INFORMATION , $POWNER , 0 , $DACL , 0 )
	EndIf
	If $RECURSE Then
		Local $H = FileFindFirstFile ( $ONAME & "\*" )
		While 1
			$NAME = FileFindNextFile ( $H )
			If $RECURSE = 1 Or $RECURSE = 2 And @extended = 1 Then
				_SETFILEOBJECTSECURITY ( $ONAME & "\" & $NAME , $DACL , $POWNER , $CLEARDACL , $RECURSE , $HASDENIEDACES , $SECURITY_INFORMATION )
			ElseIf @error Then
				ExitLoop
			ElseIf $RECURSE = 1 Or $RECURSE = 3 Then
				If $CLEARDACL Then _CLEAROBJECTDACL ( $ONAME & "\" & $NAME , $SE_FILE_OBJECT )
				_SETOBJECTSECURITY ( $ONAME & "\" & $NAME , $SE_FILE_OBJECT , $SECURITY_INFORMATION , $POWNER , 0 , $DACL , 0 )
			EndIf
		WEnd
		FileClose ( $H )
	EndIf
	If $HASDENIEDACES Then
		If $CLEARDACL Then _CLEAROBJECTDACL ( $ONAME , $SE_FILE_OBJECT )
		$RET = _SETOBJECTSECURITY ( $ONAME , $SE_FILE_OBJECT , $SECURITY_INFORMATION , $POWNER , 0 , $DACL , 0 )
	EndIf
	Return $RET
EndFunc
Func _SETREGOBJECTSECURITY ( $ONAME , ByRef $DACL , ByRef $POWNER , ByRef $CLEARDACL , ByRef $RECURSE , ByRef $HASDENIEDACES , ByRef $SECURITY_INFORMATION )
	If $RESOURCESSTATE = 0 Then _INITIATEPERMISSIONRESOURCES ( )
	Local $RET , $I = 0 , $NAME
	If Not $HASDENIEDACES Then
		If $CLEARDACL Then _CLEAROBJECTDACL ( $ONAME , $SE_REGISTRY_KEY )
		$RET = _SETOBJECTSECURITY ( $ONAME , $SE_REGISTRY_KEY , $SECURITY_INFORMATION , $POWNER , 0 , $DACL , 0 )
	EndIf
	If $RECURSE Then
		While 1
			$I += 1
			$NAME = RegEnumKey ( $ONAME , $I )
			If @error Then ExitLoop
			_SETREGOBJECTSECURITY ( $ONAME & "\" & $NAME , $DACL , $POWNER , $CLEARDACL , $RECURSE , $HASDENIEDACES , $SECURITY_INFORMATION )
		WEnd
	EndIf
	If $HASDENIEDACES Then
		If $CLEARDACL Then _CLEAROBJECTDACL ( $ONAME , $SE_REGISTRY_KEY )
		$RET = _SETOBJECTSECURITY ( $ONAME , $SE_REGISTRY_KEY , $SECURITY_INFORMATION , $POWNER , 0 , $DACL , 0 )
	EndIf
	Return $RET
EndFunc
Func _CLEAROBJECTDACL ( $ONAME , $_SE_OBJECT_TYPE = $SE_FILE_OBJECT )
	If $RESOURCESSTATE = 0 Then _INITIATEPERMISSIONRESOURCES ( )
	Local $BUFFER = DllStructCreate ( "byte[32]" ) , $ARET
	Local $DACL = DllStructGetPtr ( $BUFFER , 1 )
	DllCall ( $H__ADVAPI32DLL , "bool" , "InitializeAcl" , "Ptr" , $DACL , "dword" , DllStructGetSize ( $BUFFER ) , "dword" , $ACL_REVISION )
	If IsPtr ( $ONAME ) Then
		$ARET = DllCall ( $H__ADVAPI32DLL , "dword" , "SetSecurityInfo" , "handle" , $ONAME , "dword" , $_SE_OBJECT_TYPE , "dword" , 4 , "ptr" , 0 , "ptr" , 0 , "ptr" , $DACL , "ptr" , 0 )
	Else
		If $_SE_OBJECT_TYPE = $SE_REGISTRY_KEY Then $ONAME = _SECURITY_REGKEYNAME ( $ONAME )
		DllCall ( $H__ADVAPI32DLL , "DWORD" , "SetNamedSecurityInfo" , "str" , $ONAME , "dword" , $_SE_OBJECT_TYPE , "DWORD" , 4 , "ptr" , 0 , "ptr" , 0 , "ptr" , 0 , "ptr" , 0 )
		$ARET = DllCall ( $H__ADVAPI32DLL , "DWORD" , "SetNamedSecurityInfo" , "str" , $ONAME , "dword" , $_SE_OBJECT_TYPE , "DWORD" , 4 , "ptr" , 0 , "ptr" , 0 , "ptr" , $DACL , "ptr" , 0 )
	EndIf
	If @error Then Return SetError ( @error , 0 , 0 )
	Return SetError ( $ARET [ 0 ] , 0 , Number ( $ARET [ 0 ] = 0 ) )
EndFunc
Func _SECURITY_REGKEYNAME ( $REGKEY )
	If StringInStr ( $REGKEY , "\\" ) = 1 Then
		$REGKEY = StringRegExpReplace ( $REGKEY , "(?i)\\(HKEY_CLASSES_ROOT|HKCR)" , "\CLASSES_ROOT" )
		$REGKEY = StringRegExpReplace ( $REGKEY , "(?i)\\(HKEY_CURRENT_USER|HKCU)" , "\CURRENT_USER" )
		$REGKEY = StringRegExpReplace ( $REGKEY , "(?i)\\(HKEY_LOCAL_MACHINE|HKLM)" , "\MACHINE" )
		$REGKEY = StringRegExpReplace ( $REGKEY , "(?i)\\(HKEY_USERS|HKU)" , "\USERS" )
	Else
		$REGKEY = StringRegExpReplace ( $REGKEY , "(?i)\A(HKEY_CLASSES_ROOT|HKCR)" , "CLASSES_ROOT" )
		$REGKEY = StringRegExpReplace ( $REGKEY , "(?i)\A(HKEY_CURRENT_USER|HKCU)" , "CURRENT_USER" )
		$REGKEY = StringRegExpReplace ( $REGKEY , "(?i)\A(HKEY_LOCAL_MACHINE|HKLM)" , "MACHINE" )
		$REGKEY = StringRegExpReplace ( $REGKEY , "(?i)\A(HKEY_USERS|HKU)" , "USERS" )
	EndIf
	Return $REGKEY
EndFunc
Func _SETOBJECTSECURITY ( $ONAME , $_SE_OBJECT_TYPE , $SECURITY_INFORMATION , $POWNER = 0 , $PGROUP = 0 , $DACL = 0 , $SACL = 0 )
	Local $ACALL
	If $RESOURCESSTATE = 0 Then _INITIATEPERMISSIONRESOURCES ( )
	If $DACL And Not _ISVALIDACL ( $DACL ) Then Return 0
	If $SACL And Not _ISVALIDACL ( $SACL ) Then Return 0
	If IsPtr ( $ONAME ) Then
		$ACALL = DllCall ( $H__ADVAPI32DLL , "dword" , "SetSecurityInfo" , "handle" , $ONAME , "dword" , $_SE_OBJECT_TYPE , "dword" , $SECURITY_INFORMATION , "ptr" , $POWNER , "ptr" , $PGROUP , "ptr" , $DACL , "ptr" , $SACL )
	Else
		If $_SE_OBJECT_TYPE = $SE_REGISTRY_KEY Then $ONAME = _SECURITY_REGKEYNAME ( $ONAME )
		$ACALL = DllCall ( $H__ADVAPI32DLL , "dword" , "SetNamedSecurityInfo" , "str" , $ONAME , "dword" , $_SE_OBJECT_TYPE , "dword" , $SECURITY_INFORMATION , "ptr" , $POWNER , "ptr" , $PGROUP , "ptr" , $DACL , "ptr" , $SACL )
	EndIf
	If @error Then Return SetError ( 1 , 0 , 0 )
	If $ACALL [ 0 ] And $POWNER Then
		If _SETOBJECTOWNER ( $ONAME , $_SE_OBJECT_TYPE , _SIDTOSTRINGSID ( $POWNER ) ) Then Return _SETOBJECTSECURITY ( $ONAME , $_SE_OBJECT_TYPE , $SECURITY_INFORMATION + 4294967295 , 0 , $PGROUP , $DACL , $SACL )
	EndIf
	Return SetError ( $ACALL [ 0 ] , 0 , Number ( $ACALL [ 0 ] = 0 ) )
EndFunc
Func _SETOBJECTOWNER ( $ONAME , $_SE_OBJECT_TYPE = $SE_FILE_OBJECT , $ACCOUNTNAME = "Administrators" )
	If $RESOURCESSTATE = 0 Then _INITIATEPERMISSIONRESOURCES ( )
	Local $SID = _GETSIDSTRUCT ( $ACCOUNTNAME ) , $ARET
	Local $PSID = DllStructGetPtr ( $SID )
	If IsPtr ( $ONAME ) Then
		$ARET = DllCall ( $H__ADVAPI32DLL , "dword" , "SetSecurityInfo" , "handle" , $ONAME , "dword" , $_SE_OBJECT_TYPE , "dword" , 1 , "ptr" , $PSID , "ptr" , 0 , "ptr" , 0 , "ptr" , 0 )
	Else
		If $_SE_OBJECT_TYPE = $SE_REGISTRY_KEY Then $ONAME = _SECURITY_REGKEYNAME ( $ONAME )
		$ARET = DllCall ( $H__ADVAPI32DLL , "DWORD" , "SetNamedSecurityInfo" , "str" , $ONAME , "dword" , $_SE_OBJECT_TYPE , "DWORD" , 1 , "ptr" , $PSID , "ptr" , 0 , "ptr" , 0 , "ptr" , 0 )
	EndIf
	If @error Then Return SetError ( @error , 0 , False )
	Return SetError ( $ARET [ 0 ] , 0 , Number ( $ARET [ 0 ] = 0 ) )
EndFunc
Func _ISVALIDACL ( $ACL )
	If $ACL = 0 Then Return SetError ( 1 , 0 , 0 )
	Local $ACALL = DllCall ( $H__ADVAPI32DLL , "bool" , "IsValidAcl" , "ptr" , $ACL )
	If @error Or Not $ACALL [ 0 ] Then Return 0
	Return 1
EndFunc
Select
Case StringInStr ( "040c,080c,0c0c,100c,140c,180c" , @OSLang )
	$LANGUE = "Francais"
Case StringInStr ( "0409,0809,0c09,1009,1409,1809,1c09,2009,2409,2809,2c09,3009,3409" , @OSLang )
	$LANGUE = "Anglais"
Case StringInStr ( "0407,0807,0c07,1007,1407" , @OSLang )
	$LANGUE = "Allemand"
Case StringInStr ( "0416" , @OSLang )
	$LANGUE = "PortugaisBR"
Case Else
	$LANGUE = "Anglais"
EndSelect
Switch $LANGUE
Case $LANGUE = "Francais"
	$X = 65
	$G_EXECUTER = "Exécuter"
	$G_UAC = "Réactiver l'UAC"
	$G_TOOLS = "Supprimer les outils de désinfection"
	$G_REGSAVE = "Effectuer une sauvegarde du registre"
	$G_PURGEREST = "Purger la restauration système"
	$G_REINITPARAMS = "Réinitialisation des paramètres système"
	$G2_PROGRESS = "Nettoyage en cours..."
	$G2_UAC = "Réactivation de l'UAC"
	$G2_TOOLS = "Suppression des outils de désinfection"
	$G2_SAVE = "Sauvegarde de la base de registre"
	$G2_RESTO = "Purge de la restauration système"
	$G2_SYSPARAMS = "Réinitialisation des paramètres système"
	$R_UACOK = "Activation de l'UAC ... OK"
	$R_UACKO = "Activation de l'UAC ... Erreur !"
	$R_TOOLS = "Suppression des outils de désinfection ..."
	$R_SUPPRIME = "Supprimé"
	$R_SUPPRIMEE = "Supprimée"
	$R_ERREURSUPPR = "Erreur de suppression"
	$R_SAVEOK = "Sauvegarde de la base de registre ... OK"
	$R_SAVEKO = "Sauvegarde de la base de registre ... Erreur !"
	$R_RESTO = "Purge de la restauration système ..."
	$R_RESTOOK = "Nouveau point de restauration créé !"
	$R_RESTOKO = "Erreur ! Impossible de créer un nouveau point de restauration."
	$R_SYSPARAMS = "Réinitialisation des paramètres système ... OK"
	$R_RAPPORTCREE = "Rapport créé le"
	$R_MISAJOUR = "Mis à jour le"
	$R_NOMDUTILISATEUR = "Nom d'utilisateur"
	$R_A = "à"
	$R_HOURDE = ""
	$R_PAR = "par"
	$R_SYSTEME = "Système d'exploitation"
	$O_EOD = "Fin de désinfection"
Case $LANGUE = "Anglais"
	$X = 65
	$G_EXECUTER = "Run"
	$G_UAC = "Activate UAC"
	$G_TOOLS = "Remove disinfection tools"
	$G_REGSAVE = "Create registry backup"
	$G_PURGEREST = "Purge system restore"
	$G_REINITPARAMS = "Reset system settings"
	$G2_PROGRESS = "Cleaning in progress..."
	$G2_UAC = "Activating UAC"
	$G2_TOOLS = "Removing disinfection tools"
	$G2_SAVE = "Creating registry backup"
	$G2_RESTO = "Cleaning system restore"
	$G2_SYSPARAMS = "Resetting system settings"
	$R_UACOK = "Activating UAC ... OK"
	$R_UACKO = "Activating UAC ... Error !"
	$R_TOOLS = "Removing disinfection tools ..."
	$R_SUPPRIME = "Deleted"
	$R_SUPPRIMEE = "Deleted"
	$R_ERREURSUPPR = "Error when deleting"
	$R_SAVEOK = "Creating registry backup ... OK"
	$R_SAVEKO = "Creating registry backup ... Error !"
	$R_RESTO = "Cleaning system restore ..."
	$R_RESTOOK = "New restore point created !"
	$R_RESTOKO = "Error ! Can't create new restore point."
	$R_SYSPARAMS = "Resetting system settings ... OK"
	$R_RAPPORTCREE = "Logfile created"
	$R_MISAJOUR = "Updated"
	$R_NOMDUTILISATEUR = "Username"
	$R_A = "at"
	$R_HOURDE = ""
	$R_PAR = "by"
	$R_SYSTEME = "Operating System"
	$O_EOD = "End of disinfection"
Case $LANGUE = "Allemand"
	$X = 20
	$G_EXECUTER = "Start"
	$G_UAC = "Aktivierung der Benutzerkontensteuerung"
	$G_TOOLS = "Entfernung der Bereinigungsprogramme"
	$G_REGSAVE = "Erstellung eines Backups der Registrierungsdatenbank"
	$G_PURGEREST = "Löschung der Wiederherstellungspunkte"
	$G_REINITPARAMS = "Wiederherstellung der Systemeinstellungen"
	$G2_PROGRESS = "Bereinigung wird ausgeführt..."
	$G2_UAC = "Aktiviere die Benutzerkontensteuerung"
	$G2_TOOLS = "Entferne die Bereinigungsprogramme"
	$G2_SAVE = "Erstelle ein Backup der Registrierungsdatenbank"
	$G2_RESTO = "Lösche die Wiederherstellungspunkte"
	$G2_SYSPARAMS = "Stelle die Systemeinstellungen wieder her"
	$R_UACOK = "Aktiviere die Benutzerkontensteuerung ... OK"
	$R_UACKO = "Aktiviere die Benutzerkontensteuerung ... Fehler !"
	$R_TOOLS = "Entferne die Bereinigungsprogramme ..."
	$R_SUPPRIME = "Gelöscht"
	$R_SUPPRIMEE = "Gelöscht"
	$R_ERREURSUPPR = "Fehler beim Löschen"
	$R_SAVEOK = "Erstelle ein Backup der Registrierungsdatenbank ... OK"
	$R_SAVEKO = "Erstelle ein Backup der Registrierungsdatenbank ... Fehler !"
	$R_RESTO = "Lösche die Wiederherstellungspunkte ..."
	$R_RESTOOK = "Ein neuer Wiederherstellungspunkt wurde erstellt !"
	$R_RESTOKO = "Fehler ! Es konnte kein Wiederherstellungspunkt erstellt werden."
	$R_SYSPARAMS = "Stelle die Systemeinstellungen wieder her ... OK"
	$R_RAPPORTCREE = "Datei am"
	$R_MISAJOUR = "Aktualisiert am"
	$R_NOMDUTILISATEUR = "Benutzer"
	$R_A = "um"
	$R_HOURDE = " erstellt"
	$R_PAR = "von"
	$R_SYSTEME = "Betriebssystem"
	$O_EOD = "Ende der Bereinigung"
Case $LANGUE = "PortugaisBR"
	$X = 65
	$G_EXECUTER = "Executar"
	$G_UAC = "Ativar UAC"
	$G_TOOLS = "Remover ferramentas de desinfecção"
	$G_REGSAVE = "Criar backup do registro"
	$G_PURGEREST = "Limpar pontos da restauração do sistema"
	$G_REINITPARAMS = "Redefinir as configurações do sistema"
	$G2_PROGRESS = "Limpeza em andamento..."
	$G2_UAC = "Ativando UAC"
	$G2_TOOLS = "Removendo ferramentas de desinfecção"
	$G2_SAVE = "Criando backup do registro"
	$G2_RESTO = "Limpando pontos da restauração do sistema"
	$G2_SYSPARAMS = "Redefinindo as configurações do sistema"
	$R_UACOK = "Ativando UAC ... OK"
	$R_UACKO = "Ativando UAC ... Falha !"
	$R_TOOLS = "Removendo ferramentas de desinfecção ..."
	$R_SUPPRIME = "Removido"
	$R_SUPPRIMEE = "Removido"
	$R_ERREURSUPPR = "Falha ao remover"
	$R_SAVEOK = "Criando backup do registro ... OK"
	$R_SAVEKO = "Criando backup do registro ... Falha !"
	$R_RESTO = "Limpando pontos da restauração do sistema ..."
	$R_RESTOOK = "Novo ponto de restauração criado !"
	$R_RESTOKO = "Falha ! Não foi possível criar um novo ponto de restauração."
	$R_SYSPARAMS = "Redefinindo configurações do sistema ... OK"
	$R_RAPPORTCREE = "Relatório criado"
	$R_MISAJOUR = "Atualizado"
	$R_NOMDUTILISATEUR = "Usuário"
	$R_A = "às"
	$R_HOURDE = ""
	$R_PAR = "por"
	$R_SYSTEME = "Sistema Operacional"
	$O_EOD = "Fim da desinfecção"
EndSwitch
FileInstall ( "C:\Users\Matthieu\Documents\Dev\DelFix\Ressources\DelFix.jpg" , @TempDir & "\DelFix.jpg" )
FileInstall ( "C:\Users\Matthieu\Documents\Dev\DelFix\Ressources\erunt\ERDNT.E_E" , @TempDir & "\ERDNT.E_E" )
FileInstall ( "C:\Users\Matthieu\Documents\Dev\DelFix\Ressources\erunt\ERDNTDOS.LOC" , @TempDir & "\ERDNTDOS.LOC" )
FileInstall ( "C:\Users\Matthieu\Documents\Dev\DelFix\Ressources\erunt\ERDNTWIN.LOC" , @TempDir & "\ERDNTWIN.LOC" )
FileInstall ( "C:\Users\Matthieu\Documents\Dev\DelFix\Ressources\erunt\ERUNT.exe" , @TempDir & "\ERUNT.exe" )
FileInstall ( "C:\Users\Matthieu\Documents\Dev\DelFix\Ressources\erunt\ERUNT.EXE.MANIFEST" , @TempDir & "\ERUNT.EXE.MANIFEST" )
FileInstall ( "C:\Users\Matthieu\Documents\Dev\DelFix\Ressources\erunt\ERUNT.LOC" , @TempDir & "\ERUNT.LOC" )
FileInstall ( "C:\Users\Matthieu\Documents\Dev\DelFix\Ressources\erunt\README.txt" , @TempDir & "\README.txt" )
Global $VERSION = "1.010"
Global $UPDATE = "26/04/2015"
Global $LOGFILE = @HomeDrive & "\DelFix.txt"
Global $FORM1 = GUICreate ( "- DelFix - v" & $VERSION & " - Xplode" , 320 , 330 , + 4294967295 , + 4294967295 )
Global $PIC1 = GUICtrlCreatePic ( @TempDir & "\DelFix.jpg" , 1 , 10 , 300 , 130 )
Global $EXEC = GUICtrlCreateButton ( $G_EXECUTER , 95 , 270 , 130 , 40 , $WS_GROUP )
Global $CHECK1 = GUICtrlCreateCheckbox ( $G_UAC , $X , 155 , 245 , 20 )
Global $CHECK2 = GUICtrlCreateCheckbox ( $G_TOOLS , $X , 175 , 245 , 20 )
Global $CHECK3 = GUICtrlCreateCheckbox ( $G_REGSAVE , $X , 195 , 305 , 20 )
Global $CHECK4 = GUICtrlCreateCheckbox ( $G_PURGEREST , $X , 215 , 245 , 20 )
Global $CHECK5 = GUICtrlCreateCheckbox ( $G_REINITPARAMS , $X , 235 , 245 , 20 )
GUICtrlSetState ( $CHECK2 , $GUI_CHECKED )
If StringInStr ( "WIN_2003,WIN_XP,WIN_XPe,WIN_2000" , @OSVersion ) Then
	GUICtrlSetState ( $CHECK1 , $GUI_DISABLE )
EndIf
GUISetBkColor ( 16777215 )
GUISetState ( @SW_SHOW )
Global $FORM2 = GUICreate ( "- DelFix - " & $G2_PROGRESS & " -" , 305 , 52 , + 4294967295 , + 4294967295 )
Global $PROGRESS1 = GUICtrlCreateProgress ( 10 , 30 , 285 , 11 )
Global $LABEL1 = GUICtrlCreateLabel ( "" , 65 , 12 , 220 , 17 )
GUISetBkColor ( 16777215 )
GUISetState ( @SW_HIDE )
While 1
	$NMSG = GUIGetMsg ( )
	Switch $NMSG
	Case $GUI_EVENT_CLOSE
		FileDelete ( @TempDir & "\*.jpg" )
		FileDelete ( @TempDir & "\ER*.*" )
		FileDelete ( @TempDir & "\README.txt" )
		FileDelete ( @TempDir & "\uninst.bat" )
		Exit
	Case $EXEC
		Global Const $OSVERS = RegRead ( "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" , "ProductName" )
		If @OSArch = "x86" Then
			Global $ARCH = "32 bits"
		Else
			Global $ARCH = "64 bits"
			DllCall ( "kernel32.dll" , "int" , "Wow64DisableWow64FsRedirection" , "int" , 1 )
		EndIf
		FileDelete ( $LOGFILE )
		$HFILE = FileOpen ( $LOGFILE , "w" )
		$DATE = @MDAY & "/" & @MON & "/" & @YEAR
		$HOUR = @HOUR & ":" & @MIN & ":" & @SEC
		FileWriteLine ( $LOGFILE , "# DelFix v" & $VERSION & " - " & $R_RAPPORTCREE & " " & $DATE & " " & $R_A & " " & $HOUR & $R_HOURDE )
		FileWriteLine ( $LOGFILE , "# " & $R_MISAJOUR & " " & $UPDATE & " " & $R_PAR & " Xplode" )
		FileWriteLine ( $LOGFILE , "# " & $R_NOMDUTILISATEUR & " : " & @UserName & " - " & @ComputerName & @CRLF )
		FileWriteLine ( $LOGFILE , "# " & $R_SYSTEME & " : " & $OSVERS & " " & @OSServicePack & " (" & $ARCH & ")" )
		GUISetState ( @SW_SHOW , $FORM2 )
		GUISetState ( @SW_DISABLE , $FORM1 )
		If GUICtrlRead ( $CHECK1 ) = 1 Then
			GUICtrlSetData ( $LABEL1 , $G2_UAC )
			RegWrite ( "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" , "EnableLUA" , "REG_DWORD" , "1" )
			If Not @error Then
				FileWriteLine ( $LOGFILE , @CRLF & "~ " & $R_UACOK )
			Else
				FileWriteLine ( $LOGFILE , @CRLF & "~ " & $R_UACKO & " (" & @error & ") !" )
			EndIf
			RegWrite ( "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" , "ConsentPromptBehaviorUser" , "REG_DWORD" , "3" )
			RegWrite ( "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" , "ConsentPromptBehaviorAdmin" , "REG_DWORD" , "5" )
			RegWrite ( "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" , "PromptOnSecureDesktop" , "REG_DWORD" , "1" )
			RegWrite ( "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" , "EnableVirtualization" , "REG_DWORD" , "1" )
			RegWrite ( "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" , "EnableSecureUIAPath" , "REG_DWORD" , "1" )
		EndIf
		GUICtrlSetData ( $PROGRESS1 , "20" )
		If GUICtrlRead ( $CHECK2 ) = 1 Then
			FileWriteLine ( $LOGFILE , @CRLF & "~ " & $R_TOOLS & @CRLF & @CRLF )
			GUICtrlSetData ( $LABEL1 , $G2_TOOLS )
			For $A In $DIRLIST
				If FileExists ( $A ) Then
					If $A = @HomeDrive & "\Qoobox" Then
						_GRANTALLACCESS ( @HomeDrive & "\Qoobox\BackEnv" , $SE_FILE_OBJECT )
					EndIf
					DirRemove ( $A , 1 )
					If Not @error Then
						FileWriteLine ( $LOGFILE , $R_SUPPRIME & " : " & $A )
					Else
						FileWriteLine ( $LOGFILE , $R_ERREURSUPPR & " (" & @error & ") : " & $A )
					EndIf
				EndIf
			Next
			If FileExists ( $CFRENAMED ) Then
				FileSetAttrib ( $CFRENAMED , "-RASH" )
				FileDelete ( $CFRENAMED )
				If Not @error Then
					FileWriteLine ( $LOGFILE , $R_SUPPRIME & " : " & $CFRENAMED )
				Else
					FileWriteLine ( $LOGFILE , $R_ERREURSUPPR & " (" & @error & ") : " & $CFRENAMED )
				EndIf
			EndIf
			For $I In $FILEPATHS
				For $J In $FILENAME
					$HFILE = FileFindFirstFile ( $I & "\" & $J )
					If $HFILE = + 4294967295 Then ContinueLoop
					While 1
						$NEXTFILE = FileFindNextFile ( $HFILE )
						If @error Then ExitLoop
						If FileExists ( $I & "\" & $NEXTFILE ) Then
							If Not StringInStr ( FileGetAttrib ( $I & "\" & $NEXTFILE ) , "D" ) Then
								FileSetAttrib ( $I & "\" & $NEXTFILE , "-RASH" )
								FileDelete ( $I & "\" & $NEXTFILE )
								If Not @error Then
									FileWriteLine ( $LOGFILE , $R_SUPPRIME & " : " & $I & "\" & $NEXTFILE )
								Else
									FileWriteLine ( $LOGFILE , $R_ERREURSUPPR & " (" & @error & ") : " & $I & "\" & $NEXTFILE )
								EndIf
							EndIf
						EndIf
					WEnd
				Next
			Next
			For $C In $FILESLIST
				If FileExists ( $C ) Then
					FileDelete ( $C )
					If Not @error Then
						FileWriteLine ( $LOGFILE , $R_SUPPRIME & " : " & $C )
					Else
						FileWriteLine ( $LOGFILE , $R_ERREURSUPPR & " (" & @error & ") : " & $C )
					EndIf
				EndIf
			Next
			For $C = 0 To UBound ( $REGISTRYKEYS ) + 4294967295
				RegRead ( $REGISTRYKEYS [ $C ] , "" )
				If @error <> 1 Then
					If $REGISTRYKEYS [ $C ] = "HKLM\SYSTEM\CurrentControlSet\Enum\Root\LEGACY_ASWMBR" Then
						_GRANTALLACCESS ( "HKLM\SYSTEM\CurrentControlSet\Enum\Root\LEGACY_ASWMBR" , $SE_REGISTRY_KEY )
						_GRANTALLACCESS ( "HKLM\SYSTEM\CurrentControlSet\Enum\Root\LEGACY_ASWMBR\0000" , $SE_REGISTRY_KEY )
						_GRANTALLACCESS ( "HKLM\SYSTEM\CurrentControlSet\Enum\Root\LEGACY_ASWMBR\0000\Control" , $SE_REGISTRY_KEY )
					EndIf
					If $REGISTRYKEYS [ $C ] = "HKLM\SYSTEM\CurrentControlSet\Enum\Root\LEGACY_DWPROT" Then
						_GRANTALLACCESS ( "HKLM\SYSTEM\CurrentControlSet\Enum\Root\LEGACY_DWPROT" , $SE_REGISTRY_KEY )
						_GRANTALLACCESS ( "HKLM\SYSTEM\CurrentControlSet\Enum\Root\LEGACY_DWPROT\0000" , $SE_REGISTRY_KEY )
						_GRANTALLACCESS ( "HKLM\SYSTEM\CurrentControlSet\Enum\Root\LEGACY_DWPROT\0000\Control" , $SE_REGISTRY_KEY )
					EndIf
					RegDelete ( $REGISTRYKEYS [ $C ] )
					If Not @error Then
						FileWriteLine ( $LOGFILE , $R_SUPPRIMEE & " : " & $REGISTRYKEYS [ $C ] )
					Else
						FileWriteLine ( $LOGFILE , $R_ERREURSUPPR & " (" & @error & ") : " & $REGISTRYKEYS [ $C ] )
					EndIf
				EndIf
			Next
		EndIf
		GUICtrlSetData ( $PROGRESS1 , "40" )
		If GUICtrlRead ( $CHECK3 ) = 1 Then
			GUICtrlSetData ( $LABEL1 , $G2_SAVE )
			RunWait ( @TempDir & "\ERUNT.exe " & @WindowsDir & "\ERUNT\DelFix /noconfirmdelete" )
			If @error <> 0 Then
				FileWriteLine ( $LOGFILE , @CRLF & "~ " & $R_SAVEKO & " (" & @error & ")" & @CRLF )
			Else
				FileWriteLine ( $LOGFILE , @CRLF & "~ " & $R_SAVEOK & @CRLF )
			EndIf
		EndIf
		GUICtrlSetData ( $PROGRESS1 , "60" )
		If GUICtrlRead ( $CHECK4 ) = 1 Then
			GUICtrlSetData ( $LABEL1 , $G2_RESTO )
			_PURGERESTORE ( )
		EndIf
		GUICtrlSetData ( $PROGRESS1 , "80" )
		If GUICtrlRead ( $CHECK5 ) = 1 Then
			FileWriteLine ( $LOGFILE , @CRLF & "~ " & $R_SYSPARAMS & @CRLF )
			GUICtrlSetData ( $LABEL1 , $G2_SYSPARAMS )
			If @OSArch <> "x86" Then
				RegWrite ( "HKLM64\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" , "AutoRestartShell" , "REG_DWORD" , 0 )
			Else
				RegWrite ( "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" , "AutoRestartShell" , "REG_DWORD" , 0 )
			EndIf
			ProcessClose ( "explorer.exe" )
			RunWait ( "ipconfig /flushdns" , "" , @SW_HIDE )
			RunWait ( "netsh winsock reset" , "" , @SW_HIDE )
			If @OSArch <> "x86" Then
				RegWrite ( "HKCU64\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" , "hidden" , "REG_DWORD" , "2" )
				RegWrite ( "HKCU64\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" , "ShowSuperHidden" , "REG_DWORD" , "0" )
				RegWrite ( "HKCU64\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" , "HideFileExt" , "REG_DWORD" , "0" )
			Else
				RegWrite ( "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" , "hidden" , "REG_DWORD" , "2" )
				RegWrite ( "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" , "ShowSuperHidden" , "REG_DWORD" , "0" )
				RegWrite ( "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" , "HideFileExt" , "REG_DWORD" , "0" )
			EndIf
			EnvUpdate ( )
			If @OSArch <> "x86" Then
				RegWrite ( "HKLM64\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" , "AutoRestartShell" , "REG_DWORD" , 1 )
			Else
				RegWrite ( "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" , "AutoRestartShell" , "REG_DWORD" , 1 )
			EndIf
			Run ( "explorer.exe" )
		EndIf
		FileWriteLine ( $LOGFILE , @CRLF & "########## - EOF - ##########" )
		FileClose ( $HFILE )
		GUICtrlSetData ( $PROGRESS1 , "100" )
		GUISetState ( @SW_HIDE , $FORM2 )
		ShellExecute ( $LOGFILE )
		If GUICtrlRead ( $CHECK2 ) = 1 Then
			_UNINSTALL ( )
		Else
			GUICtrlSetData ( $PROGRESS1 , "0" )
			GUICtrlSetData ( $LABEL1 , "" )
			GUISetState ( @SW_RESTORE , $FORM1 )
			GUISetState ( @SW_ENABLE , $FORM1 )
		EndIf
	EndSwitch
WEnd
Func _UNINSTALL ( )
	OnAutoItExitRegister ( "_selfDestroy" )
	FileWriteLine ( @TempDir & "\Uninst.bat" , "@echo off" )
	FileWriteLine ( @TempDir & "\Uninst.bat" , "del /f /q " & """" & "%temp%\README.txt" & """" & ">nul 2>&1" )
	FileWriteLine ( @TempDir & "\Uninst.bat" , "del /f /q " & """" & "%temp%\ER*.*" & """" & ">nul 2>&1" )
	FileWriteLine ( @TempDir & "\Uninst.bat" , "del /f /q " & """" & "%temp%\*.jpg" & """" & ">nul 2>&1" )
	FileWriteLine ( @TempDir & "\Uninst.bat" , "del /f /q " & """" & "%temp%\*.ico" & """" & ">nul 2>&1" )
	FileWriteLine ( @TempDir & "\Uninst.bat" , "del /f /q " & """" & "%temp%\uninst.bat" & """" & ">nul 2>&1" )
	RunWait ( @TempDir & "\Uninst.bat" , "" , @SW_HIDE )
	Exit
EndFunc
Func _PURGERESTORE ( )
	FileWriteLine ( $LOGFILE , @CRLF & "~ " & $R_RESTO & @CRLF & @CRLF )
	_SR_ENABLE ( )
	$ARP = _SR_ENUMRESTOREPOINTS ( )
	For $I = 1 To UBound ( $ARP ) + 4294967295
		FileWriteLine ( $LOGFILE , $R_SUPPRIME & " : RP #" & $ARP [ $I ] [ 0 ] & " [" & $ARP [ $I ] [ 1 ] & " | " & $ARP [ $I ] [ 2 ] & "]" )
	Next
	_SR_REMOVEALLRESTOREPOINTS ( )
	_SR_CREATERESTOREPOINT ( $O_EOD )
	If Not @error Then
		FileWriteLine ( $LOGFILE , @CRLF & $R_RESTOOK )
	Else
		FileWriteLine ( $LOGFILE , @CRLF & $R_RESTOKO )
	EndIf
EndFunc
Func _SELFDESTROY ( )
	If @Compiled Then
		$PROGRAMPATH = FileGetShortName ( @ScriptFullPath )
		Run ( @ComSpec & " /c ping -n 2 localhost > nul & del /q /f """ & $PROGRAMPATH & """" , "" , @SW_HIDE )
	EndIf
EndFunc
