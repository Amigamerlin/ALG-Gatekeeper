; ALG Gatekeeper - setup script (NSIS 3, no extra plugins needed)
;
; Build:   makensis /DVERSION=1.0.0 Installer\ALGGatekeeper.nsi
; Needs:   the files to install in Installer\payload\ (the GitHub Actions workflow copies them there)
; Silent:  ALGGatekeeper-1.0.0-setup.exe /S          (install / update without questions)
;          uninstall.exe /S                           (uninstall, settings are kept)

Unicode true
ManifestDPIAware true
SetCompressor /SOLID lzma

!ifndef VERSION
  !define VERSION "1.0.0"
!endif

!define PRODUCT      "ALG Gatekeeper"
!define SERVICE      "ALGGatekeeper"
!define EXE          "ALGGatekeeper.exe"
!define CONSOLE      "ALGGatekeeperConsole.exe"
!define REGKEY       "Software\ALGGatekeeper"
!define UNINSTKEY    "Software\Microsoft\Windows\CurrentVersion\Uninstall\ALGGatekeeper"
!define LEGACY       "EvlWatcher"
!define PAYLOAD      "payload"

!include "MUI2.nsh"
!include "LogicLib.nsh"
!include "x64.nsh"
!include "FileFunc.nsh"

Name "${PRODUCT} ${VERSION}"
OutFile "ALGGatekeeper-${VERSION}-setup.exe"
InstallDir "$PROGRAMFILES64\${PRODUCT}"
RequestExecutionLevel admin
BrandingText "${PRODUCT} ${VERSION}"

VIProductVersion "${VERSION}.0"
VIAddVersionKey "ProductName" "${PRODUCT}"
VIAddVersionKey "ProductVersion" "${VERSION}"
VIAddVersionKey "FileVersion" "${VERSION}"
VIAddVersionKey "FileDescription" "${PRODUCT} setup"
VIAddVersionKey "LegalCopyright" "MIT License - based on EvlWatcher by Michael Schoenbauer"

!define MUI_ICON "${PAYLOAD}\ALGGatekeeper.ico"
!define MUI_UNICON "${PAYLOAD}\ALGGatekeeper.ico"
!define MUI_ABORTWARNING
!define MUI_FINISHPAGE_RUN "$INSTDIR\${CONSOLE}"
!define MUI_FINISHPAGE_RUN_TEXT "Open the ${PRODUCT} console"
!define MUI_FINISHPAGE_RUN_NOTCHECKED

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "${PAYLOAD}\license.txt"
!insertmacro MUI_PAGE_COMPONENTS
; on an update the folder is fixed: another folder would lose the settings
!define MUI_PAGE_CUSTOMFUNCTION_PRE SkipDirectoryOnUpdate
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

!insertmacro MUI_LANGUAGE "English"
!insertmacro MUI_LANGUAGE "Italian"

Var LegacyDir
Var IsUpdate

;--------------------------------
; helpers

; Stops a service and waits until it is stopped (max. ~40 s). Does nothing if the service does not exist.
; Usage: Push "ServiceName" / Call [un.]StopServiceAndWait / Pop $0  ($0 = "ok" or "timeout")
!macro STOP_SERVICE_FUNCTION PREFIX
Function ${PREFIX}StopServiceAndWait
  Exch $R0          ; service name
  Push $R1
  Push $R2
  Push $R3
  nsExec::ExecToLog 'sc.exe stop "$R0"'
  Pop $R1
  StrCpy $R3 0
  ${Do}
    nsExec::ExecToStack 'sc.exe query "$R0"'
    Pop $R1          ; exit code, 1060 = the service does not exist
    Pop $R2          ; output
    ${If} $R1 == 1060
      ${Break}
    ${EndIf}
    ; the output contains "STATE : 1  STOPPED" when the service is stopped
    StrCpy $R1 0
    ${Do}
      StrCpy $R2 $R2 "" 1
      ${If} $R2 == ""
        ${Break}
      ${EndIf}
      StrCpy $R1 $R2 7
      ${If} $R1 == "STOPPED"
        ${Break}
      ${EndIf}
    ${Loop}
    ${If} $R1 == "STOPPED"
      ${Break}
    ${EndIf}
    IntOp $R3 $R3 + 1
    ${If} $R3 > 40
      DetailPrint "The service $R0 did not stop in time."
      StrCpy $R1 "timeout"
      ${Break}
    ${EndIf}
    Sleep 1000
  ${Loop}
  ${If} $R1 != "timeout"
    StrCpy $R1 "ok"
  ${EndIf}
  StrCpy $R0 $R1     ; result: "ok" or "timeout"
  Pop $R3
  Pop $R2
  Pop $R1
  Exch $R0
FunctionEnd
!macroend
!insertmacro STOP_SERVICE_FUNCTION ""
!insertmacro STOP_SERVICE_FUNCTION "un."

;--------------------------------
; checks before anything is changed

Function .onInit
  ${IfNot} ${RunningX64}
    MessageBox MB_OK|MB_ICONSTOP "${PRODUCT} needs a 64-bit Windows." /SD IDOK
    Abort
  ${EndIf}

  SetRegView 64

  UserInfo::GetAccountType
  Pop $0
  ${If} $0 != "admin"
    MessageBox MB_OK|MB_ICONSTOP "Please run the setup as Administrator." /SD IDOK
    Abort
  ${EndIf}

  ; .NET Framework 4.8 or newer (Release >= 528040)
  ReadRegDWORD $0 HKLM "SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full" "Release"
  ${If} $0 == ""
  ${OrIf} $0 < 528040
    MessageBox MB_OK|MB_ICONSTOP "${PRODUCT} needs the .NET Framework 4.8 or newer.$\r$\nPlease install it first: https://dotnet.microsoft.com/download/dotnet-framework/net48" /SD IDOK
    Abort
  ${EndIf}

  ; an existing installation is updated in place
  StrCpy $IsUpdate "0"
  ReadRegStr $0 HKLM "${REGKEY}" "InstallDir"
  ${If} $0 != ""
  ${AndIf} ${FileExists} "$0\${EXE}"
    StrCpy $INSTDIR $0
    StrCpy $IsUpdate "1"
  ${EndIf}

  ; an old EvlWatcher installation (32-bit setup: 32-bit registry view)
  SetRegView 32
  ReadRegStr $LegacyDir HKLM "SOFTWARE\${LEGACY}" "Install_Dir"
  SetRegView 64
  ${If} $LegacyDir == ""
    ${If} ${FileExists} "$PROGRAMFILES32\${LEGACY}\${LEGACY}.exe"
      StrCpy $LegacyDir "$PROGRAMFILES32\${LEGACY}"
    ${ElseIf} ${FileExists} "$PROGRAMFILES64\${LEGACY}\${LEGACY}.exe"
      StrCpy $LegacyDir "$PROGRAMFILES64\${LEGACY}"
    ${EndIf}
  ${EndIf}

  ${If} $LegacyDir != ""
    MessageBox MB_OKCANCEL|MB_ICONINFORMATION "EvlWatcher was found in $LegacyDir.$\r$\n$\r$\nIt will be removed and replaced by ${PRODUCT}. Your white list, permanent bans and rule settings are taken over." /SD IDOK IDOK +2
    Abort
  ${EndIf}
FunctionEnd

;--------------------------------
; installation

Function SkipDirectoryOnUpdate
  ${If} $IsUpdate == "1"
    Abort
  ${EndIf}
FunctionEnd

Section "${PRODUCT} service" SecService
  SectionIn RO
  SetRegView 64
  SetOutPath "$INSTDIR"

  ; 1. stop the running version (stopping removes its firewall rules; bans are restored at the next start)
  DetailPrint "Stopping the service..."
  Push "${SERVICE}"
  Call StopServiceAndWait
  Pop $0
  ${If} $0 == "timeout"
    nsExec::ExecToLog 'taskkill.exe /F /IM "${EXE}"'
    Pop $0
    Sleep 3000
    Push "${SERVICE}"
    Call StopServiceAndWait
    Pop $0
    ${If} $0 == "timeout"
      MessageBox MB_OK|MB_ICONSTOP "The ${PRODUCT} service does not stop. Nothing was changed; please restart Windows and run the setup again." /SD IDOK
      Abort
    ${EndIf}
  ${EndIf}

  ; 2. keep the user's configuration
  Delete "$INSTDIR\config.previous.xml"
  ${If} ${FileExists} "$INSTDIR\config.xml"
    Rename "$INSTDIR\config.xml" "$INSTDIR\config.previous.xml"
  ${EndIf}

  ; 3. files
  File "${PAYLOAD}\${EXE}"
  File "${PAYLOAD}\${EXE}.config"
  File "${PAYLOAD}\ALGGatekeeper.Contracts.dll"
  File "${PAYLOAD}\${CONSOLE}"
  File "${PAYLOAD}\${CONSOLE}.config"
  File "${PAYLOAD}\config.xml"
  File "${PAYLOAD}\license.txt"
  File "${PAYLOAD}\ALGGatekeeper.ico"

  ; a copy of the new default configuration, in case taking over old settings fails
  InitPluginsDir
  CopyFiles /SILENT "$INSTDIR\config.xml" "$PLUGINSDIR\config.default.xml"

  ; 4. merge the previous settings into the new default configuration
  ${If} ${FileExists} "$INSTDIR\config.previous.xml"
    DetailPrint "Taking over your settings..."
    nsExec::ExecToLog '"$INSTDIR\${EXE}" /migrateconfig "$INSTDIR\config.previous.xml"'
    Pop $0
    ${If} $0 != 0
      ; something went wrong: go back to the old file, nothing is lost
      DetailPrint "Settings could not be merged (code $0), the previous config.xml is kept."
      Delete "$INSTDIR\config.xml"
      Rename "$INSTDIR\config.previous.xml" "$INSTDIR\config.xml"
    ${EndIf}
  ${EndIf}

  ; 5. replace EvlWatcher
  ${If} $LegacyDir != ""
    DetailPrint "Replacing EvlWatcher..."
    Push "${LEGACY}"
    Call StopServiceAndWait
    Pop $0
    ${If} $0 == "timeout"
      nsExec::ExecToLog 'taskkill.exe /F /IM "${LEGACY}.exe"'
      Pop $0
      Sleep 3000
    ${EndIf}
    nsExec::ExecToLog 'sc.exe delete "${LEGACY}"'
    Pop $0

    ${If} ${FileExists} "$LegacyDir\config.xml"
    ${AndIfNot} ${FileExists} "$INSTDIR\config.previous.xml"
      CopyFiles /SILENT "$LegacyDir\config.xml" "$INSTDIR\config.evlwatcher.xml"
      nsExec::ExecToLog '"$INSTDIR\${EXE}" /migrateconfig "$INSTDIR\config.evlwatcher.xml"'
      Pop $0
      ${If} $0 != 0
        DetailPrint "EvlWatcher settings could not be taken over (code $0). A copy is in config.evlwatcher.xml."
        Delete "$INSTDIR\config.xml"
        CopyFiles /SILENT "$PLUGINSDIR\config.default.xml" "$INSTDIR\config.xml"
      ${EndIf}
    ${EndIf}

    nsExec::ExecToLog '"$INSTDIR\${EXE}" /removefirewallrules /legacy'
    Pop $0

    ${If} ${FileExists} "$LegacyDir\uninstall.exe"
      ExecWait '"$LegacyDir\uninstall.exe" /S _?=$LegacyDir'
      Delete "$LegacyDir\uninstall.exe"
      RMDir "$LegacyDir"
    ${EndIf}
  ${EndIf}

  ; 6. register the service (update it if it exists)
  nsExec::ExecToStack 'sc.exe query "${SERVICE}"'
  Pop $0
  Pop $1
  ${If} $0 == 1060
    nsExec::ExecToLog 'sc.exe create "${SERVICE}" binPath= "\"$INSTDIR\${EXE}\"" start= auto DisplayName= "${PRODUCT}"'
  ${Else}
    nsExec::ExecToLog 'sc.exe config "${SERVICE}" binPath= "\"$INSTDIR\${EXE}\"" start= auto DisplayName= "${PRODUCT}"'
  ${EndIf}
  Pop $0
  ${If} $0 != 0
    MessageBox MB_OK|MB_ICONSTOP "The service could not be registered (code $0)." /SD IDOK
    Abort
  ${EndIf}

  nsExec::ExecToLog 'sc.exe description "${SERVICE}" "Watches the Windows event log for brute force attacks and bans the attackers in the Windows Firewall."'
  Pop $0
  ; restart automatically after a crash: after 5 s, 30 s, then every 60 s; counter reset after one day
  nsExec::ExecToLog 'sc.exe failure "${SERVICE}" reset= 86400 actions= restart/5000/restart/30000/restart/60000'
  Pop $0
  nsExec::ExecToLog 'sc.exe failureflag "${SERVICE}" 1'
  Pop $0

  ; 7. registry and uninstaller
  WriteRegStr HKLM "${REGKEY}" "InstallDir" "$INSTDIR"
  WriteRegStr HKLM "${REGKEY}" "Version" "${VERSION}"
  WriteRegStr HKLM "${UNINSTKEY}" "DisplayName" "${PRODUCT}"
  WriteRegStr HKLM "${UNINSTKEY}" "DisplayVersion" "${VERSION}"
  WriteRegStr HKLM "${UNINSTKEY}" "Publisher" "${PRODUCT}"
  WriteRegStr HKLM "${UNINSTKEY}" "DisplayIcon" '"$INSTDIR\${EXE}"'
  WriteRegStr HKLM "${UNINSTKEY}" "InstallLocation" "$INSTDIR"
  WriteRegStr HKLM "${UNINSTKEY}" "UninstallString" '"$INSTDIR\uninstall.exe"'
  WriteRegStr HKLM "${UNINSTKEY}" "QuietUninstallString" '"$INSTDIR\uninstall.exe" /S'
  WriteRegDWORD HKLM "${UNINSTKEY}" "NoModify" 1
  WriteRegDWORD HKLM "${UNINSTKEY}" "NoRepair" 1
  ${GetSize} "$INSTDIR" "/S=0K" $0 $1 $2
  WriteRegDWORD HKLM "${UNINSTKEY}" "EstimatedSize" $0
  WriteUninstaller "$INSTDIR\uninstall.exe"

  ; 8. start
  DetailPrint "Starting the service..."
  nsExec::ExecToLog 'sc.exe start "${SERVICE}"'
  Pop $0
  ${If} $0 != 0
    DetailPrint "The service did not start (code $0). See the Windows event log (Application, source ${PRODUCT})."
  ${EndIf}
SectionEnd

Section "Start menu shortcuts" SecShortcuts
  SetShellVarContext all
  CreateDirectory "$SMPROGRAMS\${PRODUCT}"
  CreateShortCut "$SMPROGRAMS\${PRODUCT}\${PRODUCT} Console.lnk" "$INSTDIR\${CONSOLE}"
  CreateShortCut "$SMPROGRAMS\${PRODUCT}\Uninstall ${PRODUCT}.lnk" "$INSTDIR\uninstall.exe"
SectionEnd

!insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
  !insertmacro MUI_DESCRIPTION_TEXT ${SecService} "The service that watches the event log and bans attackers, and the management console."
  !insertmacro MUI_DESCRIPTION_TEXT ${SecShortcuts} "Shortcuts for the console in the start menu."
!insertmacro MUI_FUNCTION_DESCRIPTION_END

;--------------------------------
; uninstallation

Function un.onInit
  SetRegView 64
FunctionEnd

Section "Uninstall"
  SetRegView 64

  ; stopping the service removes all its firewall rules
  Push "${SERVICE}"
  Call un.StopServiceAndWait
  Pop $0
  ${If} $0 == "timeout"
    nsExec::ExecToLog 'taskkill.exe /F /IM "${EXE}"'
    Pop $0
    Sleep 3000
  ${EndIf}

  nsExec::ExecToLog 'sc.exe delete "${SERVICE}"'
  Pop $0

  ; in case the service could not clean up
  nsExec::ExecToLog '"$INSTDIR\${EXE}" /removefirewallrules'
  Pop $0

  Delete "$INSTDIR\${EXE}"
  Delete "$INSTDIR\${EXE}.config"
  Delete "$INSTDIR\ALGGatekeeper.Contracts.dll"
  Delete "$INSTDIR\${CONSOLE}"
  Delete "$INSTDIR\${CONSOLE}.config"
  Delete "$INSTDIR\license.txt"
  Delete "$INSTDIR\ALGGatekeeper.ico"
  Delete "$INSTDIR\config.xml.tmp"
  Delete "$INSTDIR\state.xml.tmp"

  ; settings and bans are kept unless the user wants them gone (silent uninstall keeps them)
  MessageBox MB_YESNO|MB_ICONQUESTION|MB_DEFBUTTON2 "Also delete your settings (white list, permanent bans, rule settings)?" /SD IDNO IDNO keep_settings
    Delete "$INSTDIR\config.xml"
    Delete "$INSTDIR\config.previous.xml"
    Delete "$INSTDIR\config.evlwatcher.xml"
    Delete "$INSTDIR\state.xml"
  keep_settings:

  Delete "$INSTDIR\uninstall.exe"
  RMDir "$INSTDIR"

  SetShellVarContext all
  Delete "$SMPROGRAMS\${PRODUCT}\${PRODUCT} Console.lnk"
  Delete "$SMPROGRAMS\${PRODUCT}\Uninstall ${PRODUCT}.lnk"
  RMDir "$SMPROGRAMS\${PRODUCT}"

  DeleteRegKey HKLM "${UNINSTKEY}"
  DeleteRegKey HKLM "${REGKEY}"
SectionEnd
