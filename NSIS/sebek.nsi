/*
 * Copyright (C) 2001-2004 The Honeynet Project.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by The Honeynet Project.
 * 4. The name "The Honeynet Project" may not be used to endorse or promote
 *    products derived from this software without specific prior written
 *    permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

SetCompressor lzma

!define PRODUCT_NAME "Sebek"
!define PRODUCT_VERSION "3.0.4.0"
!define PRODUCT_PUBLISHER "The Honeynet Project."
!define PRODUCT_WEB_SITE "http://www.honeynet.org"

; Paths to locate the proper compiled drivers for the various supported Operating Systems.
!define WIN2000_DRIVER "..\objfre_w2K_x86\i386\SEBEK.SYS"
ReserveFile "${WIN2000_DRIVER}"
!define WINXP_DRIVER "..\objfre_wxp_x86\i386\SEBEK.SYS"
ReserveFile "${WINXP_DRIVER}"
!define WIN2003_DRIVER "..\objfre_wnet_x86\i386\SEBEK.SYS"
ReserveFile "${WIN2003_DRIVER}"
!define CONFIGWIZARD "..\CONFIGuration Wizard\Release\CONFIGuration Wizard.EXE"
ReserveFile "${CONFIGWIZARD}"

; Outname of the driver file without the .sys extension.
; If OUTPUTNAME is not set, one will be randomly selected from the list.
var OUTPUTNAME

;--------------------------------
;Configuration

;General
OutFile "Setup.exe"

;Folder selection page
InstallDir "$SYSDIR\drivers"

LicenseBkColor /gray

;; MUI 1.67 compatible ------
!include "MUI.nsh"

; MUI Settings
!define MUI_ABORTWARNING
!define MUI_ICON "${NSISDIR}\Contrib\Graphics\Icons\pixel-install.ico"
!define MUI_UNICON "${NSISDIR}\Contrib\Graphics\Icons\pixel-uninstall.ico"
!define MUI_WELCOMEFINISHPAGE_BITMAP "..\Configuration Wizard\res\WizardWatermark.bmp"
!define MUI_LICENSEPAGE_BGCOLOR /grey

; Welcome page
!insertmacro MUI_PAGE_WELCOME
; License page
!insertmacro MUI_PAGE_LICENSE "..\License.txt"
; Directory page
!insertmacro MUI_PAGE_DIRECTORY
; Instfiles page
!insertmacro MUI_PAGE_INSTFILES
; Finish page
!insertmacro MUI_PAGE_FINISH

; Language files
!insertmacro MUI_LANGUAGE "English"

; Reserve files
!insertmacro MUI_RESERVEFILE_INSTALLOPTIONS

; MUI end ------

Name "${PRODUCT_NAME} ${PRODUCT_VERSION}"
VIAddVersionKey /LANG=${LANG_ENGLISH} CompanyName "${PRODUCT_PUBLISHER}"
VIAddVersionKey /LANG=${LANG_ENGLISH} LegalCopyright "Copyright (C) ${PRODUCT_PUBLISHER}"
VIAddVersionKey /LANG=${LANG_ENGLISH} ProductName "${PRODUCT_NAME}"
VIAddVersionKey /LANG=${LANG_ENGLISH} ProductVersion "${PRODUCT_VERSION}"
VIAddVersionKey /LANG=${LANG_ENGLISH} FileVersion "${PRODUCT_VERSION}"
VIAddVersionKey /LANG=${LANG_ENGLISH} FileDescription ""
VIAddVersionKey /LANG=${LANG_ENGLISH} Comments ""
VIAddVersionKey /LANG=${LANG_ENGLISH} InternalName ""
VIAddVersionKey /LANG=${LANG_ENGLISH} LegalTrademarks ""
VIProductVersion "${PRODUCT_VERSION}"

;--------------------------------
;Language Strings

  ;Description
  LangString DESC_MAINSECTION ${LANG_ENGLISH} "SEBEK"

;--------------------------------
;Data
  
  LicenseData "..\License.txt"

Function .onInit
  Call GetParameters
  Pop $2
  # search for quoted /N
  StrCpy $1 '"'
  Push $2
  Push '"/N='
  Call StrStr
  Pop $0
  StrCpy $0 $0 "" 1 # skip quote
  StrCmp $0 "" "" next
    # search for non quoted /N
    StrCpy $1 ' '
    Push $2
    Push '/N='
    Call StrStr
    Pop $0
next:
  StrCmp $0 "" done
    # copy the value after /N=
    StrCpy $0 $0 "" 3
  # search for the next parameter
  Push $0
  Push $1
  Call StrStr
  Pop $1
  StrCmp $1 "" done
  StrLen $1 $1
  StrCpy $0 $0 -$1
def:
	StrCpy $0 "sebek"
done:
  StrCmp $0 "" def ""
  StrCpy $OUTPUTNAME $0
FunctionEnd

;--------------------------------
; Main Section

/*
  This section does a few things:
  
  1) Check for a specific driver name
  2) Detect what Operating System and Service Pack we are installing on and install the proper driver
  4) If silent, reboot. If Not, Prompt for Reboot
*/
Section "Main" MAINSECTION
  SetOutPath "$INSTDIR"
  
	MessageBox MB_OK|MB_ICONINFORMATION "DriverName is $OUTPUTNAME" /SD IDOK
  Call InstallDriver
	WriteRegDWORD HKLM "SYSTEM\CurrentControlSet\Services\$OUTPUTNAME" "Type" "1"
	WriteRegDWORD HKLM "SYSTEM\CurrentControlSet\Services\$OUTPUTNAME" "Start" "0"
	WriteRegDWORD HKLM "SYSTEM\CurrentControlSet\Services\$OUTPUTNAME" "ErrorControl" "1"
	WriteRegStr HKLM "SYSTEM\CurrentControlSet\Services\$OUTPUTNAME" "Groups" "Streams Drivers"
	; XXX: This HAS to be system32\drivers\OUTPUTNAME instead of $INSTDIR\OUTPUTNAME because of some weird issue
	; with Windows!
	WriteRegExpandStr HKLM "SYSTEM\CurrentControlSet\Services\$OUTPUTNAME" "ImagePath" "system32\drivers\$OUTPUTNAME.sys"
SectionEnd

Function InstallDriver
  Push $R0
  Push $R1
  ClearErrors

  ReadRegStr $R0 HKLM \
  "SOFTWARE\Microsoft\Windows NT\CurrentVersion" CurrentVersion

  IfErrors lbl_error
  ; We are not on Windows 2000, only 2000 and higher are supported.
  StrCpy $R1 $R0 3
  StrCmp $R1 '5.0' lbl_winnt_2000
  StrCmp $R1 '5.1' lbl_winnt_XP
  StrCmp $R1 '5.2' lbl_winnt_2003

  lbl_winnt_2000:
    File "/oname=$OUTPUTNAME.sys" ${WIN2000_DRIVER}
    Goto lbl_done

  lbl_winnt_XP:
    File "/oname=$OUTPUTNAME.sys" ${WINXP_DRIVER}
    Goto lbl_done
    
	lbl_winnt_2003:
    File "/oname=$OUTPUTNAME.sys" ${WIN2003_DRIVER}
    Goto lbl_done
    
  lbl_error:
    Abort
  lbl_done:

  Pop $R1
FunctionEnd


; GetParameters
 ; input, none
 ; output, top of stack (replaces, with e.g. whatever)
 ; modifies no other variables.

 Function GetParameters

   Push $R0
   Push $R1
   Push $R2
   Push $R3

   StrCpy $R2 1
   StrLen $R3 $CMDLINE

   ;Check for quote or space
   StrCpy $R0 $CMDLINE $R2
   StrCmp $R0 '"' 0 +3
     StrCpy $R1 '"'
     Goto loop
   StrCpy $R1 " "

   loop:
     IntOp $R2 $R2 + 1
     StrCpy $R0 $CMDLINE 1 $R2
     StrCmp $R0 $R1 get
     StrCmp $R2 $R3 get
     Goto loop

   get:
     IntOp $R2 $R2 + 1
     StrCpy $R0 $CMDLINE 1 $R2
     StrCmp $R0 " " get
     StrCpy $R0 $CMDLINE "" $R2

   Pop $R3
   Pop $R2
   Pop $R1
   Exch $R0

 FunctionEnd
 
 ; StrStr
 ; input, top of stack = string to search for
 ;        top of stack-1 = string to search in
 ; output, top of stack (replaces with the portion of the string remaining)
 ; modifies no other variables.
 ;
 ; Usage:
 ;   Push "this is a long ass string"
 ;   Push "ass"
 ;   Call StrStr
 ;   Pop $R0
 ;  ($R0 at this point is "ass string")

 Function StrStr
   Exch $R1 ; st=haystack,old$R1, $R1=needle
   Exch    ; st=old$R1,haystack
   Exch $R2 ; st=old$R1,old$R2, $R2=haystack
   Push $R3
   Push $R4
   Push $R5
   StrLen $R3 $R1
   StrCpy $R4 0
   ; $R1=needle
   ; $R2=haystack
   ; $R3=len(needle)
   ; $R4=cnt
   ; $R5=tmp
   loop:
     StrCpy $R5 $R2 $R3 $R4
     StrCmp $R5 $R1 done
     StrCmp $R5 "" done
     IntOp $R4 $R4 + 1
     Goto loop
 done:
   StrCpy $R1 $R2 "" $R4
   Pop $R5
   Pop $R4
   Pop $R3
   Pop $R2
   Exch $R1
 FunctionEnd
