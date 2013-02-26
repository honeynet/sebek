# Microsoft Developer Studio Project File - Name="sebek" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) External Target" 0x0106

CFG=sebek - Win32 Windows 2000 Checked
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "sebek.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "sebek.mak" CFG="sebek - Win32 Windows 2000 Checked"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "sebek - Win32 Windows 2000 Checked" (based on "Win32 (x86) External Target")
!MESSAGE "sebek - Win32 Windows XP Checked" (based on "Win32 (x86) External Target")
!MESSAGE "sebek - Win32 Windows 2000 Free" (based on "Win32 (x86) External Target")
!MESSAGE "sebek - Win32 Windows XP Free" (based on "Win32 (x86) External Target")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""

!IF  "$(CFG)" == "sebek - Win32 Windows 2000 Checked"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "sebek___Win32_Windows_2000_Checked"
# PROP BASE Intermediate_Dir "sebek___Win32_Windows_2000_Checked"
# PROP BASE Cmd_Line "ddkbuild -WNETW2K checked ."
# PROP BASE Rebuild_Opt "/a"
# PROP BASE Target_File "sebek.sys"
# PROP BASE Bsc_Name ""
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "sebek___Win32_Windows_2000_Checked"
# PROP Intermediate_Dir "sebek___Win32_Windows_2000_Checked"
# PROP Cmd_Line "ddkbuild -WNETW2K checked ."
# PROP Rebuild_Opt "/a"
# PROP Target_File "sebek.sys"
# PROP Bsc_Name ""
# PROP Target_Dir ""

!ELSEIF  "$(CFG)" == "sebek - Win32 Windows XP Checked"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "sebek___Win32_Windows_XP_Checked"
# PROP BASE Intermediate_Dir "sebek___Win32_Windows_XP_Checked"
# PROP BASE Cmd_Line "ddkbuild -WNETW2K checked ."
# PROP BASE Rebuild_Opt "/a"
# PROP BASE Target_File "sebek.sys"
# PROP BASE Bsc_Name ""
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "sebek___Win32_Windows_XP_Checked"
# PROP Intermediate_Dir "sebek___Win32_Windows_XP_Checked"
# PROP Cmd_Line "ddkbuild -WNETXP checked ."
# PROP Rebuild_Opt "/a"
# PROP Target_File "sebek.sys"
# PROP Bsc_Name ""
# PROP Target_Dir ""

!ELSEIF  "$(CFG)" == "sebek - Win32 Windows 2000 Free"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "sebek___Win32_Windows_2000_Free"
# PROP BASE Intermediate_Dir "sebek___Win32_Windows_2000_Free"
# PROP BASE Cmd_Line "ddkbuild -WNETW2K free ."
# PROP BASE Rebuild_Opt "/a"
# PROP BASE Target_File "sebek.sys"
# PROP BASE Bsc_Name ""
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "sebek___Win32_Windows_2000_Free"
# PROP Intermediate_Dir "sebek___Win32_Windows_2000_Free"
# PROP Cmd_Line "ddkbuild -WNETW2K free ."
# PROP Rebuild_Opt "/a"
# PROP Target_File "sebek.sys"
# PROP Bsc_Name ""
# PROP Target_Dir ""

!ELSEIF  "$(CFG)" == "sebek - Win32 Windows XP Free"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "sebek___Win32_Windows_XP_Free"
# PROP BASE Intermediate_Dir "sebek___Win32_Windows_XP_Free"
# PROP BASE Cmd_Line "ddkbuild -WNETW2K free ."
# PROP BASE Rebuild_Opt "/a"
# PROP BASE Target_File "sebek.sys"
# PROP BASE Bsc_Name ""
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "sebek___Win32_Windows_XP_Free"
# PROP Intermediate_Dir "sebek___Win32_Windows_XP_Free"
# PROP Cmd_Line "ddkbuild -WNETXP free ."
# PROP Rebuild_Opt "/a"
# PROP Target_File "sebek.sys"
# PROP Bsc_Name ""
# PROP Target_Dir ""

!ENDIF 

# Begin Target

# Name "sebek - Win32 Windows 2000 Checked"
# Name "sebek - Win32 Windows XP Checked"
# Name "sebek - Win32 Windows 2000 Free"
# Name "sebek - Win32 Windows XP Free"

!IF  "$(CFG)" == "sebek - Win32 Windows 2000 Checked"

!ELSEIF  "$(CFG)" == "sebek - Win32 Windows XP Checked"

!ELSEIF  "$(CFG)" == "sebek - Win32 Windows 2000 Free"

!ELSEIF  "$(CFG)" == "sebek - Win32 Windows XP Free"

!ENDIF 

# Begin Group "Source Files"

# PROP Default_Filter "cpp;c;cxx;rc;def;r;odl;idl;hpj;bat"
# Begin Source File

SOURCE=.\adapters.c
# End Source File
# Begin Source File

SOURCE=.\antidetection.c
# End Source File
# Begin Source File

SOURCE=.\av.c
# End Source File
# Begin Source File

SOURCE=.\consolespy.c
# End Source File
# Begin Source File

SOURCE=.\debug.c
# End Source File
# Begin Source File

SOURCE=.\exports.c
# End Source File
# Begin Source File

SOURCE=.\hooked_fn.c
# End Source File
# Begin Source File

SOURCE=.\logging.c
# End Source File
# Begin Source File

SOURCE=.\memtrack.c
# End Source File
# Begin Source File

SOURCE=.\packet.c
# End Source File
# Begin Source File

SOURCE=.\sebek.c
# End Source File
# Begin Source File

SOURCE=.\sock.c
# End Source File
# Begin Source File

SOURCE=.\util.c
# End Source File
# End Group
# Begin Group "Header Files"

# PROP Default_Filter "h;hpp;hxx;hm;inl"
# Begin Source File

SOURCE=.\adapters.h
# End Source File
# Begin Source File

SOURCE=.\antidetection.h
# End Source File
# Begin Source File

SOURCE=.\av.h
# End Source File
# Begin Source File

SOURCE=.\consolespy.h
# End Source File
# Begin Source File

SOURCE=.\debug.h
# End Source File
# Begin Source File

SOURCE=.\exports.h
# End Source File
# Begin Source File

SOURCE=.\exports_int.h
# End Source File
# Begin Source File

SOURCE=.\logging.h
# End Source File
# Begin Source File

SOURCE=.\memtrack.h
# End Source File
# Begin Source File

SOURCE=.\net.h
# End Source File
# Begin Source File

SOURCE=.\nt.h
# End Source File
# Begin Source File

SOURCE=.\packet.h
# End Source File
# Begin Source File

SOURCE=.\pe.h
# End Source File
# Begin Source File

SOURCE=.\sebek.h
# End Source File
# Begin Source File

SOURCE=.\sock.h
# End Source File
# Begin Source File

SOURCE=.\system_service.h
# End Source File
# Begin Source File

SOURCE=.\util.h
# End Source File
# End Group
# Begin Group "Resource Files"

# PROP Default_Filter "ico;cur;bmp;dlg;rc2;rct;bin;rgs;gif;jpg;jpeg;jpe"
# Begin Source File

SOURCE=.\sebek.rc
# End Source File
# End Group
# Begin Source File

SOURCE=.\MAKEFILE
# End Source File
# Begin Source File

SOURCE=.\SOURCES
# End Source File
# End Target
# End Project
