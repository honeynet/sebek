# Microsoft Developer Studio Project File - Name="Configuration Wizard" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Application" 0x0101

CFG=Configuration Wizard - Win32 Debug
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "Configuration Wizard.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "Configuration Wizard.mak" CFG="Configuration Wizard - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "Configuration Wizard - Win32 Release" (based on "Win32 (x86) Application")
!MESSAGE "Configuration Wizard - Win32 Debug" (based on "Win32 (x86) Application")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe
MTL=midl.exe
RSC=rc.exe

!IF  "$(CFG)" == "Configuration Wizard - Win32 Release"

# PROP BASE Use_MFC 6
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "Release"
# PROP BASE Intermediate_Dir "Release"
# PROP BASE Target_Dir ""
# PROP Use_MFC 6
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "Release"
# PROP Intermediate_Dir "Release"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MD /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /D "_AFXDLL" /Yu"stdafx.h" /FD /c
# ADD CPP /nologo /MT /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /D "_MBCS" /Yu"stdafx.h" /FD /c
# ADD BASE MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x409 /d "NDEBUG" /d "_AFXDLL"
# ADD RSC /l 0x409 /d "NDEBUG" /d "_AFXDLL"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 /nologo /subsystem:windows /machine:I386
# ADD LINK32 wsock32.lib Imagehlp.lib /nologo /subsystem:windows /machine:I386

!ELSEIF  "$(CFG)" == "Configuration Wizard - Win32 Debug"

# PROP BASE Use_MFC 6
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "Debug"
# PROP BASE Intermediate_Dir "Debug"
# PROP BASE Target_Dir ""
# PROP Use_MFC 6
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "Debug"
# PROP Intermediate_Dir "Debug"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MDd /W3 /Gm /GX /ZI /Od /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /D "_AFXDLL" /Yu"stdafx.h" /FD /GZ /c
# ADD CPP /nologo /MTd /W3 /Gm /GX /ZI /Od /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /D "_MBCS" /Yu"stdafx.h" /FD /GZ /c
# ADD BASE MTL /nologo /D "_DEBUG" /mktyplib203 /win32
# ADD MTL /nologo /D "_DEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x409 /d "_DEBUG" /d "_AFXDLL"
# ADD RSC /l 0x409 /d "_DEBUG" /d "_AFXDLL"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 /nologo /subsystem:windows /debug /machine:I386 /pdbtype:sept
# ADD LINK32 wsock32.lib Imagehlp.lib /nologo /subsystem:windows /debug /machine:I386 /pdbtype:sept

!ENDIF 

# Begin Target

# Name "Configuration Wizard - Win32 Release"
# Name "Configuration Wizard - Win32 Debug"
# Begin Group "Source Files"

# PROP Default_Filter "cpp;c;cxx;rc;def;r;odl;idl;hpj;bat"
# Begin Group "Property Pages"

# PROP Default_Filter ""
# Begin Source File

SOURCE=.\ConfigurationWizardConfigFileName.cpp
# End Source File
# Begin Source File

SOURCE=.\ConfigurationWizardConfigFileName.h
# End Source File
# Begin Source File

SOURCE=.\ConfigurationWizardFinish.cpp
# End Source File
# Begin Source File

SOURCE=.\ConfigurationWizardFinish.h
# End Source File
# Begin Source File

SOURCE=.\ConfigurationWizardMagicValue.cpp
# End Source File
# Begin Source File

SOURCE=.\ConfigurationWizardMagicValue.h
# End Source File
# Begin Source File

SOURCE=.\ConfigurationWizardNetworkConfig.cpp
# End Source File
# Begin Source File

SOURCE=.\ConfigurationWizardNetworkConfig.h
# End Source File
# Begin Source File

SOURCE=.\ConfigurationWizardSelectFile.cpp
# End Source File
# Begin Source File

SOURCE=.\ConfigurationWizardSelectFile.h
# End Source File
# Begin Source File

SOURCE=.\ConfigurationWizardServerConfig.cpp
# End Source File
# Begin Source File

SOURCE=.\ConfigurationWizardServerConfig.h
# End Source File
# Begin Source File

SOURCE=.\ConfigurationWizardWelcome.cpp
# End Source File
# Begin Source File

SOURCE=.\ConfigurationWizardWelcome.h
# End Source File
# End Group
# Begin Source File

SOURCE=".\Configuration Wizard.cpp"
# End Source File
# Begin Source File

SOURCE=".\Configuration Wizard.rc"
# End Source File
# Begin Source File

SOURCE=.\ConfigurationWizardSheet.cpp
# End Source File
# Begin Source File

SOURCE=.\DriverConfig.cpp
# End Source File
# Begin Source File

SOURCE=.\StdAfx.cpp
# ADD CPP /Yc"stdafx.h"
# End Source File
# End Group
# Begin Group "Header Files"

# PROP Default_Filter "h;hpp;hxx;hm;inl"
# Begin Source File

SOURCE=".\Configuration Wizard.h"
# End Source File
# Begin Source File

SOURCE=.\ConfigurationWizardSheet.h
# End Source File
# Begin Source File

SOURCE=.\DriverConfig.h
# End Source File
# Begin Source File

SOURCE=.\MersenneTwister.h
# End Source File
# Begin Source File

SOURCE=.\Resource.h
# End Source File
# Begin Source File

SOURCE=.\Singleton.h
# End Source File
# Begin Source File

SOURCE=.\StdAfx.h
# End Source File
# End Group
# Begin Group "Resource Files"

# PROP Default_Filter "ico;cur;bmp;dlg;rc2;rct;bin;rgs;gif;jpg;jpeg;jpe"
# Begin Source File

SOURCE=".\res\Configuration Wizard.ico"
# End Source File
# Begin Source File

SOURCE=".\res\Configuration Wizard.rc2"
# End Source File
# Begin Source File

SOURCE=.\res\dot.bmp
# End Source File
# Begin Source File

SOURCE=.\res\WizardHeader.bmp
# End Source File
# Begin Source File

SOURCE=.\res\WizardWatermark.bmp
# End Source File
# End Group
# Begin Source File

SOURCE=.\ReadMe.txt
# End Source File
# End Target
# End Project
