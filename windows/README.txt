################################################################################
#                                                                              #
#  Sebek-WIN32 v3.0.4:  kernel module for forensic data capture                #
#
#  Chengyu Song <songchengyu@honeynet.org>
#  Michael A. Davis <mdavis@savidtech.com>                                     #
#                                                                              #
################################################################################

Theory of operation:

  Sebek uses techniques similar to those used by rootkits.  There is one kernel driver, sebek.sys, that hooks all console operations to collect interesting data from users.  Once the data is collected, this module exports this data over the network to a remote host.  Sebek also modifies the behavior of the kernel to prevent the discovery of the packets it is transmitting. Furthermore, Sebek will hide its presence in the Registry, FileSystem, and module list.

Whats new in this version:

  -  Fix for Bug #427 (Sebek 3.0.4 declares global variables used across files as static, causes ambiguity)
  -  Fix for Bug #426 (Sebek 3.0.4 causes BSOD when accesses paged out PEB)
  -  Fix for Bug #425 (Sebek 3.0.4 proc_tlb hash function may cause out of ranges array access, causes BSOD)
  -  Fix for Bug #424 (Sebek 3.0.4 has memory leak problem in FreeProcessData)
  -  Fix for Bug #423 (Sebek 3.0.4 reports socket accept events as connect events)

Installing Sebek:

	Three files should be contained within this distribution. This file, Readme.txt, the configuration tool Configuration Wizard.exe, and the kernel driver installer Setup.exe.
	
	Copy Configuration Wizard.exe and the appropriate version of Setup.exe to the host you want Sebek installed on. The installer will start and guide you through installation of the kernel driver. The installer contains all versions of sebek and it will automatically install the appropriate version for your operating system.
	
	Now, you MUST configure sebek BEFORE rebooting your machine otherwise sebek will not function properly.
 
Configuring Sebek:

	Run Configuration Wizard.exe and let the wizard guide you through configuration of sebek. When asked for a File Location. Click the Browse button next to the box and find the sebek.sys file. If you used the installer to install sebek-win32 then sebek.sys will be in C:\winnt\system32\drivers if you installed on Windows 2000 or C:\Windows\system32\drivers if you installed on Windows XP.

Reconfiguring Sebek:

	Just rerun the configuration program and let the wizard guide you through the reconfiguration of sebek.
	
Best Practices:
	
	It is recommended to NOT keep a copy of the configuration program on the server while sebek is installed. Rather you should place the program on the server whenever you want to reconfigure sebek.
	
Uninstalling Sebek:
	
	Sebek requires some manually intervention when uninstalling the software because the installer does not register itself with the system. 
	
	The following steps are required to remove sebek from a server:
	
	1) Boot the machine with the Operating System Install CD.
	2) Select the Recovery Console by pressing 'R'
	3) If you are running XP you can ignore this step. If you are running on Windows 2000 then press C to continue to open the Recovery Console.
	4) Choose the Windows installation you wish to modify. Usually there is only one listed.
	5) Provide the Administrator password.
	6) Once you are at the prompt type, 'disable sebek' without the single quotes.
	7) Once the command completes type exit to restart the machine.
	8) Once the system is restarted remove the sebek driver file from the C:\%SystemRoot%\System32\drivers folder.
	9) Remove the sebek registry key located at HKLM\System\CurrentControlSet\Services\sebek
	10) Remove the configuration program if it is on the machine.
	
Running:  

	Sebek currently starts at boot before the core of the OS loads.

Compiling Sebek:

	You will need the following to compile Sebek and the Configuration Wizard:
	
	1) The latest Windows DDK.
	2) The latest Windows Platform SDK.
	3) Visual Studio 6 or .NET if you want to use the preconfigured workspace/project files.
	4) ddkbuild.bat from http://www.hollistech.com/Resources/ddkbuild/ddkbuild.htm. Follow the instructions at the URL before compiling sebek.
	
	Once you have all the prerequisites you should be able to open the sebek.dsw workspace in Visual Studio and build the driver.
	
FAQ:

	Q: I am having some problems with sebek on windows who can I contact?
	
	A: Report all bugs using the Honeynet Bug System at https://bugs.honeynet.org or you can contact the developer, Michael A. Davis, at mdavis@savidtech.com or join the honeypots mailing list(http://www.securityfocus.com/popups/forums/honeypots/intro.shtml) and ask for help there.
	
	Q: What if I cannot boot into Windows because sebek is causing a problem?
	
	A: Run the Repair console from your Windows Installation CD. Once you are in the repair console type 'disable sebek' and then reboot. You should now be able to load Windows because sebek is disabled.

	Q: I am not seeing any process tree or keystroke data in roo.
	
	A: Make sure you are using roo-1.0.hw-189 or later. Earlier versions contain a race condition that caused the data from the win32 version of sebek to not be captured properly.
	
	Q: What if I want to use a different name then "sebek"
	
	A: Run the installer with a command line option of '/N=NAME' where NAME is the name of the driver you want WITHOUT the .sys appended.
	
Notes:

	I do not claim this to be the end all be all of data capturing. Sebek probably has ways to be detected or disabled etc. Please be aware of this and note that this is an ongoing development effort.
	
Bugs:

	Report all bugs using the Honeynet Bug System at https://bugs.honeynet.org
