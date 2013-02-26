#--------------------------------------------------------------------
#----- Sebek Build Instructions for linux 2.6 kernel
#-----
#----- Authors: see AUTHORS file
#----- Version: $Id: BUILD,v 1.4 2005/07/12 19:56:38 cvs Exp $
#-------------------------------------------------------------------- 
Fast version:

1.  Get the kernel source for the corresponding version you want to install on.
	- needed if you want to  sebekify the raw socket implementation

2.  Configure the build
	- configure --with-kernel-dir=/location/of/kernel/source

3.  Make the sytem
	./make

4.  cd into the src directory or untall the binary dist on the target.

5.  Edit sbk_install.sh to configure the proper settings.

6.  Install
	./sbk_install.sh


#----------

Details:

1.  Why does Sebek need the kernel source?

Within the normal world of 2.6 modules the kernel source is not needed 
because the system contains module build stubs typically located in 
/lib/modules/2.6.x.y/build/ . However the current version of Sebek needs to 
copy af_packet.c from the kernel source in order to modify and install a new 
sebekified raw socket implementation.  If you are only running one honeypot
on a LAN and dont need or want to replace the RAW SOCKET implementation then
set --disable-raw-sock-replacement in the configure. At that point you dont
need to install the kernel source.

2.  What happens if you dont replace the raw socket implementation?

If you set --disable-raw-socket-replacement, sebek wont replace the raw socket
implementation.  This does *not* mean an intruder can see locally generated 
Sebek packets however.  It means Sebek packets from host A wont be hidden on 
host B.  If you have only one Sebekified host on the LAN, then this isnt so 
much of an issue.


3.  Ok, what do I have to do if I DO want to replace the raw sock imp. ?

In this case you will need to install the appropriate kernel source, like in
the case of the 2.4 kernels.  As it currently stands the only reason for
this is so that we can get a copy of af_packet.c.  In the future will will 
provide some more elegant solution, like download on demand or something.

a. Make sure you have all the requirements.

    --The Makefile of the kernel to be compiled to (that is on the 
      decompressed kernel sources or if the kernel is installed in 
      "/lib/modules/KERNEL_VERSION/build"

    --The configure file for the kernel to be compiled into. That is usually 
      in the same location of the Makefile kernel makefile (see above)

    --The kernel requires to be configured to be using kernel modules AND the 
      proc filesystem
    
    --"af_packet.c" for the kernel to be compiled into. The current build 
      process will try to locate it at "KERNEL_SOURCES/net/packet". However 
      if you are not using a custom built kernel you might want to check the 
      original sources of the file and copy it to the appropiate location.

    -- Once the kernel is appropriately configured using "make oldconfig"
       or what ever you prefer you need to do one other thing, run
      "make prepare".  Though we dont need to actually build any of the 
       kernel source, we do need to make sure the includes/asm headers are
       set.

b. Run ./configure with the appropiate directory flags and possible a 
different compiler.  Watch out for compiler problems. As the compiler flag 
right now only is used for the tests of the configure file for the module 
compilation(sebek) the same compiler as in the kernel Makefile is used.  We 
have tested linux 2.6.0 through 2.6.3 with gcc V 3.2.3 and linux 2.6.4-2.6.11
 with gcc v 3.4.3.

c. Assuming no errors run make. Make will:

   -- copy the af_packet.c from the source directory and patch it
   
   -- compile all the kernel sources using the kernel's Makefile
   
   -- make the module
   
   -- make a tar binary distribution.


BUILD TESTING:

  We have tested on a number of systems including:

  - Debian:     	2.6.8-2-686
  - Fedora Core 3: 	2.6.11-1.27
 
