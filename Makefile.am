SBK_SRC = $(srcdir)/src


EXTRA_DIST      = sbk_install.sh gen_fudge.pl configure Makefile.in COPYING README BUILD AUTHORS ChangeLog \
		  compile_filter.pl filter.txt
bin_SCRIPTS	= sbk_install.sh gen_fudge.pl compile_filter.pl
bin_PROGRAMS    = sebek bintar

sebek_SOURCES   = $(SBK_SRC)/af_packet.diff $(SBK_SRC)/net.h $(SBK_SRC)/net.c $(SBK_SRC)/util.h \
		  $(SBK_SRC)/util.c $(SBK_SRC)/syscall.h $(SBK_SRC)/syscall.c \
                  $(SBK_SRC)/filter.h $(SBK_SRC)/filter.c $(SBK_SRC)/sebek.h \
	          $(SBK_SRC)/sebek.c $(SBK_SRC)/config.h.in $(SBK_SRC)/Makefile  
bintar_SOURCES  =
DISTCLEANFILES = @PACKAGE@-@VERSION@-bin.tar

if RAW_SOCK
af_packet.c: $(SBK_SRC)/af_packet.diff	
	  cp $(KERN_SRC)/net/packet/af_packet.c $(SBK_SRC) 
	  patch  $(SBK_SRC)/af_packet.c $(SBK_SRC)/af_packet.diff

else
af_packet.c: 

endif

sebek$(EXEEXT):  af_packet.c 
	./gen_fudge.pl > $(SBK_SRC)/fudge.h
	cp $(srcdir)/sbk_install.sh $(SBK_SRC)
	cp $(srcdir)/parameters.sh  $(SBK_SRC)
	cd $(SBK_SRC); make -C $(KERN_SRC) SUBDIRS=$(PWD)/src modules

bintar$(EXEEXT): sebek 
	mkdir @PACKAGE@-@VERSION@-bin
	cp $(SBK_SRC)/sbk.ko @PACKAGE@-@VERSION@-bin
	cp $(srcdir)/parameters.sh @PACKAGE@-@VERSION@-bin
	cp $(srcdir)/sbk_install.sh @PACKAGE@-@VERSION@-bin
	cp $(srcdir)/README @PACKAGE@-@VERSION@-bin
	cp $(srcdir)/compile_filter.pl @PACKAGE@-@VERSION@-bin
	cp $(srcdir)/filter.txt @PACKAGE@-@VERSION@-bin
	chmod u+x @PACKAGE@-@VERSION@-bin/sbk_install.sh
	tar -czf @PACKAGE@-@VERSION@-bin.tar.gz @PACKAGE@-@VERSION@-bin
	rm -rf @PACKAGE@-@VERSION@-bin

clean:
	
	cd $(SBK_SRC); make -C $(KERN_SRC) SUBDIRS=$(PWD)/src clean

