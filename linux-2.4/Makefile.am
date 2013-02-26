#KERN_SRC = /usr/src/linux-2.4
KERN_SRC = @kern_src@
INCLUDES = -I$(KERN_SRC)/include
CFLAGS   = -O2 -DUSE_MOD_LICENSE -DUSE_FUDGE


EXTRA_DIST      = sbk_install.sh gen_fudge.pl af_packet_prepare.sh af_packet.c.diff.adder compile_filter.pl filter.txt get_if.pl README README.FILTER
bin_SCRIPTS	= sbk_install.sh gen_fudge.pl af_packet_prepare.sh get_if.pl
bin_PROGRAMS    = sebek cleaner bintar 

sebek_SOURCES   =  sebek.c sebek.h af_packet.diff sbk_util.c sbk_util.h filter.c filter.h
cleaner_SOURCES =  cleaner.c 
bintar_SOURCES  = 



af_packet.c: af_packet.diff
	cp -f $(KERN_SRC)/net/packet/af_packet.c .
	./af_packet_prepare.sh
	patch  af_packet.c af_packet.diff

fudge.h: gen_fudge.pl
	./gen_fudge.pl > fudge.h

sbk_OBJ: af_packet.c sebek.c filter.c sbk_util.c fudge.h
	$(CC) -c $(INCLUDES) ${DFLAGS} $(CFLAGS) $(srcdir)/sebek.c   -o sebek.o
	$(CC) -c $(INCLUDES) ${DFLAGS} $(CFLAGS) $(srcdir)/filter.c  -o filter.o
	$(CC) -c $(INCLUDES) ${DFLAGS} $(CFLAGS) $(srcdir)/sbk_util.c -o sbk_util.o
	rm af_packet.c

sebek$(EXEEXT): af_packet.c sbk_OBJ fudge.h
	ld -m elf_i386 -r -o sbk_mod.o sebek.o filter.o sbk_util.o


cleaner$(EXEEXT): cleaner.c
	$(CC) -c $(INCLUDES) $(CFLAGS) $(srcdir)/cleaner.c -o cleaner.o

bintar$(EXEEXT):  sebek cleaner
	mkdir @PACKAGE@-@VERSION@-bin
	cp sbk_mod.o @PACKAGE@-@VERSION@-bin
	cp cleaner.o @PACKAGE@-@VERSION@-bin
	cp $(srcdir)/compile_filter.pl  @PACKAGE@-@VERSION@-bin
	cp $(srcdir)/filter.txt  @PACKAGE@-@VERSION@-bin
	cp $(srcdir)/parameters.sh @PACKAGE@-@VERSION@-bin
	cp $(srcdir)/sbk_install.sh @PACKAGE@-@VERSION@-bin
	cp $(srcdir)/get_if.pl @PACKAGE@-@VERSION@-bin
	cp $(srcdir)/README @PACKAGE@-@VERSION@-bin
	cp $(srcdir)/README.FILTER @PACKAGE@-@VERSION@-bin
	chmod u+x @PACKAGE@-@VERSION@-bin/sbk_install.sh
	tar -cf @PACKAGE@-@VERSION@-bin.tar @PACKAGE@-@VERSION@-bin
	rm -rf @PACKAGE@-@VERSION@-bin
