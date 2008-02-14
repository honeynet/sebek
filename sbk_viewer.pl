#!/usr/bin/perl
#
#--------------------------------------------------------------------
# 
# Author:  Raul Siles (raul@raulsiles.com)
# Acks:    This tool (plus the Sebek write functionality) was the result of a 
#          Honeynet collaboration research project between:
#          - Telefonica Moviles España (www.telefonicamoviles.com) and 
#          - Hewlett-Packard España (www.hp.es).
# Version: 0.9 ($VERSION)
# Date:    July 2005
# Notes:
# - The "read" functionality is based on the official Sebek "sbk_ks_log.pl" tool.
#
#--------------------------------------------------------------------
#
# Copyright (C) 2005 The Honeynet Project.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 3. All advertising materials mentioning features or use of this software
#    must display the following acknowledgement:
#      This product includes software developed by The Honeynet Project.
# 4. The name "The Honeynet Project" may not be used to endorse or promote
#    products derived from this software without specific prior written
#    permission.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY
# EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
#

use strict;
use 5.004;
use Getopt::Std;
use Time::gmtime;
use POSIX;
use FileHandle;
use Socket;
use Term::ANSIColor qw(:constants);

# Version
my $VERSION = '0.9';

# Syscalls types:
use constant SBK_READ => 0;  # RED
use constant SBK_WRITE => 1; # BLUE
use constant SBK_SOCK => 2;  # GREEN
use constant SBK_OPEN => 3;  # BLACK


my $ks_read_length_limit = 100;   #----- this is the maximum size of a read we 
				  #----- will consider to be kestroke based
                                  #----- yes, this approach does suck


sub main{ 
  
    my %dat;
    my $line;
    my $arg;
    my $verbose = 0;
    my $more_verbose = 0;
    my $filterby_type = 0;
    my $filterby_pid = 0;
    my $filterby_com = 0;
    my $user_type;
    my $user_pid;
    my $user_com;


    $Term::ANSIColor::AUTORESET = 1;

    # Parsing command line arguments
    while ($arg = shift(@ARGV)) {

    	if ($arg =~ /-h/) {
           help();
           exit(1);
	} elsif ($arg =~ /-v/) {
           # Verbose mode
           $verbose = 1;
	} elsif ($arg =~ /-V/) {
           # More verbose mode
           $more_verbose = 1;
    	} elsif ($arg =~ /-t/) {
           # Filtering based on SYSCALL type
           $filterby_type = 1;
	   $user_type = shift(@ARGV);
	   if ($user_type < SBK_READ || $user_type > SBK_WRITE) {
		print "**** Error: Wrong syscall type \"$user_type\".\n\n";
		help();
		exit(1);
	   } else {
		print " filtering by SYSCALL type ($user_type)\n";
	   }
    	} elsif ($arg =~ /-p/) {
           # Filtering based on PID number
           $filterby_pid = 1;
	   $user_pid = shift(@ARGV);
	   # Check it is a PID number: Windows, Linux...?
	   # ...
	   print " filtering by PID/PPID number ($user_pid)\n";
    	} elsif ($arg =~ /-c/) {
           # Filtering based on COMMAND string
           $filterby_com = 1;
	   $user_com = shift(@ARGV);
	   print " filtering by COMMAND string ($user_com)\n";
    	} else {
           print "**** Error: Wrong argument \"$arg\".\n\n";
           help();
           exit(1);
    	}
    } # foreach

    #---- take records from sebeksniff via STDIN
    while(read(STDIN,$line,68,0) > 0){

	my $ip;
        my $magic;
	my $ver;
        my $type;
	my $counter;
	my $time_sec;
	my $time_usec;
	my $pcap_sec;
	my $pcap_usec;
	my $par_pid;
	my $pid;
	my $uid;
	my $fd;
	my $inode;
	my $com;
	my $len;
	my $data;

	my $return_code;


	($pcap_sec,$pcap_usec,$ip,$magic,$ver,$type,$counter,$time_sec,$time_usec,$par_pid,$pid,$uid,$fd,$inode,$com,$len) =
	    unpack("LLNNnnNNNNNNNNa12N",$line);

      read(STDIN,$data,$len,0);

      # Command: process name
      $com =~ s/\0//g;
      
      # ---- Filtering ---
      # By syscall TYPE:
      if ($filterby_type) {
	 if ($user_type ne $type) {
	    next;
	 }
      }
      # By PID:
      if ($filterby_pid) {
	 if ($user_pid ne $pid && $user_pid ne $par_pid) {
	    next;
	 }
      }
      # By COMMAND:
      if ($filterby_com) {
	 if ($user_com ne $com) {
	    next;
	 }
      }

      # ---- Preparing variables for printing ----
      # Source IP address:
      my $addr = inet_ntoa(pack("N",$ip));

      # Sebek timestamp:
      my $tm = gmtime($time_sec);
      my $datetime = strftime("%Y-%m-%d %H:%M:%S",$tm->sec,$tm->min,$tm->hour,$tm->mday,$tm->mon,$tm->year,$tm->wday,$tm->isdst);
     
    	 
      # ACTIONS based on the "syscall" type:
      if ($type == SBK_READ && $len <= $ks_read_length_limit) {

	$dat{$ip}{$pid}{$inode}{$fd}{"data"}             .= $data;
	$dat{$ip}{$pid}{$inode}{$fd}{"uid"}{$uid}         = 1;
        $dat{$ip}{$pid}{$inode}{$fd}{"com"}{$com}         = 1;

	if($data =~ m/\n|\r/){
	    my $log;
	    my $uid_str;
	    my $com_str;
	    my $u;
	    my $c;

	    $log  = $dat{$ip}{$pid}{$inode}{$fd}{"data"};

	    #----- map control characters
	    $log =~ s/\x1b\[A/[U-ARROW]/g;
	    $log =~ s/\x1b\[B/[D-ARROW]/g;
	    $log =~ s/\x1b\[C/[R-ARROW]/g;
	    $log =~ s/\x1b\[D/[L-ARROW]/g;
	    $log =~ s/\x1b\[3~/[DEL]/g;
	    $log =~ s/\x1b\[5~/[PAGE-U]/g;
	    $log =~ s/\x1b\[6~/[PAGE-D]/g;
	    $log =~ s/\x7f/[BS]/g;
	    $log =~ s/\x1b/[ESC]/g;
	   
	    #----- scrub other nonascii values
	    $log =~ s/[^\x20-\x7e]//g;

	    my $x = 0;
	    foreach $u (keys %{$dat{$ip}{$pid}{$inode}{$fd}{"uid"}}){
		if($x++){
		    $uid_str .= "/$u";
		}else{
		    $uid_str .= "$u";
		}
	    }

	    $x = 0;
	    foreach $c(keys %{$dat{$ip}{$pid}{$inode}{$fd}{"com"}}){
		if($x++){
		    $com_str .= "/$c";
		}else{
		    $com_str .= "$c";
		}
	    }

	    if ($verbose) {
	       print RED "[$datetime Host:$addr UID:$uid_str PID:$pid($par_pid) FD:$fd INO:$inode COM:$com_str ]#$log\n";
	    } else {
	       print RED "\n#$log\n";
	    }
	     
	    #----- delete the record
	    undef  $dat{$ip}{$pid}{$inode}{$fd};

	} #if \r or \n (SBK_READ)


      } elsif ($type == SBK_WRITE) {

	    if ($verbose) {
	       	print BLUE "[$datetime Host:$addr UID:$uid PID:$pid($par_pid) FD:$fd INO:$inode COM:$com ]#\n$data\n";
		#---- verbose will show SSH encrypted data (garbage).
		#---- Reset the terminal.
	    } else {
	        #---- Filter SSH encrypted data: net coms (socket FD >= 3).
	        if ($fd < 3) { # FD=0,1,2: stdin,stdout,stderr
  	    	   #---- Avoid typing echoing: READ --> WRITE
		   #---- Linux shell prompt and echoing is generated through FD=2
	       	   if ($len > 1) {
	    	       print BLUE "$data";
		   }
	        }
	    }
	    
      } elsif ($type == SBK_SOCK) {

	    if ($more_verbose) {
		print GREEN "[$datetime Host:$addr UID:$uid PID:$pid($par_pid) FD:$fd INO:$inode COM:$com ]#\n";
	    }
      } elsif ($type == SBK_OPEN) {
	    if ($more_verbose) {
		print BLACK "[$datetime Host:$addr UID:$uid PID:$pid($par_pid) FD:$fd INO:$inode COM:$com ]#\n";
	    }
      } else {
	    print "**** Error: Wrong syscall type \"$type\" received from net packet!\n\n";

      } #if SYSCALLS types


    } #while READ

} #main


main();

# Help function
sub help {
    print "$0 (version: $VERSION)\n";
    print "Usage: $0 [-hvV] [-t <type>][-p <pid>][-c <com>]\n\n";
    print "  -h        This screen!\n";
    print "  -v        Verbose information (Timestamp, IP, UID, PID...) for READ and WRITE syscalls only\n";
    print "  -V        Verbose information (Timestamp, IP, UID, PID...) for SOCKET and OPEN syscalls only\n";
    print "  -t <type> Filter by SYSCALL type: 0 (READ) or 1 (WRITE) only!)\n";
    print "  -p <pid>  Filter by PID/PPID (Ex.- use a \"bash\" shell PID)\n";
    print "  -c <com>  Filter by COMMAND (Ex.- \"bash\")\n";
    print "\n";
}

