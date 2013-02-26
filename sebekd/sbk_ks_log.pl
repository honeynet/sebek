#!/usr/bin/perl
#
#--------------------------------------------------------------------
#----- $Header$
#--------------------------------------------------------------------
#
# Copyright (C) 2001-2003 The Honeynet Project.
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


my $ks_read_length_limit = 100;   #----- this is the maximum size of a read we 
				  #----- will consider to be kestroke based
                                  #----- yes, this approach does suck


sub main{ 
  
    my %dat;
    my $line;


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

	next if($type != 0 ||$len > $ks_read_length_limit);

	#---- right now sbk_ks_log.pl is ignoring the sys_open records, this is silly and will be fixed
	#---- soon.

	$com =~ s/\0//g;

	my $tm = gmtime($time_sec);
	my $datetime = strftime("%Y-%m-%d %H:%M:%S",$tm->sec,$tm->min,$tm->hour,$tm->mday,$tm->mon,$tm->year,$tm->wday,$tm->isdst);

	
	$dat{$ip}{$pid}{$inode}{$fd}{"data"}             .= $data;
	$dat{$ip}{$pid}{$inode}{$fd}{"uid"}{$uid}         = 1;
        $dat{$ip}{$pid}{$inode}{$fd}{"com"}{$com}         = 1;


	if($data =~ m/\n|\r/){
	    my $log;
	    my $uid_str;
	    my $com_str;
	    my $u;
	    my $c;

	    my $addr = inet_ntoa(pack("N",$ip));
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


	    print "[$datetime Host:$addr UID:$uid_str PID:$pid FD:$fd INO:$inode COM:$com_str ]#$log\n";
	     
	    #----- delete the record
	    undef  $dat{$ip}{$pid}{$inode}{$fd};


	}
	    
	

    }


}


main();
