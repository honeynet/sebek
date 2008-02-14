#!/usr/bin/perl
#
#--------------------------------------------------------------------
#----- $Header$
#--------------------------------------------------------------------
#
# Copyright (C) 2001-2005 The Honeynet Project.
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





sub main{ 
  
    my %dat;
    my $line;
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

    my $addr;
    my $s_addr;
    my $d_addr;

    my $inode;
    my $sip;
    my $sport;
    my $dip;
    my $dport;
    my $call;
    my $proto;

    #---- take records from sebeksniff via STDIN
    while(read(STDIN,$line,68,0) > 0){

	($pcap_sec, $pcap_usec,$ip,$magic,$ver,$type,$counter,$time_sec,$time_usec,$par_pid,$pid,$uid,$fd,$inode,$com,$len) =
	    unpack("LLNNnnNNNNNNNNa12N",$line);


	read(STDIN,$data,$len,0);

	$com =~ s/\0//g;

	my $tm = gmtime($time_sec);
	my $datetime = strftime("%Y-%m-%d %H:%M:%S",$tm->sec,$tm->min,$tm->hour,$tm->mday,$tm->mon,$tm->year,$tm->wday,$tm->isdst);

	
	$addr = inet_ntoa(pack("N",$ip));
	
	if($type == 0 || $type == 3 || $type == 1 ){
	    if($type == 0){
		$type = "sys_read";
	    }
	    if($type == 3){
		$type = "sys_open";
	    }
	    print "[$datetime  type=($type) ip=($addr) pid=($par_pid:$pid) command=($com) uid=($uid) inode=($inode) fd=($fd) len=($len)]$data\n";
	}

	if($type == 2){
	    #----- socket record.
	    ($dip,$dport,$sip,$sport,$call,$proto) =
		unpack("NnNnnC",$data);

	    $d_addr = inet_ntoa(pack("N",$dip));
	    $s_addr = inet_ntoa(pack("N",$sip));
	    print "[$datetime  type=(sys_socket) ip=($addr) pid=($par_pid:$pid) command=($com) uid=($uid) inode=($inode) fd=($fd) len=($len)";
	    print " call=($call) inode=($inode)]  $proto:  $s_addr:$sport -> $d_addr:$dport\n";

	}

	
    }
}

main();
