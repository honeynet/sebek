#!/usr/bin/perl
#
#--------------------------------------------------------------------
#----- $Id: sebekd.pl 4560 2006-10-18 15:11:34Z redmaze $
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
use DBI;
use DBD::mysql;
use POSIX;
use FileHandle;
use Socket;
use English;


#-------------------------------------------------
my $dbh;
my $sensor_id   = 0;
my $db_name     = "walleye_0_3";
my $db_passwd   = ""; 
my $db_uid      = "root";
my $db_server   = "";
my $db_port     = "";


my $sebek_extract = "/usr/sbin/sbk_extract";
my $sebek_if      = "eth0";
my $sebek_port    = "1101";

my $setuid_name;
my $con_log;
#-------------------------------------------------

my %add_host_cache;
my %add_command_cache;


my $host_get_q;
my $host_add_q;
my $host_last_upd_q;

my $proc_add_q;
my $proc_check_pid_q;
my $proc_get_process_id_q;
my $proc_upd_min_t_q;
my $proc_upd_max_t_q;
my $proc_upd_pcap_max_t_q;
my $proc_upd_pcap_min_t_q;
my $proc_add_ptree_ent_q;


my $com_get_q;
my $com_add_q;

my $p2c_get_q;
my $p2c_add_q;

my $sys_read_add_q;
my $sys_open_add_q;
my $sys_socket_add_q;
my $sys_socket_get_id_q;


my $loss_add_q;


#---- prepare all the queries that we will be using.
sub prep_queries{

    my $sql;

    undef $dbh;

    do{
      $dbh = DBI->connect("DBI:mysql:database=$db_name;host=$db_server;port=$db_port",$db_uid,$db_passwd);
      if(!defined($dbh)){
	sleep 15;
      }    

    }while(!defined($dbh));

    warn "Connected to database\n";
    $dbh->{LongReadLen} = 16384;



  
    #--- prepare the process queries
    $proc_add_q             = $dbh->prepare("INSERT INTO process(sensor_id,src_ip,pcap_time_min,pcap_time_max,time_min,time_max,pid) VALUES (?,?,?, ?,? ,? ,?)");
    $proc_check_pid_q       = $dbh->prepare("SELECT process_id from process where sensor_id = ? and src_ip = ? and pid = ? ");
    $proc_get_process_id_q  = $dbh->prepare("SELECT process_id from process where sensor_id = ? and src_ip = ? and pid = ? and time_max >= ? and time_min <= ?");

    $proc_upd_min_t_q       = $dbh->prepare("UPDATE process SET time_min = ? where time_min > ? and sensor_id = ? and process_id = ? ");
    $proc_upd_max_t_q       = $dbh->prepare("UPDATE process SET time_max = ? where time_max < ? and sensor_id = ? and process_id = ? ");

    $proc_upd_pcap_min_t_q  = $dbh->prepare("UPDATE process SET pcap_time_min = ? where pcap_time_min > ? and sensor_id = ? and process_id = ? ");
    $proc_upd_pcap_max_t_q  = $dbh->prepare("UPDATE process SET pcap_time_max = ? where pcap_time_max < ? and sensor_id = ? and process_id = ? ");

    $proc_add_ptree_ent_q  = $dbh->prepare("INSERT into process_tree(sensor_id,child_process,parent_process) VALUES(?,?,?)");

    #--- prepare the command queries
    $com_get_q              = $dbh->prepare('SELECT command_id FROM command WHERE sensor_id = ? and name = ?');
    $com_add_q              = $dbh->prepare('INSERT INTO command (sensor_id,name) VALUES (?,?)');

    #--- prepare process_to_com_queries
    $p2c_get_q              = $dbh->prepare('select * from process_to_com where sensor_id = ? and process_id = ? and command_id = ?');
    $p2c_add_q              = $dbh->prepare('INSERT INTO process_to_com (sensor_id,process_id,command_id) VALUES (?,?,?)');

    #--- prepare sys_read query
    $sql   = "INSERT INTO sys_read (sensor_id,process_id, uid, pcap_time, time, counter, filed,inode, length, data)";
    $sql  .= "  VALUES (?,?,?,?,?, ?,?,?,?, ? ) ;";
    $sys_read_add_q = $dbh->prepare($sql);

    #--- prepare sys_open query
    $sql   = "INSERT INTO sys_open (sensor_id,process_id, uid, pcap_time, time, counter, filed,inode, length, filename)";
    $sql  .= "  VALUES (?,?,?,?,?, ?,?,?,?, ? ) ;";
    $sys_open_add_q = $dbh->prepare($sql);

    #--- prepare record loss add query.
    $loss_add_q = $dbh->prepare('INSERT INTO sbk_loss (sensor_id,src_ip,time,lost) VALUES (?,?,?,?)');

}




sub add_process{
    my $ip         = shift;
    my $pid        = shift;
    my $parent_pid = shift;
    my $pcap_time  = shift;
    my $time       = shift;

    my $sql;
    my $query;
    my $ret_code;

    my $process_id;

    my $parent_process_id;


   
   
    #---- check to see if this is a new process
    #---- need to add range check on time to work around pid rollover.
    $ret_code   = $proc_check_pid_q->execute($sensor_id,$ip,$pid);
    if(!defined $ret_code){return;}

    $process_id = $proc_check_pid_q->fetchrow_array();

    if(defined $process_id){

	#------ this is an existing process
	$proc_upd_min_t_q->execute($time,$time,$sensor_id,$process_id);
	$proc_upd_max_t_q->execute($time,$time,$sensor_id,$process_id);

        $proc_upd_pcap_min_t_q->execute($pcap_time,$pcap_time,$sensor_id,$process_id);
        $proc_upd_pcap_max_t_q->execute($pcap_time,$pcap_time,$sensor_id,$process_id);

    }else{
	#------ this is a new process, add it and identify the parent process
	$ret_code = $proc_add_q->execute($sensor_id,$ip,$pcap_time,$pcap_time,$time,$time,$pid);
        if(!defined $ret_code){return;}

	#------ get the process_id
	if($parent_pid){
	    #--- should this be using pcap time?
	    $ret_code   = $proc_get_process_id_q->execute($sensor_id,$ip,$pid,$time,$time);
	    $process_id = $proc_get_process_id_q->fetchrow_array();
	}


	#------ get the parent process_id
	#------ make sure the host is correct, and that the time relationship is plausible
	$parent_process_id = add_process($ip,$parent_pid,0,$pcap_time,$time);

	#------ add to process tree
	if($process_id && $parent_process_id){
	    $ret_code = $proc_add_ptree_ent_q->execute($sensor_id,$process_id,$parent_process_id);
	}

    }

   
    if(!defined $process_id){
	warn "how is process_id null coming out of add_process? $sensor_id $ip $pid\n";
    } 
    return $process_id;
}

sub add_command{
    my $command_name = shift;
    my $process_id   = shift;

    my $ret_code;

 
    my $command_id = $add_command_cache{"com_to_id"}{$command_name};

    if(!$command_id){
	#--- not in local cache, check db.
	$ret_code = $com_get_q->execute($sensor_id,$command_name);
	$command_id = $com_get_q->fetchrow_array();
    }


    if(!$command_id){
	#--- command name not in db, add it.
	$ret_code    = $com_add_q->execute($sensor_id,$command_name);
	$ret_code    = $com_get_q->execute($sensor_id,$command_name);
	$command_id  = $com_get_q->fetchrow_array();

	$add_command_cache{"com_to_id"}{$command_name} = $command_id;
    }

    #----- add process_id to command mapping.

    if(! defined $add_command_cache{"process_id_to_com_id"}{$process_id}{$command_id}){
	$ret_code = $p2c_get_q->execute($sensor_id,$process_id,$command_id);;	
	if($ret_code == "0E0" ){
	    #print "Add Process to Command_Name mapping\n";
	    $ret_code = $p2c_add_q->execute($sensor_id,$process_id,$command_id);
	}

	$add_command_cache{"process_id_to_com_id"}{$process_id}{$command_id}++;	
    }
    return $command_id;
}

#------ add a read record to the database
sub add_read{
    
    my $ip      = shift;
    my $pid     = shift;
    my $parent_pid = shift;
    my $pcap_time  = shift;
    my $time    = shift;
    my $counter = shift;
    my $fd      = shift;
    my $inode   = shift;    
    my $uid     = shift;
    my $command = shift;
    my $len     = shift;
    
    my $data    = shift;

    my $ret_code;

 

    #--- update process data
    my $process_id = add_process($ip,$pid,$parent_pid,$pcap_time, $time);
    if(!defined $process_id){return;}

	
    #--- get/update correct command id
    my $command_id = add_command($command,$process_id);
    if(!defined $command_id){return;}

    #--- update basic read record
    if($process_id && $command_id){
	$ret_code = $sys_read_add_q->execute($sensor_id,$process_id,$uid,$pcap_time,$time,$counter,$fd,$inode,$len,$data);
    
	return $ret_code;
    }
}


#------ add a read record to the database
sub add_open{
    
    my $ip      = shift;
    my $pid     = shift;
    my $parent_pid = shift;
    my $pcap_time  = shift;
    my $time    = shift;
    my $counter = shift;
    my $fd      = shift;
    my $inode   = shift;    
    my $uid     = shift;
    my $command = shift;
    my $len     = shift;
    
    my $data    = shift;

    my $ret_code;

 

    #--- update process data
    my $process_id = add_process($ip,$pid,$parent_pid,$pcap_time, $time);
    if(!defined $process_id){return;}

    #--- get/update correct command id
    my $command_id = add_command($command,$process_id);
    if(!defined $command_id){return;}
    

    #--- update basic read record
    if($process_id && $command_id){
	$ret_code = $sys_open_add_q->execute($sensor_id,$process_id,$uid,$pcap_time,$time,$counter,$fd,$inode,$len,$data);
    
	return $ret_code;
    }
}



#------ record a record loosing event;
sub report_loss{
    my $ip           = shift;
    my $time         = shift;
    my $lost         = shift;

    my $sql;
    my $query;
    my $ret_code;
 
    #$ret_code = $loss_add_q->execute($sensor_id,$ip,$time,$lost);
    warn "$time: host $ip: lost $lost\n";
}

sub add_socket{

    my $ip      = shift;
    my $pid     = shift;
    my $parent_pid = shift;
    my $pcap_time  = shift;
    my $time    = shift;
    my $counter = shift;
    my $fd      = shift;
    my $inode   = shift;
    my $uid     = shift;
    my $command = shift;
    my $len     = shift;
    my $data    = shift;

    my $dip;
    my $dport;
    my $sip;
    my $sport;
    my $call;
    my $proto;
   
    #--- update process data
    my $process_id = add_process($ip, $pid, $parent_pid,$pcap_time,$time );
    if(!defined $process_id){return;}

    #--- get/update correct command id
    my $command_id = add_command($command,$process_id);
    if(!defined $command_id){return;}


    ($dip,$dport,$sip,$sport,$call,$proto) = unpack("NnNnnC",$data);
	    
    #--- socket records
    if($process_id && $command_id){
	if(defined $con_log){
	    #------ print the log data including the database IP for the process
	    print   CONLOG "$process_id,$uid,$counter,$fd,$inode,$call,$pcap_time,$time,$proto,$sip,$sport,$dip,$dport\n";
	   
	}
	return 1;
    }
    return 0;
}


sub process_args{
    my %opt;

    getopts("i:p:U:W:P:D:S:P:I:u:l:h",\%opt);

    if($opt{h}){
	print "$0:(Loads Sebek records into specified mysql database)\n";
	print "\t-i  Monitoring interface\n";
	print "\t-p  Monitoring Port\n\n";

	print "\t-U  User ID\n";
	print "\t-W  Passwd\n";
	print "\t-D  Database Name\n";
	print "\t-S  Server Name or IP\n";
	print "\t-P  Port Number\n";
	print "\t-I  Sensor ID\n";
        print "\t-u  Username to setuid\n";
	print "\t-l  Connection Log file, used by hflow\n";  
	print "\t-h  Help\n";
	exit;
	
    }

    if($opt{i}){
	$sebek_if = $opt{i};
    }

    if($opt{p}){
	$sebek_port = $opt{p};
    }


    if($opt{U}){
	$db_uid = $opt{U};
    }

    if($opt{W}){
	$db_passwd = $opt{W};
    }
    
    if($opt{D}){
	$db_name = $opt{D};
    }

    if($opt{S}){
	$db_server = $opt{S};
    }
    
    if($opt{P}){
	$db_port = $opt{P};
    }

 
    if($opt{u}){
	$setuid_name = $opt{u};
        $UID=getpwnam($setuid_name);
        $EUID=getpwnam($setuid_name);
    }
    

    if($opt{l}){
	$con_log = $opt{l};
    }

    if($opt{I}){
	$sensor_id = unpack('N',inet_aton($opt{I}));
    }

}

sub main{ 
  
    #----- sebek PDU variables
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
    my $com;
    my $len;
    my $data;
    #----- sebek socket PDU variables
    my $inode;
    my $sip;
    my $sport;
    my $dip;
    my $dport;
    my $call;

    my $ret_code;
   
    #----- track lost records
    my %counter_lut;
    my $lost;
 
    eval{
	require DBI;
    };
    if($@){
	print STDERR " $0: needs DBI\n";
	exit 1;
    }


    #----- get input
    process_args();


    #----- open sebek_record feed
    open(SEBEK,"$sebek_extract -i $sebek_if -p $sebek_port | ") or die "unable to start $sebek_extract for reading\n";
   
    #----- open connection log
    if(defined $con_log){
	open(CONLOG,">>$con_log") or die "Unable to open $con_log for appending\n";
	autoflush CONLOG 1;
    }
  

    #----- get all of the queries ready to go;
    prep_queries();

    my $line;
    #---- take records from sbk_extract  via STDIN
    while(read(SEBEK,$line,68,0) > 0){
	
	($pcap_sec,$pcap_usec,$ip,$magic,$ver,$type,$counter,$time_sec,$time_usec,$par_pid,$pid,$uid,$fd,$inode,$com,$len) =
	    unpack("LLNNnnNNNNNNNNa12N",$line);

	read(SEBEK,$data,$len,0);



	#----- check for lost records
	if(defined $counter_lut{$ip}){
	    $lost = abs($counter - $counter_lut{$ip}) - 1;
	}else{
	    $lost = 0;
	}
	$counter_lut{$ip} = $counter;

	if($lost){
	    report_loss($ip,$pcap_sec,$lost);
	}
	

	#----- currently supports read socked and open calls(forks are encoded as null reads).
	next if($type < 0 || $type > 3);

	$com =~ s/\0//g;

	if($type == 0){
	    #----- sys_read call
	    $ret_code = add_read($ip,$pid,$par_pid,$pcap_sec,$time_sec,$counter,$fd,$inode,$uid,$com,$len,$data);
	}

	if($type == 2){
	    #----- sys_socket call  
	    $ret_code = add_socket($ip,$pid,$par_pid,$pcap_sec,$time_sec,$counter,$fd,$inode,$uid,$com,$len,$data);
	}

	if($type == 3){
	    #----- sys_open call  
	    $ret_code = add_open($ip,$pid,$par_pid,$pcap_sec,$time_sec,$counter,$fd,$inode,$uid,$com,$len,$data);
	}	
	

	if(!$ret_code){
	    #---- return code is goofy rest the db connection.
	    prep_queries();
	}

    } #end of while loop



}


main();
