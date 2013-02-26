#!/usr/bin/perl

#
# * Copyright (C) 2004 Edward Balas
#
#


use strict;
use Socket;
use Getopt::Std;

my %uname2uid;
my %text2proto;

my $pwd_file   = "/etc/passwd";
my $proto_file = "/etc/protocols";


my $OPTION_UID            = 0x0001;
my $OPTION_PROTO          = 0x0002;
my $OPTION_LIP            = 0x0004;
my $OPTION_LMASK          = 0x0008;
my $OPTION_LPORT          = 0x0010;
my $OPTION_RIP            = 0x0020;
my $OPTION_RMASK          = 0x0040;
my $OPTION_RPORT          = 0x0080;
my $OPTION_DEV            = 0x0100;
my $OPTION_INODE          = 0x0200;
my $OPTION_FS_SUBDIR      = 0x0400;  

my $OPTION_CHILD_INHERITS = 0x1000;
my $OPTION_STRICT         = 0x2000;     

my $OPTION_SOCK_C         = 0x4000;
my $OPTION_SOCK_S         = 0x8000;        


my $ACTION_IGNORE         = 0;
my $ACTION_FULL           = 1;
my $ACTION_KSO            = 2;

my @config;

my $debug = 0;


sub init_uname2uid{

    my @vals;

    open(PWD,"$pwd_file") || die "$0: unable to open $pwd_file\n";

    foreach (<PWD>){
	chop($_);
	@vals = split(':',$_);

	$uname2uid{$vals[0]} = $vals[2];
    }
}

sub init_text2proto{
    my @vals;
    
    open(PWD,"$proto_file") || die "$0: unable to open $proto_file\n";
    
    foreach (<PWD>){
	chop($_);
	@vals = split('\s+',$_);

	$text2proto{$vals[0]} = $vals[1];
    }  
}


sub parse_action{
    my $line = shift;
    my $counter = shift;
    my $in = shift;
    my $val;
    my $remainder;

    if($debug){
	warn "parse_action: $line  $counter: '$in'\n";
    }

    ($val,$remainder) = split(/\s+/,$in,2);
    $val =~ s/A-Z/a-z/g;

    if($val eq "ignore"){
	$config[$counter]{"act"} = $ACTION_IGNORE;
    }elsif($val eq "full"){
	$config[$counter]{"act"} = $ACTION_FULL;
    }elsif($val eq "keystrokes"){
	$config[$counter]{"act"} = $ACTION_KSO;
    }else{
	die "syntax error: line $line: unknown action: '$val':  $in\n";	
    }
    return $remainder;
}

sub parse_user{
    my $line = shift;
    my $counter = shift;
    my $in = shift;
    my $val;
    my $uid;

    my $remainder;

    if($debug){
	warn "parse_user: $line  $counter: '$in'\n";
    }

    ($val,$remainder) = split(/\s+/,$in,2);

    $val =~ s/A-Z/a-z/g;
    #--- map uname to userid
    $uid = $uname2uid{$val};

   
    if($uid){
	$config[$counter]{"uid"} = $uid;
	$config[$counter]{"options"} |= $OPTION_UID;
    }else{
	die "error: line $line: unknown user: '$val':  $in\n";	
    }
    return $remainder;
}


sub parse_file{
    my $line = shift;
    my $counter = shift;
    my $in = shift;
    
    my $pre;
    my $f_conf;
    my $remainder;
    
    my $attr;
    my $val;

    my @stat;

    if($debug){
	warn "parse_file: $line  $counter: '$in'\n";
    }

    ($pre,$f_conf,$remainder) = split(/\(|\)/,$in,3);
    $f_conf =~ s/A-Z/a-z/g;

    my @elem = split(' ',$f_conf);

    foreach (@elem){
	($attr,$val) = split('=',$_,2);

	if($attr eq "name"){
	    @stat = stat($val);
	    if(!$stat[0]){
	        die "error: line $line: file not found: '$val'\n";
	    }
	    $config[$counter]{"fs"}{"i"} = $stat[1];
	    $config[$counter]{"options"} |= $OPTION_INODE;
	    $config[$counter]{"fs"}{"d"} = $stat[0];
	    $config[$counter]{"options"} |= $OPTION_DEV;
	}elsif($attr eq "inc_subdirs"){
	    $config[$counter]{"options"} |= $OPTION_FS_SUBDIR;
	}elsif($attr eq "strict"){
	    $config[$counter]{"options"} |= $OPTION_STRICT;
	}else{
	    die "syntax error: line $line: unknown file attribute: '$attr':  $in\n";
	}
    }

    return $remainder;
}

sub parse_sock{
    my $line = shift;
    my $counter = shift;
    my $in = shift;
    
    my $pre;
    my $f_conf;
    my $remainder;
    
    my $attr;
    my $val;

    my @stat;

    my $ip;
    my $mask;

    if($debug){
	warn "parse_sock: $line  $counter: '$in'\n";
    }

    ($pre,$f_conf,$remainder) = split(/\(|\)/,$in,3);
    $f_conf =~ s/A-Z/a-z/g;

    my @elem = split(' ',$f_conf);

    foreach (@elem){
	($attr,$val) = split('=',$_,2);
	if(!$attr){
	    $attr = $_;
	}
	if($attr eq "proto"){
	    if(! $val =~ /\d+/){
		die "syntax error: line $line: unknown attribute value: '$attr' = '$val'\n";
	    }	
	    $config[$counter]{"sock"}{"pr"} = $text2proto{$val};
	    $config[$counter]{"options"} |= $OPTION_PROTO;
	}elsif($attr eq "local_port"){
	    if(!($val =~ /^\d+$/)){
		die "syntax error: line $line: unknown attribute value: '$attr' = '$val'\n";
	    }	
	    $config[$counter]{"sock"}{"lp"} = $val;
	    $config[$counter]{"options"} |= $OPTION_LPORT;
	}elsif($attr eq "rem_port"){
	    if(!($val =~ /^\d+$/)){
		die "syntax error: line $line: unknown attribute value: '$attr' = '$val'\n";
	    }	
	    $config[$counter]{"sock"}{"rp"} = $val;
	    $config[$counter]{"options"} |= $OPTION_RPORT;
	}elsif($attr eq "rem_ip"){
	    ($ip,$mask) = split('/',$val);
	     if(! ($ip =~ /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/)){
		die "syntax error: line $line: unknown attribute value: 'rip' = '$ip'\n";
	    }	
	    if(!($mask =~ /^\d+$/)){
		die "syntax error: line $line: unknown attribute value: 'rmask' = '$mask'\n";
	    }	
	    $config[$counter]{"sock"}{"rip"} = unpack('N',inet_aton($ip));
	    $config[$counter]{"options"} |= $OPTION_RIP;
	    $config[$counter]{"sock"}{"r_mask"} = $mask;
	    $config[$counter]{"options"} |= $OPTION_RMASK;
	}elsif($attr eq "local_ip"){
	    ($ip,$mask) = split('/',$val);  
	    if(! ($ip =~ /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/)){
		die "syntax error: line $line: unknown attribute value: 'lip' = '$ip'\n";
	    }	
	    if(! ($mask =~ /^\d+$/)){
		die "syntax error: line $line: unknown attribute value: 'lmask' = '$mask'\n";
	    }	
	    $config[$counter]{"sock"}{"lip"} = unpack('N',inet_aton($ip));
	    $config[$counter]{"options"} |= $OPTION_LIP;
	    $config[$counter]{"sock"}{"l_mask"} = $mask;
	    $config[$counter]{"options"} |= $OPTION_LMASK;
	}elsif($attr eq "strict"){
	    $config[$counter]{"options"} |= $OPTION_STRICT;
	}elsif($attr eq "client"){
	   
	    $config[$counter]{"options"} |= $OPTION_SOCK_C;
	}elsif($attr eq "server"){
	    
	    $config[$counter]{"options"} |= $OPTION_SOCK_S;
	}else{
	    die "syntax error: line $line: unknown sock attribute: '$attr': $in\n";
	}
    }
    return $remainder;
}    

sub parse_options{
    my $line = shift;
    my $counter = shift;
    my $in = shift;
    
    my $pre;
    my $f_conf;
    my $remainder;
    
    my $attr;
    my $val;

    my @stat;

    if($debug){
	warn "parse_options: $line  $counter: '$in'\n";
    }

    ($pre,$f_conf,$remainder) = split(/\(|\)/,$in,3);
    $f_conf =~ s/A-Z/a-z/g;
    
    my @elem = split(/' '/,$f_conf);

    foreach (@elem){
	if($_ eq "follow_child_proc"){
	    $config[$counter]{"options"} |= $OPTION_CHILD_INHERITS;
	}else{
	    die "syntax error: line $line: unknown option: '$_'\n";
	}
    }

    return $remainder;
}


sub parse_line{
    my $line = shift;
    my $counter  = shift;
    my $in       = shift;

    if($debug){
	warn "parse_line: $line  $counter: '$in'\n";
    }

    my $attr;
    my $val;
    my $action_def = 0;

    $val = $in;
    while(1){
	($attr,$val) = split('=',$val,2);

	
	#print "$attr <-> $val\n";
	
	$attr =~ s/A-Z/a-z/g;
	$attr =~ s/^\s+//;

	if(!defined $attr || $attr eq ""){
	    last;
	}
	
	if($attr eq "action"){
	    $val = parse_action($line,$counter,$val);
	    $action_def=1;
	}elsif($attr eq "user"){
	    $val = parse_user($line,$counter,$val);
	}elsif($attr eq "file"){
	    $val = parse_file($line,$counter,$val);
	}elsif($attr eq "sock"){
	    $val = parse_sock($line,$counter,$val);
	}elsif($attr eq "opt"){
	    $val = parse_options($line,$counter,$val);
	}else{
	    die "syntax error: line $line: unknown attribute: '$attr'\n";
	}
	if(!$action_def){
	    die "syntax error: line $line: no action defined\n";  
	}

    }
}


sub main{

    my $input_file;
    my $output_file = "-";

    #------- get user input
    my %opt;
    
    getopts("i:o:hd",\%opt);
    
    if($opt{i}){
        $input_file = $opt{i};
    }
    
    if($opt{o}){
        $output_file = $opt{o};
    }
    
    
    init_uname2uid();
    init_text2proto();

    my %config;
    my $counter;
    
    if($opt{h}){
        print "$0:(Compile Sebek filter cofiguration)\n";
        print "\t-i  input  file\n";
        print "\t-o  output file\n";
	print "\t-d  debugging output to stderr\n";
        print "\t-h  Help\n";
        exit;	
    }

    if($opt{d}){
	$debug = 1;
    }
    
    
    #----- open files
    open(IN,"$input_file") || die " $0 : unable to open $input_file\n";
    open(OUT,">$output_file") || die "$0 : unable to open $output_file\n";

    my %config;
    my $counter = 0;
    my $line    = 0;
   

    #----- read in configuration
    while(<IN>){
	$line++;
	next if(/^\#/ || /^$/);   #--- skip comments or blank lines
	chop($_);
	parse_line($line,$counter,$_);
	$counter++;
    }

    #----- ouput configuraton
    $counter = 0;
    
    my $act;
    my $uid;

    my $lip;
    my $lipmask;
    my $rip;
    my $ripmask;
    my $proto;
    my $lport;
    my $rport;

    my $dev;
    my $inode;
    my $subdirs;

    my $options;

    my $rec;

    foreach (@config){

	$act      = $$_{"act"};
	$uid      = $$_{"uid"};
	$options  = $$_{"options"};

	$proto    = $$_{"sock"}{"pr"};
	$lport    = $$_{"sock"}{"lp"};
	$rport    = $$_{"sock"}{"rp"};
	$rip      = $$_{"sock"}{"rip"};
	$lip      = $$_{"sock"}{"lip"};
	$ripmask  = $$_{"sock"}{"r_mask"};
	$lipmask  = $$_{"sock"}{"l_mask"};

	$dev      = $$_{"fs"}{"d"};
	$inode    = $$_{"fs"}{"i"};
	$subdirs  = $$_{"fs"}{"inc_sd"};

	#----- 

	print "$counter $act:";
	print "$options:";
	print "$uid:";
	print "$proto:$lip:$lipmask:$lport:$rip:$ripmask:$rport:";
	print "$dev:$inode\n";
	
	$counter++;
	#--- 32 bytes
	#---         7  2 7 7  8 
	$rec = pack("CSLSLCSLCSLLC",$act,$options,$uid,$proto,$lip,$lipmask,$lport,$rip,$ripmask,$rport,$dev,$inode,0);
	syswrite(OUT,$rec,32);
	      
    }
}

main();
