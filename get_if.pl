#!/usr/bin/perl
#
# * Copyright (C) 2004 Edward Balas
# * All rights reserved.

#---  get_if.pl
#---    
#---  this prints the interface associated with the default route
#---  if there is no default route, then no interface name is printed.

use strict;

my $file="/proc/net/route";


sub main{
    my @row;
    
    open(ROUTE,$file) or die;

    while(<ROUTE>){
	#chop;
	@row = split('\s+',$_);
	if($row[1] eq "00000000" && $row[7] eq "00000000"){
	    print $row[0]."\n";
	    return 1;
	}
    }
    
    return -113
}


main();

