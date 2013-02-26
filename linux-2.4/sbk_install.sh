#!/bin/sh
#------------------------------------------------------------------------------
#----- SEBEK LINUX CLIENT INSTALL SCRIPT --------------------------------------
#------------------------------------------------------------------------------


#------------------------------------------------------------------------------
#-----  USER CONFIGURABLE OPTIONS  --------------------------------------------
#----- NOTE: YOU MUST SPECIFIY A MAGIC VALUE AND DESTINATION PORT 
#------------------------------------------------------------------------------


#----- FILTER:
#-----
#----- File that contains the collection filter
#-----
FILTER="./filter.txt"


#----- INTERFACE:
#-----
#----- Identifies the interface from which Sebek will log
#----- This does not need to be an interface that has a
#----- configured IP address.
#-----
INTERFACE="eth0"

#----- DESTINATION_IP:
#-----
#----- sets destination IP for sebek packets
#-----
#----- If the collector is on the LAN, this value can be any address.
#-----
DESTINATION_IP="10.0.0.1"


#----- DESTINATION_MAC:
#-----
#----- sets destination MAC addr for sebek packets
#-----
#----- If the collector is running on the LAN, use the MAC from
#----- the collectors NIC.
#-----
#----- If the collector is multiple hops a way, set this to the MAC
#----- of Default Gateway's NIC
#-----
DESTINATION_MAC="FF:FF:FF:FF:FF:FF"


#----- SOURCE_PORT:
#-----
#----- defines the source udp port sebek sends to
#-----
#----- If multiple sebek hosts are behind NAT the source port
#----- is one way of distinguishing the two hosts
#-----
#----- Range:  1      to  655536
#----- Range:  0x0001 to  0xffff
#-----
SOURCE_PORT=1101


#----- DESTINATION_PORT:
#-----
#----- defines the destination udp port sebek sends to
#-----
#----- ALL HONEYPOTS that belong to the same group  NEED
#----- to use the SAME value for this.
#-----
#----- Range:  1      to  655536
#----- Range:  0x0001 to  0xffff
#-----
DESTINATION_PORT=0


#----- MAGIC_VAL
#-----
#----- defines the magic value in the sebek record, it
#----- used along with the Destination Port to identify 
#----- packets to hide from userspace on this host. Its
#----- an unsigned 32 bit integer.
#-----
#-----  ALL HONEYPOTS that belong to the same group  NEED
#----- to use the SAME value for this.
#-----
#----- Range 1          to  4.29497 billion
#----- Range 0x00000001 to  0xffffffff
#-----
MAGIC_VAL=1111


#----- KEYSTROKE_ONLY:
#-----
#----- controls if we only collect keystrokes, in this case anything that
#----- has a read length of 1. This is a binary option.
#----- 
#----- if set to 1: will only collect keystrokes
#----- if set to 0: will collect ALL read data(generates a LOT of data)
#-----   
KEYSTROKE_ONLY=1


#----- SOCKET_TRACKING:
#-----
#----- Controls if we only collect information on network connections
#----- This is a binary flag.
#----- 
#----- if set to 1: will track socket connections
#----- if set to 0: will not track sockets
#-----   
SOCKET_TRACKING=1

#----- TESTING:
#------
#----- Used to control if the kernel module is hidden. This is a binary option.
#-----
#----- if set to 1: kernel module wont be hiddent and can be rmmoded
#----- if set to 0: kernel module is hidden and cant be removed after install.
#-----
TESTING=0


#---- MODULE NAME:
#------
#---- Used to control the name of the module, this should NOT be set to sebek
#---- 
#---- if set this defines the variable, if not a random name is selected
#----
#----  example MODULE_NAME="foobar.o"
#----
MODULE_NAME=

#----- WRITE_TRACKING:
#-----
#----- Controls if we also collect data from write calls. 
#----- This is a binary option.
#-----
#----- if set to 1: will record write data
#----- if set to 0: will not record write data
#-----
WRITE_TRACKING=0




#------------------------------------------------------------------------------
#----- !! END OF USER CONFIGURABLE OPTIONS !!----------------------------------
#------------------------------------------------------------------------------


#----- source parameters -----
. ./parameters.sh


#------------------------------------------------------------------------------
echo $"Installing Sebek:"


if [ $DESTINATION_PORT -eq 0 ] ; then
    echo $"     ERROR:  Undefined Destination Port"
    exit 1
fi

if [ $MAGIC_VAL -eq 0 ] ; then
    echo $"     ERROR:  Undefined Magic Value"
    exit 1
fi


if [ ! $MODULE_NAME  ] ; then
    MODULE_NAME=${RAND_MOD_NAME}
fi


if [ $FILTER ]; then
    export LANG=POSIX
    ./compile_filter.pl -i ${FILTER} -o ./filter.of
    RETVAL=$?

    if [ $RETVAL -ne 0 ] ; then
        echo $"  unable to compile filter";
        exit
    fi

    FILTER="./filter.of";
fi



cp sbk_mod.o ${MODULE_NAME}

/sbin/insmod  -y ${MODULE_NAME}   ${DIP_PARM}=${DESTINATION_IP}\
			     ${DMAC_PARM}=${DESTINATION_MAC}\
                             ${DPORT_PARM}=${DESTINATION_PORT}\
                             ${SPORT_PARM}=${SOURCE_PORT}\
                             ${INT_PARM}=${INTERFACE} \
                             ${KSO_PARM}=${KEYSTROKE_ONLY}\
                             ${ST_PARM}=${SOCKET_TRACKING}\
                             ${FILTER_PARM}=${FILTER}\
                             ${MAGIC_PARM}=${MAGIC_VAL}\
                             ${TESTING_PARM}=${TESTING}\
                             ${WT_PARM}=${WRITE_TRACKING}
RETVAL=$?

if [ $RETVAL -eq 0 ] ; then
    #----- sebek module install succeeded
    echo $"  ${MODULE_NAME} installed successfully"


    #----- if we are NOT testing then hide the sebek module
    if [ $TESTING -eq 0 ] ; then   

        #-----  hide the sebek module with cleaner
	/sbin/insmod  ./cleaner.o
	RETVAL=$?

	if [ $RETVAL -eq 0 ] ; then
	    echo $"  cleaner.o installed successfully"
	fi



        #----- remove the cleaner module
	/sbin/rmmod cleaner
	RETVAL=$?

	if [ $RETVAL -eq 0 ] ; then
	    echo $"  cleaner.o removed successfully"
	fi

    fi

else
   #----- instal of the sebek module failed.
   echo $"  ${MODULE_NAME} install failed" 

fi
