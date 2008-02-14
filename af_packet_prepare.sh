#!/bin/bash

patch -N -s  af_packet.c af_packet.c.diff.adder
#patch  af_packet.c af_packet.diff
echo 'end of prepare, rejects are OK here';


