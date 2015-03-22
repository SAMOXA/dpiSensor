#!/bin/bash

insmod ./interface.ko link=$1 output_dev=$2 debug=1
dmesg | tail
