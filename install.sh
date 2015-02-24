#!/bin/bash

insmod ./interface.ko link=$1
dmesg | tail
