#!/bin/bash

./uninstall.sh
make
./install.sh $1 $2
