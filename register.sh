#!/bin/bash

comp_mode=$1

make clean
make $comp_mode

sudo chown "$USER" /dev/watchpoints
sudo chmod u+wr /dev/watchpoints
