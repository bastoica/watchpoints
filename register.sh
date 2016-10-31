#!/bin/bash

make clean
make watchpoints

sudo chown "$USER" /dev/watchpoints
sudo chmod u+wr /dev/watchpoints
