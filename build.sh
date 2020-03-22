#!/bin/bash

gcc -O3 -o dupdup.bin dupdup.c -lpcap -lnet $1
