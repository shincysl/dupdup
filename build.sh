#!/bin/bash

gcc -O3 -o dupdup dupdup.c -lpcap -lnet $1
