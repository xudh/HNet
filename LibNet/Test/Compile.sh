#! /bin/sh

gcc -std=gnu99 -O2 -Wall -fno-strict-aliasing -I../Include -L../Library Test.c -lNet

