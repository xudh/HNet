#! /bin/sh

gcc -std=gnu99 -O2 -Wall -fno-strict-aliasing -I../Include -L../Library TestOnvifServer.c -lOnvif -lpthread -o TestOnvifServer
gcc -std=gnu99 -O2 -Wall -fno-strict-aliasing -I../Include -L../Library TestOnvifClient.c -lOnvif -o TestOnvifClient

