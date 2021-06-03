#!/bin/bash
gcc client.c -o client -Wall -g -g3  -pthread -L/usr/lib -lssl -lcrypto
./client "$@"