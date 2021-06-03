#!/bin/bash
gcc server.c -o server -Wall -g -g3  -pthread -L/usr/lib -lssl -lcrypto
./server "$@"