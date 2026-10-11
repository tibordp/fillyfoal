# Makefile fragment
# build rules
CC = cc
all: main

main: main.o
	$(CC) -o $@ $^
# clean
