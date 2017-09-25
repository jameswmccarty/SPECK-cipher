# Makefile for SPECK cipher

CC = gcc
CFLAGS = -ansi -Werror -Wall -O2
LFLAGS = 

all: speck testvect

speck: speck.c
	$(CC) $(CFLAGS) speck.c -o speck $(LFLAGS)

testvect: test_vectors.c
	$(CC) $(CFLAGS) test_vectors.c -o testvect $(LFLAGS)

clean:
	\rm testvect speck
