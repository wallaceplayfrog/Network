cc = gcc
ping.out : ping.o
	cc -o ping.out ping.o

ping.o : ping.c ping.h
	cc -c ping.c
clean :
	rm ping.out ping.o