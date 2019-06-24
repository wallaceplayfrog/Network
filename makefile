cc = gcc
ping : ping.o
	cc -o ping ping.o

ping.o : ping.c ping.h
	cc -c ping.c
clean :
	rm ping ping.o