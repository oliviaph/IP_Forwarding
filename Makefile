#Olivia Houghton
#Makefile for Programming Assignment 2, CS371 

ipforward : Source.o
	g++ -o ipforward Source.o
Source.o : Source.cpp
	g++ -c Source.cpp
clean:
	rm -f *.o
