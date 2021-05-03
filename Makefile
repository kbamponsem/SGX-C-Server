CC=gcc
FLAGS=-Wall 
LINKS=-lulfius -ljansson

compile:
	$(CC) -o server server.c $(LINKS)

all: compile run

run:
	./server 8080
	
clean:
	rm server