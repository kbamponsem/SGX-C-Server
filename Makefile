CC=gcc
FLAGS=-Wall 
LINKS=-lulfius -ljansson

compile:
	$(CC) -o server server.c $(LINKS)

all: compile

clean:
	rm server