# Benjamin Smith bxs566 11/07/2024
# makefile
CC=gcc
CXX=g++
LD=gcc
CFLAGS=-Wall -Werror -g
LDFLAGS=$(CFLAGS)

TARGETS=proj4

all: $(TARGETS)

proj4: proj4.o
	$(CC) $(CFLAGS) -o $@ next.c $< 

%.o: %.c
	$(CC) $(CFLAGS) -c $<

%.o: %.cc
	$(CXX) $(CFLAGS) -c $<

clean:
	rm -f *.o

distclean: clean
	rm -f $(TARGETS)
