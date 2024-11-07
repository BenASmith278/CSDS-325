# Benjamin Smith bxs566 10/23/2024
# makefile
CC=gcc
CXX=g++
LD=gcc
CFLAGS=-Wall -Werror -g
LDFLAGS=$(CFLAGS)

TARGETS=proj3

all: $(TARGETS)

proj3: proj3.o
	$(CC) $(CFLAGS) -o $@ $< 

%.o: %.c
	$(CC) $(CFLAGS) -c $<

%.o: %.cc
	$(CXX) $(CFLAGS) -c $<

clean:
	rm -f *.o

distclean: clean
	rm -f $(TARGETS)
