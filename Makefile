CC = g++
CPPFLAGS = -std=c++17
LDLIBS = -lpcap

all: airodump

airodump: main.o mac.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f airodump *.o
