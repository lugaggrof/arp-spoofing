LDLIBS=-lpcap
CXXFLAGS=-g

all: arp-spoof

main.o: mac.h ip.h ethhdr.h arphdr.h ipv4hdr.h main.h main.cpp

ipv4hdr.o: ip.h ipv4hdr.h ipv4hdr.cpp

arphdr.o: mac.h ip.h arphdr.h arphdr.cpp

ethhdr.o: mac.h ethhdr.h ethhdr.cpp

ip.o: ip.h ip.cpp

mac.o : mac.h mac.cpp

arp-spoof: main.o arphdr.o ipv4hdr.o ethhdr.o ip.o mac.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f arp-spoof *.o
