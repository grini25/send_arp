all : pcap_test

pcap_test: main.o
	g++ -g -o send_arp main.o -lpcap -g

main.o:
	g++ -g -c -o main.o main.cpp

clean:
	rm -f send_arp
	rm -f *.o

