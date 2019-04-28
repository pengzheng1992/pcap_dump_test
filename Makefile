all: pcap_offline.o
	gcc -o pcap_offline pcap_offline.o -lpcap -Wall -O3

pcap_offline.o: pcap_offline.c
	gcc -c pcap_offline.c -lpcap -Wall -O3

clean:
	rm *.o
	rm pcap_offline

run:
#	./pcap_offline -p ~/pcap/equinix-chicago.dirA.20160121-125911.UTC.anon.pcap
#	./pcap_offline -p ~/pcap/equinix-chicago.dirA.20160218-130000.UTC.anon.pcap
#	./pcap_offline -p ~/pcap/equinix-chicago.dirA.20160317-130100.UTC.anon.pcap
	./pcap_offline -p ./xjtu_http_00.pcap
