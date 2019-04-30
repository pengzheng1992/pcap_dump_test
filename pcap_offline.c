// Author: PZ
// to test the function pcap_dump()

#include <string.h>
#include <stdio.h>
#include <pcap.h>
#include <time.h>

#define IN
#define OUT

int cnt = 0;

void print_usage() {
    fprintf(stderr, "Usage: ./pcap_offline -p filename\n");
}

int parse_args(IN int argc, IN char **argv, OUT const char **file) {
    for (int i = 1; i < argc; ++i) {
        char *arg = argv[i];
        if (!strcmp(arg, "-p") && i + 1 < argc)	{
            *file = argv[++i];
        } else {
            fprintf(stderr, "Unknown option '%s'.\n", arg);
            print_usage();
            return 1;
        }
    }
    return 0;
}

void getPacket(u_char * arg, const struct pcap_pkthdr * pkthdr, const u_char * packet)  
{  	
    ++cnt;
	printf("cnt: %d\n", cnt);
	if (cnt % 2 == 1) {
		pcap_dump((u_char*)arg, pkthdr, packet);  

		printf("Number of bytes: %d\n", pkthdr->caplen);  
		printf("Recieved time: %s", ctime((const time_t *)&pkthdr->ts.tv_sec));   
		  
		for(bpf_u_int32 i=0; i<pkthdr->len; ++i)  
		{  
		  printf(" %02x", packet[i]);  
		  if( (i + 1) % 16 == 0 )  
		  {  
		    printf("\n");  
		  }  
		}  
		  
		printf("\n\n");  
	}
}  

void callback(u_char *args, const struct pcap_pkthdr *pcap_header, const u_char *pcap_content) {
    ++cnt;
	return;
}

int main(IN int argc, IN char *argv[]) {
	pcap_t *handler;
	char errbuf[PCAP_ERRBUF_SIZE];
	const char* file = "";

	if (parse_args(IN argc, IN argv, OUT &file)) {
		fprintf(stderr, "Couldn't parse args.\n");
		return 1;
	}

	// open the file
	if ((handler = pcap_open_offline(file, errbuf)) == NULL) {
		fprintf(stderr, "Couldn't open file: %s\n%s\n", file, errbuf);
		print_usage();
		return 1;
	} else {
		printf("Open file: %s\n", file);
	}

	pcap_dumper_t *dumpfile;  
	time_t t_time;
	time(&t_time);
	struct tm *ps_time;	
	ps_time = localtime(&t_time);
	char current[1024];
	sprintf(current, "%04d%02d%02d%02d_%02d_%02d.pcap", ps_time->tm_year + 1900, ps_time->tm_mon+1, ps_time->tm_mday, ps_time->tm_hour, ps_time->tm_min, ps_time->tm_sec);
	 /* Open the dump file */  
	dumpfile = pcap_dump_open(handler, current);  

	// capture the packets
	pcap_loop(handler, 10, getPacket, (u_char*)dumpfile);
    
	printf("cnt: %d\n", cnt);

	// close the session
	pcap_close(handler);

	return 0;
}
