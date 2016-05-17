#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>


#define T_A 1 //Ipv4 address
#define T_NS 2 //Nameserver
#define T_CNAME 5 // canonical name
#define T_SOA 6 /* start of authority zone */
#define T_PTR 12 /* domain name pointer */
#define T_MX 15 //Mail server

//DNS header structure
struct DNS_HEADER
{
    unsigned short id; // identification number

    unsigned char rd :1; // recursion desired
    unsigned char tc :1; // truncated message
    unsigned char aa :1; // authoritive answer
    unsigned char opcode :4; // purpose of message
    unsigned char qr :1; // query/response flag

    unsigned char rcode :4; // response code
    unsigned char cd :1; // checking disabled
    unsigned char ad :1; // authenticated data
    unsigned char z :1; // its z! reserved
    unsigned char ra :1; // recursion available

    unsigned short q_count; // number of question entries
    unsigned short ans_count; // number of answer entries
    unsigned short auth_count; // number of authority entries
    unsigned short add_count; // number of resource entries
};

//Constant sized fields of query structure
struct QUESTION
{
    unsigned short qtype;
    unsigned short qclass;
};


//Pointers to resource record contents
struct RES_RECORD
{
    unsigned short type;
    unsigned short _class;
    unsigned int ttl;
    unsigned short data_len;
};

//Structure of a Query
typedef struct
{
    unsigned char *name;
    struct QUESTION *ques;
} QUERY;

void set_header(struct DNS_HEADER *dns) {
		dns->id = (unsigned short) htons(getpid());
		dns->qr = 0; //This is a query
		dns->opcode = 0; //This is a standard query
		dns->aa = 0; //Not Authoritative
		dns->tc = 0; //This message is not truncated
		dns->rd = 1; //Recursion Desired
		dns->ra = 0; //Recursion not available! hey we dont have it (lol)
		dns->z = 0;
		dns->ad = 0;
		dns->cd = 0;
		dns->rcode = 0;
		dns->q_count = htons(1); //we have only 1 question
		dns->ans_count = 0;
		dns->auth_count = 0;
		dns->add_count = 0;

}


int main(int argc, char *argv[]) {
		int sock, sendSize, i;
		struct sockaddr_in servAddr;
		struct sockaddr_in fromAddr;
		unsigned int fromSize;
		int respStringLen, type, position = 0;
		unsigned char buf[1024],*reader;
		char *qname,  host[100], *rname, *rdata, *qname_len, *ip;

		//struct RES_RECORD answers[20],auth[20],addit[20]; //the replies from the DNS server
		struct RES_RECORD *rrecord = NULL;
		struct DNS_HEADER *dns = NULL;
		struct QUESTION *qinfo = NULL;

		//initialize socket
		if((sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
				printf("socket() failed.\n");
		memset(&servAddr, 0, sizeof(servAddr));
		servAddr.sin_family = AF_INET;
		servAddr.sin_addr.s_addr = inet_addr("127.0.0.2");
		servAddr.sin_port = htons(53);

		//Set the DNS structure to standard queries
		dns = (struct DNS_HEADER *)&buf;
		set_header(dns);

		printf("请输入想要查找的中文域名:\n");
		scanf("%s", host);

		position += sizeof(struct DNS_HEADER);
		qname_len =(char*)&buf[position];
		//*qname_len = strlen(host);
		sprintf(qname_len, "%c", (int)strlen(host));
		//printf("qname len %s\n",qname_len);


		position += 1;
		qname =(char*)&buf[position];
		strcpy(qname, host);

		printf("请输入查询类型: \n");
		scanf("%d",&type);

		position += (strlen((const char*)qname) + 1);
		qinfo = (struct QUESTION*)&buf[position];
		qinfo->qtype = htons(type); //type of the query , A , MX , CNAME , NS etc
		qinfo->qclass = htons(1); //its internet

		position += sizeof(struct QUESTION);
		printf("Sending Packet...\n");
		if((sendSize = sendto(sock,buf,position,0,(struct sockaddr*)&servAddr,sizeof(servAddr)))<0)
		{
			perror("sendto failed");
		}

		fromSize = sizeof(fromAddr);
		if((respStringLen = recvfrom(sock, buf, 1024, 0,
				(struct sockaddr *) &fromAddr, &fromSize)) < 0)
			printf("recvfrom() failed.\n");
		if(servAddr.sin_addr.s_addr != fromAddr.sin_addr.s_addr) {
				printf("Error: received a packet from unknown source.\n");
				exit(1);
		}
		printf("Done\n");

		dns = (struct DNS_HEADER*) &buf;

		if(ntohs(dns->add_count)==0) {
			position += sizeof(struct RES_RECORD);
			if(ntohs(qinfo->qtype)==1) {
				struct in_addr *rdata = (struct in_addr*)&buf[position];
				ip = inet_ntoa(*rdata);
				if(dns->rcode!=3)
					printf("The address is %s\n",ip);
				else
					printf("No record found!\n");

			}
			else if(ntohs(qinfo->qtype)==5) {//CNAME
				position++;
				rdata = (char *)&buf[position];
				printf("The canonical name is %s\n",rdata);
			}


		} else {//MX or NS
            if(ntohs(qinfo->qtype)==15)
			position += 2;

			position += sizeof(struct RES_RECORD);
			rdata = (char *)&buf[position];
			printf("The 服务器 is %s\n",rdata);
			position += (strlen(rdata)+1);


			position += sizeof(struct RES_RECORD);
			struct in_addr *rdata = (struct in_addr*)&buf[position];
			ip = inet_ntoa(*rdata);
			printf("The address is %s\n",ip);
		}


		close(sock);
		exit(0);
	}



