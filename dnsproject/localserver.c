#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>
#include <string.h>

#define BUFFSIZE 1024
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
    short type;
    short _class;
    int ttl;
    short data_len;
};

//Structure of a Query
typedef struct
{
    unsigned char *name;
    struct QUESTION *ques;
} QUERY;

void Die(char *mess) { perror(mess); exit(1); }

char* convert_type(int qtype) {
	char * q_type = malloc(5);
	switch(qtype) {
		case 1: strcpy(q_type, "A"); break;
		case 2: strcpy(q_type, "NS"); break;
		case 5: strcpy(q_type, "CNAME"); break;
		case 6: strcpy(q_type, "SOA"); break;
		case 12: strcpy(q_type, "PTR"); break;
		case 15: strcpy(q_type, "MX"); break;
	}
	return q_type;
}

char* checklocalrecord(char* name, int type) {
	FILE *fp;
	int i, j, k, temp = 0;
	char line[100], content[20][100], recordname[30];
	char  *p, *qtype;

	qtype = convert_type(type);

	fp = fopen("local.db" , "r");
	if(fp == NULL)
		perror("Error opening file");
	else
	{
		while(fgets(line, 200, fp)!= NULL)
		{
        	strcpy(content[temp], line);
        	temp++;
 		}
		fclose(fp);
	}

	for(i = 0; i < temp; i++){

		if((p = strstr(content[i],qtype)))
		{
			for(j = 0; j<= strlen(content[i]); j++)
			{
				if(content[i][j] == ',')
				{
					for(k = 0; k < j; k++)
						recordname[k] = content[i][k];
					recordname[j]='\0';
					if(strcmp(name, recordname) == 0)
					{
						p =strstr(content[i], name);
						return p;
					}
					else
						break;
				}
			}
		}
	}
	p = NULL;
	return p;
}

int split(char *record,char field[5][100]) {
	int i, j, k, mark = -1, type = 0;
	if(record != NULL)
	{
		for(i = 0; i <= strlen(record); i++)
		{
			if(record[i] == ',' || record[i] == '\n')
			{
				k = 0;
				for(j = mark + 1; j < i; j++)
				{
					field[type][k] = record[j];
					k++;
				}
				field[type][k] = '\0';
				mark = i;
				type++;
		}
	}
		return 1;
	}
	else
		return 0;
}

short check_name_position(char* buf, char* name) {
	short offset = 0;
	char *start = buf;
	char *end =  buf + sizeof(struct DNS_HEADER)+1;
	if(strcmp(name,end)==0) {
		offset = end - start-1;

	}
	end = buf + 1;
	return offset;
}

void set_record(struct RES_RECORD *rrecord, char* rtype, char* rclass, char* rttl, short length) {
	int i;
	for(i=0;i<16;i++) {
		if(strcmp(convert_type(i),rtype)==0)
			rrecord->type = htons(i);
	}
	rrecord->_class = htons(1);
	rrecord->ttl = htonl(86400);
	rrecord->data_len = htons(length);
}

char* queryrootserver(char* data, short length, char* ansbuf) {
	int sock, received = 0;
	struct sockaddr_in echoserver;
	char buf[BUFFSIZE];
	char *ip=NULL, *qname;

	struct DNS_HEADER *dns = NULL;
	//dns = (struct DNS_HEADER *)data;

	/* Create the TCP socket */
	if ((sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
		Die("Failed to create socket");
	}
	/* Construct the server sockaddr_in structure */
	memset(&echoserver, 0, sizeof(echoserver));       /* Clear struct */
	echoserver.sin_family = AF_INET;                  /* Internet/IP */
	echoserver.sin_addr.s_addr = inet_addr("127.0.0.3");  /* IP address */
	echoserver.sin_port = htons(53);       /* server port */

	/* Establish connection */
	if (connect(sock,
		(struct sockaddr *) &echoserver,
		sizeof(echoserver)) < 0) {
		Die("Failed to connect with server");
	}


	/* Send the word to the server */
	if (send(sock, data, length, 0) != length) {
		Die("Mismatch in number of sent bytes");
	}

	/* Receive the next ip back from the server */
	//while (received < BUFFSIZE) {
	int bytes = 0;
	if ((bytes = recv(sock, buf, BUFFSIZE, 0)) < 0) {
		printf("receive error.\n");
	}
	received += bytes;
	buf[bytes] = '\0';

	dns = (struct DNS_HEADER *)&buf[2];

	if(ntohs(dns->add_count)>0) {
		short position = 0;
		position += (3+sizeof(struct DNS_HEADER));
		qname = (char *)&buf[position];

		position += (strlen(qname)+1);
		position += (sizeof(struct QUESTION)+sizeof(struct RES_RECORD));

		struct in_addr *rdata = (struct in_addr*)&buf[position];

		ip = inet_ntoa(*rdata);
		printf("Send to %s for query\n", ip);
	}else {
		char *tempbuf = (char *)buf;
		memcpy(ansbuf, tempbuf, received);
	}

	return ip;
}

short querytldserver(char* next_ip, char* data, short length, char* ansbuf) {
	int sock;
	struct sockaddr_in echoserver;
	char buf[BUFFSIZE];
	//char *qname, *rname, *rdata;
	int received = 0;
	//struct DNS_HEADER *dns = NULL;

	/* Create the TCP socket */
	if ((sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
		Die("Failed to create socket");
	}
	/* Construct the server sockaddr_in structure */
	memset(&echoserver, 0, sizeof(echoserver));       /* Clear struct */
	echoserver.sin_family = AF_INET;                  /* Internet/IP */
	echoserver.sin_addr.s_addr = inet_addr(next_ip);  /* IP address */
	echoserver.sin_port = htons(53);       /* server port */

	/* Establish connection */
	if (connect(sock,
		(struct sockaddr *) &echoserver,
		sizeof(echoserver)) < 0) {
	Die("Failed to connect with server");
	}

	/* Send the word to the server */
	if (send(sock, data, length, 0) != length) {
		Die("Mismatch in number of sent bytes");
	}

	int bytes = 0;
	if ((bytes = recv(sock, buf, BUFFSIZE-1, 0)) < 0) {
		printf("receive error.\n");
		//Die("Failed to receive bytes from server");
	}
	received += bytes;
	buf[bytes] = '\0';        /* Assure null terminated string */

	char *tempbuf = (char *)buf;
	tempbuf += 2;
	memcpy(ansbuf, tempbuf, received);
	close(sock);
	return received -2;
}


void set_header(struct DNS_HEADER *dns, int anscount, int authcount, int addcount) {
	dns->qr = 1; //This is a response
	dns->opcode = 0; //This is a standard query
	dns->aa = 0; //Not Authoritative
	dns->tc = 0; //This message is not truncated
	dns->rd = 1; //Recursion Desired
	dns->ra = 0; //Recursion not available!
	dns->z = 0;
	dns->ad = 0;
	dns->cd = 0;
	dns->rcode = 0;
	dns->q_count = htons(1); //we have only 1 question
	dns->ans_count = htons(1);
	dns->auth_count = htons(authcount);
	dns->add_count = htons(addcount);
}

int main(int argc, char *argv[]) {
		int sock;
		struct sockaddr_in servAddr;
		struct sockaddr_in clntAddr;
		unsigned int cliAddrLen;
		int recvMsgSize;
		char buf[BUFFSIZE];
		char  *p, *qname, *name, *rname, *add, recordfield[5][100], addrecord[5][100], *r_data, *next_ip;

		struct DNS_HEADER *dns = NULL;
		struct QUESTION *qinfo = NULL;
		struct RES_RECORD *r_record;

		if((sock = socket(PF_INET, SOCK_DGRAM, 0)) < 0)
				printf("socket() failed.\n");

		memset(&servAddr, 0, sizeof(servAddr));
		servAddr.sin_family = AF_INET;
		servAddr.sin_addr.s_addr = inet_addr("127.0.0.2");
		servAddr.sin_port = htons(53);

		if((bind(sock, (struct sockaddr *) &servAddr, sizeof(servAddr)))<0)
				printf("bind() failed.\n");

		for(;;) {
				int anscount = 0, authcount = 0, addcount = 0;
				short position = 0;
				cliAddrLen = sizeof(clntAddr);

				printf("**************************************\n");
				printf("*Local server listen at 127.0.0.2\n");
				printf("**************************************\n");
				if((recvMsgSize = recvfrom(sock, buf, BUFFSIZE,
						0, (struct sockaddr *) &clntAddr, &cliAddrLen))<0)
				printf("recvfrom() failed.\n");

				dns = (struct DNS_HEADER*)&buf;

				position += sizeof(struct DNS_HEADER);
				position++;
				qname =(char*)&buf[position];
				printf("*Query Name: %s\n", qname);

				position += (strlen((const char*)qname) + 1);
				qinfo = (struct QUESTION*)&buf[position];
				p = checklocalrecord(qname,ntohs(qinfo->qtype));

				position += sizeof(struct QUESTION);
				if(split(p,recordfield)!=0) {
					anscount++;
					name = recordfield[0];
					short temp = check_name_position((char *)buf, name);
					if(temp != 0) {
						unsigned short *offset = (unsigned short *)&buf[position];
						*offset = htons(temp+49152);
						position += 2;
					} else {
						char *rname_len = (char *)&buf[position];
						sprintf(rname_len, "%c", (int)strlen(name));
						position++;

						rname = (char *)&buf[position];
						strcpy(rname,name);
						position  += (strlen((const char*)rname) + 1);
					}
//Answer section
					if((strcmp(recordfield[3], "MX") == 0) || (strcmp(recordfield[3], "NS") == 0)) {

						r_record = (struct RES_RECORD*)&buf[position];
						int r_length = strlen(recordfield[4]) + 4;
                        if(strcmp(recordfield[3], "NS")==0)    r_length-=2;
						set_record(r_record, recordfield[3],recordfield[2], recordfield[1], r_length);
						position += sizeof(struct RES_RECORD);

                        if(strcmp(recordfield[3], "NS") == 0) {
                            position -= 2;
                            //NS has not preference
                        }
						char *r_data_len = (char *)&buf[position];
						sprintf(r_data_len, "%c", (int)strlen(recordfield[4]));
						int offset2 = position;
						position++;
						r_data = (char *)&buf[position];
						strcpy(r_data,recordfield[4]);
						r_data[strlen(r_data)] = '\0';
						position += (strlen(r_data)+1);
//additional section
						add = checklocalrecord(recordfield[4], 1);
						if(split(add,addrecord)!=0) {
							/**
							short *add_len = (short *)&buf[position];
							int temp_add_len = position;
							position += 2;

							temp = check_name_position((char *)buf, addrecord[0]);
							if(temp != 0) {
							*/
							unsigned short *offset = (unsigned short *)&buf[position];
							*offset = htons(offset2+49152);
							position += 2;

							r_record = (struct RES_RECORD*)&buf[position];
							int r_length2 = strlen(addrecord[4]);

							printf("*My Answer: %s\n", addrecord[4]);
							set_record(r_record, addrecord[3],addrecord[2], addrecord[1], r_length2);

							position += sizeof(struct RES_RECORD);

							position -= 2;
							struct in_addr *rdata = NULL;
							rdata = (struct in_addr*)&buf[position];
							inet_aton(addrecord[4],rdata);
							position += sizeof(struct in_addr);

							addcount++;

						}
					}
					else {

						r_record = (struct RES_RECORD*)&buf[position];
						int r_length = sizeof(struct in_addr);
						set_record(r_record, recordfield[3],recordfield[2], recordfield[1], r_length);
						position += sizeof(struct RES_RECORD);

						position -= 2;
						struct in_addr *rdata = NULL;
						rdata = (struct in_addr*)&buf[position];
						inet_aton(recordfield[4],rdata);
						position += sizeof(struct in_addr);
						printf("*My Answer: %s\n",recordfield[4]);

					}

					set_header(dns, anscount, authcount, addcount);

					if((sendto(sock, buf, position, 0,
						(struct sockaddr *) &clntAddr, sizeof(clntAddr))) < 0)
						printf("sendto() error.\n");
				}
				else {
					printf("Send to 127.0.0.3 for query\n");
					//switch_to_tcp
					char tcpbuf[BUFFSIZE];
					short *buf_len = malloc(2);
					*buf_len = htons(position);
					memcpy(&tcpbuf[0], buf_len, 2);

					char *tempbuf = (char *)&tcpbuf[2];
					memcpy(tempbuf, buf, position);

					char ansbuf1[BUFFSIZE];
					next_ip = queryrootserver(tcpbuf, position+2, ansbuf1);
					if(next_ip!=NULL) {
						char ansbuf2[BUFFSIZE];
						short ans_len = querytldserver(next_ip,tcpbuf, position+2, ansbuf2);

						if((sendto(sock, ansbuf2, ans_len, 0,
							(struct sockaddr *) &clntAddr, sizeof(clntAddr))) < 0)
						printf("sendto() error.\n");
					} else {
						short *len = (short *)&ansbuf1;
						char finalbuf[BUFFSIZE];
						char *tempbuf = (char *)ansbuf1;

						tempbuf += 2;
						memcpy(finalbuf, tempbuf, *len-2);

						if((sendto(sock, finalbuf, *len-2, 0,
							(struct sockaddr *) &clntAddr, sizeof(clntAddr))) < 0)
							printf("sendto() error.\n");
					}
				}

			}

}


