#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>

#define MAXPENDING 5    /* Max connection requests */
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

char* checktld1record(char* name, int type) {
	FILE *fp;
	int i, j, k, temp = 0;
	char line[100], content[20][100], recordname[30];
	char  *p, *qtype;

	qtype = convert_type(type);

	fp = fopen("tld1.db" , "r");
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

	for(i = 0; i < temp; i++)
    {
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
	char *end =  buf + sizeof(struct DNS_HEADER)+3;
	if(strcmp(name,end)==0) {
		offset = end - start-3;
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
	dns->ans_count = htons(anscount);
	dns->auth_count = htons(authcount);
	dns->add_count = htons(addcount);
}

void set_error_header(struct DNS_HEADER *dns) {
	dns->qr = 1; //This is a response
	dns->opcode = 0; //This is a standard query
	dns->aa = 0; //Not Authoritative
	dns->tc = 0; //This message is not truncated
	dns->rd = 1; //Recursion Desired
	dns->ra = 0; //Recursion not available!
	dns->z = 0;
	dns->ad = 0;
	dns->cd = 0;
	dns->rcode = 3;
	dns->q_count = htons(1); //we have only 1 question
	dns->ans_count = htons(0);
	dns->auth_count = htons(0);
	dns->add_count = htons(0);
}

void HandleClient(int sock) {
	char buf[BUFFSIZE];
	int received = -1, anscount = 0, authcount = 0, addcount = 0;
	short position = 2;
	char  *p, *qname, *name, *rname, *add, recordfield[5][100], addrecord[5][100], *r_data;

	struct DNS_HEADER *dns = NULL;
	struct QUESTION *qinfo = NULL;
	struct RES_RECORD *r_record;
	/* Receive message */
	if ((received = recv(sock, buf, BUFFSIZE, 0)) < 0) {
		Die("Failed to receive initial bytes from client");
	}

	dns = (struct DNS_HEADER*)&buf[position];

	position += sizeof(struct DNS_HEADER);
	position++;
	qname =(char*)&buf[position];
	printf("*Query Name: %s\n", qname);

	position += (strlen((const char*)qname) + 1);
	qinfo = (struct QUESTION*)&buf[position];
	p = checktld1record(qname,ntohs(qinfo->qtype));

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

			add = checktld1record(recordfield[4], 1);
			if(split(add,addrecord)!=0) {
				/**
				short *add_len = (short *)&buf[position];
				int temp_add_len = position;
				position += 2;

				temp = check_name_position((char *)buf, addrecord[0]);
				if(temp != 0) {
				*/
				unsigned short *offset = (unsigned short *)&buf[position];
				*offset = htons(offset2+49150);

				//if(strcmp(recordfield[3], "MX") == 0)
				position += 2;//preference

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
		else if(strcmp(recordfield[3], "CNAME") == 0){
			r_record = (struct RES_RECORD*)&buf[position];
			int r_length = strlen(recordfield[4])+2;
			position -=2;
			set_record(r_record, recordfield[3],recordfield[2], recordfield[1], r_length);
			position += sizeof(struct RES_RECORD);

			char *r_data_len = (char *)&buf[position];
			sprintf(r_data_len, "%c", (int)strlen(recordfield[4]));
			position++;

			r_data = (char *)&buf[position];
			strcpy(r_data,recordfield[4]);
			r_data[strlen(r_data)] = '\0';
			position += (strlen(r_data)+1);
			printf("*My Answer: %s\n",recordfield[4]);
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
	}else {
		//operation when no match found
		printf("No record found!\n");
		set_error_header(dns);

	}

		short *buf_len = malloc(2);
		*buf_len = htons(position-2);
		memcpy(&buf[0], buf_len, 2);
		/* Send back received data */
		if (send(sock, buf, position, 0) <0) {
			Die("Failed to send bytes to client");
		}

	close(sock);
}



int main(int argc, char *argv[]) {
	int serversock, clientsock;
	struct sockaddr_in echoserver, echoclient;

	/* Create the TCP socket */
	if ((serversock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
		Die("Failed to create socket");
	}
	/* Construct the server sockaddr_in structure */
	memset(&echoserver, 0, sizeof(echoserver));       /* Clear struct */
	echoserver.sin_family = AF_INET;                  /* Internet/IP */
	echoserver.sin_addr.s_addr = inet_addr("127.0.0.4");   /* Incoming addr */
	echoserver.sin_port = htons(53);       /* server port */

	/* Bind the server socket */
	if (bind(serversock, (struct sockaddr *) &echoserver,
		               sizeof(echoserver)) < 0) {
		Die("Failed to bind the server socket");
	}

	/* Listen on the server socket */
	if (listen(serversock, MAXPENDING) < 0) {
		Die("Failed to listen on server socket");
	}



	/* Run until cancelled */
	while (1) {
		printf("**************************************\n");
		printf("*TLD server 1 listen at 127.0.0.4\n");
		printf("**************************************\n");

		unsigned int clientlen = sizeof(echoclient);
		/* Wait for client connection */
		if ((clientsock =
		   accept(serversock, (struct sockaddr *) &echoclient,
			  &clientlen)) < 0) {
			Die("Failed to accept client connection");
		}

		HandleClient(clientsock);
	}
}
