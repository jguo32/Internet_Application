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

short check_name_position(char* buf, char* name) {
	short offset = 0;
	char *start = buf;
	char *end =  buf + sizeof(struct DNS_HEADER)+3;
	if(strcmp(name,end)==0) {
		offset = end - start-3;
		//printf("offset: %d\n",offset);
		/**
		char *temp = malloc(strlen(hexoffset) + strlen("C0")+1);
		strcpy(temp, "c0");
		strcat(temp,hexoffset);*/
		
	} 
	end = buf + 1;
	return offset;
}

char* check_root_record(char* name) {
	FILE *fp;
	char *qname=malloc(strlen(name)+1);
	strcpy(qname, name);
	int i, temp = 0;
	char line[100], content[20][100], *record, *ip=NULL;
	char *head = qname;
	char *end = strstr(qname,"的");
	if(end!=NULL) {
		qname[end-head] = '\0';
		fp = fopen("root.db" , "r");
		if(fp == NULL)
			perror("Error opening file");
		else {
			while(fgets(line, 200, fp)!= NULL)
			{
				strcpy(content[temp], line);
				temp++;
			}
			fclose(fp);	
			
			for(i = 0; i < temp; i++) {
				if((record = strstr(content[i], qname)))
					break;
			}
		}
		ip = strstr(record,"1");
		ip[strlen(ip)-2] = '\0';
		
	}
	//printf("the ip is %s\n",ip);
	return ip;

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
	int received = -1;
	char *qname, *rtype, *rclass, *ttl;
	short position = 2;
	struct DNS_HEADER *dns = NULL;
	struct RES_RECORD *r_record;
	int anscount = 0, authcount = 0, addcount = 0;
	
	/* Receive message */
	if ((received = recv(sock, buf, BUFFSIZE, 0)) < 0) {
		Die("Failed to receive initial bytes from client");
	}	
	
	short *buf_len = malloc(2);
	qname =(char*)&buf[sizeof(struct DNS_HEADER)+3];
	
	
	char *ip = check_root_record(qname);
	printf("*Query Name: %s\n",qname);
		
	dns = (struct DNS_HEADER*)&buf[position];
	position += sizeof(struct DNS_HEADER);
	position++;	
	position += (strlen(qname) + 1);
	position += sizeof(struct QUESTION);
	
	if(ip!=NULL) {
		printf("*My Answer: %s\n",check_root_record(qname));
		short temp = check_name_position((char *)buf, qname);

		unsigned short *offset = (unsigned short *)&buf[position];
		*offset = htons(temp+49152);
		position += 2;
		
		r_record = (struct RES_RECORD*)&buf[position];
		int r_length = sizeof(struct in_addr);
		rtype = "A";
		rclass = "IN";
		ttl = "86400";
		set_record(r_record, rtype, rclass, ttl, r_length);
		position += sizeof(struct RES_RECORD);
		
		position -= 2;
		struct in_addr *rdata = NULL;
		rdata = (struct in_addr*)&buf[position];	
		inet_aton(ip,rdata);
		position += sizeof(struct in_addr);
		addcount++;
		
		*buf_len = htons(position-2);
		memcpy(&buf[0], buf_len, 2);

		set_header(dns, anscount, authcount, addcount);


	}	else {
			printf("Server not found!\n");
			set_error_header(dns);
			*buf_len = htons(position-2);
			memcpy(&buf[0], buf_len, 2);
	}
	if (send(sock, buf, position, 0) < position) {
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
	echoserver.sin_addr.s_addr = inet_addr("127.0.0.3");   /* Incoming addr */
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
		printf("*Root server listen at 127.0.0.3\n");
		printf("**************************************\n");
		
		unsigned int clientlen = sizeof(echoclient);
		/* Wait for client connection */
		if ((clientsock =
		   accept(serversock, (struct sockaddr *) &echoclient,
			  &clientlen)) < 0) {
			Die("Failed to accept client connection");
		}
		//fprintf(stdout, "Client connected: %s\n",
		//	      inet_ntoa(echoclient.sin_addr));
		HandleClient(clientsock);
	}
}
