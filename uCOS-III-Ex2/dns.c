//DNS Query Program on Linux
//Author : Silver Moon (m00n.silv3r@gmail.com)
//Dated : 29/4/2009

//Header Files
//#include<stdio.h> //printf
 #include  <includes.h>
#include<string.h>    //strlen
#include<stdlib.h>    //malloc
//#include<sys/socket.h>    //you know what this is for
//#include<arpa/inet.h> //inet_addr, inet_ntoa, ntohs etc
 
//DNS Server
static CPU_INT08U dns_server[]="208.67.222.222";

//Types of DNS resource records
#define T_A 1     /* Ipv4 address */
#define T_NS 2    /* Nameserver */
#define T_CNAME 5 /* canonical name */
#define T_SOA 6   /* start of authority zone */
#define T_PTR 12  /* domain name pointer */
#define T_MX 15   /* Mail server */

#define BUFFER_SIZE (48)
#define MAX_ANS (10)
#define MAX_BYTES (20)
#define NAME_LENGTH (15)
#define QUESTION_SIZE (sizeof(struct DNS_HEADER) + (NAME_LENGTH+1) + sizeof(struct QUESTION))
 
//Function Prototypes
NET_IP_ADDR ngethostbyname(const char*, CPU_INT16U);
#ifdef HOST_IN_URL_FORMAT
static void ChangetoDnsNameFormat(CPU_CHAR*,CPU_CHAR*);
#endif
static void SkipName(CPU_INT08U*,CPU_INT08U*,CPU_INT16U*);
 
//DNS header structure
struct DNS_HEADER
{
  CPU_INT16U id; // identification number

  CPU_INT08U rd      :1; // recursion desired
  CPU_INT08U tc      :1; // truncated message
  CPU_INT08U aa      :1; // authoritive answer
  CPU_INT08U opcode  :4; // purpose of message
  CPU_INT08U qr      :1; // query/response flag

  CPU_INT08U rcode   :4; // response code
  CPU_INT08U cd      :1; // checking disabled
  CPU_INT08U ad      :1; // authenticated data
  CPU_INT08U z       :1; // its z! reserved
  CPU_INT08U ra      :1; // recursion available

  CPU_INT16U q_count; // number of question entries
  CPU_INT16U ans_count; // number of answer entries
  CPU_INT16U auth_count; // number of authority entries
  CPU_INT16U add_count; // number of resource entries
};
/* 2 + 1 + 1 + 2 + 2 + 2 + 2 = 12 */
 
//Constant sized fields of query structure
struct QUESTION
{
  CPU_INT16U qtype;
  CPU_INT16U qclass;
}; /* 2 + 2 = 4 */
 
//Constant sized fields of the resource record structure
//#pragma pack(push, 1)
struct R_DATA
{
  CPU_INT16U type;
  CPU_INT16U _class;
  CPU_INT32U ttl;
  CPU_INT16U data_len;
}__attribute__ ((packed)); /* 2 + 2 + 4 + 2 = 10 */
//#pragma pack(pop)
 
//Pointers to resource record contents
union RES_RECORD
{
  struct R_DATA resource;
  CPU_INT08U rdata[sizeof(struct R_DATA)];
};

typedef union
{
  struct
  {
    struct DNS_HEADER header;
    char name[NAME_LENGTH+1];
    struct QUESTION ques;
    CPU_INT08U ans[BUFFER_SIZE];
  }FIELDS;
  CPU_INT08U RAW[QUESTION_SIZE+BUFFER_SIZE];
} FRAME_ut;

#ifdef UNUSED
int main( int argc, char *argv[])
{
  //#ifdef HOST_IN_URL_FORMAT
  //const char hostname[]="m2.exosite.com";
  //#else
  const char hostname[]="\2m2\7exosite\3com";
  //#endif
   
  //Now get the ip of this hostname, A record
  ngethostbyname(hostname, T_A);

  return 0;
}
#endif
 
/*
 * Perform a DNS query by sending a packet
 * */
NET_IP_ADDR ngethostbyname(const char *host, CPU_INT16U query_type)
{
  CPU_INT08U *reader;
  CPU_INT16U i, stop, s;
  FRAME_ut frame;
  struct sockaddr_in dest;
  union RES_RECORD answer; //the replies from the DNS server

  s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP); //UDP packet for DNS queries

  dest.sin_family = AF_INET;
  dest.sin_port = htons(53);
  dest.sin_addr.s_addr = inet_addr(dns_server); //dns servers

  //Set the DNS structure to standard queries
  frame.FIELDS.header.id = 12345; //(CPU_INT16U) htons(12345/*getpid()*/);
  frame.FIELDS.header.qr = 0; //This is a query
  frame.FIELDS.header.opcode = 0; //This is a standard query
  frame.FIELDS.header.aa = 0; //Not Authoritative
  frame.FIELDS.header.tc = 0; //This message is not truncated
  frame.FIELDS.header.rd = 1; //Recursion Desired
  frame.FIELDS.header.ra = 0; //Recursion not available! hey we dont have it (lol)
  frame.FIELDS.header.z = 0;
  frame.FIELDS.header.ad = 0;
  frame.FIELDS.header.cd = 0;
  frame.FIELDS.header.rcode = 0;
  frame.FIELDS.header.q_count = htons(1); //we have only 1 question
  frame.FIELDS.header.ans_count = 0;
  frame.FIELDS.header.auth_count = 0;
  frame.FIELDS.header.add_count = 0;

  #ifdef HOST_IN_URL_FORMAT
  ChangetoDnsNameFormat(frame.FIELDS.name, host);
  #else
  if ( strlen( host ) == (NAME_LENGTH) )
  {
    strcpy(frame.FIELDS.name, host);
  }
  else
  {
    return 0;
  }
  #endif
  
  frame.FIELDS.ques.qtype = htons( query_type ); //type of the query, A, MX, CNAME, NS etc
  frame.FIELDS.ques.qclass = htons(1);

  /*Sending Packet...*/
  if ( sendto(s, frame.RAW, QUESTION_SIZE, 0, (struct sockaddr*)&dest, sizeof(dest)) < 0 )
  {
    return 0;
  }
  /*Done*/
   
  //Receive the answer
  i = sizeof(dest);
  /*Receiving answer...*/
  if ( recvfrom(s,frame.RAW, QUESTION_SIZE+BUFFER_SIZE, 0, (struct sockaddr*)&dest, (socklen_t*)&i) < 0 )
  {
    return 0;
  }
  /*Done*/

  //move ahead of the dns header and the query field
  reader = frame.FIELDS.ans;

  //Start reading answers
  stop=0;

  for (i=0;(i<ntohs(frame.FIELDS.header.ans_count)) && (i < MAX_ANS) ;i++)
  {
    SkipName(reader,frame.RAW,&stop);
    reader = reader + stop;

    memcpy(answer.rdata, reader, sizeof(struct R_DATA));
    reader = reader + sizeof(struct R_DATA);

    if (   (ntohs(answer.resource.type) == T_A) //if it's an ipv4 address
        && (ntohs(answer.resource.data_len) >= 4)  )
    {
      return reader[0] * 16777216
           + reader[1] * 65536
           + reader[2] * 256
           + reader[3] * 1;
    }
    else
    {
      SkipName(reader, frame.RAW, &stop);
      reader = reader + stop;
    }
  }
  
  return  0;
}


static void SkipName(CPU_INT08U* reader,CPU_INT08U* buffer,CPU_INT16U* count)
{
  CPU_INT32U jumped=0,offset;

  *count = 1;

  //read null-terminated names following pointers
  while (*reader != 0)
  {
    if (*reader >= 0xC0U) /* Pointer found */
    {
      offset = ((*reader)-0xC0U)*256 + *(reader+1);
      reader = buffer + offset - 1;
      jumped = 1; //we have jumped to another location so counting wont go up!
    }

    reader = reader+1;

    if (jumped == 0)
    {
      *count = *count + 1; //if we havent jumped to another location then we can count up
    }
  }

  if (jumped == 1)
  {
    *count = *count + 1; //number of steps we actually moved forward in the packet
  }
}

#ifdef HOST_IN_URL_FORMAT
/*
 * This will convert www.google.com to \3www\6google\3com 
 * */
static void ChangetoDnsNameFormat(CPU_CHAR* dns,CPU_CHAR* host) 
{
  CPU_INT16U lock = 0, i;
  
  strcat((CPU_INT08U*)host, ".");
   
  for (i = 0 ; i < strlen((CPU_INT08U*)host) ; i++) 
  {
    if (host[i]=='.') 
    {
      *dns++ = i-lock;
      for ( ; lock < i ; lock++ ) 
      {
        *dns++ = host[lock];
      }
      lock++; //or lock=i+1;
    }
  }
  *dns++='\0';
}
#endif
