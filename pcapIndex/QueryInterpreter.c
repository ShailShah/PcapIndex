/* gcc -Wall -o pcapindex pcapindex.c -lpcap */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <pcap.h>

#define ETH_SIZE 14
#define MAX_SIZE 1000

void query_interpreter(int count);
void display_packet(int packet_id);


//indirection array
int indir_arr[100];

//global variables
FILE *fp=NULL;
FILE *fin;
struct pcap_pkthdr header;
const u_char *packet;
pcap_t *handle;
char errbuf[PCAP_ERRBUF_SIZE];
struct ipheader *ip;
struct tcpheader *tcp;	
struct udpheader *udp;


u_char arr_normal[100][65535];
u_char * arr_comp_input=&arr_normal[0][0];
u_char arr_normal_1[100][256];
u_char * arr_comp_input_1=&arr_normal_1[0][0];

//Sizes of compressed bitmaps
int d1,d2,d3,d4,d5,d6,d7,d8,d9,d10,d11;

struct pcap_hdr_global{
        u_int magic_number;   /* magic number */
        u_short version_major;  /* major version number */
        u_short version_minor;  /* minor version number */
        int  thiszone;       /* GMT to local correction */
        u_int sigfigs;        /* accuracy of timestamps */
        u_int snaplen;        /* max length of captured packets, in octets */
        u_int network;        /* data link type */
};

struct pcap_hdr_packet{
        u_int ts_sec;         /* timestamp seconds */
        u_int ts_usec;        /* timestamp microseconds */
        u_int incl_len;       /* number of octets of packet saved in file */
        u_int orig_len;       /* actual length of packet */
};

struct ipheader{
	u_char ip_vhl;		/* version << 4 | header length >> 2 */
	u_char ip_tos;		/* type of service */
	u_short ip_len;		/* total length */
	u_short ip_id;		/* identification */
	u_short ip_off;		/* fragment offset field */
	#define IP_RF 0x8000		/* reserved fragment flag */
	#define IP_DF 0x4000		/* dont fragment flag */
	#define IP_MF 0x2000		/* more fragments flag */
	#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
	u_char ip_ttl;		/* time to live */
	u_char ip_p;		/* protocol */
	u_short ip_sum;		/* checksum */
	struct in_addr ip_src,ip_dst; /* source and dest address */
};
#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)		(((ip)->ip_vhl) >> 4)

struct tcpheader{
	u_short th_sport;	/* source port */
	u_short th_dport;	/* destination port */
	u_long th_seq;		/* sequence number */
	u_long th_ack;		/* acknowledgement number */
	u_char th_offx2;	/* data offset, rsvd */
	#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
	u_char th_flags;
	#define TH_FIN 0x01
	#define TH_SYN 0x02
	#define TH_RST 0x04
	#define TH_PUSH 0x08
	#define TH_ACK 0x10
	#define TH_URG 0x20
	#define TH_ECE 0x40
	#define TH_CWR 0x80
	#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
	u_short th_win;		/* window */
	u_short th_sum;		/* checksum */
	u_short th_urp;		/* urgent pointer */
};

struct udpheader{
	u_short	uh_sport;		/* source port */
	u_short	uh_dport;		/* destination port */
	u_short	uh_ulen;		/* datagram length */
	u_short	uh_sum;			/* datagram checksum */
};



//////////////////////////////////////////////////
///////////// COMPRESSION ////////////////////////
//////////////////////////////////////////////////

static void _RLE_WriteRep( unsigned char *out, unsigned int *outpos,
    unsigned char marker, unsigned char symbol, unsigned int count )
{
    unsigned int i, idx;

    idx = *outpos;
    if( count <= 3 )
    {
        if( symbol == marker )
        {
            out[ idx ++ ] = marker;
            out[ idx ++ ] = count-1;
        }
        else
        {
            for( i = 0; i < count; ++ i )
            {
                out[ idx ++ ] = symbol;
            }
        }
    }
    else
    {
        out[ idx ++ ] = marker;
        -- count;
        if( count >= 128 )
        {
            out[ idx ++ ] = (count >> 8) | 0x80;
        }
        out[ idx ++ ] = count & 0xff;
        out[ idx ++ ] = symbol;
    }
    *outpos = idx;
}


/*************************************************************************
* _RLE_WriteNonRep() - Encode a non-repeating symbol, 'symbol'. 'marker'
* is the marker symbol, and special care has to be taken for the case
* when 'symbol' == 'marker'.
*************************************************************************/

static void _RLE_WriteNonRep( unsigned char *out, unsigned int *outpos,
    unsigned char marker, unsigned char symbol )
{
    unsigned int idx;

    idx = *outpos;
    if( symbol == marker )
    {
        out[ idx ++ ] = marker;
        out[ idx ++ ] = 0;
    }
    else
    {
        out[ idx ++ ] = symbol;
    }
    *outpos = idx;
}



/*************************************************************************
*                            PUBLIC FUNCTIONS                            *
*************************************************************************/


/*************************************************************************
* RLE_Compress() - Compress a block of data using an RLE coder.
*  in     - Input (uncompressed) buffer.
*  out    - Output (compressed) buffer. This buffer must be 0.4% larger
*           than the input buffer, plus one byte.
*  insize - Number of input bytes.
* The function returns the size of the compressed data.
*************************************************************************/

int RLE_Compress( unsigned char *in, unsigned char *out,
    unsigned int insize )
{
    unsigned char byte1, byte2, marker;
    unsigned int  inpos, outpos, count, i, histogram[ 256 ];

    /* Do we have anything to compress? */
    if( insize < 1 )
    {
        return 0;
    }

    /* Create histogram */
    for( i = 0; i < 256; ++ i )
    {
        histogram[ i ] = 0;
    }
    for( i = 0; i < insize; ++ i )
    {
        ++ histogram[ in[ i ] ];
    }

    /* Find the least common byte, and use it as the repetition marker */
    marker = 0;
    for( i = 1; i < 256; ++ i )
    {
        if( histogram[ i ] < histogram[ marker ] )
        {
            marker = i;
        }
    }

    /* Remember the repetition marker for the decoder */
    out[ 0 ] = marker;
    outpos = 1;

    /* Start of compression */
    byte1 = in[ 0 ];
    inpos = 1;
    count = 1;

    /* Are there at least two bytes? */
    if( insize >= 2 )
    {
        byte2 = in[ inpos ++ ];
        count = 2;

        /* Main compression loop */
        do
        {
            if( byte1 == byte2 )
            {
                /* Do we meet only a sequence of identical bytes? */
                while( (inpos < insize) && (byte1 == byte2) &&
                       (count < 32768) )
                {
                    byte2 = in[ inpos ++ ];
                    ++ count;
                }
                if( byte1 == byte2 )
                {
                    _RLE_WriteRep( out, &outpos, marker, byte1, count );
                    if( inpos < insize )
                    {
                        byte1 = in[ inpos ++ ];
                        count = 1;
                    }
                    else
                    {
                        count = 0;
                    }
                }
                else
                {
                    _RLE_WriteRep( out, &outpos, marker, byte1, count-1 );
                    byte1 = byte2;
                    count = 1;
                }
            }
            else
            {
                /* No, then don't handle the last byte */
                _RLE_WriteNonRep( out, &outpos, marker, byte1 );
                byte1 = byte2;
                count = 1;
            }
            if( inpos < insize )
            {
                byte2 = in[ inpos ++ ];
                count = 2;
            }
        }
        while( (inpos < insize) || (count >= 2) );
    }

    /* One byte left? */
    if( count == 1 )
    {
        _RLE_WriteNonRep( out, &outpos, marker, byte1 );
    }

    return outpos;
}


/*************************************************************************
* RLE_Uncompress() - Uncompress a block of data using an RLE decoder.
*  in      - Input (compressed) buffer.
*  out     - Output (uncompressed) buffer. This buffer must be large
*            enough to hold the uncompressed data.
*  insize  - Number of input bytes.
*************************************************************************/

void RLE_Uncompress( unsigned char *in, unsigned char *out,
    unsigned int insize )
{
    unsigned char marker, symbol;
    unsigned int  i, inpos, outpos, count;

    /* Do we have anything to uncompress? */
    if( insize < 1 )
    {
        return;
    }

    /* Get marker symbol from input stream */
    inpos = 0;
    marker = in[ inpos ++ ];

    /* Main decompression loop */
    outpos = 0;
    do
    {
        symbol = in[ inpos ++ ];
        if( symbol == marker )
        {
            /* We had a marker byte */
            count = in[ inpos ++ ];
            if( count <= 2 )
            {
                /* Counts 0, 1 and 2 are used for marker byte repetition
                   only */
                for( i = 0; i <= count; ++ i )
                {
                    out[ outpos ++ ] = marker;
                }
            }
            else
            {
                if( count & 0x80 )
                {
                    count = ((count & 0x7f) << 8) + in[ inpos ++ ];
                }
                symbol = in[ inpos ++ ];
                for( i = 0; i <= count; ++ i )
                {
                    out[ outpos ++ ] = symbol;
                }
            }
        }
        else
        {
            /* No marker, plain copy */
            out[ outpos ++ ] = symbol;
        }
    }
    while( inpos < insize );
}


////////////////////////////////////////////////////
///////////////////////////////////////////////////
//////////////////////////////////////////////////////



void query_interpreter(int count){
		
	fp=fopen("trace4","r");
	handle=pcap_fopen_offline(fp,errbuf);
	
	if(handle==NULL){
		fprintf(stderr, "error reading pcap file: %s\n", errbuf);
		exit(1);
	}
	
	if (pcap_datalink(handle)!=DLT_EN10MB) {
		fprintf(stderr,"Unsupported link-layer header type. Packets cannot be processed\n");
		exit(1);
	}
		
	int srcip1[]={-1,-1,-1,-1};
	int dstip1[]={-1,-1,-1,-1};
	int srcport1=-1;
	int dstport1=-1;
	int protocol1=-1;
	int srcip2[]={-1,-1,-1,-1};
	int dstip2[]={-1,-1,-1,-1};
	int srcport2=-1;
	int dstport2=-1;
	int protocol2=-1;
	char found;
	char finalarray1[2][100]={};
	char finalarray2[2][100]={};
	
	int i=0,j,k=0,l;
	printf("\nEnter the index filter\n\n");
	char some[2][100]={};
	
	char *filter=(char *)malloc(100*sizeof(char ));
	char *token;
	fgets(filter,150,stdin);
	
	for(l=0;l<strlen(filter);l++)
		if(filter[l]==';'||filter[l]==':')
			found=filter[l];
			
	if(found==';'){
		token=strtok(filter,";");
		while(token!=NULL){
	   		strcpy(some[i++],token);	
			token = strtok(NULL,";");
		}
	}
	else if(found==':'){	
		token=strtok(filter,":");
		while(token!=NULL){
			strcpy(some[i++],token);
    		 token = strtok(NULL,":");
		}	
	}
	else {
		strcpy(some[0],filter);	
	}
	
	for(j=0;j<2;j++){
		k=0;
		if(some[j]!=NULL){
			token=strtok(some[j],"=");
			while(token!=NULL){
				if(j==0)
					strcpy(finalarray1[k++],token);
				else
					strcpy(finalarray2[k++],token);			 
				token = strtok(NULL,"=");
			}	
		}
	}
	
	if(strcmp(finalarray1[0],"srcip")==0){
		k=2;
		token=strtok(finalarray1[1],".");
		while(token!=NULL){
			strcpy(finalarray1[k++],token);
			token = strtok(NULL,".");
		}
		for(l=0;l<4;l++)
			if(finalarray1[l+2][0]!='*')
				srcip1[l]=atoi(finalarray1[l+2]);
			else srcip1[l]=-2;
	}
	else if(strcmp(finalarray1[0],"dstip")==0){
		k=2;
		token=strtok(finalarray1[1],".");
		while(token!=NULL){
			strcpy(finalarray1[k++],token);
			token = strtok(NULL,".");
		}
		for(l=0;l<4;l++)
			if(finalarray1[l+2][0]!='*')
				dstip1[l]=atoi(finalarray1[l+2]);
			else dstip1[l]=-2;

	}
	else if(strcmp(finalarray1[0],"srcport")==0){
		srcport1=atoi(finalarray1[1]);
	}
	else if(strcmp(finalarray1[0],"dstport")==0){
		dstport1=atoi(finalarray1[1]);	
	}
	else if(strcmp(finalarray1[0],"protocol")==0){
		protocol1=atoi(finalarray1[1]);	
	}
	
	
	
	if(strcmp(finalarray2[0],"srcip")==0){
		k=2;
	   token=strtok(finalarray2[1],".");
		while(token!=NULL){
			strcpy(finalarray2[k++],token);
			token = strtok(NULL,".");
		}
		for(l=0;l<4;l++)
			if(finalarray2[l+2][0]!='*')
				srcip2[l]=atoi(finalarray2[l+2]);
			else srcip2[l]=-2;

	}
	else if(strcmp(finalarray2[0],"dstip")==0) {
		k=2;
		token=strtok(finalarray2[1],".");
		while(token!=NULL){
			strcpy(finalarray2[k++],token);
			token = strtok(NULL,".");
		}
		for(l=0;l<4;l++)
			if(finalarray2[l+2][0]!='*')
				dstip2[l]=atoi(finalarray2[l+2]);
			else dstip2[l]=-2;

	}
	else if(strcmp(finalarray2[0],"srcport")==0){
		srcport2=atoi(finalarray2[1]);
	}
	else if(strcmp(finalarray2[0],"dstport")==0){
		dstport2=atoi(finalarray2[1]);	
	}
	else if(strcmp(finalarray2[0],"protocol")==0){
		protocol2=atoi(finalarray2[1]);	
	}

///////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////// uncompressing according to the input ////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////

	int count1[count],count2[count];
	
	memset(count1,0,count);
	memset(count2,0,count);
	int c1=0,c2=0;
	int d[11];
	u_char arr_temp_1[100][256]={0};
	u_char arr_temp_2[100][256]={0};
	u_char arr_temp_3[100][256]={0};
	u_char arr_temp_4[100][256]={0};
	u_char arr_temp_5[100][65535]={0};

	u_char * arr_temp_1p=&arr_temp_1[0][0];
	u_char * arr_temp_2p=&arr_temp_2[0][0];
	u_char * arr_temp_3p=&arr_temp_3[0][0];	
	u_char * arr_temp_4p=&arr_temp_4[0][0];	
	u_char * arr_temp_5p=&arr_temp_5[0][0];
	fin=fopen("size.txt","r");
		fread(d,sizeof(int),sizeof(d),fin);
	fclose(fin);
	d1=d[0];d2=d[1];d3=d[2];d4=d[3];d5=d[4];d6=d[5];d7=d[6];d8=d[7];d9=d[8];d10=d[9];d11=d[10];
		//pointers to compressed arrays
	u_char  comp_src_1[d1];
	u_char  comp_src_2[d2];
	u_char  comp_src_3[d3];
	u_char  comp_src_4[d4];
	u_char  comp_dst_1[d5];
	u_char  comp_dst_2[d6];
	u_char  comp_dst_3[d7];
	u_char  comp_dst_4[d8];
	u_char  comp_protoco[d11];
	u_char  comp_src_po[d9];
	u_char  comp_dst_po[d10];
	
						//Reading the compressed data from the file		
						fin=fopen("ip_src_1.txt","r");
							fread(comp_src_1,sizeof(u_char),sizeof(comp_src_1),fin);
						fclose(fin);
						fin=fopen("ip_src_2.txt","r");
							fread(comp_src_2,sizeof(u_char),sizeof(comp_src_2),fin);
						fclose(fin);
						fin=fopen("ip_src_3.txt","r");
							fread(comp_src_3,sizeof(u_char),sizeof(comp_src_3),fin);
						fclose(fin);
						fin=fopen("ip_src_4.txt","r");
							fread(comp_src_4,sizeof(u_char),sizeof(comp_src_4),fin);
						fclose(fin);

						fin=fopen("ip_dst_1.txt","r");
							fread(comp_dst_1,sizeof(u_char),sizeof(comp_dst_1),fin);
						fclose(fin);
						fin=fopen("ip_dst_2.txt","r");
							fread(comp_dst_2,sizeof(u_char),sizeof(comp_dst_2),fin);
						fclose(fin);
						fin=fopen("ip_dst_3.txt","r");
							fread(comp_dst_3,sizeof(u_char),sizeof(comp_dst_3),fin);
						fclose(fin);
						fin=fopen("ip_dst_4.txt","r");
							fread(comp_dst_4,sizeof(u_char),sizeof(comp_dst_4),fin);
						fclose(fin);
						fin=fopen("src_port.txt","r");
							fread(comp_src_po,sizeof(u_char),sizeof(comp_src_po),fin);
						fclose(fin);
						fin=fopen("dst_port.txt","r");
							fread(comp_dst_po,sizeof(u_char),sizeof(comp_dst_po),fin);
						fclose(fin);
						
						fin=fopen("protocol.txt","r");
							fread(comp_protoco,sizeof(u_char),sizeof(comp_protoco),fin);
						fclose(fin);
						fin=fopen("indirection_array.txt","r");
							fread(indir_arr,sizeof(indir_arr),1,fin);
						fclose(fin);

	////uncompressing for the first input
					if(strcmp(finalarray1[0],"srcip")==0){
						RLE_Uncompress(comp_src_1,arr_temp_1p,d1);
						RLE_Uncompress(comp_src_2,arr_temp_2p,d2);
						RLE_Uncompress(comp_src_3,arr_temp_3p,d3);
						RLE_Uncompress(comp_src_4,arr_temp_4p,d4);
				
						if(srcip1[0]==-2){
							for(i=0;i<count;i++){
									count1[c1++]=i;
								}
							}
						else if(srcip1[1]==-2){
							for(i=0;i<count;i++){
								if(*(arr_temp_1p+(256*i)+srcip1[0]))
									count1[c1++]=i;
								}
							}
						else if(srcip1[2]==-2){
							for(i=0;i<count;i++){
								if(*(arr_temp_1p+(256*i)+srcip1[0])&*(arr_temp_2p+(256*i)+srcip1[1]))
									count1[c1++]=i;
								}	
						}
						else if(srcip1[3]==-2){
							for(i=0;i<count;i++){
								if(*(arr_temp_1p+(256*i)+srcip1[0])&*(arr_temp_2p+(256*i)+srcip1[1])&*(arr_temp_3p+(256*i)+srcip1[2]))
									count1[c1++]=i;
								}	
						}
						else {		
							for(i=0;i<count;i++){
								if((*(arr_temp_1p+(256*i)+srcip1[0]))&(*(arr_temp_2p+(256*i)+srcip1[1]))&(*(arr_temp_3p+(256*i)+srcip1[2]))&(*(arr_temp_4p+(256*i)+srcip1[3])))
									count1[c1++]=i;
								}	
						}
											
						
					}
					else if(strcmp(finalarray1[0],"dstip")==0){
						RLE_Uncompress(comp_dst_1,arr_temp_1p,d5);
						RLE_Uncompress(comp_dst_2,arr_temp_2p,d6);
						RLE_Uncompress(comp_dst_3,arr_temp_3p,d7);
						RLE_Uncompress(comp_dst_4,arr_temp_4p,d8);
						
						if(dstip1[0]==-2){
							for(i=0;i<count;i++){
									count1[c1++]=i;
								}
							}
						else if(dstip1[1]==-2){
							for(i=0;i<count;i++){
								if(*(arr_temp_1p+(256*i)+dstip1[0]))
									count1[c1++]=i;
								}
							}
						else if(dstip1[2]==-2){
							for(i=0;i<count;i++){
								if(*(arr_temp_1p+(256*i)+dstip1[0])&*(arr_temp_2p+(256*i)+dstip1[1]))
									count1[c1++]=i;
								}	
						}
						else if(dstip1[3]==-2){
							for(i=0;i<count;i++){
								if(*(arr_temp_1p+(256*i)+dstip1[0])&*(arr_temp_2p+(256*i)+dstip1[1])&*(arr_temp_3p+(256*i)+dstip1[2]))
									count1[c1++]=i;
								}	
						}
						else {
							for(i=0;i<count;i++){
							if(*(arr_temp_1p+(256*i)+dstip1[0])&*(arr_temp_2p+(256*i)+dstip1[1])&*(arr_temp_3p+(256*i)+dstip1[2])&*(arr_temp_4p+(256*i)+dstip1[3]))
									count1[c1++]=i;
							}	
						}
					}	
					
					else if(strcmp(finalarray1[0],"srcport")==0){
						RLE_Uncompress(comp_src_po,arr_temp_5p,d9);
						for(i=0;i<count;i++){
							if(*(arr_temp_5p+(65535*i)+srcport1)){
									count1[c1++]=i;
							}
						}
					}
					
					else if(strcmp(finalarray1[0],"dstport")==0){
						RLE_Uncompress(comp_dst_po,arr_temp_5p,d10);
						for(i=0;i<count;i++){
							if(*(arr_temp_5p+(65535*i)+dstport1)){
									count1[c1++]=i;
							}
						}
					}
					
					else if(strcmp(finalarray1[0],"protocol")==0){
						RLE_Uncompress(comp_protoco,arr_temp_1p,d11);				
						for(i=0;i<count;i++){
							if(*(arr_temp_1p+(256*i)+protocol1)){
									
									count1[c1++]=i;
							}
						}	
					}

		//////// uncompressing for second input///////
		
				if(strcmp(finalarray2[0],"srcip")==0){
				
						RLE_Uncompress(comp_src_1,&arr_temp_1[0][0],d1);
						RLE_Uncompress(comp_src_2,&arr_temp_2[0][0],d2);
						RLE_Uncompress(comp_src_3,&arr_temp_3[0][0],d3);
						RLE_Uncompress(comp_src_4,&arr_temp_4[0][0],d4);
						
						if(srcip2[0]==-2){
							for(i=0;i<count;i++){
									count2[c2++]=i;
								}
							}
						else if(srcip2[1]==-2){
							for(i=0;i<count;i++){
								if(*(arr_temp_1p+(256*i)+srcip2[0]))
									count2[c2++]=i;
								}
							}
						else if(srcip2[2]==-2){
							for(i=0;i<count;i++){
								if(*(arr_temp_1p+(256*i)+srcip2[0])&*(arr_temp_2p+(256*i)+srcip2[1]))
									count2[c2++]=i;
								}	
						}
						else if(srcip2[3]==-2){
							for(i=0;i<count;i++){
								if(*(arr_temp_1p+(256*i)+srcip2[0])&*(arr_temp_2p+(256*i)+srcip2[1])&*(arr_temp_3p+(256*i)+srcip2[2]))
									count2[c2++]=i;
								}	
						}
						else {
							for(i=0;i<count;i++){
								if(*(arr_temp_1p+(256*i)+srcip2[0])&*(arr_temp_2p+(256*i)+srcip2[1])&*(arr_temp_3p+(256*i)+srcip2[2])&*(arr_temp_4p+(256*i)+srcip2[3]))
									count2[c2++]=i;
								}	
						}
											
						
					}
					else if(strcmp(finalarray2[0],"dstip")==0){
						RLE_Uncompress(comp_dst_1,&arr_temp_1[0][0],d5);
						RLE_Uncompress(comp_dst_2,&arr_temp_2[0][0],d6);
						RLE_Uncompress(comp_dst_3,&arr_temp_3[0][0],d7);
						RLE_Uncompress(comp_dst_4,&arr_temp_4[0][0],d8);
						
						if(dstip2[0]==-2){
							for(i=0;i<count;i++){
									count2[c2++]=i;
								}
							}
						else if(dstip2[1]==-2){
							for(i=0;i<count;i++){
								if(*(arr_temp_1p+(256*i)+dstip2[0]))
									count2[c2++]=i;
								}
							}
						else if(dstip2[2]==-2){
							for(i=0;i<count;i++){
								if(*(arr_temp_1p+(256*i)+dstip2[0])&*(arr_temp_2p+(256*i)+dstip2[1]))
									count2[c2++]=i;
								}	
						}
						else if(dstip2[3]==-2){
							for(i=0;i<count;i++){
								if(*(arr_temp_1p+(256*i)+dstip2[0])&*(arr_temp_2p+(256*i)+dstip2[1])&*(arr_temp_3p+(256*i)+dstip2[2]))
									count2[c2++]=i;
								}	
						}
						else {
							for(i=0;i<count;i++){
							if(*(arr_temp_1p+(256*i)+dstip2[0])&*(arr_temp_2p+(256*i)+dstip2[1])&*(arr_temp_3p+(256*i)+dstip2[2])&*(arr_temp_4p+(256*i)+dstip2[3]))
									count2[c2++]=i;
							}	
						}
					}	
					
					else if(strcmp(finalarray2[0],"srcport")==0){
						RLE_Uncompress(comp_src_po,&arr_temp_5[0][0],d9);
						for(i=0;i<count;i++){
							if(*(arr_temp_5p+(65535*i)+srcport2)){
									count2[c2++]=i;
							}
						}
					}
					
					else if(strcmp(finalarray2[0],"dstport")==0){
						RLE_Uncompress(comp_dst_po,&arr_temp_5[0][0],d10);
						for(i=0;i<count;i++){
							if(*(arr_temp_5p+(65535*i)+dstport2)){
									count2[c2++]=i;
							}
						}
					}
					
					else if(strcmp(finalarray2[0],"protocol")==0){
						RLE_Uncompress(comp_protoco,&arr_temp_1[0][0],d11);
						for(i=0;i<count;i++){
							if(*(arr_temp_1p+(256*i)+protocol2)){
									count2[c2++]=i;
							}
						}	
					}
			
	//checking the number of arguments
	switch(found){
		case ':':	//for the case AND
					for(l=0;l<c1;l++)
						for(j=0;j<c2;j++)
							if(count1[l]==count2[j])	
							display_packet(count1[l]);
					break;	
		case ';':	//for the case OR
					for(l=0;l<c1;l++)
						display_packet(count1[l]);
					int f;
					for(j=0;j<c2;j++){
						f=0;
						for(l=0;l<c1;l++)	
							if(count1[l]==count2[j])
							{f=1;	break;}
						if(f==0)
							display_packet(count2[j]);
					}
					break;
		default:	for(l=0;l<c1;l++)
						display_packet(count1[l]);
			
		};
		
	pcap_close(handle);

}

void display_packet(int packet_id){
	printf("\n");
	struct pcap_pkthdr *hdr;
	fseek(fp,(long)indir_arr[packet_id],SEEK_SET);
	pcap_next_ex(handle,&hdr,&packet);
	ip=(struct ipheader *)(packet+ETH_SIZE);
	
	int ip_size;
	ip_size=IP_HL(ip)*4;
	udp=(struct udpheader *)(packet+ETH_SIZE+ip_size);	
	tcp=(struct tcpheader *)(packet+ETH_SIZE+ip_size);
		
	printf("Frame number:%d-----------------------------\n",packet_id+1);
	printf("Src IP: %s\n",inet_ntoa((*ip).ip_src));
	printf("Dst IP: %s\n",inet_ntoa((*ip).ip_dst));
	
	if((*ip).ip_p==17){
		printf("Protocol: UDP\n");	
	}
	else if((*ip).ip_p==6){
		printf("Protocol: TCP\n");
	}
	else{
		printf("Unknown protocol\n");
	}
	
		
	if((*ip).ip_p==17){
		printf("Src Port: %d\n",ntohs((*udp).uh_sport));							
		printf("Dst Port: %d\n",ntohs((*udp).uh_dport));
	}
	else if((*ip).ip_p==6){
		printf("Src Port: %d\n",ntohs((*tcp).th_sport));							
		printf("Dst Port: %d\n",ntohs((*tcp).th_dport));							
	}
	else{
		
	}	
	
	
	printf("----------------------------------------------\n");
}
int main(int argc,char *argv[]){
	

	query_interpreter(100);
	
	return 0;
}

