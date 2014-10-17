/* gcc -Wall -o pcapindex pcapindex.c -lpcap */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <pcap.h>

#define ETH_SIZE 14
#define MAX_SIZE 1000

void packet_indexer(int count);
void packet_parser(struct in_addr *ip_src,struct in_addr *ip_dst,u_char *ip_p,u_short *sport,u_short *dport);
void ip_src_bi(int packet_id,struct in_addr ip_src);
void ip_dst_bi(int packet_id,struct in_addr ip_dst);
void proto_bi(int packet_id,u_char ip_p);
void sport_bi(int packet_id,u_short sport);
void dport_bi(int packet_id,u_short dport);
void query_interpreter(int count);
void display_packet(int packet_id);
void ip_src_bi_1(int packet_id,struct in_addr ip_src);
void ip_src_bi_2(int packet_id,struct in_addr ip_src);
void ip_src_bi_3(int packet_id,struct in_addr ip_src);
void ip_src_bi_4(int packet_id,struct in_addr ip_src);
void ip_dst_bi_1(int packet_id,struct in_addr ip_src);
void ip_dst_bi_2(int packet_id,struct in_addr ip_src);
void ip_dst_bi_3(int packet_id,struct in_addr ip_src);
void ip_dst_bi_4(int packet_id,struct in_addr ip_src);

//pointers to compressed arrays
	u_char * comp_src_1;
	u_char * comp_src_2;
	u_char * comp_src_3;
	u_char * comp_src_4;
	u_char * comp_dst_1;
	u_char * comp_dst_2;
	u_char * comp_dst_3;
	u_char * comp_dst_4;
	u_char * comp_protoco;
	u_char * comp_src_po;
	u_char * comp_dst_po;

//indirection array
int indir_arr[100];

//global variables
FILE *fp=NULL;
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
int d[11];
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



///////////////////////////////////////////////////////////////////////
///////////////////////////////packet_indexer//////////////////////////
///////////////////////////////////////////////////////////////////////

void packet_indexer(int count){
	struct pcap_pkthdr *header1;
	struct in_addr ip_src,ip_dst;	
	u_char ip_p;
	u_short sport,dport;	
	int i,offset=24;
	
	//pointers to compressed arrays
	comp_src_1=(u_char *)malloc(65535 * sizeof(u_char));
	comp_src_2=(u_char *)malloc(65535 * sizeof(u_char));
	comp_src_3=(u_char *)malloc(2560 * sizeof(u_char));
	comp_src_4=(u_char *)malloc(2560 * sizeof(u_char));
	comp_dst_1=(u_char *)malloc(2560 * sizeof(u_char));
	comp_dst_2=(u_char *)malloc(2560 * sizeof(u_char));
	comp_dst_3=(u_char *)malloc(2560 * sizeof(u_char));
	comp_dst_4=(u_char *)malloc(2560 * sizeof(u_char));
	comp_protoco=(u_char *)malloc(65535 * sizeof(u_char));
	comp_src_po=(u_char *)malloc(65535 * sizeof(u_char));
	comp_dst_po=(u_char *)malloc(65535 * sizeof(u_char));
	
	//ip_src_1
	handle=pcap_open_offline("trace4",errbuf);
	for(i=0;i<count;i++){
		packet=pcap_next(handle,&header);
		indir_arr[i]=offset;
		offset+=16+header.caplen;
		packet_parser(&ip_src,&ip_dst,&ip_p,&sport,&dport);
		
		ip_src_bi_1(i,ip_src);
	}
	pcap_close(handle);
	d1=RLE_Compress(arr_comp_input_1,comp_src_1,25600);	

	fp=fopen("ip_src_1.txt","w");
		fwrite(comp_src_1,1,d1,fp);
	fclose(fp);


	memset(arr_normal_1,0,25600);
	
	//ip_src_2
	handle=pcap_open_offline("trace4",errbuf);
	for(i=0;i<count;i++){
		packet=pcap_next(handle,&header);
		//indir_arr[i]=offset;
		//offset+=header.caplen+16;
		packet_parser(&ip_src,&ip_dst,&ip_p,&sport,&dport);
		
		ip_src_bi_2(i,ip_src);
	}
	pcap_close(handle);
	d2=RLE_Compress(arr_comp_input_1,comp_src_2,25600);	
	
	fp=fopen("ip_src_2.txt","w");
		fwrite(comp_src_2,1,d2,fp);
	fclose(fp);

	memset(arr_normal_1,0,25600);
	
	//ip_src_3
	handle=pcap_open_offline("trace4",errbuf);
	for(i=0;i<count;i++){
		packet=pcap_next(handle,&header);
		//indir_arr[i]=offset;
		//offset+=header.caplen+16;
		packet_parser(&ip_src,&ip_dst,&ip_p,&sport,&dport);
		
		ip_src_bi_3(i,ip_src);
	}
	pcap_close(handle);
	d3=RLE_Compress(arr_comp_input_1,comp_src_3,25600);	
	
	fp=fopen("ip_src_3.txt","w");
		fwrite(comp_src_3,1,d3,fp);
	fclose(fp);
	
	memset(arr_normal_1,0,25600);
	
	//ip_src_4	
	handle=pcap_open_offline("trace4",errbuf);
	for(i=0;i<count;i++){
		packet=pcap_next(handle,&header);
		//indir_arr[i]=offset;
		//offset+=header.caplen+16;
		packet_parser(&ip_src,&ip_dst,&ip_p,&sport,&dport);
		
		ip_src_bi_4(i,ip_src);
	}
	pcap_close(handle);
	d4=RLE_Compress(arr_comp_input_1,comp_src_4,25600);
	
	memset(arr_normal_1,0,25600);	
	fp=fopen("ip_src_4.txt","w");
		fwrite(comp_src_4,1,d4,fp);
	fclose(fp);
	
	//ip_dst_1
	handle=pcap_open_offline("trace4",errbuf);
	for(i=0;i<count;i++){
		packet=pcap_next(handle,&header);
		//indir_arr[i]=offset;
		//offset+=header.caplen+16;
		packet_parser(&ip_src,&ip_dst,&ip_p,&sport,&dport);
		
		ip_dst_bi_1(i,ip_dst);	
	}
	pcap_close(handle);
	d5=RLE_Compress(arr_comp_input_1,comp_dst_1,25600);
	memset(arr_normal_1,0,25600);
	fp=fopen("ip_dst_1.txt","w");
		fwrite(comp_dst_1,1,d5,fp);
	fclose(fp);
	
	//ip_dst_2	
	handle=pcap_open_offline("trace4",errbuf);
	for(i=0;i<count;i++){
		packet=pcap_next(handle,&header);
		//indir_arr[i]=offset;
		//offset+=header.caplen+16;
		packet_parser(&ip_src,&ip_dst,&ip_p,&sport,&dport);
		
		ip_dst_bi_2(i,ip_dst);	
	}
	pcap_close(handle);
	d6=RLE_Compress(arr_comp_input_1,comp_dst_2,25600);	
	memset(arr_normal_1,0,25600);
	fp=fopen("ip_dst_2.txt","w");
		fwrite(comp_dst_2,1,d6,fp);
	fclose(fp);

	//ip_dst_3
	handle=pcap_open_offline("trace4",errbuf);
	for(i=0;i<count;i++){
		packet=pcap_next(handle,&header);
		//indir_arr[i]=offset;
		//offset+=header.caplen+16;
		packet_parser(&ip_src,&ip_dst,&ip_p,&sport,&dport);
		
		ip_dst_bi_3(i,ip_dst);	
	}
	pcap_close(handle);
	d7=RLE_Compress(arr_comp_input_1,comp_dst_3,25600);	
	
	memset(arr_normal_1,0,25600);
	fp=fopen("ip_dst_3.txt","w");
		fwrite(comp_dst_3,1,d7,fp);
	fclose(fp);

	
	//ip_dst_4
	handle=pcap_open_offline("trace4",errbuf);
	for(i=0;i<count;i++){
		packet=pcap_next(handle,&header);
		//indir_arr[i]=offset;
		//offset+=header.caplen+16;
		packet_parser(&ip_src,&ip_dst,&ip_p,&sport,&dport);
		
		ip_dst_bi_4(i,ip_dst);	
	}
	pcap_close(handle);
	d8=RLE_Compress(arr_comp_input_1,comp_dst_4,25600);	
	memset(arr_normal_1,0,25600);
	fp=fopen("ip_dst_4.txt","w");
		fwrite(comp_dst_4,1,d8,fp);
	fclose(fp);
	
	//source port			
	handle=pcap_open_offline("trace4",errbuf);
	for(i=0;i<count;i++){
		packet=pcap_next(handle,&header);
		//indir_arr[i]=offset;
		//offset+=header.caplen+16;
		packet_parser(&ip_src,&ip_dst,&ip_p,&sport,&dport);
		
		sport_bi(i,sport);
	}
	pcap_close(handle);
	d9=RLE_Compress(arr_comp_input,comp_src_po,6553500);	
	
	memset(arr_normal,0,6553500);
	fp=fopen("src_port.txt","w");
		fwrite(comp_src_po,1,d9,fp);
	fclose(fp);
	
	//destination port
	handle=pcap_open_offline("trace4",errbuf);
	for(i=0;i<count;i++){
		packet=pcap_next(handle,&header);
		//indir_arr[i]=offset;
		//offset+=header.caplen+16;
		packet_parser(&ip_src,&ip_dst,&ip_p,&sport,&dport);
		
		dport_bi(i,dport);	
	}
	pcap_close(handle);
	d10=RLE_Compress(arr_comp_input,comp_dst_po,6553500);	
	memset(arr_normal,0,6553500);
	fp=fopen("dst_port.txt","w");
		fwrite(comp_dst_po,1,d10,fp);
	fclose(fp);
	
	//protocol		
	handle=pcap_open_offline("trace4",errbuf);
	for(i=0;i<count;i++){
		packet=pcap_next(handle,&header);
		//indir_arr[i]=offset;
		//offset+=header.caplen+16;
		packet_parser(&ip_src,&ip_dst,&ip_p,&sport,&dport);
		
		proto_bi(i,ip_p);
	}
	pcap_close(handle);
	d11=RLE_Compress(arr_comp_input_1,comp_protoco,25600);		
	memset(arr_normal_1,0,25600);
	fp=fopen("protocol.txt","w");
		fwrite(comp_protoco,1,d11,fp);
	fclose(fp);

	d[0]=d1;d[1]=d2;d[2]=d3;d[3]=d4;d[4]=d5;d[5]=d6;d[6]=d7;d[7]=d8;d[8]=d9;d[9]=d10;d[10]=d11;
	fp=fopen("size.txt","w");
		fwrite(d,sizeof(d),1,fp);
	fclose(fp);
	fp=fopen("indirection_array.txt","w");
		fwrite(indir_arr,sizeof(indir_arr),1,fp);
	fclose(fp);

}



void packet_parser(struct in_addr *ip_src,struct in_addr *ip_dst,u_char *ip_p,u_short *sport,u_short *dport){
	ip = (struct ipheader *)malloc(sizeof(struct ipheader));
	ip=(struct ipheader *)(packet+ETH_SIZE);
			
	int ip_size;
	ip_size=IP_HL(ip)*4;
	udp=(struct udpheader *)(packet+ETH_SIZE+ip_size);	
	tcp=(struct tcpheader *)(packet+ETH_SIZE+ip_size);
		
	*ip_src=(*ip).ip_src;
	*ip_dst=(*ip).ip_dst;
	*ip_p=(*ip).ip_p;
		
	if((int)(*ip_p)==6){
		*sport=(*tcp).th_sport;
		*dport=(*tcp).th_dport;
	}	
	else if((int)(*ip_p)==17){
		*sport=(*udp).uh_sport;
		*dport=(*udp).uh_dport;
	}
	else{
		return;
	}	
	
}

void ip_src_bi_1(int packet_id,struct in_addr ip_src){
	char *temp=inet_ntoa(ip_src);
	int byte1;
	
	byte1=atoi(strtok(temp,"."));
	arr_normal_1[packet_id][byte1]=1;		
}

void ip_src_bi_2(int packet_id,struct in_addr ip_src){
	char *temp=inet_ntoa(ip_src);
	int byte1,byte2;
	
	byte1=atoi(strtok(temp,"."));
	byte2=atoi(strtok(NULL,"."));
	arr_normal_1[packet_id][byte2]=1;
}

void ip_src_bi_3(int packet_id,struct in_addr ip_src){
	char *temp=inet_ntoa(ip_src);
	int byte1,byte2,byte3;
	
	byte1=atoi(strtok(temp,"."));
	byte2=atoi(strtok(NULL,"."));
	byte3=atoi(strtok(NULL,"."));
	arr_normal_1[packet_id][byte3]=1;	

}

void ip_src_bi_4(int packet_id,struct in_addr ip_src){
	char *temp=inet_ntoa(ip_src);
	int byte1,byte2,byte3,byte4;
	
	byte1=atoi(strtok(temp,"."));
	byte2=atoi(strtok(NULL,"."));
	byte3=atoi(strtok(NULL,"."));
	byte4=atoi(strtok(NULL,"."));
	arr_normal_1[packet_id][byte4]=1;	

}

void ip_dst_bi_1(int packet_id,struct in_addr ip_dst){
	char *temp=inet_ntoa(ip_dst);
	int byte1;
	
	byte1=atoi(strtok(temp,"."));
	arr_normal_1[packet_id][byte1]=1;		
}

void ip_dst_bi_2(int packet_id,struct in_addr ip_dst){
	char *temp=inet_ntoa(ip_dst);
	int byte1,byte2;
	
	byte1=atoi(strtok(temp,"."));
	byte2=atoi(strtok(NULL,"."));
	arr_normal_1[packet_id][byte2]=1;
}

void ip_dst_bi_3(int packet_id,struct in_addr ip_dst){
	char *temp=inet_ntoa(ip_dst);
	int byte1,byte2,byte3;
	
	byte1=atoi(strtok(temp,"."));
	byte2=atoi(strtok(NULL,"."));
	byte3=atoi(strtok(NULL,"."));
	arr_normal_1[packet_id][byte3]=1;
}

void ip_dst_bi_4(int packet_id,struct in_addr ip_dst){
	char *temp=inet_ntoa(ip_dst);
	int byte1,byte2,byte3,byte4;
	
	byte1=atoi(strtok(temp,"."));
	byte2=atoi(strtok(NULL,"."));
	byte3=atoi(strtok(NULL,"."));
	byte4=atoi(strtok(NULL,"."));
	arr_normal_1[packet_id][byte4]=1;	

}

void proto_bi(int packet_id,u_char ip_p){
	int temp=(int)ip_p;
	arr_normal_1[packet_id][temp]=1;
}

void sport_bi(int packet_id,u_short sport){
	int temp=ntohs(sport);
	arr_normal[packet_id][temp]=1;
}

void dport_bi(int packet_id,u_short dport){
	int temp=ntohs(dport);
	arr_normal[packet_id][temp]=1;
}

	

int main(int argc,char *argv[]){
	int i;
	packet_indexer(100);	
	
	return 0;
}

