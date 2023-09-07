#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <errno.h>

#include <sys/types.h>
#include <sys/socket.h>
//#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <sys/time.h>
#include <time.h>
#include <math.h>

#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <linux/tcp.h>
#include <netdb.h>
#include <mariadb/mysql.h>

#define SUPPORT_OUTPUT

#define ETHER_ADDR_LEN	6
#define SIZE_ETHERNET 14
#define SIZE_IP_STR 16
#define SIZE_IP 20
#define SIZE_TCP 20


//char if_bind_global[] = "lo" ;
char if_bind_global[] = "enp03s";
//int if_bind_global_len = 2 ;
int if_bind_global_len= 6 ;

int sendraw_mode = 1;


/* Ethernet header */
struct sniff_ethernet {
	u_char ether_dhost[ETHER_ADDR_LEN]; 
	u_char ether_shost[ETHER_ADDR_LEN]; 
	u_short ether_type; 
};

/* IP header */
struct sniff_ip {
	u_char ip_vhl;		
	u_char ip_tos;		
	u_short ip_len;		
	u_short ip_id;		
	u_short ip_off;		
#define IP_RF 0x8000		
#define IP_DF 0x4000	
#define IP_MF 0x2000		
#define IP_OFFMASK 0x1fff	
	u_char ip_ttl;		
	u_char ip_p;		
	u_short ip_sum;		
	struct in_addr ip_src,ip_dst; 
};
#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)		(((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
	u_short th_sport;	
	u_short th_dport;	
	tcp_seq th_seq;		
	tcp_seq th_ack;		
	u_char th_offx2;	
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
	u_short th_win;		
	u_short th_sum;		
	u_short th_urp;		
};

struct check_domain_struct {
		char domain[256];
};


void got_packet(u_char *args, const struct pcap_pkthdr *header,const u_char *packet);

int pcap_len(struct sniff_ethernet **ethernet, struct sniff_ip **ip, struct sniff_tcp **tcp, char **payload , const u_char *packet);//성공하면 payload_len값 반환, 실패하면 -1 반환
void print_info(const struct sniff_ethernet *ethernet,const struct sniff_ip *ip,const struct sniff_tcp *tcp, const char *, const u_char* ); 
int get_domain(char* payload, u_char ** domain);                                                                     					//성공하면 doamain 길이값 반환
int get_check_domain(char* chk_domain[],int row_cnt);                                                           						//성공하면 체크할 domain 개수 반환
int domain_check(const u_char* domain, const int domain_len, const int chk_domain_cnt,char* chk_domain[]);  							//block해야하면 0 아니면 0아닌 값
void free_get_chk_domain(int cnt,char *chk_domain[]);
void insert_db_func(struct sniff_ip *ip, struct sniff_tcp *tcp, char * src_ip_str, char * dst_ip_str, char * domain,int result);

int print_chars(char print_char, int nums);

unsigned short in_cksum ( u_short *addr , int len );

int sendraw( u_char* pre_packet , int mode ) ;

void got_packet(u_char *args, const struct pcap_pkthdr *header,
    const u_char *packet);


int g_ret = 0 ;
MYSQL *db_connection = NULL;
MYSQL conn;
MYSQL_RES *result;
MYSQL_ROW row;


struct pseudohdr {
        u_int32_t   saddr;
        u_int32_t   daddr;
        u_int8_t    useless;
        u_int8_t    protocol;
        u_int16_t   tcplength;
};


int gbl_debug = 1;





char* chk_domain[256];
int chk_domain_cnt = 0;

int main(int argc, char *argv[])
{
	pcap_t *handle;			
	char *dev;			
	char errbuf[PCAP_ERRBUF_SIZE];	
	struct bpf_program fp;		
	char filter_exp[] = "port 80";	
	bpf_u_int32 mask;		
	bpf_u_int32 net;		
	struct pcap_pkthdr header;	
	const u_char *packet;		


	dev = pcap_lookupdev(errbuf); 
	if (dev == NULL) {  
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf); 
		return(2);
	}
	
    
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) { 
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
		net = 0;
		mask = 0;
	}


	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf); 
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return(2);
	}

	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) { 
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}   
       
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}

    mysql_init(&conn);
	db_connection = mysql_real_connect(
			&conn,		
			"192.168.1.116",		
			"dbuser",		
			"1234",	
			"project-db",	
			3306,			
			(char*)NULL,		
			0		
	);
	
	if ( db_connection == NULL ) {
		fprintf ( stderr , "ERROR: mariadb connection error: %s\n",
					mysql_error(&conn)
			);
		return 1;
	} else { 
		fprintf ( stdout , "INFO: mariadb connection OK\n" );
	} 
	 
	int result = 0; 
	result = pcap_loop(handle, 0, got_packet, NULL) ; 
	
	if( result != 0 ) {
		fprintf(stderr, "ERROR: pcap_loop end with error !!!!\n");
	} else {
		fprintf(stdout, "INFO: pcap_loop end without error.\n");
	}
	
	mysql_close(db_connection);

	pcap_close(handle);
	
	free_get_chk_domain(chk_domain_cnt, chk_domain);


	return(0);
}



void got_packet(u_char *args, const struct pcap_pkthdr *header,
    const u_char *packet) {

	struct sniff_ethernet *ethernet; 
	struct sniff_ip *ip;
	struct sniff_tcp *tcp; 
	char *payload; 
    unsigned short int payload_len = 0;
	int result; 
	
	char src_ip_str[SIZE_IP_STR];
	char dst_ip_str[SIZE_IP_STR];
	

    if((payload_len = pcap_len(&ethernet, &ip, &tcp, &payload, packet)) == -1) 
    {
        printf("pcap len error\n");
        return;
    }

	if(payload_len == 0)
		return;

    u_char* domain;
    int domain_len = 0;

	
	domain_len = get_domain(payload, &domain);
	if(domain_len == 0)
		return;

	chk_domain_cnt = get_check_domain(chk_domain, chk_domain_cnt);
	
	result = domain_check(domain, domain_len, chk_domain_cnt, chk_domain);

	//insert log to db .
	insert_db_func(ip,tcp,src_ip_str,dst_ip_str,domain,result);

    if( result == 0)
	{
		int sendraw_ret = sendraw(packet , sendraw_mode);
		print_info(ethernet, ip, tcp, payload, domain);
		return;
	}
	
	
	

}    //end of got_packet function.	


int pcap_len(struct sniff_ethernet ** ethernet, struct sniff_ip ** ip, struct sniff_tcp ** tcp, char **payload, const u_char *packet){
	u_int size_ip;
	u_int size_tcp;
	
	*ethernet = (struct sniff_ethernet*)(packet); 
	*ip = (struct sniff_ip*)(packet + SIZE_ETHERNET); 

	size_ip = IP_HL(*ip)*4; 
	if (size_ip < 20) {
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return -1;
	}
	*tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
	
	size_tcp = TH_OFF(*tcp)*4;
	if (size_tcp < 20) {
		printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
		return -1;
	}
	*payload = (char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);

	unsigned short int payload_len = 0;
	payload_len = ntohs((*ip)->ip_len) - size_ip - size_tcp ;

    return payload_len;
}

int get_domain(char* payload, u_char ** domain){
    u_char* domain_end = NULL;
	u_char* domain_str;
	#define HOST_LEN 6 
	int domain_len = 0;
	
	domain_str = strstr(payload, "Host: ");
	if (strstr(payload, "connect") != NULL)
	{
		return 0;
	}
	if (domain_str != NULL) {
		domain_end = strstr(domain_str, "\x0d\x0a");
		if (domain_end != NULL){
			domain_len = domain_end - domain_str - HOST_LEN;
			*domain = (char *)malloc(domain_len + 1);
			strncpy(*domain, domain_str + HOST_LEN, domain_len);
			strcpy((*domain)+domain_len,"\0");
		}
	}
	
    return domain_len;
}

void insert_db_func(struct sniff_ip *ip, struct sniff_tcp *tcp, char * src_ip_str, char * dst_ip_str, char * domain,int result){

    char *src_ip_buffer, *dst_ip_buffer;
	
    int query_stat = 0;
	char query_str[1048576] = { 0x00 };

	src_ip_buffer = inet_ntoa(ip->ip_src);
	strcpy(src_ip_str, src_ip_buffer);

	dst_ip_buffer = inet_ntoa(ip->ip_dst);
	strcpy(dst_ip_str, dst_ip_buffer);

	
	sprintf(query_str , "INSERT INTO tb_packet_log ( src_ip , src_port , dst_ip , dst_port , "
								" domain, result ) VALUES "
				"( '%s' , %u , '%s' , %u , '%s',%d )" ,
		src_ip_str , 	
		ntohs(tcp->th_sport),	
		dst_ip_str ,	
		ntohs(tcp->th_dport),	
		domain,		
        result 
        );
	
	query_stat = mysql_query( db_connection , query_str );
	if ( query_stat != 0 ) {
		fprintf ( stderr , "ERROR: mariadb query error: %s\n", mysql_error(&conn) );
		return;
	} else {
		fprintf ( stdout , "INFO: mariadb query OK\n" );
	}
	

}


int get_check_domain(char* chk_domain[256], int row_cnt){
	
	char* new_select_command = NULL;
	int new_row_cnt;
	
	mysql_query( db_connection , "SELECT domain FROM blocked_domain_list" );
	result = mysql_store_result(db_connection);
	
	if(row_cnt == 0)
    {
		row_cnt = mysql_num_rows(result);

		for ( int i = 0; i < row_cnt; i++){
			chk_domain[i] = malloc(256);
			if ( chk_domain[i] == NULL ) {
				fprintf(stderr, "ERROR: malloc fail !!\n");	
			}
		}

		for(int i = 0; i < row_cnt; i++)
		{
			row=mysql_fetch_row(result);
			strcpy(chk_domain[i],row[0]);
		}
	}

	else if (row_cnt != (new_row_cnt = mysql_num_rows(result))){
		
		if(row_cnt < new_row_cnt)
		{
			new_select_command = malloc(100);
			sprintf( new_select_command , "SELECT domain FROM blocked_domain_list ORDER BY created_at DESC LIMIT %d", (new_row_cnt - row_cnt) );
			mysql_query( db_connection , new_select_command );
			result = mysql_store_result(db_connection);

			while(row_cnt < new_row_cnt)
			{	
				printf("chk_domain : %s\n",chk_domain[row_cnt-1]);
				chk_domain[row_cnt] = malloc(256);
				if ( chk_domain[row_cnt] == NULL ) {
					fprintf(stderr, "ERROR: malloc fail !!\n");	
				}
				row=mysql_fetch_row(result);
				printf("dddd : %s\n",chk_domain[row_cnt]);
				strcpy(chk_domain[row_cnt] ,row[0]);
				row_cnt++;
			}
		}
		else
		{
			free(*chk_domain);
			row_cnt = new_row_cnt;

			for ( int i = 0; i < row_cnt; i++){
				chk_domain[i] = malloc(256);
				if ( chk_domain[i] == NULL ) {
					fprintf(stderr, "ERROR: malloc fail !!\n");	
				}
			}

			for(int i = 0; i < row_cnt; i++)
			{
				row=mysql_fetch_row(result);
				strcpy(chk_domain[i],row[0]);
			}
		}
	}
	
	mysql_free_result(result);
	
    return row_cnt;
}


int domain_check(const u_char* domain, const int domain_len, const int chk_domain_cnt, char* chk_domain[chk_domain_cnt]){
	if(domain_len) {
		int cmp_ret = 1;

		for ( int i = 0; i < chk_domain_cnt; i++) {
			int str1_len = strlen(chk_domain[i]);
		
			if ( str1_len != domain_len ){
				continue; 
			} else { 
				printf("domain : %s \n", domain);
				printf("chk domain : %s \n", chk_domain[i]);
			}
			cmp_ret = strcmp(domain, chk_domain[i]);

			if(cmp_ret == 0){
				return cmp_ret; 
			}
		} //end for loop 1.
		
        return 1;
	} // end if domain_len .

}


void print_info(const struct sniff_ethernet *ethernet,const struct sniff_ip *ip,const struct sniff_tcp *tcp, const char* payload, const u_char* domain_str)
{
    char *IPbuffer, *IPbuffer2;
	char IPbuffer_str[SIZE_IP_STR];
	char IPbuffer2_str[SIZE_IP_STR];

	IPbuffer = inet_ntoa(ip->ip_src);
	strcpy(IPbuffer_str, IPbuffer);

	IPbuffer2 = inet_ntoa(ip->ip_dst);
	strcpy(IPbuffer2_str, IPbuffer2);
    
    unsigned short tcp_src_port = 0;
	unsigned short tcp_dst_port = 0;

	tcp_src_port = ntohs(tcp->th_sport); //bin엔디안에서(network) small엔디안으로(host), 2byte short
	tcp_dst_port = ntohs(tcp->th_dport);
    // print domain name .
    printf("INFO: Domain = %s .\n", domain_str);
	
    printf("DATA: IP src : %s\n", IPbuffer_str);
    printf("DATA: IP src : %s\n", IPbuffer2_str);
    printf("DATA : src Port : %u\n", tcp_src_port);
    printf("DATA : dst Port : %u\n", tcp_dst_port);
}

void free_get_chk_domain(int chk_domain_cnt,char *chk_domain[chk_domain_cnt]){
	int i;
	for(i=0; i < chk_domain_cnt; i++)
    if ( chk_domain[i] != NULL )
		{
			free(chk_domain[i]);
			chk_domain[i] = NULL;
		} else {
			fprintf(stderr, "CRIT : check_domain_str"
								" was already free (line = %d)\n",__LINE__);
		}
	
}

unsigned short in_cksum(u_short *addr, int len)
{
        int         sum=0;
        int         nleft=len;
        u_short     *w=addr;
        u_short     answer=0;
        while (nleft > 1){
            sum += *w++;
            nleft -= 2;
        }

        if (nleft == 1){
            *(u_char *)(&answer) = *(u_char *)w ;
            sum += answer;
        }
		
        sum = (sum >> 16) + (sum & 0xffff);
        sum += (sum >> 16);
        answer = ~sum;
        return(answer);
}
// end in_cksum function .

int sendraw( u_char* pre_packet, int mode)
{
	char change_payload[] = 
		"HTTP/1.1 200 OK\x0d\x0a"
		"Content-Length: 230\x0d\x0a"
		"Content-Type: text/html"
		"\x0d\x0a\x0d\x0a"
		"<html>\r\n"
			"<head>\r\n"
				"<meta charset=\"UTF-8\">\r\n"
				"<title>\r\n"
					"CroCheck - WARNING - PAGE\r\n"
						"SITE BLOCKED - WARNING - \r\n"
				"</title>\r\n"
			"</head>\r\n"
			"<body>\r\n"
				"<center>\r\n"
					"<img   src=\"http://127.0.0.1:3000/warning.jpg\" alter=\"*WARNING*\">\r\n"
					"<h1>SITE BLOCKED</h1>\r\n"
				"</center>\r\n"
			"</body>\r\n"
		"</html>";
	const struct sniff_ethernet *ethernet;  
	u_char packet[1600];
	int raw_socket;
	int on=1;
	struct iphdr *iphdr;
	struct tcphdr *tcphdr;
	struct in_addr source_address, dest_address;
	struct sockaddr_in address;
	struct pseudohdr *pseudo_header;
	struct in_addr ip;
	int pre_payload_size = 0 ;
	u_char *payload = NULL ;
	int size_vlan = 0 ;
	int sendto_result = 0 ;
	int vlan_tag_disabled = 0 ;

	int ret = 0 ;

	// raw socket 생성
	raw_socket = socket( AF_INET, SOCK_RAW, IPPROTO_RAW );
	if ( raw_socket < 0 ) {
		print_chars('\t',6);
		fprintf(stderr,"Error in socket() creation - %s\n", strerror(errno));
		fprintf(stderr,"Error in socket() creation - %s\n", strerror(errno));
		return -2;
	}

	setsockopt( raw_socket, IPPROTO_IP, IP_HDRINCL, (char *)&on, sizeof(on)); //어느 특정한 프로토콜 계층 컨넥트 없이 도메인을 바로 전송할 수 있도록 해주는 함수

	if ( if_bind_global != NULL ) {
		if( setsockopt( raw_socket, SOL_SOCKET, SO_BINDTODEVICE, if_bind_global, if_bind_global_len ) == -1 ) {;
		//if_bind_global_len에 packet 특정 네트워크 인터페이스의 바인딩
			print_chars('\t',6);
			fprintf(stderr,"ERROR: setsockopt() - %s\n", strerror(errno));
			return -2;
		}

	}

	ethernet = (struct sniff_ethernet*)(pre_packet);
	if ( ethernet->ether_type == (unsigned short)*(unsigned short*)&"\x81\x00" ) { //ether type \x81\00 = (vlan이 있다. (but 거의 없음 여기 들어 올 일이 없음))
		size_vlan = 4;
		memcpy(packet, pre_packet, size_vlan);
	} else if (ethernet->ether_type == (unsigned short)*(unsigned short*)&"\x08\x00" ) { //거의 여기
		size_vlan = 0;
		vlan_tag_disabled = 1 ;
	} else {
		fprintf(stderr,"NOTICE: ether_type diagnostics failed .......... \n");
	}
	
	if ( vlan_tag_disabled == 1 ) {
		size_vlan = 0 ;
		memset (packet, 0x00, 4) ;	//패킷에 valn부분에 아무것도 안 들어 있기 때문에 그냥 초기화 (아니라면 vlan을 살려놔야 함)
	}
		// TCP, IP 헤더 초기화
		iphdr = (struct iphdr *)(packet + size_vlan) ;
		memset( iphdr, 0, 20 );
		tcphdr = (struct tcphdr *)(packet + size_vlan + SIZE_IP);
		memset( tcphdr, 0, 20 );

		struct iphdr* ip_p = (struct iphdr *)(pre_packet + size_vlan + SIZE_ETHERNET);
		struct tcphdr* tcp_p = (struct tcphdr *)(pre_packet + size_vlan + SIZE_ETHERNET + SIZE_IP);

		source_address.s_addr = 
		ip_p->daddr ;
		// twist s and d address
		dest_address.s_addr = ip_p->saddr ;		// for return response
		iphdr->id = ip_p->id ;
		pre_payload_size = ntohs( ip_p->tot_len ) - ( SIZE_IP + tcp_p->doff * 4 ) ;

		tcphdr->source = tcp_p->dest ;		// twist s and d port
		tcphdr->dest = tcp_p->source ;		// for return response
		tcphdr->seq = tcp_p->ack_seq ;
		tcphdr->ack_seq = tcp_p->seq  + htonl(pre_payload_size)  ;
		tcphdr->window = tcp_p->window ;

		tcphdr->doff = 5;

		tcphdr->ack = 1;
		tcphdr->psh = 1;

		tcphdr->fin = 1;
		// 가상 헤더 생성.
		pseudo_header = (struct pseudohdr *)((char*)tcphdr-sizeof(struct pseudohdr));
		pseudo_header->saddr = source_address.s_addr;
		pseudo_header->daddr = dest_address.s_addr;
		pseudo_header->useless = (u_int8_t) 0;
		pseudo_header->protocol = IPPROTO_TCP;
		pseudo_header->tcplength = htons( sizeof(struct tcphdr) + strlen(change_payload) + 1);
		
		
		// choose output content
		// write post_payload ( redirecting data 2 )
		//post_payload_size = 201 + 67  ;   // Content-Length: header is changed so post_payload_size is increased.
		//post_payload_size = 230 + 93  ;   // Content-Length: header is changed so post_payload_size is increased.
		//memcpy ( (char*)packet + 40, "HTTP/1.1 200 OK" + 0x0d0a + "Content-Length: 1" + 0x0d0a + "Content-Type: text/plain" + 0x0d0a0d0a + "a" , post_payload_size ) ;
		memcpy ( (char*)packet + 40, change_payload , strlen(change_payload) + 1 ) ;
		
		pseudo_header->tcplength = htons( sizeof(struct tcphdr) + strlen(change_payload) + 1);

		tcphdr->check = in_cksum( (u_short *)pseudo_header,
						sizeof(struct pseudohdr) + sizeof(struct tcphdr) + strlen(change_payload) + 1);

		iphdr->version = 4;
		iphdr->ihl = 5;
		iphdr->protocol = IPPROTO_TCP;
		//iphdr->tot_len = 40;
		iphdr->tot_len = htons(SIZE_IP + SIZE_TCP + strlen(change_payload) + 1);

		iphdr->id = ip_p->id + htons(1);
		
		memset( (char*)iphdr + 6 ,  0x40  , 1 );
		
		iphdr->ttl = 60;
		iphdr->saddr = source_address.s_addr;
		iphdr->daddr = dest_address.s_addr;
		// IP 체크섬 계산.
		iphdr->check = in_cksum( (u_short *)iphdr, sizeof(struct iphdr));

		address.sin_family = AF_INET;

		address.sin_port = tcphdr->dest ;
		address.sin_addr.s_addr = dest_address.s_addr;

		if ( mode == 1 ) {
			sendto_result = sendto( raw_socket, &packet, ntohs(iphdr->tot_len), 0x0,
									(struct sockaddr *)&address, sizeof(address) ) ;
			if ( sendto_result != ntohs(iphdr->tot_len) ) {
				fprintf ( stderr,"ERROR: sendto() - %s\n", strerror(errno) ) ;
				ret = -10 ;
			} else {
				ret = 1 ;
			}
		} 

		if ( (unsigned int)iphdr->daddr == (unsigned int)*(unsigned int*)"\xCB\xF6\x53\x2C" ) {
			printf("##########################################################################################################################\n");
			printf("##########################################################################################################################\n");
			printf("##########################################################################################################################\n");
			printf("##########################################################################################################################\n");
			printf("##########################################################################################################################\n");
			printf("##########################################################################################################################\n");
			printf("##########################################################################################################################\n");
			printf( "address1 == %hhu.%hhu.%hhu.%hhu\taddress2 == %X\taddress3 == %X\n",
					*(char*)((char*)&source_address.s_addr + 0),*(char*)((char*)&source_address.s_addr + 1),
					*(char*)((char*)&source_address.s_addr + 2),*(char*)((char*)&source_address.s_addr + 3),
					source_address.s_addr,	(unsigned int)*(unsigned int*)"\xCB\xF6\x53\x2C" );
		}
		close( raw_socket );
			
	return ret ;
}
// end sendraw function .


int print_chars(char print_char, int nums)
{
	int i = 0;
	for ( i ; i < nums ; i++) {
		printf("%c",print_char);
	}
	return i;
}



