#include "gbn.h"

state_t s;

uint16_t checksum(uint16_t *buf, int nwords)
{
	uint32_t sum;

	for (sum = 0; nwords > 0; nwords--)
		sum += *buf++;
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	return ~sum;
}

ssize_t gbn_send(int sockfd, const void *buf, size_t len, int flags){
	
	/* TODO: Your code here. */

	/* Hint: Check the data length field 'len'.
	 *       If it is > DATALEN, you will have to split the data
	 *       up into multiple packets - you don't have to worry
	 *       about getting more than N * DATALEN.
	 */

	return(-1);
}

ssize_t gbn_recv(int sockfd, void *buf, size_t len, int flags){

	/* TODO: Your code here. */

	return(-1);
}

int gbn_close(int sockfd){

	/* TODO: Your code here. */

	return(-1);
}

int gbn_connect(int sockfd, const struct sockaddr *server, socklen_t socklen){

	/* TODO: Your code here. */

	return(-1);
}

int gbn_listen(int sockfd, int backlog){

	/* No "Listening" in UDP sockets */
	
	printf("'Listening'. sockfd: %d, backlog: %d \n", sockfd, backlog);

	/* Set the status to closed, since there is no connection active if we are listening*/
	s.current_state = CLOSED;

	return(0);
}

int gbn_bind(int sockfd, const struct sockaddr *server, socklen_t socklen){

	int bind_status;

    printf("Binding(),  sockfd: %d\n", sockfd);

	/*
	WHERE DOES THIS GO?
	int yes=1;

	// lose the pesky "Address already in use" error message
	if (setsockopt(listener,SOL_SOCKET,SO_REUSEADDR,&yes,sizeof yes) == -1) {
 		perror("setsockopt");
    	exit(1);
	} 

	*/

    if ((bind_status = bind(sockfd, server, socklen)) == -1) {
        perror("Bind error");
        return(-1);
    }

	return bind_status;

	/* return(-1); */
}	

int gbn_socket(int domain, int type, int protocol){

	/*----- Randomizing the seed. This is used by the rand() function -----*/
	srand((unsigned)time(0));

	printf("Making Socket. domain: %d, type %d, protocol %d\n", domain, type, protocol);

	/* Initialize a random seq number used when sending or receiving packets */
    s.seq_num = (uint8_t)rand();

	/* Set initial window size to 1 (2^0)*/
    s.window_size = 1;

    /* Make a signal handler
	 TODOL Figure this out.
	*/
    signal(SIGALRM, timeout_hdler);

    printf("Seq num: %d, Window size: %d\n", s.seq_num, s.window_size);

    int sockfd = socket(domain, type, protocol);

	printf("Socket created %d\n", sockfd);

	return sockfd;
}

int gbn_accept(int sockfd, struct sockaddr *client, socklen_t *socklen){

	/* Called by receiver */

	/* TODO: Your code here. */
	printf("gbn_accept() called. socket: %d, client address: %d\n", sockfd, client->sa_family);

    printf("Current state: %d\n", s.current_state);

	/* 1. Wait for a SYN Packet to arrive
	   2. Send a SYN_ACK Packet back. 
	   3. Upon Successful complete of these steps, update state machine to be connected. 
	   ?. Handle rejection 
	   ?. Handle Timeout
	   ?. Handle Max Attempts */

	/* Allocate memory for a SYN packet to be received*/
	gbnhdr *incoming_pkt = alloc_recv_pkt();

	/* Create a SYN_ACK Packet to be sent */


	/* Wait for the SYN Packet */ 

	/* Validate */

	/* Send SYN_ACK*/

	/* Confirm send */

	/* update state */

	free(incoming_pkt);

	return(-1);
}

ssize_t maybe_recvfrom(int  s, char *buf, size_t len, int flags, struct sockaddr *from, socklen_t *fromlen){

	/*----- Packet not lost -----*/
	if (rand() > LOSS_PROB*RAND_MAX){


		/*----- Receiving the packet -----*/
		int retval = recvfrom(s, buf, len, flags, from, fromlen);

		/*----- Packet corrupted -----*/
		if (rand() < CORR_PROB*RAND_MAX){
			/*----- Selecting a random byte inside the packet -----*/
			int index = (int)((len-1)*rand()/(RAND_MAX + 1.0));

			/*----- Inverting a bit -----*/
			char c = buf[index];
			if (c & 0x01)
				c &= 0xFE;
			else
				c |= 0x01;
			buf[index] = c;
		}

		return retval;
	}
	/*----- Packet lost -----*/
	return(len);  /* Simulate a success */
}

ssize_t maybe_sendto(int  s, const void *buf, size_t len, int flags, \
                     const struct sockaddr *to, socklen_t tolen){

    char *buffer = malloc(len);
    memcpy(buffer, buf, len);
    
    
    /*----- Packet not lost -----*/
    if (rand() > LOSS_PROB*RAND_MAX){
        /*----- Packet corrupted -----*/
        if (rand() < CORR_PROB*RAND_MAX){
            
            /*----- Selecting a random byte inside the packet -----*/
            int index = (int)((len-1)*rand()/(RAND_MAX + 1.0));

            /*----- Inverting a bit -----*/
            char c = buffer[index];
            if (c & 0x01)
                c &= 0xFE;
            else
                c |= 0x01;
            buffer[index] = c;
        }

        /*----- Sending the packet -----*/
        int retval = sendto(s, buffer, len, flags, to, tolen);
        free(buffer);
        return retval;
    }
    /*----- Packet lost -----*/
    else
        return(len);  /* Simulate a success */
}

gbnhdr *alloc_recv_pkt(){

	// Allocated memory for an incoming packet
	gbnhdr *incoming_packet = malloc(size_of(*incoming_packet));
	// Set data to 0's
	memset(incoming_packet, 0, size_of(*incoming_packet));

	return(incoming_packet);
}

uint8_t validate(gbnhdr *packet){
	/*TODO: Implement*/
	return(-1);
};

void build_packet(gbnhdr *data_packet, uint8_t pkt_type ,uint32_t pkt_seqnum, const void *buffr, size_t data_len){
	/* Construct a packet */

	printf("Building packet. Paylod Length: %d\n", (int)data_len);

	/* Memory Already Allocated */
	/* Set Packet type  */
	/* Set Packet Seqnum */
	/* Zero out data  and checksum */
	
	/* Set Payload_len */ 
	/* Copy Data from buff*/
	/**/

	return(-1);
}

void timeout_hdler(int signum) {
	/* TODO: FIX THIS */


    /* apparently bad practice to printf in signal use flag instead */
    printf("\nTIMEOUT has occured with signum: %d\n", signum);

    /* TODO is this safe? race condition? */
    signal(SIGALRM, timeout_hdler);
}

