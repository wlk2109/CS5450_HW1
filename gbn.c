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

int gbn_connect(int sockfd, const struct sockaddr *server, socklen_t socklen) {

	/* 1. Create SYN Packet
	   2. Send SYN Packet to reciever and move to SYN_SENT
	   3. Wait for SYNACK and update state machine to ESTABLISHED
	   ?. Handle rejection 
	   ?. Handle Timeout
	   ?. Handle Max Attempts */

	printf("gbn_connect() called. socket: %d, server address: %d socklen: %d\n", sockfd, server->sa_family, socklen);
    printf("Current state: %d\n", s.current_state);

	/* Create SYN Packet */
	gbnhdr *SYN_pkt = alloc_pkt();
	build_empty_packet(SYN_pkt, SYN , s.seq_num);

	/* Create SYNACK Packet */
	gbnhdr *SYNACK_pkt = alloc_pkt();

	/* Begin trying to establish connection */
	int counter = 0;

	/* Try 5 attempts max */
	while(counter > MAX_ATTEMPTS) {

		if (s.current_state == CLOSED) {

			/*Try sending packet to establish connection */
			printf("Sending SYN packet. Seqnum: %d\n", SYN_pkt->seqnum);

			if (maybe_sendto(sockfd, SYN_pkt, sizeof(SYN_pkt), 0, server, socklen) == -1) {
				perror("Sending SYN Packet returned an error\n");
				return(-1);
			}

			/* Change state to sent */
			s.current_state = SYN_SENT;
			
			printf("Changed current state to SYN_SENT now waiting for SYN_ACK\n");
		}
		
		if (s.current_state == SYN_SENT) {
			
			counter++;
			alarm(TIMEOUT);

			if (maybe_recvfrom(sockfd, SYNACK_pkt, sizeof(SYNACK_pkt), 0, server, &socklen) == -1) {
				
				if (errno == EINTR) {
					perror("TIMEOUT error in waiting for SYNACK packet\n");
				} else {
					perror("Error in recieving SYNACK packet\n");
				}
				
				s.current_state = CLOSED;
				continue;
			}
		}

		if ((SYNACK_pkt->type == SYNACK) && (validate(SYNACK_pkt) == 1)) {

			alarm(0);
			printf("Recieved SYNACK packet successfully\n");

			s.address =  *(struct sockaddr *) &server;
			s.sock_len = socklen;
			s.current_state = ESTABLISHED;
			s.seq_num = SYN_pkt->seqnum;
			s.current_state = ESTABLISHED;

			printf("Connection Established with server\n");
			free(SYN_pkt);
			free(SYNACK_pkt);

			return sockfd;
		}

	}
	
	if (counter > MAX_ATTEMPTS) {
		printf("Reached maximum attempts");
		free(SYN_pkt);
		free(SYNACK_pkt);
		return(-1);
	}

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

	lose the pesky "Address already in use" error message
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

    /* initialize signal handler	*/
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
	gbnhdr *incoming_pkt = alloc_pkt();

	int attempts = 0;
	ssize_t recvd_bytes;

	/* Check Attempts Number*/
	while(attempts < MAX_ATTEMPTS){

		
		/* Wait for the SYN Packet, if socket is currently closed. */ 
		if (s.current_state == CLOSED){

			/*TODO: Confirm this is proper Alarm spot*/
			alarm(TIMEOUT);
			attempts++;
			printf("Waiting for SYNthia...\n Attempt #: %d\n", attempts);

			if ((recvd_bytes = maybe_recvfrom(sockfd, incoming_pkt, sizeof(incoming_pkt), 0, client, socklen)) == -1){
				/* Maybe_recvfrom failed, TIMEOUT did not occur */
				if (errno != EINTR) {
					perror("Recv From Failed\n");
					s.current_state = CLOSED;
					/* Attempt again */
					continue;
				}
			}
			/* Received data successfully */
			/* Turn off alarm*/
			alarm(0);

			printf("\nPacket received! Bytes: %d, Packet Type: %d\n", (int)recvd_bytes, incoming_pkt->type);
			
		}
		else{
			/* Connection isn't closed */
			/* REJECT */
			printf("Rejecting connection. Socket already in use\n");
			return(-1);

			/* Backlog? */
		}

		/* Validate */
		if ((incoming_pkt->type == SYN) && (validate(incoming_pkt))){
			
			printf("SYN City\n");

			s.current_state = SYN_RCVD;
			s.seq_num = incoming_pkt -> seqnum;

			
			/* Create a SYN_ACK Packet to be sent */
			printf("Making SYN_ACK packet\n");
			gbnhdr* SYNACK_packet = alloc_pkt();
			build_empty_packet(SYNACK_packet, SYNACK, s.seq_num);

			/* Send SYN_ACK*/
			attempts = 0;
			while(attempts < MAX_ATTEMPTS){

				if (maybe_sendto(sockfd, SYNACK_packet, sizeof(SYNACK_packet), 0, client, *socklen) == -1){
				/* Maybe_sendto failed, TIMEOUT did not occur */
					perror("sendto Failed.\n");
					/* Attempt again */
					attempts++;
					if (attempts == MAX_ATTEMPTS){
						/* Too Many Attempts*/
						printf("Sendto max attempts exceeded. Connection closed. \n");
						s.current_state = CLOSED;
						s.seq_num = 0;

						free(incoming_pkt);
						free(SYNACK_packet);
						return(-1);
					}
					continue;
				}
				break;
			}

            s.current_state = ESTABLISHED;
            s.address = *client;
            s.sock_len = *socklen;

            printf("Current state ESTABLISHED: %d\n", s.current_state);

            free(incoming_pkt);
            free(SYNACK_packet);
            return sockfd;
		}

	}
	printf("\nMax Attempts exceeded. Connection Broken. Exiting\n");
	s.current_state = CLOSED;

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

gbnhdr *alloc_pkt(){

	/* Allocated memory for an incoming packet */
	gbnhdr *packet = malloc(sizeof(*packet));
	/* Set data to 0's */
	memset(packet, 0, sizeof(*packet));

	return(packet);
}

uint8_t validate(gbnhdr *packet){
	/*TODO: Implement*/
	uint16_t rcvd_checksum = packet->checksum;
	packet->checksum = (uint16_t)0;

	uint16_t pkt_checksum = checksum((uint16_t  *)packet, sizeof(*packet) / sizeof(uint16_t));
	printf("rcvd_checksum: %d pkt_checksum: %d\n", rcvd_checksum, pkt_checksum);
	
	if (rcvd_checksum == pkt_checksum){
		return(1);
	}
	
	printf("Invalid Checksum.");
	return(-1);
};

void build_data_packet(gbnhdr *data_packet, uint8_t pkt_type ,uint32_t pkt_seqnum, const void *buffr){

	/* Construct a packet */

	printf("Building packet. Paylod Length: %d\n", (int)sizeof(*buffr));

	/* Memory Already Allocated */

	/* Zero out data  and checksum */
	memset(data_packet->data, 0, sizeof(data_packet->data));
	data_packet->checksum = (uint16_t)0;

	/* Set Packet type  */
	data_packet->type = pkt_type;

	/* Set Packet Seqnum */
	data_packet->seqnum = pkt_seqnum;

	/* Copy Data from buff*/
	memcpy(data_packet->data, buffr, sizeof(*buffr));

	/* Add Checksum*/
	data_packet->checksum = checksum((uint16_t  *)data_packet, sizeof(*data_packet) / sizeof(uint16_t));
}

void build_empty_packet(gbnhdr *data_packet, uint8_t pkt_type ,uint32_t pkt_seqnum){

	/*TODO: COnfirm Word Size for Checksum calculation*/


	/* Construct a packet */
	printf("Building empty packet. Packet Type: %d\n", pkt_type);

	/* Zero out checksum */
	data_packet->checksum = (uint16_t)0;

	/* Set Packet type  */
	data_packet->type = pkt_type;

	/* Set Packet Seqnum */
	data_packet->seqnum = pkt_seqnum;

	/* Add Checksum*/
	data_packet->checksum = checksum((uint16_t  *)data_packet, sizeof(*data_packet) / sizeof(uint16_t));
}

void timeout_hdler(int signum) {

    printf("\nTIMEOUT has occured with signum: %d\n", signum);

    /* TODO is this safe? race condition? */
    signal(SIGALRM, timeout_hdler);
}

