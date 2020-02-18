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
	printf("\n<---------------------- GBN_SEND() ---------------------->\n\n");

	/* TODO: Your code here. */
	printf("This side is the sender.\n");
	s.sender = TRUE;

	/* Hint: Check the data length field 'len'.
	 *       If it is > DATALEN, you will have to split the data
	 *       up into multiple packets - you don't have to worry
	 *       about getting more than N * DATALEN.
	 */
	

	/* Get total number of packets*/
	s.num_packets = 1;
	s.remainder = len % DATALEN;

	if (len > DATALEN){
		s.num_packets = len / DATALEN;
		if (s.num_packets*DATALEN + s.remainder != len){
			perror("Packet division error\n");
			return (-1);
		}
	}

	printf("Sending %d bytes of data. Total Packets = %d. Remainder = %d\n", len, s.num_packets, s.remainder);

	
	/* Iterate when receiving a valid acknowledgement.
	 * track initial sequence number (in the case of a cumulative ack)
	 */
	uint16_t packets_sent = 0; /* Count of packets sent SUCCESSFULLY */
	uint32_t initial_seq_num = s.seq_num;
	uint32_t most_recent_ack;
	uint8_t packets_out = 0; /* Number of outstanding packets */
	uint8_t attempts = 0;


	/* Allocate memory for incoming ack packet 
	 * Should only need 1 because ACKs are coming in 1 at a time.
	 * 	Need a data structure to track ACKS? 
	 */
	 gbnhdr *DATAACK_packet = alloc_pkt();


	/* Allocate Memory for outgoing packets
	 * Use array of packet headers *
	 * Number of elements is the number of packets TOTAL
	 * Plus 1 or first packet with remainder data.
	 */
	gbnhdr *outgoing_packets[s.num_packets + 1];
	
	for (int i = 0; i < s.num_packets+1; i++){
		uint16_t buffer_pos = i-1;
		outgoing_packets[i] = alloc_pkt();
		if (i == 0) {
			printf("Building Remainder Packet.\n");
			/* Build Remainder packets 
			 * Total packets first, then remainder
			 */
			build_empty_packet(outgoing_packets[i], DATA, initial_seq_num);
			gbnhdr *rem_packet = outgoing_packets[i];
			printf("1\n");
			memcpy(rem_packet->data, &s.num_packets, sizeof(s.num_packets));
			printf("2\n");
			memcpy(rem_packet->data+sizeof(uint16_t), &s.remainder, sizeof(s.remainder));
			printf("Done\n");
		}
		else {
			/* Build Payload packets 
			 * Can simply start buffer at correct position, since build data packet writes 1024 each time.
			 */
			if (i == s.num_packets && s.remainder > 0){
				build_data_packet(outgoing_packets[i], DATA, initial_seq_num + i, buf+buffer_pos*DATALEN, s.remainder);
			}
			else{
				build_data_packet(outgoing_packets[i], DATA, initial_seq_num + i, buf+buffer_pos*DATALEN, 1024);
			}
		}
	}


	printf("\n<---------------------- Sending Packets ---------------------->\n\n");

	if (packets_sent == 0){
		printf("\n<---------------------- Sending Remainder ---------------------->\n\n");
	}
	while( packets_out < s.window_size){
		
		if (attempts >= MAX_ATTEMPTS){
			perror("Max Attempts exceded. Exiting.\n");
			for (int i = 0; i < s.num_packets+1; i++){
				free(outgoing_packets[i]);
			}
			return (-1);
		}
		attempts++;
	}
	/* Send packets.
	 * 
	 * 
	 * Track number of outstanding packets. Make less than or equal to window size.
	 * 
	 */
	
	printf("\n<---------------------- Receiving Acks ---------------------->\n\n");
	/* Get Acks
	 *
	 * Track last_ack_recvd for duplicate?
	 * 
	 * If Ack is good (seq_num >= expected seq_num): 
	 * 
	 * -Increment packets_sent
	 * -Increment "Consecutive Acks count?"
	 * -Increment expected seq_num
	 * 
	 * If Ack is bad: (timeout/duplicate Ack).
	 * 1. Reduce window size.
	 * 2. Resend all packets
	 * 
	 * 
	 */


	/* Window Size:
	 * Can either 
	 * A. wait for all acks before sending more packets (and increase window size)
	 * or
	 * B. send new packets as acks come in and keep track of target_ack for window size increase
	 * 
	 * Performance for B likely better.
	 */

	/* CASES:
	 * 
	 * TODO: Make sure all of these are covered.
	 * 
	 * Notes: No packets sent out of order (per Piazza).
	 * Means Duplicate Ack indicates a corrupted or lost packet
	 * 
	 * Full Success (packet sent, ack received in order)
	 * 
	 * Full Failure (Packet lost or corrupted)
	 * - Duplicate Ack
	 * - Timeout
	 * 
	 * Cumulative Success (Multi Packet Sent, Later Ack Received)
	 * - Middle ack fails in some way
	 * 
	 * 
	 * 
	 */

	return(-1);
}

ssize_t gbn_recv(int sockfd, void *buf, size_t len, int flags){
	printf("\n<---------------------- GBN_RECV() ---------------------->\n\n");

	printf("This side is the receiver.\n");
	s.sender = FALSE;

	/* check for end of message, return 0 */
	if (s.message_complete){
		printf("Message transmission complete\n");
		return 0;
	}

	printf("Last acked packet seq_num: %d\n", s.seq_num);
	/* track expected sequence number */
	uint8_t expected_seq_num = (uint8_t) s.seq_num + 1;
	printf("Expected packet seq_num: %d (should be %d)\n", expected_seq_num, (uint8_t)s.seq_num+1 );
	/* Allocate packet to receive? */
	printf("Allocating incoming packet\n");
	gbnhdr *incoming_packet = alloc_pkt();

	int attempts = 0;
	ssize_t recvd_bytes;

	/*  allocate ack packet with expected sequence number */
	printf("Building ACK packet\n");

	gbnhdr *ACK_packet = alloc_pkt();
	build_empty_packet(ACK_packet, DATAACK, expected_seq_num);
	
	while (s.current_state == ESTABLISHED){
		if (attempts >= MAX_ATTEMPTS){
			/* Max Attempts exceeded */
			perror("Maximum attempts exceded. Exiting\n");
			free(incoming_packet);
			free(ACK_packet);
			return(-1);
		}
		
		attempts++;
		printf("Waiting to maybe recvfrom. Attempt Number: %d\n", attempts);
		recvd_bytes = maybe_recvfrom(sockfd, incoming_packet, sizeof(*incoming_packet), flags, &s.address, &s.sock_len);
		if(recvd_bytes == -1){
			if (errno != EINTR) {
				perror("Recv From Failed\n");
				/* Attempt again */
				continue;
				}
		}


		printf("Maybe Recv From Success\n");
		printf("Received packet: %d. Expected Packet: %d\n", incoming_packet->seqnum, expected_seq_num);

		if (incoming_packet->type != DATA){
			perror(" Incorrect Packet Type Received. Connection out of Synch. Exiting.\n");
			free(incoming_packet);
			free(ACK_packet);
			return(-1);
		}

		/* validate packet and SeqNum*/
		if (validate(incoming_packet) && incoming_packet->seqnum == expected_seq_num){
			
			/* TODO: Use first packet to establish number and remainder.*/

			/* TODO: Check payload length somehow.*/
			/* TODO: Count Packets */
			size_t payload_len = len;

			/* if packet is valid, write data, send new ack */
			printf("Packet is valid. Sending acknowledgement for packet %d\n", ACK_packet->seqnum);
			memcpy(buf, incoming_packet->data, payload_len);
			s.seq_num++;
			printf("Copied %d bytes to buf and increased seq_num to %d\n", payload_len, s.seq_num);
			/* If length of received, relevant payload is less than a full data packet payload, last packet is received*/
			if (payload_len < len){
				printf("End of message detected.\n");
				/* Change state to indicate end of message and then return 0? */
				/*  TODO: Handle end of send call */
				s.message_complete = TRUE;
			}
		}

		else{
			/* Packet is corrupted, send old ack. */
			ACK_packet->seqnum = (uint8_t)s.seq_num;
			printf("Packet is Corrupted or Out of Order. Sending acknowledgement %d\n", ACK_packet->seqnum);
		}

		attempts = 0;
		printf("MaybeSendTo Call\n");
		/* Send Acknowledgement */
		while (TRUE){
			if (attempts<=MAX_ATTEMPTS){
				perror("Max attempts exceed on sending ack. Connection compromised.\n");
				free(incoming_packet);
				free(ACK_packet);
				return(-1);
			}
			attempts++;
			if(maybe_sendto(sockfd, ACK_packet, sizeof(*ACK_packet), flags, &s.address, s.sock_len) == -1){
				printf("Sendto Failed, retrying\n");
				continue;
			}
			break;
		}
		/* free memory */
		free(incoming_packet);
		free(ACK_packet);
		/* return bytes recieved */
		return(recvd_bytes);
	}

	perror("Connection is not established. Exiting\n");

	/* free memory, turn off timer */
	free(incoming_packet);
	free(ACK_packet);
	
	return(-1);
}

int gbn_close(int sockfd){
	printf("\n<---------------------- GBN_CLOSE() ---------------------->\n\n");

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
	
	printf("\n<---------------------- GBN_CONNECT() ---------------------->\n\n");

	printf("gbn_connect() called. socket: %d, server address: %d socklen: %d\n", sockfd, server->sa_family, socklen);
    printf("Current state: %d\n", s.current_state);

	/* Create SYN Packet */
	gbnhdr *SYN_pkt = alloc_pkt();
	build_empty_packet(SYN_pkt, SYN , s.seq_num);
	
	printf("Creating SYNACK\n");

	/* Create SYNACK Packet */
	gbnhdr *SYNACK_pkt = alloc_pkt();

	printf("Counter = 0\n");
	/* Begin trying to establish connection */
	int counter = 0;

	/* Try 5 attempts max */
	while(counter < MAX_ATTEMPTS) {

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
		
		printf("SYNACK Unsuccessfully received.\n");
		
		/* TODO: Figure out how to handle this case. */

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

	printf("\n<---------------------- GBN_ACCEPT() ---------------------->\n\n");

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
			alarm(TIMEOUT*6);
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
			/* TODO: REJECT (send rejection packet) */
			printf("Rejecting connection. Socket already in use\n");
			return(-1);
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
		else{
			printf("Invalid SYN Packet Received. Retrying.\n");
			continue;
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

	uint16_t rcvd_checksum = packet->checksum;
	packet->checksum = (uint16_t)0;

	uint16_t pkt_checksum = checksum((uint16_t  *)packet, sizeof(*packet) / sizeof(uint16_t));
	printf("rcvd checksum: %d. expected checksum: %d\n", rcvd_checksum, pkt_checksum);
	
	if (rcvd_checksum == pkt_checksum){
		return(1);
	}
	
	printf("Invalid Checksum.\n");
	return(-1);
};

void build_data_packet(gbnhdr *data_packet, uint8_t pkt_type ,uint32_t pkt_seqnum, const void *buffr, size_t len){

	/* Construct a packet */

	printf("Building packet. Paylod Length: %d\n", len);

	/* Memory Already Allocated */

	/* Zero out data  and checksum */
	memset(data_packet->data, 0, sizeof(data_packet->data));
	data_packet->checksum = (uint16_t)0;

	/* Set Packet type  */
	data_packet->type = pkt_type;

	/* Set Packet Seqnum */
	data_packet->seqnum = (uint8_t)pkt_seqnum;

	/* Copy Data from buff*/
	memcpy(data_packet->data, buffr, len);

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
	/* TODO: SIGACTION, Not Signal SA_ONSTACK or SA_RESTART*/

    printf("\nTIMEOUT has occured with signum: %d\n", signum);

    /* TODO is this safe? race condition? */
    signal(SIGALRM, timeout_hdler);
}

