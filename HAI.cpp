#define WIN32_LEAN_AND_MEAN
#define  USE_TCP 1
#include <winsock2.h>
#include <stdio.h>
#include "HAI.h"
#include "aes.h"
#include <errno.h>


// Link with ws2_32.lib
#pragma comment(lib, "Ws2_32.lib")


int hai_net_recv_msg(hai_comm_id *id, hai_msg_type *type, void *msg, int *len);
static int hai_net_recv_unsec_msg(hai_comm_id *id, hai_msg_type *type, void *msg, int *len);
int hai_net_send_msg(hai_comm_id *id, hai_msg_type type, const void *msg, int len);
static int hai_net_send_unsec_msg(hai_comm_id *id, hai_msg_type type, const void *msg, int len);
static int crc16(const void *data, int len);
static int omni_recv_msg(hai_comm_id *id, int *type, void *msg, int *len);
static int omni_send_msg(hai_comm_id *id, int type, void *msg, int len);
int hai_net_open(hai_comm_id *id, const char *ip_address, int port, const unsigned char *private_key);
int hai_net_close(hai_comm_id *id);
int omni_command(hai_comm_id *id, int cmd, int p1, int p2);


int omni_sys_info(hai_comm_id *id, sys_info *data);

int main(void) {

	//----------------------
	// Declare and initialize variables.
	hai_comm_id id;
	WSADATA wsaData;
	sys_info si = { 0 };

	unsigned char omni_model;
	unsigned char omni_major_version;
	unsigned char omni_minor_version;

	//----------------------
	// Initialize Winsock
	err = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (err != NO_ERROR) {
		printf("WSAStartup failed: %d\n", err);
		return 1;
	}

	if ((err = hai_net_open(&id, HAI_IP_ADDRESS, HAI_PORT, private_key)) != 0)
	{
		printf("error opening hai network connection\n");
		return err;
	}

	/* Request system info */
	if ((err = omni_sys_info(&id, &si)) != 0)
	{
		printf("error getting system info\n");
		return err;
	}


	omni_model = si.model;
	omni_major_version = si.major;
	omni_minor_version = si.minor;

	switch (omni_model)
	{
	case OMNILT:
		printf("OMNILT\n");
		break;
	case OMNI2E:
		printf("OMNI2E\n");
		break;
	case OMNIPRO2:
		printf("OMNIPRO2\n");
		break;
	case LUMINA:
		printf("LUMINA\n");
		break;
	case LUMINAPRO:
		printf("LUMINAPRO\n");
		break;
	case OMNI:
		printf("OMNI\n");
		break;
	case OMNI2:
	case OMNIPRO:
		printf("OMNIPRO\n");
		break;
	}

	/* Turn Uint 14 ON for 60 seconds */


	if ((err = omni_command(&id, CMD_ON, 60, 14)) != 0)
		printf("Failed to turn lights on\n");
	else printf("Turned lights on successfully\n");

	/* Close network connection */
	hai_net_close(&id);
	return 0;
}

/* Function to open network connection */
int hai_net_open(hai_comm_id *id, const char *ip_address, int port,
	const unsigned char *private_key)
{
	struct hostent *hostp;
	hai_ack_new_session ack_msg;
	char buffer[1024] = { 0 };
	int err, len, i, addr;
	hai_msg_type type;

	/* Check arguments */
	if ((id == NULL) || (ip_address == NULL) || (private_key == NULL))
		return EHAIARGUMENT;

	/* Check ip address */
	if (strlen(ip_address) == 0)
		return EHAIARGUMENT;

	/* Set connection type */
	id->serial_mode = 0;

	/* Lookup address */
	if ((hostp = gethostbyname(ip_address)) != NULL)
		addr = *((int*)hostp->h_addr);
	else
		addr = inet_addr(ip_address);


	// Create a SOCKET for connecting to server
	id->s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (id->s == INVALID_SOCKET) {
		printf("Error at socket(): %ld\n", WSAGetLastError());
		WSACleanup();
		return 1;
	}

	//----------------------
	// The sockaddr_in structure specifies the address family,
	// IP address, and port of the server to be connected to.

	memset((char*)&(id->omni), 0, sizeof(id->omni));
	id->omni.sin_family = AF_INET;
	id->omni.sin_addr.s_addr = inet_addr(HAI_IP_ADDRESS);
	id->omni.sin_port = htons(HAI_PORT);

	//----------------------
	// Connect to server.
	err = connect(id->s, (SOCKADDR*)&id->omni, sizeof(id->omni));
	if (err == SOCKET_ERROR) {
		closesocket(id->s);
		printf("Unable to connect to server: %ld\n", WSAGetLastError());
		WSACleanup();
		return 1;
	}
	/* Reset sequence */
	id->tx_sequence = 1;

	/* Send new session request */
	if ((err = hai_net_send_unsec_msg(id, (hai_msg_type)CLIENT_REQUEST_NEW_SESSION, NULL, 0))
		!= 0)
		return err;

	/* Wait for response */
	len = sizeof(ack_msg);
	if ((err = hai_net_recv_unsec_msg(id, &type, &ack_msg, &len)) != 0)
		return err;
	if (type != CONTROLLER_ACKNOWLEDGE_NEW_SESSION)
		return EHAIRESPONSE;
	else
		printf("Controller acknowledges new session\n");

	/* Save session ID and update private key */
	memcpy(id->private_key, private_key, 16);
	for (i = 0; i < 5; i++)
	{
		id->session_id[i] = ack_msg.session_id[i];
		id->private_key[i + 11] ^= ack_msg.session_id[i];
	}

	/* Send secure connection request */
	if ((err = hai_net_send_msg(id, (hai_msg_type)CLIENT_REQUEST_SECURE_CONNECTION,
		id->session_id, 5)) != 0)
		return err;

	/* Wait for response */
	if ((err = hai_net_recv_msg(id, &type, buffer, &len)) != 0)
		return err;

	/* Test result */
	if (type != CONTROLLER_ACKNOWLEDGE_SECURE_CONNECTION)
		return EHAIRESPONSE;
	else printf("Controller acknowledges secure connection\n");

	for (i = 0; i < 5; i++)
	{
		if (id->session_id[i] != (unsigned char)buffer[i])
			return EHAISESSION;
	}

	return 0;
}


/* Function to close network connection */
int hai_net_close(hai_comm_id *id)
{
	int err = 0;
	hai_msg_type type;

	/* Check file handle */
	if (id->s == 0)
		return EHAISESSION;

	/* Send client session terminated */
	if ((err = hai_net_send_unsec_msg(id, (hai_msg_type)CLIENT_SESSION_TERMINATED, NULL, 0))
		!= 0)
		goto exit_err;

	/* Wait for response */
	if ((err = hai_net_recv_unsec_msg(id, &type, NULL, NULL)) != 0)
		goto exit_err;
	if (type != CONTROLLER_SESSION_TERMINATED)
		err = EHAIRESPONSE;
	else printf("Network connection closed\n");

	/* Close socket */
exit_err:
	closesocket(id->s);
	return err;
}


/* Function to send a secure message */
int hai_net_send_msg(hai_comm_id *id, hai_msg_type type, const void *msg,
	int len)
{
	char buffer[1024];
	char sec_buffer[1024];
	int tx_len, err, i;
	aes_t aes;

	/* Calc data lenth rounded up to next 16 byte count */
	tx_len = (len + 15) & ~0xF;

	/* Copy data */
	memset(buffer, 0, sizeof(buffer));
	memcpy(buffer, msg, len);

	/* XOR data */
	for (i = 0; i < (tx_len / 16); i++)
	{
		buffer[0 + (16 * i)] ^= (id->tx_sequence >> 8) & 0xFF;
		buffer[1 + (16 * i)] ^= (id->tx_sequence) & 0xFF;
	}

	/* Encrypt message */
	memset(sec_buffer, 0, sizeof(sec_buffer));
	MakeKey(&aes, (char *)(id->private_key), "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 16, 16);
	Encrypt(&aes, buffer, sec_buffer, tx_len, ECB);

	/* Send message */
	if ((err = hai_net_send_unsec_msg(id, type,
		sec_buffer, tx_len)) != 0)
		return err;

	return 0;
}


/* Function to receive a secure message */
int hai_net_recv_msg(hai_comm_id *id, hai_msg_type *type, void *msg,
	int *len)
{
	char sec_buffer[1024] = { 0 };
	char buffer[1024] = { 0 };
	int cnt, err, rx_len, i;
	aes_t aes;

	/* Wait for response */
	cnt = 1024;
	memset(sec_buffer, 0, sizeof(sec_buffer));
	if ((err = hai_net_recv_unsec_msg(id, type, sec_buffer, &cnt)) != 0)
		return err;

	/* Calc data lenth rounded up to next 16 byte count */
	rx_len = (cnt + 15) & ~0xF;

	/* Fill in results */
	if (len != NULL)
	{
		if (*len < cnt)
			cnt = *len;
		else
			*len = cnt;
	}

	if ((cnt != 0) && (msg != NULL))
	{
		/* Decrypt message */
		memset(buffer, 0, sizeof(buffer));
		MakeKey(&aes, (char *)(id->private_key), "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 16, 16);
		Decrypt(&aes, sec_buffer, buffer, rx_len, ECB);

		/* XOR data */
		for (i = 0; i < (rx_len / 16); i++)
		{
			buffer[0 + (16 * i)] ^= (id->rx_sequence >> 8) & 0xFF;
			buffer[1 + (16 * i)] ^= (id->rx_sequence) & 0xFF;
		}

		/* Copy message */
		memcpy(msg, buffer, cnt);
	}

	return 0;
}


const char *hai_net_strerror(int err)
{

	switch (err)
	{
	case EHAIARGUMENT:
		return "Bad HAI communication function argument";
	case EHAIRESPONSE:
		return "Unexpected HAI response";
	case EHAISESSION:
		return "Bad session ID from HAI";
	case EHAITIMEOUT:
		return "Network time-out";
	}

	return NULL;
}


/* Function to send an unsecure message */
static int hai_net_send_unsec_msg(hai_comm_id *id, hai_msg_type type,
	const void *msg, int len)
{
	char buffer[1024] = { 0 };
	hai_msg_header *header = (hai_msg_header*)&buffer;
	int packet_len = sizeof(hai_msg_header)+len;

	/* Check file handle */
	if (id->s == 0)
		return EHAISESSION;

	/* Prepare packet */
	SET16(header->sequence, id->tx_sequence);
	SET8(header->type, type);
	SET8(header->resv0, 0);
	if ((len != 0) && (msg != NULL))
		memcpy(buffer + sizeof(hai_msg_header), msg, len);

	/* Send packet */
	if (sendto(id->s, buffer, packet_len, 0, (struct sockaddr *) &(id->omni),
		sizeof(id->omni)) != packet_len)
		return errno;

	/* Increment sequence */
	if (id->tx_sequence < 65535)
		id->tx_sequence++;
	else
		id->tx_sequence = 1;

	return 0;
}


/* Function to receive an unsecure message */
static int hai_net_recv_unsec_msg(hai_comm_id *id, hai_msg_type *type,
	void *msg, int *len)
{
	char buffer[1024] = { 0 };
	hai_msg_header *header = (hai_msg_header*)&buffer;
	int cnt, recv_len, retval;
	//		struct timeval tv = { 0 };
	//		fd_set rfds;

	/* Check file handle */
	if (id->s == 0)
		return EHAISESSION;
	/* Read packet */
	cnt = recv(id->s, buffer, 1024, 0);
	id->rx_sequence = GET16(header->sequence);

	/* Fill in results */
	recv_len = cnt - sizeof(hai_msg_header);
	if (type != NULL)
		*type = (hai_msg_type)GET8(header->type);
	if (len != NULL)
	{
		if (*len < recv_len)
			recv_len = *len;
		else
			*len = recv_len;
	}
	if ((recv_len != 0) && (msg != NULL))
		memcpy(msg, buffer + sizeof(hai_msg_header), recv_len);

	return 0;
}



int omni_sys_info(hai_comm_id *id, sys_info *data)
{
	omni_msg req = { 0 };
	omni_msg_sys_info resp = { 0 };
	int err, type, len;

	/* Send request system information */
	if ((err = omni_send_msg(id, OMNI_TYPE_REQ_SYS_INFO,
		&req, sizeof(req))) != 0)
		return err;

	/* Get system information */
	len = sizeof(resp);
	if ((err = omni_recv_msg(id, &type,
		&resp, &len)) != 0)
		return err;
	if (type != OMNI_TYPE_SYS_INFO)
		return EOMNIRESPONSE;

	/* Return results */
	memcpy(data, &resp.data, sizeof(sys_info));

	return 0;
}


static int omni_send_msg(hai_comm_id *id, int type, void *msg, int len)
{
	omni_msg_header *header = (omni_msg_header *)msg;
	unsigned char *crc_ptr = (unsigned char*)msg + len - 2;
	int crc, err;

	/* Setup header */
	SET8(header->start, OMNI_START);
	SET8(header->type, type);
	SET8(header->len, len - 4);

	/* Calc CRC */
	crc = crc16((unsigned char*)msg + 1, len - 3);
	crc_ptr[0] = crc & 0xFF;
	crc_ptr[1] = (crc >> 8) & 0xFF;

#ifdef DEBUG_OMNI
	{
		int i;

		printf("Tx: ");
		for (i = 0; i < GET8(header->len) + 4; i++)
			printf("0x%02x ", ((unsigned char*)msg)[i]);
		printf("\n");
	}
#endif

	/* Send message */
	/* Send network message */
	if ((err = hai_net_send_msg(id, (hai_msg_type)OMNI_LINK_MESSAGE,
		msg, len)) != 0)
		return err;
	return 0;
}

/********************************************************************************/

static int omni_recv_msg(hai_comm_id *id, int *type, void *msg, int *len)
{
	int err, crc;
	omni_msg_header *header = (omni_msg_header *)msg;
	unsigned char *crc_ptr;

	/* Recv message */
	/* Recv network message */
	if ((err = hai_net_recv_msg(id, (hai_msg_type*)type, msg, len)) != 0)
	{

		int i;

		printf("Rx: ");
		for (i = 0; i < GET8(header->len) + 4; i++)
			printf("0x%02x ", ((unsigned char*)msg)[i]);
		printf("\n");
		return err;
	}

#ifdef DEBUG_OMNI
	{
		int i;

		printf("Rx: ");
		for (i = 0; i < GET8(header->len) + 4; i++)
			printf("0x%02x ", ((unsigned char*)msg)[i]);
		printf("\n");
	}
#endif

	/* Check header */
	if (GET8(header->start) != OMNI_START)
		return EOMNIRESPONSE;

	/* Return data */
	*type = GET8(header->type);
	*len = GET8(header->len);

	/* Check CRC */
	crc_ptr = (unsigned char*)msg + *len + 2;
	crc = crc16((unsigned char*)msg + 1, *len + 1);
	if ((crc_ptr[0] != (crc & 0xFF)) || (crc_ptr[1] != ((crc >> 8) & 0xFF)))
		return EOMNICRC;

	return 0;
}


static int crc16(const void *data, int len)
{
	unsigned char *buf = (unsigned char*)data;
	unsigned short crc = 0;

	while (len > 0)
	{
		int i;

		crc ^= *buf;
		for (i = 0; i < 8; i++)
		{
			int flag;

			flag = ((crc & 1) != 0);
			crc >>= 1;
			if (flag)
				crc ^= 0xA001;
		}
		len--;
		buf++;
	}

	return crc;
}

int omni_command(hai_comm_id *id, int cmd, int p1, int p2)
{
	omni_msg_unit_cmd req;
	omni_msg resp;
	int err, type, len;

	/* Send command */
	SET8(req.cmd, cmd);
	SET8(req.p1, p1);
	SET16(req.p2, p2);
	if ((err = omni_send_msg(id, OMNI_TYPE_COMMAND,
		&req, sizeof(req))) != 0)
		return err;

	/* Get acknowledgement */
	len = sizeof(resp);
	if ((err = omni_recv_msg(id, &type,
		&resp, &len)) != 0)
		return err;
	if (type != OMNI_TYPE_ACK)
		return EOMNIRESPONSE;

	return 0;
}
