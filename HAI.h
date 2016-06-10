#define HAI_PORT 4369
#define HAI_IP_ADDRESS "XXX.XXX.XXX.XXX"
unsigned char private_key[16] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };

int err;

typedef enum {
	/** Message type to request a new session */
	CLIENT_REQUEST_NEW_SESSION = 1,
	/** Message type to acknowledge a new session */
	CONTROLLER_ACKNOWLEDGE_NEW_SESSION = 2,
	/** Message type to request a secure connection */
	CLIENT_REQUEST_SECURE_CONNECTION = 3,
	/** Message type to acknowledge a secure connection */
	CONTROLLER_ACKNOWLEDGE_SECURE_CONNECTION = 4,
	/** Message type to terminate a session */
	CLIENT_SESSION_TERMINATED = 5,
	/** Message type to indicate the controller terminated the session */
	CONTROLLER_SESSION_TERMINATED = 6,
	/** Message type to indicate an error creating a new session */
	CONTROLLER_CANNOT_START_NEW_SESSION = 7,
#ifdef USE_TCP
	/** Message type to indicate an Omni-Link II message */
	OMNI_LINK_MESSAGE = 32
#else
	/** Message type to indicate an Omni-Link message */
	OMNI_LINK_MESSAGE = 16,
#endif
} hai_msg_type;


typedef struct
{
	/** Open socket or serial device handle */
	int s;
	/** Structure containing network address of Omni */
	struct sockaddr_in omni;
	/** Next transmit sequence number */
	int tx_sequence;
	/** Next expected receive sequence number */
	int rx_sequence;
	/** Session ID */
	unsigned char session_id[5];
	/** Private key */
	unsigned char private_key[16];
	/** Flag to indicate serial mode */
	int serial_mode;
} hai_comm_id;


typedef struct
{
	unsigned char start;
	unsigned char len;
	unsigned char type;
} omni_msg_header;

typedef struct
{
	omni_msg_header header;
	unsigned char crc[2];
} omni_msg;


typedef struct
{
	omni_msg_header header;
	unsigned char code[4];
	unsigned char crc;
} omni_msg_login;

typedef struct
{
	/** Omni model number.  */
	unsigned char model;
	/** Firmware version major number. */
	unsigned char major;
	/** Firmware version minor number. */
	unsigned char minor;
	/** Firmware version rev number. */
	unsigned char rev;
	/** Local phone number. */
	unsigned char phone[25];
} sys_info;


typedef struct
{
	omni_msg_header header;
	sys_info data;
	unsigned char crc[2];
} omni_msg_sys_info;


#define OMNILT                  9       /**< HAI OmniLT */
#define OMNI                    2       /**< HAI Omni */
#define OMNI2                   15      /**< HAI Omni II */
#define OMNI2E                  30      /**< HAI Omni IIe */
#define OMNIPRO                 4       /**< HAI OmniPro */
#define OMNIPRO2                16      /**< HAI OmniPro II */
#define LUMINA                  36      /**< HAI Lumina */
#define LUMINAPRO               37      /**< HAI Lumina Pro */

#define OMNI_TYPE_ACK                   0x01
#define OMNI_TYPE_LOGIN                 0x20

#ifndef __ELASTERROR
#define __ELASTERROR    2000
#endif

#define HAI_NET_TIMEOUT         3

#define CMD_OFF                 0       /**< Turn off unit */
#define CMD_ON                  1       /**< Turn unit on */


/** Error code for invalid argument */
#define EHAIARGUMENT    __ELASTERROR + 1
/** Error code for unexpected response */
#define EHAIRESPONSE    __ELASTERROR + 2
/** Error code for invalid session ID */
#define EHAISESSION     __ELASTERROR + 3
/** Error code for netowrk time-out */
#define EHAITIMEOUT     __ELASTERROR + 4
/** Define for max HAI comm error code */
#define __ELASTHAI      __ELASTERROR + 10


/** Message type to request a new session */
#define CLIENT_REQUEST_NEW_SESSION  1
/** Message type to acknowledge a new session */
#define CONTROLLER_ACKNOWLEDGE_NEW_SESSION  2
/** Message type to request a secure connection */
#define CLIENT_REQUEST_SECURE_CONNECTION   3
/** Message type to acknowledge a secure connection */
#define CONTROLLER_ACKNOWLEDGE_SECURE_CONNECTION  4
/** Message type to terminate a session */
#define  CLIENT_SESSION_TERMINATED  5
/** Message type to indicate the controller terminated the session */
#define  CONTROLLER_SESSION_TERMINATED   6
/** Message type to indicate an error creating a new session */
#define CONTROLLER_CANNOT_START_NEW_SESSION   7
// #ifdef USE_TCP
/** Message type to indicate an Omni-Link II message */
#define  OMNI_LINK_MESSAGE  32

/** Macro to read a \a val8. */
#define GET8(a)         (a)
/** Macro to write a \a val8. */
#define SET8(a,b)       (a) = ((b) & 0xFF)
/** Macro to read a \a val16. */
#define GET16(a)        (((a)[0] << 8) | (a)[1])
/** Macro to write a \a val16. */
#define SET16(a,b)      {(a)[0] = ((b) >> 8) & 0xFF; \
	(a)[1] = (b)& 0xFF; }
/** Macro to read a \a val24. */
#define GET24(a)        (((a)[0] << 16) | ((a)[1] << 8) | (a)[2])
/** Macro to write a \a val24. */
#define SET24(a,b)      {(a)[0] = ((b) >> 16) & 0xFF; \
	(a)[1] = ((b) >> 8) & 0xFF; \
	(a)[2] = (b)& 0xFF; }
/** Macro to read a \a val32. */
#define GET32(a)        (((a)[0] << 24) | ((a)[1] << 16) \
	| ((a)[2] << 8) | (a)[3])
/** Macro to write a \a val32. */
#define SET32(a,b)      {(a)[0] = ((b) >> 24) & 0xFF; \
	(a)[1] = ((b) >> 16) & 0xFF; \
	(a)[2] = ((b) >> 8) & 0xFF; \
	(a)[3] = (b)& 0xFF;

/** Error code for invalid Omni argument */
#define EOMNIARGUMENT           __ELASTHAI + 1
/** Error code for unexpected Omni response */
#define EOMNIRESPONSE           __ELASTHAI + 2
/** Error code for bad CRC */
#define EOMNICRC                __ELASTHAI + 3
/** Error code for end of data */
#define EOMNIEOD                __ELASTHAI + 4
/** Define for max Omni protocol error code */
#define __ELASTOMNI             __ELASTHAI + 10

#define OMNI_START                      0x21
//0x5A

#define OMNI_TYPE_REQ_SYS_INFO          0x16
//#define OMNI_TYPE_SYS_INFO              0x12
#define OMNI_TYPE_SYS_INFO               0x17
#define OMNI_TYPE_COMMAND               0x14


typedef struct
{
	unsigned char sequence[2];
	unsigned char type;
	unsigned char resv0;
} hai_msg_header;

typedef struct
{
	/* val16 protocol_ver; */
	unsigned char protocol_ver1;
	unsigned char protocol_ver2;
	unsigned char session_id[5];
} hai_ack_new_session;


typedef struct
{
	omni_msg_header header;
	unsigned char cmd;
	unsigned char p1;
	unsigned char p2[2];
	unsigned char crc[2];
} omni_msg_unit_cmd;
