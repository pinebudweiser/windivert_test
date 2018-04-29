#include <stdio.h>
#include <WinSock2.h>
#include <windows.h>
#include <stdint.h>
#include "windivert.h"

#define MAX_PACKET_SIZE 0xFFFF
#define PROTOCOL_TCP	0x6
#define VERSION_IPV4	0x4
#define HTTP_PORT		80

#pragma comment (lib,"Ws2_32.lib")

typedef struct
{
	WINDIVERT_IPHDR ip;
	WINDIVERT_TCPHDR tcp;
}TCP_PACKET;

void dump_16(uint8_t* packet, uint32_t len)
{
	uint32_t i = 0;
	for (i = 0; i < len; i++)
	{
		if (!(i % 16))
		{
			printf("\n");
		}
		printf("%02X ", packet[i]);
	}
}

int main()
{
	HANDLE windvtHandle;
	uint8_t packet[MAX_PACKET_SIZE];
	uint32_t packetLen;
	WINDIVERT_ADDRESS recvAddr;
	TCP_PACKET* recvTcpPacket;
	BOOL blockHTTP = FALSE;

	windvtHandle = WinDivertOpen("true", WINDIVERT_LAYER_NETWORK, 0, 0);
	if (windvtHandle == INVALID_HANDLE_VALUE)
	{
		DWORD errorCode;

		errorCode = GetLastError();
		printf(" [Err] %d code search in https://reqrypt.org/windivert-doc.html\n", errorCode);
		
		return FALSE;
	}
	while (TRUE)
	{
		if (!WinDivertRecv(windvtHandle, packet, MAX_PACKET_SIZE, &recvAddr, &packetLen))
		{
			printf(" [Err] WinDivertRect failed.. error_code: %d\n", GetLastError());
			continue;
		}

		recvTcpPacket = (TCP_PACKET*)(packet);

		if (recvTcpPacket->ip.Version == VERSION_IPV4 &&
			recvTcpPacket->ip.Protocol == PROTOCOL_TCP)
		{
			if (ntohs(recvTcpPacket->tcp.DstPort) == (UINT16)HTTP_PORT ||
				ntohs(recvTcpPacket->tcp.SrcPort) == (UINT16)HTTP_PORT)
			{
				dump_16(packet, packetLen);
				printf(" [BLOCK] HTTP\n");
				blockHTTP = TRUE;
			}
		}
		if (blockHTTP == FALSE)
		{
			if (!WinDivertSend(windvtHandle, packet, packetLen, &recvAddr, NULL))
			{
				printf(" [Err] WinDivertSend failed.. error_code: %d\n", GetLastError());
			}
		}
		blockHTTP = FALSE;
	}
	WinDivertClose(windvtHandle);

	return TRUE;
}