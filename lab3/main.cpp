#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS 
#include <stdio.h>
#include <winsock2.h>
#include <Windows.h>
#include <pcap.h>
#include <cstdint>

#pragma comment(lib, "packet.lib")
#pragma comment(lib, "wpcap.lib")
#pragma comment(lib,"WS2_32.lib")

#define ETH_ARP      0x0806   // 以太网帧类型表示后面数据的类型，对于ARP请求或应答来说，该字段的值为x0806
#define ARP_HARDWARE 1        // 硬件类型字段值为表示以太网地址
#define ETH_IP       0x0800   // 协议类型字段表示要映射的协议地址类型值为x0800表示IP地址
#define ARP_REQUEST  1        // ARP请求
#define ARP_RESPONSE 2        // ARP应答

//14字节以太网首部
typedef struct EthernetHeader
{
	u_char DestMAC[6];    // 目的MAC地址6字节
	u_char SrcMAC[6];    // 源MAC地址 6字节
	u_short EthType;      // 上一层协议类型，如0x0800代表上一层是IP协议，0x0806为arp  2字节
}EthernetHeader;

//28字节ARP帧结构
typedef struct ArpHeader
{
	unsigned short HdType;    // 硬件类型
	unsigned short ProType;   // 协议类型
	unsigned char HdSize;     // 硬件地址长度
	unsigned char ProSize;    // 协议地址长度
	unsigned short OP;        // 操作类型，ARP请求(1)，ARP应答(2)，RARP请求(3)，RARP应答(4)。
	u_char SrcMac[6];           // 源MAC地址
	u_char SrcIp[4];            // 源IP地址
	u_char DestMac[6];           // 目的MAC地址
	u_char DestIp[4];            // 目的IP地址
}ArpHeader;

//定义整个arp报文包，总长度42字节
struct ArpPacket {
	EthernetHeader *ed;
	ArpHeader *ah;
};

pcap_t * OpenPcap(int nChoose, pcap_if_t **ptr);
void BuildArpRequest(EthernetHeader *eh, ArpHeader *ah, u_char *sendbuf, const u_char *src_ip, const u_char *dest_ip);
void BuildArpRequest(EthernetHeader *eh, ArpHeader *ah, u_char *sendbuf, const u_char *src_mac, const u_char *src_ip, const u_char *dest_ip);
void BuildArpResponse(EthernetHeader *eh, ArpHeader *ah, u_char *sendbuf, const u_char *src_mac, const u_char *src_ip, const u_char *dest_ip, const u_char *dest_mac);
void DisplayDevs();
void PrintEtherHeader(const u_char * packetData);//打印帧首部
void PrintArpHeader(const u_char * packetData);
void MonitorAdapter(int nChoose);
void MonitorAdapter(pcap_t *handle);
bool SendArpRequestSelf(pcap_t *handle, const u_char *src_ip, const u_char *dest_ip, u_char *SendIp, u_char *SendMac);
bool SendArpRequest(pcap_t *handle, const u_char *src_mac, const u_char *src_ip, const u_char *dest_ip);
bool CapArpPacket(pcap_t *handle, const u_char *src_ip, const u_char *dest_ip);
bool CapArpPacket(pcap_t *handle, const u_char *src_ip, const u_char *dest_ip, u_char *SendIp, u_char *SendMac);
bool SetFilter(pcap_if_t *ptr, pcap_t *handle);// 设置过滤器
void GetDevIp(u_char* RevIp, pcap_if_t* ptr);
void PrintDevInfo(pcap_if_t *ptr);
void PrintIp(u_char* Ip);
void PrintMac(u_char* Mac);
bool CompareIP(u_char* Ip1, u_char* Ip2);

int main(int argc, char *argv[])
{
	printf("ARP_Packet Experiment\n");
	DisplayDevs();

	int dev_id = 4;
	printf("Input the dev_id:");
	scanf("%d", &dev_id);
	pcap_if_t *ptr = nullptr;

	pcap_t *handle;            // 打开网络适配器

	EthernetHeader eh;         // 定义以太网包头
	ArpHeader ah;              // 定义ARP包头

	u_char sendbuf[42]; // arp包结构大小42个字节

	u_char SendIp[4] = { 0x00, 0x00, 0x00, 0x00 };
	u_char SendMac[6] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	u_char RevIp[4] = { 0x00, 0x00, 0x00, 0x00 };
	u_char RevMac[6] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

	u_char MyIp[4] = { 0x00, 0x00, 0x00, 0x00 };
	u_char MyMac[6] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

	handle = OpenPcap(dev_id, &ptr);      // 拿到第三个网卡的句柄
	GetDevIp(RevIp, ptr);
	if (SetFilter(ptr, handle) == false) {
		printf("Set Filter Fail!");
	};
	printf("___________before send,sendip and recip___________\n");
	PrintIp(SendIp);
	PrintIp(RevIp);
	printf("___________________________________________________\n");

	// 发送 ARP 请求，获取本机 MAC 地址
	printf("发送 ARP 请求，获取本机 MAC 地址! \n");
	SendArpRequestSelf(handle, SendIp, RevIp, MyIp, MyMac);  // 发送 ARP 请求到本机 IP 并 监听并提取本机 MAC 地址

	PrintIp(MyIp);
	PrintMac(MyMac);

	//向网络发送数据包
	printf("\n向网络发送一个数据包\n输入请求的IP地址:");
	char str[15] = "10.130.65.111";
	scanf("%s", str);
	// 将IP地址转换为u_char数组
	if (inet_pton(AF_INET, str, &RevIp) != 1) {
		printf("无效的 IP 地址");
		return 1;
	}


	printf("Input RevIp: ");
	PrintIp(RevIp);
	// 发送 ARP 请求，获取目标设备的 MAC 地址
	printf("发送 ARP 请求，获取目标设备的 MAC 地址! \n");
	SendArpRequest(handle, MyMac, MyIp, RevIp);  // 发送 ARP 请求到目标设备 IP

	system("pause");
	return 0;
}



pcap_t* OpenPcap(int nChoose, pcap_if_t** ptr) {
	pcap_t* pcap_handle;
	pcap_if_t* alldevs;
	char errbuf[PCAP_ERRBUF_SIZE];

	// 获取到所有设备列表
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
		exit(0);

	// 找到指定的网卡设备
	for (int x = 0; x < nChoose - 1; ++x)
		alldevs = alldevs->next;

	*ptr = alldevs; // 修改指针的值

	PrintDevInfo(*ptr);

	if ((pcap_handle = pcap_open((*ptr)->name,  // 设备名
		65536,         // 每个包长度
		PCAP_OPENFLAG_PROMISCUOUS,  // 混杂模式
		1000,          // 读取超时时间
		NULL,          // 远程机器验证
		errbuf         // 错误缓冲池
	)) == NULL) {
		pcap_freealldevs(alldevs);
		exit(0);
	}

	printf("成功打开该网卡\n");
	return pcap_handle;
}

void BuildArpRequest(EthernetHeader *eh, ArpHeader *ah, u_char *sendbuf, const u_char *src_ip, const u_char *dest_ip) {
	// 开始填充ARP包
	memset(eh->DestMAC, 0xff, 6);      // 以太网首部目的MAC地址,全为广播地址
	memset(eh->SrcMAC, 0x0f, 6);      // 以太网首部源MAC地址
	//memcpy(eh->SrcMAC, src_mac, 6);   // 以太网首部源MAC地址
	memset(ah->SrcMac, 0x00, 6);      // ARP字段源MAC地址
	memset(ah->DestMac, 0x00, 6);         // ARP字段目的MAC地址
	memcpy(ah->SrcIp, src_ip, 4);        // ARP字段源IP地址
	memcpy(ah->DestIp, dest_ip, 4);          // ARP字段目的IP地址

	// 赋值MAC地址
	eh->EthType = htons(ETH_ARP);   //htons：将主机的无符号短整形数转换成网络字节顺序
	ah->HdType = htons(ARP_HARDWARE);
	ah->ProType = htons(ETH_IP);
	ah->HdSize = 6;
	ah->ProSize = 4;
	ah->OP = htons(ARP_REQUEST);

	// 构造一个ARP请求
	memset(sendbuf, 0, sizeof(sendbuf));            // ARP清零
	memcpy(sendbuf, eh, sizeof(*eh));               // 首先把eh以太网结构填充上
	memcpy(sendbuf + sizeof(*eh), ah, sizeof(*ah));  // 接着在eh后面填充arp结构
}

void BuildArpRequest(EthernetHeader *eh, ArpHeader *ah, u_char *sendbuf, const u_char *src_mac, const u_char *src_ip, const u_char *dest_ip) {
	// 开始填充ARP包
	memset(eh->DestMAC, 0xff, 6);      // 以太网首部目的MAC地址,全为广播地址
	memcpy(eh->SrcMAC, src_mac, 6);      // 以太网首部源MAC地址
	memcpy(ah->SrcMac, src_mac, 6);      // ARP字段源MAC地址
	memset(ah->DestMac, 0xff, 6);         // ARP字段目的MAC地址
	memcpy(ah->SrcIp, src_ip, 4);        // ARP字段源IP地址
	memcpy(ah->DestIp, dest_ip, 4);          // ARP字段目的IP地址

	// 赋值MAC地址
	eh->EthType = htons(ETH_ARP);   //htons：将主机的无符号短整形数转换成网络字节顺序
	ah->HdType = htons(ARP_HARDWARE);
	ah->ProType = htons(ETH_IP);
	ah->HdSize = 6;
	ah->ProSize = 4;
	ah->OP = htons(ARP_REQUEST);

	// 构造一个ARP请求
	memset(sendbuf, 0, sizeof(sendbuf));            // ARP清零
	memcpy(sendbuf, eh, sizeof(*eh));               // 首先把eh以太网结构填充上
	memcpy(sendbuf + sizeof(*eh), ah, sizeof(*ah));  // 接着在eh后面填充arp结构
}

void BuildArpResponse(EthernetHeader *eh, ArpHeader *ah, u_char *sendbuf, const u_char *src_mac, const u_char *src_ip, const u_char *dest_ip, const u_char *dest_mac) {
	// 开始填充ARP包
	memcpy(eh->DestMAC, dest_mac, 6);      // 以太网首部目的MAC地址,全为广播地址
	memcpy(eh->SrcMAC, src_mac, 6);   // 以太网首部源MAC地址
	memcpy(ah->SrcMac, src_mac, 6);      // ARP字段源MAC地址
	memcpy(ah->DestMac, dest_mac, 6);         // ARP字段目的MAC地址
	memcpy(ah->SrcIp, src_ip, 4);        // ARP字段源IP地址
	memcpy(ah->DestIp, dest_ip, 4);          // ARP字段目的IP地址

	// 赋值MAC地址
	eh->EthType = htons(ETH_ARP);   //htons：将主机的无符号短整形数转换成网络字节顺序
	ah->HdType = htons(ARP_HARDWARE);
	ah->ProType = htons(ETH_IP);
	ah->HdSize = 6;
	ah->ProSize = 4;
	ah->OP = htons(ARP_RESPONSE);

	// 构造一个ARP请求
	memset(sendbuf, 0, sizeof(sendbuf));            // ARP清零
	memcpy(sendbuf, eh, sizeof(*eh));               // 首先把eh以太网结构填充上
	memcpy(sendbuf + sizeof(*eh), ah, sizeof(*ah));  // 接着在eh后面填充arp结构
}

void GetDevIp(u_char* RevIp, pcap_if_t* ptr) {
	pcap_addr_t* a;

	// 将所选择的网卡的IP设置为请求的IP地址
	/*
	for (a = ptr->addresses; a != NULL; a = a->next) {
		if (a->addr->sa_family == AF_INET) {
			// 使用strcpy将IP地址的字符串表示形式复制到RevIp指向的位置
			strcpy(RevIp, inet_ntoa(((struct sockaddr_in*)(a->addr))->sin_addr));
		}
	}
	*/
	int i = 0;
	// 将所选择的网卡的IP设置为请求的IP地址
	for (a = ptr->addresses; a != NULL; a = a->next) {
		if (a->addr->sa_family == AF_INET) {
			// 获取IP地址的结构体
			struct sockaddr_in* sa = (struct sockaddr_in*)(a->addr);
			// 获取IP地址的32位整数表示形式
			uint32_t ipAddress = sa->sin_addr.s_addr;

			// 将32位整数表示形式的IP地址转换为4个 u_char 数组
			for (int j = 0; j < 4; ++j) {
				RevIp[i++] = (ipAddress >> (j * 8)) & 0xFF;
			}
		}
	}
	printf("Get Dev Ip:");
	PrintIp(RevIp);
}

void DisplayDevs() {

	pcap_if_t *alldevs;//设备链表
	pcap_if_t *d;//用于遍历
	char errbuf[PCAP_ERRBUF_SIZE];

	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1) {
		fprintf(stderr, "Error in pcap_findalldevs_ex: %s\n", errbuf);
		return;
	}

	int i = 0, inum;

	// 显示所有检测到的设备
	pcap_addr_t* a;
	for (d = alldevs; d != NULL; d = d->next) {
		printf("\n");
		printf("网卡%d\n", ++i);
		PrintDevInfo(d);
	}
	if (i == 0) {
		printf("No interfaces found! Make sure Npcap is installed.\n");
		return;
	}
	pcap_freealldevs(alldevs);
}

void PrintIp(u_char* Ip) {
	for (int i = 0; i < 4; ++i) {
		printf("%u", Ip[i]);
		if (i < 3) {
			printf(".");
		}
	}
	printf("\n");
}

void PrintMac(u_char* Mac) {
	for (int i = 0; i < 6; ++i) {
		printf("%02X", Mac[i]);
		if (i < 5) {
			printf(":");
		}
	}
	printf("\n");
}


bool CompareIP(const u_char* ip1, const u_char* ip2) {
	for (int i = 0; i < 4; ++i) {
		if (ip1[i] != ip2[i]) {
			return false; // 如果有任何一个字节不相等，则返回false
		}
	}
	return true; // 所有字节相等
}



void PrintEtherHeader(const u_char * packetData)//传入数据包
{
	struct EthernetHeader * eth_protocol;
	eth_protocol = (struct EthernetHeader *)packetData;

	u_short ether_type = ntohs(eth_protocol->EthType);  // 以太网类型//转换字节序
	u_char *ether_src = eth_protocol->SrcMAC;         // 以太网原始MAC地址//源地址
	u_char *ether_dst = eth_protocol->DestMAC;         // 以太网目标MAC地址//目标地址

	printf("类型: 0x%x \t", ether_type);
	//printf("原mac地址：%s6", ether_src);
	printf("原MAC地址: %02X:%02X:%02X:%02X:%02X:%02X \t",
		ether_src[0], ether_src[1], ether_src[2], ether_src[3], ether_src[4], ether_src[5]);//按照mac格式打印
	printf("目标MAC地址: %02X:%02X:%02X:%02X:%02X:%02X \n",
		ether_dst[0], ether_dst[1], ether_dst[2], ether_dst[3], ether_dst[4], ether_dst[5]);
}

void PrintArpHeader(const u_char * packetData) {
	struct EthernetHeader *eth_protocol;
	eth_protocol = (struct EthernetHeader *)packetData;

	if (ntohs(eth_protocol->EthType) == 0x0806) {  // 检查是否是 ARP 协议
		struct ArpHeader *arp_protocol;
		arp_protocol = (struct ArpHeader *)(packetData + sizeof(struct EthernetHeader));

		printf("ARP 操作类型: %s\n", ntohs(arp_protocol->OP) == 1 ? "ARP 请求" : "ARP 应答");
		printf("硬件类型: %u\n", ntohs(arp_protocol->HdType));
		printf("协议类型: 0x%x\n", ntohs(arp_protocol->ProType));
		printf("硬件地址长度: %u\n", arp_protocol->HdSize);
		printf("协议地址长度: %u\n", arp_protocol->ProSize);

		printf("源MAC地址: %02X:%02X:%02X:%02X:%02X:%02X\n",
			arp_protocol->SrcMac[0], arp_protocol->SrcMac[1], arp_protocol->SrcMac[2],
			arp_protocol->SrcMac[3], arp_protocol->SrcMac[4], arp_protocol->SrcMac[5]);

		printf("源IP地址: %u.%u.%u.%u\n",
			arp_protocol->SrcIp[0], arp_protocol->SrcIp[1], arp_protocol->SrcIp[2], arp_protocol->SrcIp[3]);

		printf("目的MAC地址: %02X:%02X:%02X:%02X:%02X:%02X\n",
			arp_protocol->DestMac[0], arp_protocol->DestMac[1], arp_protocol->DestMac[2],
			arp_protocol->DestMac[3], arp_protocol->DestMac[4], arp_protocol->DestMac[5]);

		printf("目的IP地址: %u.%u.%u.%u\n",
			arp_protocol->DestIp[0], arp_protocol->DestIp[1], arp_protocol->DestIp[2], arp_protocol->DestIp[3]);
	}
	else {
		printf("不是 ARP 协议\n");
	}
}


void MonitorAdapter(int nChoose)
{
	pcap_if_t *adapters;
	char errbuf[PCAP_ERRBUF_SIZE];
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &adapters, errbuf) != -1)
	{
		// 遍历，找到指定的网卡
		for (int x = 0; x < nChoose - 1; ++x)
			adapters = adapters->next;

		char errorBuf[PCAP_ERRBUF_SIZE];

		// PCAP_OPENFLAG_PROMISCUOUS = 网卡设置为混杂模式
		// 1000 => 1000毫秒如果读不到数据直接返回超时
		pcap_t * handle = pcap_open(adapters->name, 65534, 1, PCAP_OPENFLAG_PROMISCUOUS, 0, 0);

		if (adapters == NULL)
			return;

		printf("开始侦听: %s \n", adapters->description);
		pcap_pkthdr *Packet_Header;    // 数据包头//捕获该数据包的时间戳、数据包的长度等等
		const u_char * Packet_Data;    // 数据包
		int retValue;
		while ((retValue = pcap_next_ex(handle, &Packet_Header, &Packet_Data)) >= 0)//大于0才是真正捕获到
		{
			if (retValue == 0)
				continue;
			printf("侦听长度: %d \n", Packet_Header->len);
			PrintEtherHeader(Packet_Data);
			PrintArpHeader(Packet_Data);
		}
	}
}

void MonitorAdapter(pcap_t *handle)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	if (handle == NULL)
		return;
	pcap_pkthdr *Packet_Header;    // 数据包头//捕获该数据包的时间戳、数据包的长度等等
	const u_char * Packet_Data;    // 数据包
	int retValue;
	while ((retValue = pcap_next_ex(handle, &Packet_Header, &Packet_Data)) >= 0)//大于0才是真正捕获到
	{
		if (retValue == 0)
			continue;
		printf("侦听长度: %d \n", Packet_Header->len);
		PrintEtherHeader(Packet_Data);
		PrintArpHeader(Packet_Data);
	}
}

bool SendArpRequestSelf(pcap_t *handle, const u_char *src_ip, const u_char *dest_ip, u_char *SendIp, u_char *SendMac) {
	EthernetHeader eh;
	ArpHeader ah;
	unsigned char sendbuf[42];
	pcap_pkthdr *Packet_Header;
	const u_char *Packet_Data;
	char errbuf[PCAP_ERRBUF_SIZE];//错误信息缓冲区

	BuildArpRequest(&eh, &ah, sendbuf, src_ip, dest_ip);
	// 发送 ARP 请求包
	if (pcap_sendpacket(handle, sendbuf, 42) == 0) {
		printf("发送ARP请求成功!\n");
	}

	printf("捕获 ARP 响应!\n");
	return CapArpPacket(handle, src_ip, dest_ip, SendIp, SendMac);

	return false;
}

bool SendArpRequest(pcap_t *handle, const u_char *src_mac, const u_char *src_ip, const u_char *dest_ip) {
	EthernetHeader eh;
	ArpHeader ah;
	unsigned char sendbuf[42];

	BuildArpRequest(&eh, &ah, sendbuf, src_mac, src_ip, dest_ip);
	// 发送 ARP 请求包
	if (pcap_sendpacket(handle, sendbuf, 42) == 0) {
		printf("发送ARP请求成功!\n");
		return CapArpPacket(handle, src_ip, dest_ip);
	}
	return false;
}
bool CapArpPacket(pcap_t *handle, const u_char *src_ip, const u_char *dest_ip, u_char *SendIp, u_char *SendMac) {
	printf("捕获 ARP 响应!\n");
	pcap_pkthdr *Packet_Header;
	const u_char *Packet_Data;
	char errbuf[PCAP_ERRBUF_SIZE];//错误信息缓冲区

	while (true) {
		int n = pcap_next_ex(handle, &Packet_Header, &Packet_Data);
		if (n == -1)
		{
			printf("捕获数据包时发生错误：%d\n", errbuf);
			return false;
		}
		else
		{
			if (n == 0)
			{
				printf("没有捕获到数据报\n");
			}

			else
			{
				printf("捕获到数据报\n");
				ArpPacket *IPPacket = (ArpPacket*)Packet_Data;
				PrintArpHeader(Packet_Data);
				struct ArpHeader *arp_protocol;
				arp_protocol = (struct ArpHeader *)(Packet_Data + sizeof(struct EthernetHeader));
				if (CompareIP(arp_protocol->DestIp, src_ip) && CompareIP(arp_protocol->SrcIp, dest_ip))
				{
					printf("捕获到回复的数据报，请求 IP 与其 MAC 地址对应关系：\n");
					printf("---------------------\n");
					printf("IP:");
					PrintIp(arp_protocol->SrcIp);
					printf("MAC:");
					PrintMac(arp_protocol->SrcMac);
					printf("---------------------\n");
					printf("\n");

					u_char* a;
					int i = 0;
					if (SendIp != NULL) {
						// 复制 arp_protocol->SrcIp 到 SendIp
						for (int j = 0; j < 4; ++j) {
							SendIp[i++] = arp_protocol->SrcIp[j];
						}

						// 复制 arp_protocol->SrcMac 到 SendMac
						for (int j = 0; j < 6; ++j) {
							SendMac[j] = arp_protocol->SrcMac[j];
						}
					}
					break;
				}
			}
		}
	}
	return true;
}

bool CapArpPacket(pcap_t *handle, const u_char *src_ip, const u_char *dest_ip) {
	printf("捕获 ARP 响应!\n");
	pcap_pkthdr *Packet_Header;
	const u_char *Packet_Data;
	char errbuf[PCAP_ERRBUF_SIZE];//错误信息缓冲区

	while (true)
	{
		int n = pcap_next_ex(handle, &Packet_Header, &Packet_Data);
		if (n == -1)
		{
			printf("捕获数据包时发生错误：%d\n", errbuf);
			return false;
		}
		else
		{
			if (n == 0)
			{
				printf("没有捕获到数据报\n");
			}

			else
			{
				printf("捕获到数据报\n");
				ArpPacket *IPPacket = (ArpPacket*)Packet_Data;
				PrintArpHeader(Packet_Data);
				printf("\n");
				struct ArpHeader *arp_protocol;
				arp_protocol = (struct ArpHeader *)(Packet_Data + sizeof(struct EthernetHeader));
				if (CompareIP(arp_protocol->DestIp, src_ip) && CompareIP(arp_protocol->SrcIp, dest_ip))
				{
					// 判断是不是一开始发的包
					printf("捕获到回复的数据报，请求 IP 与其 MAC 地址对应关系：\n");
					printf("---------------------\n");
					printf("IP:");
					PrintIp(arp_protocol->SrcIp);
					printf("MAC:");
					PrintMac(arp_protocol->SrcMac);
					printf("---------------------\n");
					printf("\n");
					break;
				}
			}
		}
	}
	return true;
}

bool SetFilter(pcap_if_t *ptr, pcap_t *handle) {
	// 编译过滤器，只捕获 ARP 包
	PrintDevInfo(ptr);
	u_int netmask;
	if (ptr->addresses == NULL) {
		printf("无法获取地址信息\n");
		return false;
	}
	// 继续访问地址信息
	netmask = ((sockaddr_in*)(ptr->addresses->netmask))->sin_addr.S_un.S_addr;
	bpf_program fcode;
	char packet_filter[] = "ether proto \\arp";
	if (pcap_compile(handle, &fcode, packet_filter, 1, netmask) < 0)
	{
		printf("无法编译数据包过滤器。检查语法\n");
		return false;
	}

	// 设置过滤器
	if (pcap_setfilter(handle, &fcode) < 0)
	{
		printf("过滤器设置错误\n");
		return false;
	}
	printf("过滤器设置成功\n");
	return true;
}

void PrintDevInfo(pcap_if_t *ptr) {
	printf("Device: %s\n", ptr->name);
	printf("Description: %s\n", ptr->description ? ptr->description : "N/A");
	pcap_addr_t* a;
	for (a = ptr->addresses; a != NULL; a = a->next)
	{
		if (a->addr->sa_family == AF_INET)
		{
			printf("  IP地址：%s\n", inet_ntoa(((struct sockaddr_in*)(a->addr))->sin_addr));
			printf("  子网掩码：%s\n", inet_ntoa(((struct sockaddr_in*)(a->netmask))->sin_addr));
			printf("  广播地址：%s\n", inet_ntoa(((struct sockaddr_in*)(a->broadaddr))->sin_addr));
			printf("\n");
		}
	}
	// 可以继续打印其他信息
	printf("\n");

};

/*
int pcap_findalldevs_ex(
	char * source;      //指定从哪儿获取网络接口列表
	struct pcap_rmauth auth;    //用于验证，由于是本机，置为NULL
	pcap_if_t ** alldevs;       //当该函数成功返回时，alldevs指向获取的列表数组的第一个
								//列表中每一个元素都是一个pcap_if_t结构
	char * errbuf               //错误信息缓冲区
);

struct pcap_if{
	struct pcap_if *next;               //指向链表中下一个元素
	char *name;                         //代表WinPcap为该网络接口卡分配的名字
	char *description;                  //代表WinPcap对该网络接口卡的描述
	struct pcap_addr* addresses;        //addresses指向的链表中包含了这块网卡的所有IP地址
	u_int flags;                        //标识这块网卡是不是回送网卡
}

pcap_t * pcap_open(
	const char *source;             //要打开的网卡的名字
	int snaplen,
	int flags,                      //指定以何种方式打开网卡，常用的有混杂模式
	int read_timeout,               //数据包捕获函数等待一个数据包的最大时间，超时则返回0
	struct pcap_rmauth *auth,
	char *errbuf
)

int pcap_next_ex(
	pcap_t *p;//当为调用pcap_open()成功之后返回的值，它指定了捕获哪块网卡上的数据包
	struct pcap_pkthdr ** pkt_header,//捕获该数据包的时间戳、数据包的长度等等信息
	u_char ** pkt_data//捕获到的网络数据包
)

int pcap_compile(pcap_t *p, struct bpf_program *fp, const char *str, int optimize, bpf_u_int32 netmask);
p：指向打开的pcap文件或设备的指针。
fp：指向表示过滤程序的bpf_program结构体的指针。
str：指向过滤表达式字符串的指针。
optimize：用于指定是否优化过滤表达式的执行。设为1时表示启用优化。
netmask：用于指定网络掩码。

int pcap_setfilter(pcap_t *p, struct bpf_program *fp);
p：指向打开的pcap文件或设备的指针。
fp：指向表示过滤程序的bpf_program结构体的指针。

int pcap_loop(pcap_t *p, int cnt, pcap_handler callback, u_char *user);
p：指向打开的pcap文件或设备的指针。
cnt：用于指定捕获的数据包的数量，-1表示捕获数据包的数量没有限制。
callback：指向用户自定义的回调函数的指针，用于处理每一个捕获到的数据包。
user：传递给回调函数的用户指针。

*/