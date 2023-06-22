#include<stdio.h>
#include<stdlib.h>
#include<stdbool.h>
#include<string.h>
#include<locale.h>
#include<pcap.h>
#include<net/ethernet.h>
#include<netinet/ip.h>
#include<netinet/ip_icmp.h>
#include<netinet/tcp.h>
#include<netinet/udp.h>
#include<linux/if_ether.h>
#include<netinet/in.h>
#include<netinet/ether.h>
#include<time.h>
#include<pthread.h>

#include "dnshdr.h"

void init(void);
void atexitHandler(void);
bool interface(void);
int inputNumbers(int lowerLimit, int upperLimit);
void createFileStream(char data[]);

void configuringNetworkInterfaces(void);

int protocolSelection(void);
int dnsSelection(void);
int httpSelection(void);
int fileWriteSelection(void);


void createInterceptionStream(char filter[]);
_Noreturn void* interceptionThread(void* arg);
void interceptionProcess(char* filter);

char* printTime(const struct pcap_pkthdr *header, char timeBuffer[]);

void outputData(const char* data);

void interceptedEthernetPacketsHandler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void interceptedIpPacketsHandler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void interceptedTCPPacketsHandler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void interceptedUDPPacketsHandler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void interceptedARPPacketsHandler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void interceptedICMPPacketsHandler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

void dnsProtocolSelectionForHandler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void interceptedDNSPacketsFromUDPProtocolHandler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void interceptedDNSPacketsFromTCPProtocolHandler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void interceptedDNSPacketsHandler(char* dnsPayload, struct dnshdr* dnsHeader, char* result);

bool isHTTP(const u_char* payload);
void printHTTP(const u_char *payload, int payloadSize, char* result);
void interceptedHTTPPackets80PortHandler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

pcap_if_t* networkInterfaces;

pcap_t *handle;
char* devName;

char ipFilter[] = "ip";
char tcpFilter[] = "tcp";
char ethernetIPv4Filter[] = "ether proto 0x0800";
char ethernetIPv6Filter[] = "ether proto 0x86DD";
char udpFilter[] = "udp";
char arpFilter[] = "arp";
char icmpFilter[] = "icmp";

char dnsUdpPort53Filter[] = "udp port 53";
char dnsTcpPort53filter[] = "tcp port 53";
char dnsFilter[] = "dns";

char httpFilter[] = "tcp port http";
char httpTcpPort80Filter[] = "tcp port 80";
char httpTcpPort8080Filter[] = "tcp port 8080";

FILE* file;
bool fileWriteChoice;
int counter = 0;

int main()
{
    init();

    setlocale(LC_ALL, "RU");

    file = stdout;

    while(true)
    {
        system("clear");
        printf("E - interception Ethernet-packets\n"
                      "P - interception IP-packets\n"
                      "T - interception TCP-packets\n"
                      "U - interception UDP-packets\n"
                      "A - interception ARP-packets\n"
                      "I - interception ICMP-packets\n"
                      "D - interception DNS-packets\n"
                      "H - interception HTTP-packets\n"
                      "C - configuring network interfaces\n"
                      "F - file write setup\n"
                      "q - exit\n");
        switch(getchar())
        {
            case 'E':
            {
                if(protocolSelection() == 1)
                {
                    if (fileWriteChoice == true)
                        createFileStream("EthernetIPv4Packets.txt");
                    createInterceptionStream(ethernetIPv4Filter);
                }
                else
                {
                    if(fileWriteChoice == true)
                        createFileStream("EthernetIPv6Packets.txt");
                    createInterceptionStream(ethernetIPv6Filter);
                }
                break;
            }
            case 'P':
            {
                if(fileWriteChoice == true)
                    createFileStream("IPPackets.txt");
                createInterceptionStream(ipFilter);
                break;
            }
            case 'T':
            {
                if(fileWriteChoice == true)
                    createFileStream("TCPPackets.txt");
                createInterceptionStream(tcpFilter);
                break;
            }
            case 'U':
            {
                if(fileWriteChoice == true)
                    createFileStream("UDPPackets.txt");
                createInterceptionStream(udpFilter);
                break;
            }
            case 'A':
            {
                if(fileWriteChoice == true)
                    createFileStream("ARPPackets.txt");
                createInterceptionStream(arpFilter);
                break;
            }
            case 'I':
            {
                if(fileWriteChoice == true)
                    createFileStream("ICMPPackets.txt");
                createInterceptionStream(icmpFilter);
                break;
            }
            case 'D':
            {
                if(fileWriteChoice == true)
                    createFileStream("DNSPackets.txt");

                int choice = dnsSelection();
                if(choice == 1)
                    createInterceptionStream(dnsUdpPort53Filter);
                else if(choice == 2)
                    createInterceptionStream(dnsTcpPort53filter);
                else
                    createInterceptionStream(dnsFilter);
                break;
            }
            case 'H':
            {
                if(fileWriteChoice == true)
                    createFileStream("HTTPPackets.txt");

                int choice = httpSelection();
                if (choice == 1)
                    createInterceptionStream(httpFilter);
                else if (choice == 2)
                    createInterceptionStream(httpTcpPort80Filter);
                else if (choice == 3)
                    createInterceptionStream(httpTcpPort8080Filter);
                break;
            }
            case 'C':
            {
                configuringNetworkInterfaces();
                break;
            }
            case 'F':
            {
                if(fileWriteSelection() == 1)
                    fileWriteChoice = true;
                else
                {
                    fileWriteChoice = false;
                    file = stdout;
                }
                break;
            }
            case 'q':
                return EXIT_SUCCESS;
        }
    }

}

void init(void)
{
    char errbuf[PCAP_ERRBUF_SIZE];

    if(atexit(atexitHandler))
    {
        perror("atexit");
        return;
    }

    if (pcap_findalldevs(&networkInterfaces, errbuf) == -1)
    {
        fprintf(stderr, "Error finding devices: %s\n", errbuf);
        return;
    }
}

void atexitHandler(void)
{
    pcap_freealldevs(networkInterfaces);
}

bool interface(void)
{
    while(true)
    {
        if(getchar() == 'q')
        {
            system("clear");
            return true;
        }
    }
}

int inputNumbers(int lowerLimit, int upperLimit)
{
    char buffer[50];
    int value;
    char* endptr;

    while(true)
    {
        if (fgets(buffer, sizeof(buffer), stdin) == NULL)
        {
            printf("Error of input!\n");
        }

        buffer[strcspn(buffer, "\n")] = '\0';

        value = strtol(buffer, &endptr, 10);
        if (endptr == buffer || *endptr != '\0')
        {
            continue;
        }
        else if(value < lowerLimit || value > upperLimit)
            printf("There is no such number\n");
        else
            return value;
    }
}

void createFileStream(char data[])
{
    FILE* stream = fopen(data, "a");
    file = stream;

}

void configuringNetworkInterfaces(void)
{
    system("clear");

    int countOfNetworkInterfaces = 0;

    for (pcap_if_t *i = networkInterfaces; i != NULL; i = i->next)
    {
        printf("%s\n", i->name);
        countOfNetworkInterfaces++;
    }

    printf("Select interface(1 - %d): ", countOfNetworkInterfaces);

    int value = inputNumbers(1, countOfNetworkInterfaces);
    int temp = 0;

    for(pcap_if_t *i = networkInterfaces; i != NULL; i = i->next)
    {
        if(temp == value - 1)
        {
            devName = i->name;
            break;
        }
        temp++;
    }

}

int protocolSelection(void)
{
    system("clear");
    printf("1 - IPv4 protocol\n"
                  "2 - IPv6 protocol\n");
    return inputNumbers(1, 2);
}

int dnsSelection(void)
{
    system("clear");
    printf("1 - UDP protocol\n"
                  "2 - TCP protocol\n"
                  "3 - Any\n");
    return inputNumbers(1,3);
}

int httpSelection(void)
{
    system("clear");
    printf("1 - All packets\n"
                  "2 - Packets from 80 port\n"
                  "3 - Local packets\n");
    return inputNumbers(1, 3);
}

int fileWriteSelection(void)
{
    system("clear");
    printf("1 - write to file\n"
                  "2 - don't write to file\n");
    return inputNumbers(1, 2);
}

void createInterceptionStream(char filter[])
{
    pthread_t interceptionStream;
    int res = pthread_create(&interceptionStream, NULL, interceptionThread, filter);
    if(res)
    {
        fprintf(stderr, "Failed to create stream");
        return;
    }

    if(interface())
    {
        pcap_breakloop(handle);
        pcap_close(handle);
    }

    if(fileWriteChoice == true)
    {
        fclose(file);
    }

    counter = 0;
}

_Noreturn void* interceptionThread(void* arg)
{
    char* filter = (char*) arg;
    interceptionProcess(filter);
}

void interceptionProcess(char* filter)
{
    system("clear");

    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    bpf_u_int32 net;
    bpf_u_int32 mask;
    pcap_if_t *dev;

    if(devName == NULL || *devName == '\0')
    {
        dev = networkInterfaces;
        devName = dev->name;
    }

    if (pcap_lookupnet(devName, &net, &mask, errbuf) == -1)
    {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", devName, errbuf);
        net = 0;
        mask = 0;
    }

    handle = pcap_open_live(devName, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL)
    {
        fprintf(stderr, "Couldn't open device %s: %s\n", devName, errbuf);
        return;
    }

    if (pcap_compile(handle, &fp, filter, 0, net) == -1)
    {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter, pcap_geterr(handle));
        return;
    }

    if (pcap_setfilter(handle, &fp) == -1)
    {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter, pcap_geterr(handle));
        return;
    }

    if(strcmp(filter, "ip") == 0)
        pcap_loop(handle, -1, interceptedIpPacketsHandler, (u_char*)handle);
    if(strcmp(filter, "tcp") == 0)
        pcap_loop(handle, -1, interceptedTCPPacketsHandler, (u_char*)handle);
    if((strcmp(filter, "ether proto 0x0800") == 0) || (strcmp(filter, "ether proto 0x86DD") == 0))
        pcap_loop(handle, -1, interceptedEthernetPacketsHandler, (u_char*)handle);
    if(strcmp(filter, "udp") == 0)
        pcap_loop(handle, -1, interceptedUDPPacketsHandler, (u_char*)handle);
    if(strcmp(filter, "arp") == 0)
        pcap_loop(handle, -1, interceptedARPPacketsHandler, (u_char*)handle);
    if(strcmp(filter, "icmp") == 0)
        pcap_loop(handle, -1, interceptedICMPPacketsHandler, (u_char*)handle);
    if(strcmp(filter, "udp port 53") == 0)
        pcap_loop(handle, -1, interceptedDNSPacketsFromUDPProtocolHandler, (u_char *) handle);
    if(strcmp(filter, "tcp port 53") == 0)
        pcap_loop(handle, -1, interceptedDNSPacketsFromTCPProtocolHandler, (u_char *) handle);
    if(strcmp(filter, "dns") == 0)
        pcap_loop(handle, -1, dnsProtocolSelectionForHandler, (u_char*)handle);
    if(strcmp(filter, "tcp port http") == 0 || strcmp(filter, "tcp port 80") == 0 || strcmp(filter, "tcp port 8080") == 0)
        pcap_loop(handle, -1, interceptedHTTPPackets80PortHandler, (u_char*)handle);
}

char* printTime(const struct pcap_pkthdr *header, char timeBuffer[])
{
    time_t timestamp = header->ts.tv_sec;
    struct tm *timeinfo = localtime(&timestamp);
    char buffer[80];
    strftime(buffer, 80, "%d.%m.%Y %H:%M:%S", timeinfo);
    sprintf(timeBuffer, "Timestamp: %s.%06ld\n", buffer, header->ts.tv_usec);

    return timeBuffer;
}

void outputData(const char* data)
{
    if (file == stdout)
        printf("%s", data);
    else
        fputs(data, file);
}

void interceptedEthernetPacketsHandler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    char *result = malloc(64 * (header->len) * sizeof(char));
    struct ethhdr *ethernetHeader;
    ethernetHeader = (struct ethhdr*) packet;
    counter++;
    char timeBuffer[256];

    if(fileWriteChoice == true)
        printf("Was intercepted %d packets\n", counter);

    sprintf(result, "Ethernet-packet\nPacket size: %d\nNumber of bytes: %d\nDestination MAC: %s\nSource MAC: %s\nType: %hu\n",
            header->len,
            header->caplen,
            ether_ntoa((struct ether_addr *) ethernetHeader->h_dest),
            ether_ntoa((struct ether_addr *) ethernetHeader->h_source),
            ntohs(ethernetHeader->h_proto));

    strcat(result, printTime(header, timeBuffer));

    strcat(result, "Packet data:\n");
    char hexByte[4];
    for(int i = ETH_HLEN; i < header->len; i++) {
        sprintf(hexByte, "%02X ", packet[i]);
        strcat(result, hexByte);
    }
    strcat(result, "\n\n");

    outputData(result);
}

void interceptedIpPacketsHandler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    char *result = malloc(64 * (header->len) * sizeof(char));
    char timeBuffer[256];
    counter++;

    if(fileWriteChoice == true)
        printf("Was intercepted %d packets\n", counter);

    struct iphdr* ipHeader = (struct iphdr*)(packet + sizeof(struct ethhdr));

    struct in_addr sourceAddress, destinationAddress;
    sourceAddress.s_addr = ipHeader->saddr;
    destinationAddress.s_addr = ipHeader->daddr;

    unsigned int protocol = ipHeader->protocol;
    int size = ntohs(ipHeader->tot_len);

    sprintf(result, "IP-packets\nPacket size: %d\nNumber of bytes: %d\nIP-packet from %s to %s\nProtocol: %d\nPacket size: %d\n",
            header->len,
            header->caplen,
            inet_ntoa(sourceAddress),
            inet_ntoa(destinationAddress),
            protocol,
            size);

    strcat(result, printTime(header, timeBuffer));

    strcat(result, "Packet data:\n");
    int packetSize = header->caplen;
    char hexByte[4];
    for (int i = sizeof(struct iphdr) + sizeof(struct ethhdr); i < packetSize; i++)
    {
        sprintf(hexByte, "%02X ", packet[i]);
        strcat(result, hexByte);
    }

    strcat(result, "\n\n");
    outputData(result);

}

void interceptedTCPPacketsHandler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    struct ethhdr* ethernetHeader;
    struct iphdr* ipHeader;
    struct tcphdr* tcpHeader;
    int headerSize, tcpDataSize, packetSize;

    char timeBuffer[256];
    counter++;

    if(fileWriteChoice == true)
        printf("Was intercepted %d packets\n", counter);

    ethernetHeader = (struct ethhdr*) packet;
    headerSize = sizeof(struct ethhdr);
    ipHeader = (struct iphdr*)(packet + headerSize);
    headerSize += ipHeader->ihl * 4;
    tcpHeader = (struct tcphdr*)(packet + headerSize);
    tcpDataSize = ntohs(ipHeader->tot_len) - (ipHeader->ihl * 4) - (tcpHeader->doff * 4);
    packetSize = ntohs(ethernetHeader->h_proto) + headerSize + tcpDataSize;

    char *result = malloc(8 * packetSize * sizeof(char));

    sprintf(result, "TCP-packet\nPacket size: %d\nNumber of bytes: %d\nSource-IP: %s\nDestination IP: %s\nSource Port: %d\nDestination Port: %d\nSequence Number: %u\nAcknowledgment Number: %u\nData Offset: %d bytes\nWindow Size: %d\nChecksum: %d\nUrgent Pointer: %d\nData Size: %d bytes\nPacket Size: %d bytes\nFlags: ",
           header->len,
           header->caplen,
           inet_ntoa(*(struct in_addr *)&ipHeader->saddr),
           inet_ntoa(*(struct in_addr *)&ipHeader->daddr),
           ntohs(tcpHeader->source),
           ntohs(tcpHeader->dest),
           ntohl(tcpHeader->seq),
           ntohl(tcpHeader->ack_seq),
           (tcpHeader->doff)*4,
           ntohs(tcpHeader->window),
           ntohs(tcpHeader->check),
           tcpHeader->urg_ptr,
           tcpDataSize,
           packetSize);

    if(tcpHeader->urg)
        strcat(result,"U");
    if(tcpHeader->ack)
        strcat(result, "A");
    if(tcpHeader->psh)
        strcat(result, "P");
    if(tcpHeader->rst)
        strcat(result, "R");
    if(tcpHeader->syn)
        strcat(result, "S");
    if(tcpHeader->fin)
        strcat(result, "F");
    strcat(result, "\n");

    strcat(result, printTime(header, timeBuffer));

    if(tcpDataSize != 0)
    {
        strcat(result, "Packet data:\n");
        char hexByte[4];
        for (int i = 0; i < tcpDataSize; i++)
        {
            sprintf(hexByte, "%02X ", packet[headerSize + tcpHeader->doff * 4 + i]);
            strcat(result, hexByte);
        }

        strcat(result, "\n\n");
    }
    else
        strcat(result, "\n");

    outputData(result);
}

void interceptedUDPPacketsHandler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    struct iphdr* ipHeader;
    struct udphdr* udpHeader;

    char* udpData;

    ipHeader = (struct iphdr*)(packet + sizeof(struct ethhdr));
    udpHeader = (struct udphdr*)(packet + sizeof(struct ethhdr) + sizeof(struct iphdr));
    udpData = (char*)(packet + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr));

    char *result = malloc(16 * ntohs(udpHeader->len) * sizeof(char));
    char timeBuffer[256];
    counter++;

    if(fileWriteChoice == true)
        printf("Was intercepted %d packets\n", counter);

    sprintf(result, "UDP-packet\n");

    sprintf(result + strlen(result), "Packet size: %d\n", header->len);
    sprintf(result + strlen(result), "Number of bytes: %d\n", header->caplen);
    sprintf(result + strlen(result), "Source-IP: %s\n", inet_ntoa(*(struct in_addr *)&ipHeader->saddr));
    sprintf(result + strlen(result), "Destination IP: %s\n", inet_ntoa(*(struct in_addr *)&ipHeader->daddr));
    sprintf(result + strlen(result), "Source Port: %d\n", ntohs(udpHeader->source));
    sprintf(result + strlen(result), "Destination Port: %d\n", ntohs(udpHeader->dest));
    sprintf(result + strlen(result), "Length: %d\n", ntohs(udpHeader->len));
    sprintf(result + strlen(result), "Checksum: %04X\n", ntohs(udpHeader->check));

    strcat(result, printTime(header, timeBuffer));

    sprintf(result + strlen(result), "Packet data:\n");

    for (int i = 0; i < ntohs(udpHeader->len) - sizeof(struct udphdr); i++)
        sprintf(result + strlen(result), "%02X ", udpData[i]);

    sprintf(result + strlen(result), "\n\n");

    outputData(result);
}

void interceptedARPPacketsHandler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    struct arphdr* arpHeader;
    arpHeader = (struct arphdr*)(packet + sizeof(struct ethhdr));

    char *result = malloc(64 * (header->len) * sizeof(char));
    char timeBuffer[256];
    counter++;

    if(fileWriteChoice == true)
        printf("Was intercepted %d packets\n", counter);

    sprintf(result, "ARP-packet\n");

    sprintf(result + strlen(result), "Packet size: %d\n", header->len);
    sprintf(result + strlen(result), "Number of bytes: %d\n", header->caplen);
    sprintf(result + strlen(result), "Hardware Type: %u\n", ntohs(arpHeader->ar_hrd));
    sprintf(result + strlen(result), "Protocol Type: %u\n", ntohs(arpHeader->ar_pro));
    sprintf(result + strlen(result), "Hardware Address Length: %u\n", arpHeader->ar_hln);
    sprintf(result + strlen(result), "Protocol Address Length: %u\n", arpHeader->ar_pln);
    sprintf(result + strlen(result), "Operation: %u\n", ntohs(arpHeader->ar_op));

    const u_char* arpData = packet + sizeof(struct ethhdr) + sizeof(struct arphdr);

    sprintf(result + strlen(result), "Sender MAC Address: %s\n", ether_ntoa((struct ether_addr*)(arpData)));
    arpData += 6;
    sprintf(result + strlen(result), "Sender IP Address: %s\n", inet_ntoa(*(struct in_addr*)(arpData)));
    arpData += 4;
    sprintf(result + strlen(result), "Target MAC Address: %s\n", ether_ntoa((struct ether_addr*)(arpData)));
    arpData += 6;
    sprintf(result + strlen(result), "Target IP Address: %s\n", inet_ntoa(*(struct in_addr *)(arpData)));

    strcat(result, printTime(header, timeBuffer));

    sprintf(result + strlen(result), "\n");

    outputData(result);
}

void interceptedICMPPacketsHandler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    struct icmphdr* icmpHeader;
    icmpHeader = (struct icmphdr*)(packet + sizeof(struct ethhdr) + sizeof(struct iphdr));

    char *result = malloc(64 * (header->len) * sizeof(char));
    char timeBuffer[256];
    counter++;

    if(fileWriteChoice == true)
        printf("Was intercepted %d packets\n", counter);

    sprintf(result, "ICMP-packet\n");

    sprintf(result + strlen(result), "Packet size: %d\n", header->len);
    sprintf(result + strlen(result), "Number of bytes: %d\n", header->caplen);
    sprintf(result + strlen(result), "Type: %hhu\n", icmpHeader->type);
    sprintf(result + strlen(result), "Code: %hhu\n", icmpHeader->code);
    sprintf(result + strlen(result), "Checksum: %hu\n", ntohs(icmpHeader->checksum));
    sprintf(result + strlen(result), "Identifier: %hu\n", ntohs(icmpHeader->un.echo.id));
    sprintf(result + strlen(result), "Sequence number: %hu\n", ntohs(icmpHeader->un.echo.sequence));

    strcat(result, printTime(header, timeBuffer));

    sprintf(result + strlen(result), "Packet data:\n");

    for(int i = 0; i < (int)(header->caplen - sizeof(struct ethhdr) - sizeof(struct iphdr) - sizeof(struct icmphdr)); i++)
        sprintf(result + strlen(result), "%02X ", packet[sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct icmphdr) + i]);

    sprintf(result + strlen(result), "\n\n");

    outputData(result);

}

void dnsProtocolSelectionForHandler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    struct iphdr* ipHeader;
    ipHeader = (struct iphdr*)packet;
    if(ipHeader->protocol == IPPROTO_UDP)
        interceptedDNSPacketsFromUDPProtocolHandler(args, header, packet);
    else
        interceptedDNSPacketsFromTCPProtocolHandler(args, header, packet);
}

void interceptedDNSPacketsFromTCPProtocolHandler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    struct iphdr* ipHeader;
    struct tcphdr* tcpHeader;
    char* dnsPayload;
    struct dnshdr* dnsHeader;

    ipHeader = (struct iphdr*)(packet + sizeof(struct ethhdr));
    tcpHeader = (struct tcphdr*)(packet + sizeof(struct ethhdr) + sizeof(struct iphdr));
    dnsPayload = (char*)(packet + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr));
    dnsHeader = (struct dnshdr*)dnsPayload;

    int dnsPacketSize = ntohs(ipHeader->tot_len);

    char *result = malloc(16 * dnsPacketSize * sizeof(char));
    char timeBuffer[256];

    sprintf(result, "DNS-packet\n");

    strcat(result, printTime(header, timeBuffer));

    sprintf(result + strlen(result), "Packet size: %d\n", header->len);
    sprintf(result + strlen(result), "Number of bytes: %d\n", header->caplen);
    sprintf(result + strlen(result), "Source IP address: %s\n", inet_ntoa(*(struct in_addr*)&ipHeader->saddr));
    sprintf(result + strlen(result), "Destination IP address: %s\n", inet_ntoa(*(struct in_addr*)&ipHeader->daddr));
    sprintf(result + strlen(result), "Source port: %d\n", ntohs(tcpHeader->source));
    sprintf(result + strlen(result), "Destination port: %d\n", ntohs(tcpHeader->dest));

    interceptedDNSPacketsHandler(dnsPayload, dnsHeader, result);
}

void interceptedDNSPacketsFromUDPProtocolHandler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    struct iphdr* ipHeader;
    struct udphdr* udpHeader;
    char* dnsPayload;
    struct dnshdr* dnsHeader;

    ipHeader = (struct iphdr*)(packet + sizeof(struct ethhdr));
    udpHeader = (struct udphdr*)(packet + sizeof(struct ethhdr) + sizeof(struct iphdr));
    dnsPayload = (char*)(packet + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr));
    dnsHeader = (struct dnshdr*)dnsPayload;

    int dnsPacketSize = ntohs(ipHeader->tot_len);

    char *result = malloc(16 * dnsPacketSize * sizeof(char));
    char timeBuffer[256];

    sprintf(result, "DNS-packet\n");

    strcat(result, printTime(header, timeBuffer));

    sprintf(result + strlen(result), "Packet size: %d\n", header->len);
    sprintf(result + strlen(result), "Number of bytes: %d\n", header->caplen);
    sprintf(result + strlen(result), "Source IP address: %s\n", inet_ntoa(*(struct in_addr*)&ipHeader->saddr));
    sprintf(result + strlen(result), "Destination IP address: %s\n", inet_ntoa(*(struct in_addr*)&ipHeader->daddr));
    sprintf(result + strlen(result), "Source port: %d\n", ntohs(udpHeader->source));
    sprintf(result + strlen(result), "Destination port: %d\n", ntohs(udpHeader->dest));

    interceptedDNSPacketsHandler(dnsPayload, dnsHeader, result);
}

void interceptedDNSPacketsHandler(char* dnsPayload, struct dnshdr* dnsHeader, char* result)
{
    sprintf(result + strlen(result), "Transaction ID: 0x%04x\n", ntohs(dnsHeader->id));
    sprintf(result + strlen(result), "Flags: 0x%04x\n", ntohs(dnsHeader->flags));
    sprintf(result + strlen(result), "Questions: %hu\n", ntohs(dnsHeader->qdcount));
    sprintf(result + strlen(result), "Answer RRs: %hu\n", ntohs(dnsHeader->ancount));
    sprintf(result + strlen(result), "Authority RRs: %hu\n", ntohs(dnsHeader->nscount));
    sprintf(result + strlen(result), "Additional RRs: %hu\n", ntohs(dnsHeader->arcount));

    sprintf(result + strlen(result), "DNS query: %s\n", dnsPayload);

    sprintf(result + strlen(result), "\n");

    counter++;

    if(fileWriteChoice == true)
        printf("Was intercepted %d packets\n", counter);

    outputData(result);
}

bool isHTTP(const u_char* payload)
{
    if (memcmp(payload, "HTTP/", 5) == 0)
    {
        return 1;
    } else
    {
        return 0;
    }
}

void printHTTP(const u_char *payload, int payloadSize, char* result)
{
    for (int i = 0; i < payloadSize; i++)
        sprintf(result + strlen(result), "%c", payload[i]);
    sprintf(result + strlen(result), "\n");

    outputData(result);
}

void interceptedHTTPPackets80PortHandler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    const u_char *payload;
    int payloadSize;

    struct ethhdr *ethHeader = (struct ethhdr*)packet;
    struct iphdr *ipHeader = (struct iphdr*)(packet + sizeof(struct ethhdr));
    struct tcphdr *tcpHeader = (struct tcphdr*)(packet + sizeof(struct ethhdr) + ipHeader->ihl*4);

    char *result = malloc(64 * (header->len) * sizeof(char));
    char timeBuffer[256];
    counter++;

    if(fileWriteChoice == true)
        printf("Was intercepted %d packets\n", counter);

    payload = packet + sizeof(struct ethhdr) + ipHeader->ihl*4 + tcpHeader->doff*4;
    payloadSize = ntohs(ipHeader->tot_len) - (ipHeader->ihl*4 + tcpHeader->doff*4);

    if(payloadSize > 0 && isHTTP(payload))
    {
        sprintf(result, "HTTP-packet\n");

        strcat(result, printTime(header, timeBuffer));

        sprintf(result + strlen(result), "Packet size: %d\n", header->len);
        sprintf(result + strlen(result), "Number of bytes: %d\n", header->caplen);
        sprintf(result + strlen(result), "Source IP address: %s\n", inet_ntoa(*(struct in_addr *) &ipHeader->saddr));
        sprintf(result + strlen(result), "Destination IP address: %s\n", inet_ntoa(*(struct in_addr *) &ipHeader->daddr));
        sprintf(result + strlen(result), "Source port: %d\n", ntohs(tcpHeader->source));
        sprintf(result + strlen(result), "Destination port: %d\n\n", ntohs(tcpHeader->dest));

        if (ntohs(tcpHeader->dest) == 80) {
            sprintf(result + strlen(result), "HTTP request:\n");
            printHTTP(payload, payloadSize, result);
        } else if (ntohs(tcpHeader->source) == 80) {
            sprintf(result + strlen(result), "HTTP response:\n");
            printHTTP(payload, payloadSize, result);
        }

        printf("\n");
    }
}

