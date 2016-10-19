/********************************************************
* Programa  : dhcpcl                                 	*
* Módulo    : dhcpcl.c                           	*
* Autor     : Moises Martinez Muñoz                 	*
* Autor     : Ignacio Alvarez Santiago       		*
*********************************************************/


//Librerias del sistema

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h> 
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_ether.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/in.h>
#include <netpacket/packet.h>
#include <net/route.h>
#include <errno.h>
#include <pthread.h>

#define STRING_LEN		255
#define ETH_LEN			6
#define ETH_LEN_MAX		16
#define ETH_IP_LEN		4
#define ARPHDR_ETHER 1

#define LONG_SNAME_DHCP 	64
#define LONG_FILE_DHCP		128
#define LONG_OPTS_DHCP		312
#define LONG_HOSTNAME_DHCP	256

#define MAX_OFERTAS		16
#define PUERTOCLIENTE		68
#define PUERTOSERVIDOR		67
#define FLAGSUNI		0
#define FLAGSBROAD		32768

#define BOOTREQUEST     	1
#define BOOTREPLY       	2

#define DHCPDISCOVER    	1
#define DHCPOFFER       	2
#define DHCPREQUEST     	3
#define DHCPDECLINE     	4
#define DHCPACK         	5
#define DHCPNACK        	6
#define DHCPRELEASE     	7

#define TAM_ENVIO_ARP		28
#define TAM_RESPUESTA_ARP	46
#define TAM_IP			20
#define TAM_UDP			8
#define TAM_DHCP		364
#define TAM_ENVIO_DHCP		392
#define TAM_RESPUESTA_DHCP 576

#define INIT			1
#define SELECTING		2
#define REQUESTING		3
#define BOUND			4
#define RENEWING		5
#define REBINDING		6
#define DECLINE			7
#define EXIT			8

#define TIMEOUT			64
#define T1CONST			0.5
#define T2CONST			0.875

#define TESPERA                 500
#define TARP                    3

//Estructuras de control de la aplicación

struct dhcphdr
{
   u_int8_t  op;                   
   u_int8_t  htype;                
   u_int8_t  hlen;                 
   u_int8_t  hops;                 
   u_int32_t xid;                  
   u_int16_t secs;                 
   u_int16_t flags;                
   struct in_addr ciaddr;          
   struct in_addr yiaddr;          
   struct in_addr siaddr;          
   struct in_addr giaddr;          
   char chaddr [ETH_LEN_MAX];     
   char sname [LONG_SNAME_DHCP];   
   char file [LONG_FILE_DHCP];      
   char opciones[LONG_OPTS_DHCP];
};


struct paqueteArp
{
	struct ethhdr cabecera_eth;
	struct arphdr cabecera_arp;
	char senderMac [ETH_LEN];
	char senderIP[ETH_IP_LEN];
	char targetMac [ETH_LEN];
	char targetIP[ETH_IP_LEN];
};

struct paquete
{
   struct iphdr cabecera_ip;
   struct udphdr cabecera_udp;
   struct dhcphdr cabecera_dhcp;
};


struct respuesta
{
	int mensaje;
	u_int32_t  leaseTime;
	u_long  xid;
	struct in_addr direccionIP;
	struct in_addr direccionSubNet;
	struct in_addr direccionMascara;
	struct in_addr direccionRouter;
	struct in_addr direccionDns1;
	struct in_addr direccionDns2;
	char hostname[STRING_LEN];
};

struct opciones
{
   	u_int32_t leaseTime;
	u_int32_t timeOut;
	u_long xid;
	u_int32_t depuracion;
	u_long direccion;
   	char hostname[STRING_LEN];
   	char interfaz[STRING_LEN];
	u_int8_t T;
	u_int8_t H;
	u_int8_t A;
	u_int8_t L;
};
