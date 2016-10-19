/********************************************************
* Programa  : dhcpcl                                 	*
* Módulo    : dhcpcl.c                           	*
* Autor     : Moises Martinez Muñoz                 	*
* Autor     : Ignacio Alvarez Santiago       		*
*********************************************************/

#include "dhcpcl.h"
#include "lOfertas.h"

//Variables globales de control

pthread_mutex_t barrera;

struct sigaction senal1;			//Estructura para el manejo de señales
struct sigaction senal2;			//Estructura para el manejo de señales

struct in_addr direccionIP;		//Variable que almacena la ip obtenida
struct in_addr direccionServidor;	//Variable que almacena la ip del servidor
struct opciones opciones;		//Estructura para el almacenamiento de las opciones de entrada

int salir		= 0;
int estado 	= 1;
double Lease	= 0;
double T1		= 0;
double T2		= 0;

lOfertas L	= NULL;			//Lista de almacenamiento de las opciones.

u_char direccionHW[ETH_LEN_MAX]	= "";
u_char direccionBC[ETH_LEN]  		= {255,255,255,255,255,255};
u_char direccionFR[ETH_LEN]  		= {0,0,0,0,0,0};


char *tiempoActual()
{
	time_t tiempo;
	char static cadena[80];
	struct tm *PtrTiempo;
	
	int hora;
	int minutos;

	tiempo    = time(NULL);
	PtrTiempo = localtime(&tiempo);
	strftime(cadena,80,"%Y-%m-%d %H:%M:%S",PtrTiempo);
	
	hora    	= (int) PtrTiempo->tm_gmtoff;
	minutos 	= (hora / 60) % 60; 
	hora 	= hora / 3600;
	
	if (hora >= 0)
		sprintf(cadena, "%s+%.2d:%.2d", cadena, hora, minutos);
	else
		sprintf(cadena, "%s-%.2d:%.2d", cadena, hora, minutos);

	return cadena;
}

void imprimirMensaje(char * cadena)
{
	if (opciones.depuracion)
		printf("%s\n", cadena);
}


u_short calcularCheksum(u_short *datos, int longitud)
{

	int auxLongitud 	= longitud;
	int suma 		= 0;
	u_short *d 		= datos;
	u_short resultado = 0;

	while (auxLongitud > 1) 
	{
		suma += *d++;
		auxLongitud -= sizeof(short);
	}

	if (auxLongitud == 1) 
	{
        *(u_char *) (&resultado) = *(u_char *) d;
        suma += resultado;
    }

    suma  = (suma >> 16) + (suma & 0xFFFF);
    suma += (suma >> 16);
    resultado = ~suma;
    return (resultado);
}


struct paqueteArp generarCabeceraArp(u_long dirBuscada)
{
	struct paqueteArp paquete;
	u_long dirOrigen;

	dirOrigen    = inet_addr("0.0.0.0");

	memset(&paquete, 0, sizeof(struct paqueteArp));

	memcpy(&paquete.cabecera_eth.h_source[0],&direccionHW[0], ETH_LEN);
	memcpy(&paquete.cabecera_eth.h_dest[0],&direccionBC[0], ETH_LEN);
	paquete.cabecera_eth.h_proto 	= htons(ETHERTYPE_ARP);

	paquete.cabecera_arp.ar_hrd 	= htons(ARPHDR_ETHER);
	paquete.cabecera_arp.ar_pro 	= htons(ETH_P_IP);
	paquete.cabecera_arp.ar_hln 	= ETH_LEN;
	paquete.cabecera_arp.ar_pln 	= ETH_IP_LEN;
	paquete.cabecera_arp.ar_op  	= htons(ARPOP_REQUEST);

	memcpy(&paquete.senderMac[0],&direccionHW[0],ETH_LEN);
	memcpy(&paquete.senderIP[0],&dirOrigen,ETH_IP_LEN);
	memcpy(&paquete.targetMac[0],&direccionFR[0],ETH_LEN);
	memcpy(&paquete.targetIP[0],&dirBuscada,ETH_IP_LEN);
	
	return paquete;
}


struct iphdr generarCabeceraIp()
{
   struct iphdr cabecera;
   
   u_short *buffer;
   
   buffer = malloc(sizeof(struct iphdr));
   
   memset(&cabecera, 0, sizeof(struct iphdr));
   
   cabecera.version  = 4;
   cabecera.ihl      = 5;
   cabecera.tos      = 0;
   cabecera.tot_len  = htons(TAM_ENVIO_DHCP);
   cabecera.id       = htons(opciones.xid);
   cabecera.frag_off = htons(0x4000);
   cabecera.ttl      = 128;
   cabecera.protocol = 17;
   cabecera.saddr    = inet_addr("0.0.0.0");
   cabecera.daddr    = inet_addr("255.255.255.255");
   
   memcpy(buffer, &cabecera, sizeof(struct iphdr));
   
   cabecera.check = calcularCheksum(buffer, sizeof(struct iphdr));
   
   free(buffer);
   
   return cabecera;
}

struct udphdr generarCabeceraUdp()
{
   struct udphdr cabecera;
   
   memset(&cabecera, 0, sizeof(struct udphdr));
   
   cabecera.source   = htons(PUERTOCLIENTE);
   cabecera.dest     = htons(PUERTOSERVIDOR);
   cabecera.len      = htons(TAM_UDP + TAM_DHCP);
   cabecera.check    = 0;
   
   return cabecera;
}

struct dhcphdr generarCabeceraDhcp(struct in_addr direccionCliente, struct in_addr direccionServidor, int operacion, int flags)
{
   struct dhcphdr cabecera;

	int posicion = 16;
	u_int32_t leaseAux;
     
	bzero(&cabecera,sizeof(struct dhcphdr));

	cabecera.op    = BOOTREQUEST;		//BOOTREQUEST
	cabecera.htype = 1;			//Ethernet 10 MB
	cabecera.hlen  = ETH_LEN;		//Longitud en octetos de la dirección de red
	cabecera.hops  = 0;
	cabecera.xid   = htonl(opciones.xid);
	cabecera.secs  = htons(0);
	cabecera.flags = htons(flags);


	if (estado > BOUND)
		memcpy(&cabecera.ciaddr,&direccionIP,ETH_IP_LEN);

	memcpy(cabecera.chaddr,direccionHW,ETH_LEN);

	//Introduccimos las opcion de magic cookie (RFC 2132)
	cabecera.opciones[0] = '\x63';
	cabecera.opciones[1] = '\x82';
	cabecera.opciones[2] = '\x53';
	cabecera.opciones[3] = '\x63';
	//Introducimos la opción del tipo de paquete
	cabecera.opciones[4] = 53;  
	cabecera.opciones[5] = '\x01';        
	cabecera.opciones[6] = operacion;
	//Introducimos el identificador del cliente
	cabecera.opciones[7] = 61;  
	cabecera.opciones[8] = '\x07';        
	cabecera.opciones[9] = '\x01';
	memcpy(&cabecera.opciones[10],direccionHW,6);
	
	
	//Opciones no obligatorias;

	if ((direccionCliente.s_addr != INADDR_ANY) && ((estado < 4) || ((estado > 4) && (flags != 0))))
	{
		cabecera.opciones[posicion] = 50;
		posicion++;
		cabecera.opciones[posicion] = 4;
		posicion++;
		memcpy(&cabecera.opciones[posicion],&direccionCliente,sizeof(direccionCliente));
		posicion += 4;
	}
	
	if (strcmp(opciones.hostname,"") != 0)
	{
		cabecera.opciones[posicion] = 12;
		posicion++;
		cabecera.opciones[posicion] = strlen(opciones.hostname);
		posicion++;
		memcpy(&cabecera.opciones[posicion],opciones.hostname,strlen(opciones.hostname));
		posicion += strlen(opciones.hostname);
	}

	if (opciones.leaseTime > 0)
	{
		cabecera.opciones[posicion] = 51;
		posicion++;
		cabecera.opciones[posicion] = 4;
		posicion++;

		leaseAux = htonl(opciones.leaseTime);
		memcpy(&cabecera.opciones[posicion], &leaseAux, sizeof(u_int32_t));
		posicion += 4;
	}

	if ((operacion == DHCPREQUEST) && ((estado < 4) || ((estado > 4) && (flags != 0))))
	{
		cabecera.opciones[posicion] = 54;
		posicion++;
		cabecera.opciones[posicion] = '\x04';
		posicion++;
		memcpy(&cabecera.opciones[posicion],&direccionServidor,sizeof(direccionServidor));
		posicion +=4;
	}

	if ((operacion == DHCPDISCOVER) || (operacion == DHCPREQUEST))
	{
		//Indicamos los elementos que queremos que nos responda en el ACK
		
		cabecera.opciones[posicion] = 55;
		posicion++;
		cabecera.opciones[posicion] = '\x0A';
		posicion++;
		cabecera.opciones[posicion] = 1;	   //Mascara de red
		posicion++;
		cabecera.opciones[posicion] = 3;	   //Direccion router
		posicion++;
		cabecera.opciones[posicion] = 6;	   //DNS Primario
		posicion++;
		cabecera.opciones[posicion] = 12;	//Hostname
		posicion++;
		cabecera.opciones[posicion] = 15;	//Domain Name
		posicion++;
		cabecera.opciones[posicion] = 17;	//Root Path
		posicion++;
		cabecera.opciones[posicion] = 28;	//BroadCast Adress
		posicion++;
		cabecera.opciones[posicion] = 40;	//Network Information Service Domain
		posicion++;
		cabecera.opciones[posicion] = 41;	//Network Information Service Servers
		posicion++;
		cabecera.opciones[posicion] = 42;	//Network Time Protocol Servers
		posicion++;
	}
	
	cabecera.opciones[posicion] = 255;
	
	return cabecera;
}


struct paquete generarPaquete(struct in_addr dirSolicitada, struct in_addr dirServidor, int operacion, int flags)
{
   struct paquete dhcp;
   
	dhcp.cabecera_ip   = generarCabeceraIp();
	dhcp.cabecera_udp  = generarCabeceraUdp(); 
	dhcp.cabecera_dhcp = generarCabeceraDhcp(dirSolicitada, dirServidor, operacion, flags);

	return dhcp;
}


/************************************************************************/
/***************FUNCIONES DE CONTROL DEL INTERFAZ************************/
/************************************************************************/

void obtenerDireccionHardware()
{
	struct ifreq ifreq;

	int s;

	s = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);

	if(s >= 0)
	{
		strcpy(ifreq.ifr_name, opciones.interfaz);
		
		if (ioctl(s, SIOCGIFHWADDR, &ifreq) != -1) 
		{
			memcpy(&direccionHW[0],&ifreq.ifr_hwaddr.sa_data,ETH_LEN);
		}
	}
	else
	{
		if (opciones.depuracion)
			fprintf(stderr,"Error: Error al crear el socket para la obtención de la direccion MAC (Codigo Error: %d).\n", errno);
		exit(0);
	}

	close(s);
}

int obtenerInterfaz()
{
   struct ifreq ifreq;

   int s;
   int resultado;
   
   s = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
		
   strcpy(ifreq.ifr_name, opciones.interfaz);

	if ( ioctl (s, SIOCGIFINDEX, &ifreq) >= 0 )
		resultado = ifreq.ifr_ifindex;
   else
      resultado = -1;
      
   close(s);   
   return resultado;
}


int interfazActivo()
{
	struct ifreq ifreq;

	int s;
	int resultado = 0;

	s = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);

	strcpy(ifreq.ifr_name, opciones.interfaz);

	if (ioctl(s, SIOCGIFFLAGS, &ifreq) >= 0)
	{
		resultado = (ifreq.ifr_flags & IFF_UP);		
	}

	close(s);
	
	return resultado;
}


void modificarInterfaz(int accion)
{
	struct ifreq ifreq;

	int s;

	s = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);

	strcpy(ifreq.ifr_name, opciones.interfaz);

	if (ioctl(s, SIOCGIFFLAGS, &ifreq) != -1) 
	{
		if (accion == 1) //ACTIVAR
			ifreq.ifr_flags |= IFF_UP;
		else if (accion == 2) //DESACTIVAR
			ifreq.ifr_flags &= ~IFF_UP;
		if (ioctl(s, SIOCSIFFLAGS, &ifreq) == -1)
		{
			if (opciones.depuracion)			
				fprintf(stderr,"Error: Error al modificar los flags del interfaz %s (Codigo Error: %d).\n", opciones.interfaz, errno);
			exit(0);
		}
	}
	else
	{
		if (opciones.depuracion)
			fprintf(stderr,"Error: Error al obtener la mascara de flags del interfaz %s (Codigo Error: %d).\n", opciones.interfaz, errno);
		exit(0);
	}

	close(s);
}


void modifyRoute(int s, struct in_addr destino, struct in_addr gateway, struct in_addr mascara, u_long flags, u_int16_t metrica, int operacion)
{
	struct sockaddr_in addr;
	struct rtentry route;

	if (opciones.depuracion)
	{
		printf("Creacion de ruta: ");
		printf("Destino %s ", inet_ntoa(destino));
		printf("Pasarela %s ",inet_ntoa(gateway));
		printf("Mascara %s Metrica %d\n",inet_ntoa(mascara), (metrica -1));
	}

	bzero (&route, sizeof (struct rtentry));

	route.rt_dev = opciones.interfaz;

	bzero((char *)&addr, sizeof(addr));
	addr.sin_family	= AF_INET;
	addr.sin_addr	= destino;
	memcpy (&route.rt_dst, &addr, sizeof (struct sockaddr_in));

	if (gateway.s_addr != INADDR_ANY)
	{
		bzero((char *)&addr, sizeof(addr));
		addr.sin_family	= AF_INET;
		addr.sin_addr	= gateway;
		memcpy (&route.rt_gateway, &addr, sizeof (struct sockaddr_in));
	}
	
	bzero((char *)&addr, sizeof(addr));
	addr.sin_family	= AF_INET;
	addr.sin_addr	= mascara;
	memcpy (&route.rt_genmask, &addr, sizeof (struct sockaddr_in));

	//Indicamos el flag G
	if (gateway.s_addr != INADDR_ANY)
	    route.rt_flags |= RTF_GATEWAY;

	//Indicamos el flag U
	route.rt_flags |= RTF_UP;
	route.rt_flags |= flags;

	route.rt_metric = metrica;

	if (ioctl(s, operacion, &route) < 0)
	{
		if (opciones.depuracion)
		{
			if (operacion == SIOCDELRT)
				fprintf(stderr,"Error: Eliminación incorrecta en tabla de rutas (Codigo Error: %d).\n", errno);
			else if (operacion == SIOCADDRT)
				fprintf(stderr,"Error: Creación incorrecta en tabla de rutas (Codigo Error: %d).\n", errno);
		}	
	}
}

void asignarDireccion(int s, int codigo, u_long direccion)
{
	struct sockaddr_in addr;
	struct ifreq ifreq;

	strcpy(ifreq.ifr_name, opciones.interfaz);

	bzero((char *)&addr, sizeof(addr));
	addr.sin_family		= AF_INET;
	addr.sin_addr.s_addr	= direccion;
	memcpy (&ifreq.ifr_addr, &addr, sizeof (struct sockaddr_in));

	if (ioctl (s, codigo, &ifreq) == -1)
	{
		if (opciones.depuracion)
			fprintf(stderr,"Error: Error al insertar la Ip en el interfaz %s (Codigo Error: %d).\n", opciones.interfaz, errno);
		exit(0);
	}
}

void configurarInterfaz(struct respuesta respuesta)
{
	struct in_addr ceros;
	struct in_addr net;

	int s;

	printf("#[%s] IP %s;",tiempoActual(),inet_ntoa(respuesta.direccionIP));
	printf(" leasetime %d;",respuesta.leaseTime);
	printf(" subnet mask %s;",inet_ntoa(respuesta.direccionMascara));
	printf(" router %s;",inet_ntoa(respuesta.direccionRouter));
	if (strlen(respuesta.hostname) != 0)
		printf(" hostname: %s;", respuesta.hostname);
	printf(" primary DNS %s;",inet_ntoa(respuesta.direccionDns1));
	printf(" secondary DNS %s\n",inet_ntoa(respuesta.direccionDns2));

	s = socket(AF_INET, SOCK_DGRAM, 0);

	if(s >= 0)
	{
		asignarDireccion(s,SIOCSIFADDR,respuesta.direccionIP.s_addr);
		asignarDireccion(s,SIOCSIFNETMASK,respuesta.direccionMascara.s_addr);
		asignarDireccion(s,SIOCSIFBRDADDR,(respuesta.direccionIP.s_addr | ~respuesta.direccionMascara.s_addr));	

		inet_aton("0.0.0.0",&ceros);
		net.s_addr   = (respuesta.direccionRouter.s_addr & respuesta.direccionMascara.s_addr);

		modifyRoute(s,net,ceros,respuesta.direccionMascara,0,1,SIOCADDRT);
		modifyRoute(s,ceros,respuesta.direccionRouter,ceros,0,1,SIOCADDRT);	

	}
	else
	{
		if (opciones.depuracion)
			fprintf(stderr,"Error: Error al crear el socket para la configuración del interfaz %s (Codigo Error: %d).\n", opciones.interfaz, errno);
		exit(0);
	}

	close(s);

}


/************************************************************************/
/************************************************************************/
/************************************************************************/


/************************************************************************/
/***************FUNCIONES DE CONTROL DE LOS SOCKETS**********************/
/************************************************************************/

int crearSocketPacket()
{
	int s;

	s = socket(PF_PACKET, SOCK_DGRAM, htons(ETH_P_IP));

	if (s < 0)
	{
		if (opciones.depuracion)
			fprintf(stderr,"Error: Creación erronea del socket PACKET (Codigo Error: %d).\n", errno);
		exit(0);
	}

	return s;
}


int crearSocketRaw()
{
	int s;

	s = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ARP));

	if (s < 0)
	{
		if (opciones.depuracion)
			fprintf(stderr,"Error: Creación erronea del socket RAW (Codigo Error: %d).\n", errno);
		exit(0);
	}

	return s;
}


int crearSocket(int broadcast)
{
	struct sockaddr_in client_addr;

	int s;
	int opcion = 1;

	bzero((char *)&client_addr, sizeof(client_addr)); 		//Inicializamos el cliente	

	client_addr.sin_family		= AF_INET;
        client_addr.sin_port            = htons(PUERTOCLIENTE);
        client_addr.sin_addr	        = direccionIP;
	bzero(&client_addr.sin_zero,sizeof(client_addr.sin_zero));

	s = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);

	if (s >= 0)
	{

		if (setsockopt(s,SOL_SOCKET,SO_REUSEADDR,(char *)&opcion,sizeof(opcion)) < 0)
		{
			if (opciones.depuracion)			
				fprintf(stderr,"Error: Error al activar la reutilización de la dirección IP (Codigo Error: %d).\n", errno);
			exit(0);
	   	}
		if (broadcast)
		{
			if (setsockopt(s, SOL_SOCKET,SO_BROADCAST,(char *)&opcion,sizeof(opcion)) < 0)
			{
				if (opciones.depuracion)
					fprintf(stderr,"Error: Error al activar el modo broadcast para el socket.\n");
				exit(0);
	   		}
		}

		if (setsockopt(s, SOL_SOCKET, SO_BINDTODEVICE,(char *) &opciones.interfaz, sizeof(opciones.interfaz)) < 0)
		{
			if (opciones.depuracion)
				fprintf(stderr,"Error: Error al asociar el interfaz %s al socket.\n", opciones.interfaz);
			exit(0);
	   	}

		if (bind (s, (struct sockaddr *)&client_addr, sizeof(client_addr)) < 0)
		{
			if (opciones.depuracion)
				fprintf(stderr,"Error: Error al realizar el bind sobre el socket.\n");
			exit(0);
      }
	        
	}
	else
	{
		if (opciones.depuracion)
			fprintf(stderr,"Error: Creación erroneo del socket UDP (Codigo Error: %d).\n", errno);
		exit(0);
	}

	return s;
}


void cerrarSocket(int s)
{
	close(s);
}

/************************************************************************/
/************************************************************************/
/************************************************************************/

struct respuesta obtenerDatosRespuesta(struct dhcphdr cabecera)
{
	int i 	 = 4;	
	int terminar = 0;
	int longitud;
	int tipo;

	struct respuesta respuesta;

	bzero(&respuesta,sizeof(struct respuesta));

	respuesta.mensaje = cabecera.opciones[6];

	while ((i < LONG_OPTS_DHCP) && (!terminar))
	{
		tipo     = cabecera.opciones[i];
		i 	+= 1;
		longitud = cabecera.opciones[i];		
		i 	+= 1;

		switch (tipo)
		{
			case   1://Obtención de mascara de Red
				memcpy(&respuesta.direccionMascara,&cabecera.opciones[i],longitud);
				break;
			case   3://Obtención de la dirección del router
				memcpy(&respuesta.direccionRouter,&cabecera.opciones[i],longitud);
				printf("LA DIRECCION ES %s\n", inet_ntoa(respuesta.direccionRouter));
				break;
			case   6://Obtención de la dirección DNS
				memcpy(&respuesta.direccionDns1,&cabecera.opciones[i],4);				
				if (longitud > 4)				
					memcpy(&respuesta.direccionDns2,&cabecera.opciones[i + 4],4);
				break;
			case  12://Obtención del nombre del dominio
				memcpy(&respuesta.hostname,&cabecera.opciones[i],longitud);	
				break;		
			case  51://Lease Time
				memcpy(&respuesta.leaseTime,&cabecera.opciones[i],longitud);
				respuesta.leaseTime = ntohl(respuesta.leaseTime);
				break;
			case  54://identificador del servidor (IP)
				memcpy(&respuesta.direccionSubNet,&cabecera.opciones[i],longitud);
				break;			
			case 255://Fin de opciones
				terminar = 1;
				break;
			case  -1://Fin de opciones
				terminar = 1;
				break;
		}
		
		i += longitud;
		
	}

	respuesta.direccionIP = cabecera.yiaddr;
	respuesta.xid         = ntohl(cabecera.xid);

	return respuesta;
	
}

void arpRequest(int s, u_long direccion)
{
	struct sockaddr_ll addr_sll;
	struct paqueteArp paquete;

	char *peticion;

	int tamano;
	int resultado;

	bzero((char*)&addr_sll, sizeof(addr_sll));
	addr_sll.sll_family     = AF_PACKET;
   	addr_sll.sll_protocol   = htons(ETH_P_ARP);
   	addr_sll.sll_ifindex    = obtenerInterfaz();
	addr_sll.sll_pkttype    = PACKET_BROADCAST;
   	addr_sll.sll_hatype     = 0xFFFF;
   	addr_sll.sll_halen      = ETH_LEN;
	memcpy(&addr_sll.sll_addr[0], &direccionBC[0],ETH_LEN);

	paquete = generarCabeceraArp(direccion);

	peticion = malloc(sizeof(struct paqueteArp));
	tamano   = sizeof(struct paqueteArp);

	memcpy(peticion,&paquete,sizeof(struct paqueteArp));
	
	resultado = sendto(s, (char *) peticion, tamano, 0, (struct sockaddr *) &addr_sll, sizeof(struct sockaddr_ll));
	
	free(peticion);

	if (resultado != tamano)
	{
		if (opciones.depuracion)
			fprintf(stderr,"Error: Error al realizar la petición ARP.\n");
		exit(0);
	}
}

int arpResponse(int s, u_long direccion)
{
	struct sockaddr_ll addr_sll;
	struct timeval tiempo;
	struct paqueteArp paquete;

	u_long dirAuxiliar;

	char *respuesta;

	int resultado;
	int recibido   = 0;
	int detectado  = 0;

	fd_set recepcion;
	socklen_t tamano;

	bzero((char*)&addr_sll, sizeof(addr_sll));
	addr_sll.sll_family    	= AF_PACKET;
   	addr_sll.sll_protocol  	= htons(ETH_P_ARP);
  	addr_sll.sll_ifindex   	= obtenerInterfaz();
	tamano		 	= sizeof(addr_sll);
	tiempo.tv_sec  		= TARP;
	tiempo.tv_usec 		= 0;

	FD_ZERO(&recepcion);
	FD_CLR(s, &recepcion);
	FD_SET(s, &recepcion);

	respuesta = malloc(sizeof(struct paqueteArp));

	do
	{
		recibido = select(s+1, &recepcion, NULL, NULL, &tiempo);

		if (recibido)
		{	
			memset(respuesta, 0, sizeof(struct paqueteArp));
			resultado = recvfrom(s, (char *)respuesta, sizeof(struct paqueteArp), 0, (struct sockaddr *) &addr_sll, (socklen_t *) &tamano);	

			if (resultado == sizeof(struct paqueteArp))
			{
				memcpy(&paquete, respuesta, sizeof(struct paqueteArp));
				memcpy(&dirAuxiliar,&paquete.targetIP[0],ETH_IP_LEN);

				if (direccion == dirAuxiliar)
				{
                                        if (opciones.depuracion)
					        fprintf(stderr,"Error: Detectada respuesta ARP con la IP solicitada.\n");
					detectado = 1;
				}
			}			
		}
		
	} while ((recibido > 0) && (!detectado));

	free(respuesta);

	return detectado;
}

/************************************************************************/
/**********************FUNCIONES MENSAJES DHCP***************************/
/************************************************************************/

void dhcpDiscover(int s, int flags)
{
	struct sockaddr_ll addr_sll;
	struct net_if_s;	
	struct paquete paquete;
	
	struct in_addr direccionSolicitada;
	struct in_addr direccionServer;

	int resultado = 0;

	char * peticion;
	
	bzero((char*)&addr_sll, sizeof(addr_sll));
	addr_sll.sll_family     = AF_PACKET;
   	addr_sll.sll_protocol   = htons(ETH_P_IP);
   	addr_sll.sll_ifindex    = obtenerInterfaz();
   	addr_sll.sll_pkttype    = PACKET_BROADCAST;
   	addr_sll.sll_hatype     = 0xFFFF;
   	addr_sll.sll_halen      = ETH_LEN;
	memcpy(&addr_sll.sll_addr[0], &direccionBC[0],ETH_LEN);
	

	direccionSolicitada.s_addr = opciones.direccion;
	direccionServer.s_addr		= 0;
	
	paquete  = generarPaquete(direccionSolicitada,direccionServer,DHCPDISCOVER,flags);
	
	printf("#[%s] (0x%lx) PID = %i.\n",tiempoActual(),opciones.xid,getpid());

	peticion = malloc(TAM_ENVIO_DHCP);
	bzero(peticion,TAM_ENVIO_DHCP);
	
	memcpy(peticion, &paquete, TAM_ENVIO_DHCP);
	
	resultado = sendto(s, (char *) peticion, TAM_ENVIO_DHCP, 0, (struct sockaddr *) &addr_sll, sizeof(addr_sll));
	
	free(peticion);

	if (resultado != TAM_ENVIO_DHCP)
	{
		if (opciones.depuracion)
			fprintf(stderr,"Error: Error al realizar el DCHPDISCOVER (Codigo Error: %d).\n", errno);
		exit(0);
	}
	else
		printf("#[%s] (0x%lx) DHCPDISCOVER sent.\n",tiempoActual(),opciones.xid);
}

int dhcpOffer(int s)
{
	struct sockaddr_ll addr_sll;
	struct timeval tiempo;
   	struct paquete paquete;
   	struct respuesta datos;

	fd_set recepcion;
	socklen_t tamano;

	int resultado;
	int respuestas = 0;
	int recibido   = 0;

	char *respuesta;
	
	bzero((char*)&addr_sll, sizeof(addr_sll));
	addr_sll.sll_family     = AF_PACKET;
   	addr_sll.sll_protocol   = htons(ETH_P_IP);
   	addr_sll.sll_ifindex    = obtenerInterfaz();
	
	tamano		   = sizeof(struct sockaddr_ll);
	tiempo.tv_sec  = opciones.timeOut;
	tiempo.tv_usec = 0;

	respuesta = malloc(TAM_RESPUESTA_DHCP);

	FD_ZERO(&recepcion);
	FD_CLR(s, &recepcion);
	FD_SET(s, &recepcion);

	do
	{
		recibido = select(s+1, &recepcion, NULL, NULL, &tiempo);

		if (recibido)
		{		
			bzero(respuesta, sizeof(struct paquete));
			resultado = recvfrom(s, (char *)respuesta, TAM_RESPUESTA_DHCP, 0, (struct sockaddr *) &addr_sll, (socklen_t *) &tamano);	

			if (resultado == TAM_RESPUESTA_DHCP)
			{			
				memcpy(&paquete, respuesta, sizeof(struct paquete));		
				datos = obtenerDatosRespuesta(paquete.cabecera_dhcp);
				
				pthread_mutex_lock (&barrera);
				insertar(&L, datos.direccionSubNet, datos.direccionIP, datos.xid);
				pthread_mutex_unlock (&barrera);
	
				printf("#[%s] (0x%lx) DHCPOFFER received from %s",tiempoActual(),datos.xid,inet_ntoa(datos.direccionSubNet));
				printf(" (offered %s).\n", inet_ntoa(datos.direccionIP));

				//Modificamos el tiempo de espero puesto que hemos recibido al menos una oferta,
				//de esta forma recogemos las demás ofertas que se hayan enviado.

				tiempo.tv_sec  = 0;
				tiempo.tv_usec = TESPERA;

				respuestas++;
			}
		}

	} while (recibido > 0);

	free(respuesta);

	return respuestas;
}

void dhcpPrequest(int s, lOfertas oferta, int flags)
{
	struct sockaddr_ll addr_sll;
	struct in_addr direccionCliente;
	struct in_addr direccionServer;
   	struct paquete paquete;

	int resultado = 0;
	u_long xid = 0;

	char * peticion;
	
	bzero((char*)&addr_sll, sizeof(addr_sll));
	addr_sll.sll_family     = AF_PACKET;
   	addr_sll.sll_protocol   = htons(ETH_P_IP);
   	addr_sll.sll_ifindex    = obtenerInterfaz();
   	addr_sll.sll_pkttype    = PACKET_BROADCAST;
   	addr_sll.sll_hatype     = 0xFFFF;
   	addr_sll.sll_halen      = ETH_LEN;
	memcpy(&addr_sll.sll_addr[0], &direccionBC[0],ETH_LEN);


	direccionServer   = obtenerDirServer(oferta);
	direccionCliente  = obtenerDirIP(oferta);
	xid		  = obtenerXid(oferta);

	printf("DIRECCION SERVER REQUEST %s\n", inet_ntoa(direccionServer));

	paquete = generarPaquete(direccionCliente, direccionServer, DHCPREQUEST, flags);

	peticion = malloc(TAM_ENVIO_DHCP);
	
	memcpy(peticion,&paquete,TAM_ENVIO_DHCP);
	
	resultado = sendto(s, peticion, TAM_ENVIO_DHCP, 0, (struct sockaddr *) &addr_sll, sizeof(struct sockaddr_ll));
	
	free(peticion);

	if (resultado != TAM_ENVIO_DHCP)
	{
		if (opciones.depuracion)
			fprintf(stderr,"Error: Error al realizar el DCHPPREQUEST (Codigo Error: %d).\n", errno);
		exit(0);
	}
	else
	{
		printf("#[%s] (0x%lx) DHCPREQUEST sent to all (binding %s).\n",tiempoActual(),xid,inet_ntoa(direccionServer));
	}
}


void dhcpPrequestWithIP(int s, int flags, u_long dirServidor)
{
	struct sockaddr_in server_addr;
   	struct dhcphdr paquete;

	int resultado = 0;

	char * peticion;
	
	bzero ((char *)&server_addr, sizeof(server_addr)); 			//Inicializamos el servidor
	server_addr.sin_addr.s_addr 	= dirServidor;				//Asignamos la ip del servidor.
	server_addr.sin_family		= AF_INET;       	 		//La familia del servidor tipo Red
	server_addr.sin_port       	= htons (PUERTOSERVIDOR); 		//El puerto del servidor en formato Red
	bzero(&server_addr.sin_zero,sizeof(server_addr.sin_zero));

	//Sumamos 1 al XID puesto que es una nueva petición y no puede ser el mismo que antes.
	opciones.xid++;

	paquete = generarCabeceraDhcp(direccionIP,direccionServidor,DHCPREQUEST,flags);

	peticion = malloc(TAM_DHCP);
	
	memcpy(peticion,&paquete,TAM_DHCP);
	
	resultado = sendto(s, peticion, TAM_DHCP, 0, (struct sockaddr *) &server_addr, sizeof(server_addr));

	free(peticion);

	if (resultado != TAM_DHCP)
	{
		if (opciones.depuracion)
			fprintf(stderr,"Error: Error al realizar el DCHPPREQUEST (Codigo Error: %d).\n", errno);
		exit(0);
	}
	else
	{
		printf("#[%s] (0x%lx) DHCPREQUEST sent to %s ",tiempoActual(), opciones.xid, inet_ntoa(direccionServidor));
		printf("(Renewing %s). \n", inet_ntoa(direccionIP));
	}
}



struct respuesta dhcpAck(int s)
{
	struct sockaddr_ll addr_sll;
	struct paquete paquete;
	struct timeval tiempo;
	struct respuesta respuestaServidor;

	fd_set recepcion;

	int resultado;
	int tamano;
	int recibido    = 0;
	int respuestaRecibida = 0;

	char *respuesta;
	
	bzero((char*)&addr_sll, sizeof(addr_sll));
	addr_sll.sll_family     	= AF_PACKET;
   	addr_sll.sll_protocol   	= htons(ETH_P_IP);
   	addr_sll.sll_ifindex    	= obtenerInterfaz();

	tamano 		   		= sizeof(addr_sll);
	tiempo.tv_sec 			= opciones.timeOut;
	tiempo.tv_usec 		        = 0;

	FD_ZERO(&recepcion);
	FD_SET(s, &recepcion);

	respuesta = malloc(TAM_RESPUESTA_DHCP);
	bzero(respuesta,sizeof(struct paquete));
	
	do
	{
		recibido = select(s+1, &recepcion, NULL, NULL, &tiempo);

		if (recibido)
		{
			
			resultado = recvfrom(s,(char *)respuesta, TAM_RESPUESTA_DHCP, 0, (struct sockaddr *) &addr_sll, (socklen_t *) &tamano);				

			if (resultado == TAM_RESPUESTA_DHCP)
			{	

				memcpy(&paquete,respuesta,sizeof(struct paquete));	

				respuestaServidor = obtenerDatosRespuesta(paquete.cabecera_dhcp);

				if (respuestaServidor.mensaje == DHCPACK)
				{
					printf("#[%s] (0x%lx) DHCPACK received: %s with leasing %d seconds.\n",tiempoActual(),respuestaServidor.xid,inet_ntoa(respuestaServidor.direccionIP), respuestaServidor.leaseTime);

				}
				else if (respuestaServidor.mensaje == DHCPNACK)
				{
					printf("#[%s] (0x%lx) DHCPNACK received: %s.\n",tiempoActual(),respuestaServidor.xid,inet_ntoa(respuestaServidor.direccionRouter));
				}

				respuestaRecibida = 1;
			}
		}
		
	} while ((recibido > 0) && (!respuestaRecibida));

	free(respuesta);

	return respuestaServidor;
}


struct respuesta dhcpAckWithIP(int s, u_long dirServidor)
{
	struct sockaddr_in server_addr;
	struct dhcphdr paquete;
	struct timeval tiempo;
	struct respuesta respuestaServidor;

	fd_set recepcion;

	int resultado;
	int tamano;
	int recibido    = 0;
	int respuestaRecibida = 0;

	char *respuesta;

	bzero ((char *)&server_addr, sizeof(server_addr)); 				//Inicializamos el servidor
	server_addr.sin_addr.s_addr = dirServidor;					//Asignamos la ip del servidor.
	server_addr.sin_family      = AF_INET; 	 					//La familia del servidor tipo Red
	server_addr.sin_port        = htons (PUERTOSERVIDOR);	 			//El puerto del servidor en formato Red
	bzero(&server_addr.sin_zero,sizeof(server_addr.sin_zero));

	tamano 		   = sizeof(server_addr);
	tiempo.tv_sec 	= opciones.timeOut;
	tiempo.tv_usec = 0;

	FD_ZERO(&recepcion);
	FD_SET(s, &recepcion);

	respuesta = malloc(sizeof (struct dhcphdr));
	bzero(respuesta,sizeof(struct dhcphdr));

	do
	{
		recibido = select(s+1, &recepcion, NULL, NULL, &tiempo);

		if (recibido)
		{

			resultado = recvfrom(s,(char *)respuesta, sizeof(struct dhcphdr), 0, (struct sockaddr *) &server_addr, (socklen_t *) &tamano);				

			if (resultado == sizeof(struct dhcphdr))
			{
				memcpy(&paquete,respuesta,sizeof(struct dhcphdr));	

				respuestaServidor = obtenerDatosRespuesta(paquete);

				if (respuestaServidor.mensaje == DHCPACK)
				{
					printf("#[%s] (0x%lx) DHCPACK received: %s with leasing %d seconds.\n",tiempoActual(),respuestaServidor.xid,inet_ntoa(respuestaServidor.direccionIP), respuestaServidor.leaseTime);

				}
				else if (respuestaServidor.mensaje == DHCPNACK)
				{
					printf("#[%s] (0x%lx) DHCPNACK received: %s.\n",tiempoActual(),respuestaServidor.xid,inet_ntoa(server_addr.sin_addr));
				}

				respuestaRecibida = 1;
			}
		}
		
	} while ((recibido > 0) && (!respuestaRecibida));

	free(respuesta);

	return respuestaServidor;
}


void dhcpDecline(int s)
{
	struct sockaddr_ll addr_sll;
   	struct paquete paquete;

	int resultado = 0;

	char * peticion;
	
	bzero((char*)&addr_sll, sizeof(addr_sll));
	addr_sll.sll_family     = AF_PACKET;
   	addr_sll.sll_protocol   = htons(ETH_P_IP);
   	addr_sll.sll_ifindex    = obtenerInterfaz();
  	addr_sll.sll_pkttype    = PACKET_BROADCAST;
   	addr_sll.sll_hatype     = 0xFFFF;
   	addr_sll.sll_halen      = ETH_LEN;
	memcpy(&addr_sll.sll_addr[0], &direccionBC[0],ETH_LEN);

	paquete = generarPaquete(direccionIP,direccionServidor,DHCPDECLINE,FLAGSUNI);

	peticion = malloc(TAM_ENVIO_DHCP);
	
	memcpy(peticion,&paquete,TAM_ENVIO_DHCP);

	resultado = sendto(s, peticion, TAM_ENVIO_DHCP, 0, (struct sockaddr *) &addr_sll, sizeof(struct sockaddr_ll));
	
	free(peticion);

	if (resultado != TAM_ENVIO_DHCP)
	{
		if (opciones.depuracion)		
			fprintf(stderr,"Error: Error al realizar el DHCPDECLINE (Codigo Error: %d).\n", errno);
		exit(0);
	}
	else
		printf("#[%s] (0x%lx) DHCPDECLINE sent %s rejected.\n",tiempoActual(),opciones.xid,inet_ntoa(direccionIP));
}

void dhcpRelease(int s)
{
	struct sockaddr_in server_addr;
	struct dhcphdr paquete;

	int resultado = 0;

	char * peticion;

	bzero ((char *)&server_addr, sizeof(server_addr)); 			//Inicializamos el servidor
	server_addr.sin_addr.s_addr = direccionServidor.s_addr;			//Asignamos la ip del servidor.
	server_addr.sin_family      = AF_INET; 	 				//La familia del servidor tipo Red
	server_addr.sin_port        = htons (PUERTOSERVIDOR);	 		//El puerto del servidor en formato Red
	bzero(&server_addr.sin_zero,sizeof(server_addr.sin_zero));

	opciones.xid++;

	paquete = generarCabeceraDhcp(direccionIP,direccionServidor,DHCPRELEASE, FLAGSUNI);

	peticion = malloc(TAM_DHCP);
	
	memcpy(peticion,&paquete,TAM_DHCP);

	resultado = sendto(s, peticion, TAM_DHCP, 0, (struct sockaddr *) &server_addr, sizeof(struct sockaddr));
	
	free(peticion);

	if (resultado != TAM_DHCP)
	{
		if (opciones.depuracion)		
			fprintf(stderr,"Error: Error al realizar el DHCPRELEASE (Codigo Error: %d).\n", errno);
		exit(0);
	}
	else
		printf("#[%s] (0x%lx) DHCPRELEASE sent %s.\n",tiempoActual(),opciones.xid,inet_ntoa(direccionIP));

}

int solicitudArp(u_long direccion)
{
	int s;
	int resultado;

	s = crearSocketRaw();

	arpRequest(s, direccion);
		
	resultado = arpResponse(s, direccion);

	cerrarSocket(s);

	return resultado;
}

/************************************************************************/
/************************FUNCIONES MANEJO SENALES***********************/
/************************************************************************/


void dhcpSigInt()
{
	printf("#[%s] SIGINT received.\n",tiempoActual());
	
	pthread_mutex_lock (&barrera);
        eliminar(&L);
    	pthread_mutex_unlock (&barrera);
          
	exit(0);
}


void dhcpSigUser2()
{
	int s;

	printf("#[%s] SIGUSR2 received.\n",tiempoActual());

	if (interfazActivo())
	{
		s = crearSocket(0);

		dhcpRelease(s);

		cerrarSocket(s);

		modificarInterfaz(2);
	}
	else
		fprintf(stderr, "Error: %s is already disabled.\n", opciones.interfaz);
		
	
	pthread_mutex_lock (&barrera);
        eliminar(&L);
    	pthread_mutex_unlock (&barrera);
	
	exit(0);
}



/************************************************************************/
/*************FUNCIONES DE TRATAMIENTO DE PARAMETROS*********************/
/************************************************************************/

void imprimirAyuda()
{
	system("clear");
	printf("dhcpl interface [-t timeout] [-h hostname] [-a IP address] [-l leasetime] [-d]\n");
}


int cargarParametro(int argc, char *argv[])
{
        int error;

        char opcion;

        if (argc > 1)
	   {

               srand(time(NULL));
			opciones.xid	  	= random() % 265144;
			opciones.timeOut	= TIMEOUT;

                error                   = 0;
                opterr                  = 0;

                memcpy(opciones.interfaz,argv[1],strlen(argv[1]));

                while ((opcion = getopt (argc, argv, "t:h:a:l:")) != -1) 
                {
                        switch (opcion) 
                        {
                             	case 't': opciones.timeOut = atoi(optarg);
                                  	break;
			        		case 'h': memcpy(opciones.hostname,optarg,strlen(optarg));
				        		break;
			        		case 'a': opciones.direccion = inet_addr(optarg);
				        		break;
			        		case 'l': opciones.leaseTime = atoi(optarg);
				        		break;
			        		case '?': if (optopt == 'd') opciones.depuracion = 1;
                                        else error = 1;
                                 	break;
                        }

		              	if (error != 0)
					{
						imprimirAyuda();
						error = 1;
					}
                }

        }
	else
	{
		imprimirAyuda();
   		error = 2;
	}

	return error;

}


/************************************************************************/
/******************FUNCIONES DE EJECUCION DE ESTADOS*********************/
/************************************************************************/

int estadoInit(int s)
{
	dhcpDiscover(s, FLAGSUNI);
	return SELECTING;
}


int estadoSelecting(int s)
{
     lOfertas oferta = NULL;

	int ofertas;

	ofertas = dhcpOffer(s);

	if (ofertas > 0)
	{
		pthread_mutex_lock (&barrera);
          oferta = seleccionarOferta(L,  opciones.direccion);
          pthread_mutex_unlock (&barrera);

		dhcpPrequest(s, oferta, FLAGSUNI);
          
          pthread_mutex_lock (&barrera);
          eliminar(&L);
          pthread_mutex_unlock (&barrera);
		
		return REQUESTING;
	}
	else
	{
		salir = 1;
		return EXIT;
	}
}


int estadoRequesting(int s)
{
	struct respuesta respuesta;

	memset(&respuesta, 0, sizeof(struct respuesta));

	respuesta = dhcpAck(s);

	if (respuesta.mensaje == DHCPACK)
	{
		direccionIP 		= respuesta.direccionIP;
		direccionServidor       = respuesta.direccionSubNet;
		T1		        = respuesta.leaseTime * T1CONST;
		T2			= (respuesta.leaseTime * T2CONST) - T1;
		Lease 			= respuesta.leaseTime - T1 - T2;

                if (opciones.depuracion)
                        printf("TIEMPOS T1: %f T2: %f LeaseTime: %f\n", T1, T2, Lease);

		if (solicitudArp(direccionIP.s_addr) == 0)
		{
			configurarInterfaz(respuesta);
			return BOUND;
		}
		else
			return DECLINE;
	}
	else
		return INIT;
}

int estadoBound()
{
	sleep(T1);
	return RENEWING;
}

int estadoRenewing()
{
	struct respuesta respuesta;
	int s;

	memset(&respuesta, 0, sizeof(struct respuesta));

	s = crearSocket(0);

	dhcpPrequestWithIP(s, FLAGSUNI, direccionServidor.s_addr);
	respuesta = dhcpAckWithIP(s, direccionServidor.s_addr);

	cerrarSocket(s);

	if (respuesta.mensaje == DHCPACK)
	{
		T1	= respuesta.leaseTime * T1CONST;
		T2	= (respuesta.leaseTime * T2CONST) - T1;
		Lease 	= respuesta.leaseTime - T1 - T2;

                if (opciones.depuracion)
                        printf("TIEMPOS T1: %f T2: %f LeaseTime: %f\n", T1, T2, Lease);

		return BOUND;
	}
	else
	{
		sleep(T2);
		s = crearSocket(1);
		dhcpPrequestWithIP(s, FLAGSBROAD, INADDR_BROADCAST);
		cerrarSocket(s);
		
		return REBINDING;
	}
}

int estadoRebinding()
{
	struct respuesta respuesta;
	int s;

	memset(&respuesta, 0, sizeof(struct respuesta));

	s = crearSocket(1);
	respuesta = dhcpAckWithIP(s, INADDR_ANY);
	cerrarSocket(s);

	if (respuesta.mensaje == DHCPACK)
	{
		T1	= respuesta.leaseTime * T1CONST;
		T2	= (respuesta.leaseTime * T2CONST) - T1;
		Lease 	= respuesta.leaseTime - T1 - T2;

                if (opciones.depuracion)
                        printf("TIEMPOS T1: %f T2: %f LeaseTime: %f\n", T1, T2, Lease);

		return BOUND;
	}
	else
	{
		sleep(Lease);
		salir = 1;
		return EXIT;
	}
}

int estadoDecline()
{
	int s;

	s = crearSocketPacket();

	dhcpDecline(s);

	cerrarSocket(s);
	
	salir = 1;

	return EXIT;
}


/************************************************************************/
/*********************FUNCIONES PRINCIPAL (MAIN)*************************/
/************************************************************************/


int main (int argc, char *argv[]) 
{
	int s;
   
   	senal1.sa_handler = dhcpSigInt; 	   //Asociamos la funcion dhcpRelease al manejador
	senal1.sa_flags   = 0; 			   //Establecemos los flags por defecto 0
	sigemptyset (&senal1.sa_mask); 	   //Establecemos como vacia la mascara de la estructura
	sigaction (SIGINT, &senal1, NULL);    //Instalamos el manjeador asociado a SIGINT

	senal2.sa_handler = dhcpSigUser2; 	   //Asociamos la funcion dhcpRelease al manejador
	senal2.sa_flags   = 0; 			   //Establecemos los flags por defecto 0
	sigemptyset (&senal2.sa_mask); 	   //Establecemos como vacia la mascara de la estructura
	sigaction (SIGUSR2, &senal2, NULL);   //Instalamos el manjeador asociado a SIGUSR2

	memset(&opciones, 0, sizeof(struct opciones));

	if (cargarParametro(argc,argv) == 0)
	{
		if (!interfazActivo())
		{
			modificarInterfaz(1);

		   	obtenerDireccionHardware();

			while (!salir)
			{
				switch (estado)
				{
					case INIT:
								s = crearSocketPacket();	
								estado = estadoInit(s);								
								break;
					case SELECTING:
								estado = estadoSelecting(s);
								break;
					case REQUESTING:
								estado = estadoRequesting(s);
								cerrarSocket(s);
								break;
					case BOUND:
								estado = estadoBound();
								break;
					case RENEWING:
								estado = estadoRenewing();
								break;
					case REBINDING:
								estado = estadoRebinding();
								break;
					case DECLINE:
								estado = estadoDecline();
								break;
				}
			}
			
			if (interfazActivo())
                                modificarInterfaz(2);
                	else
                		fprintf(stderr, "Error: %s is already disabled.\n", opciones.interfaz);
			
		}
		else
		{
			fprintf(stderr,"Error: %s is already enabled.\n", opciones.interfaz);
		}
	}
   
   return 0;
}
