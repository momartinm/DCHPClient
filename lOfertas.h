/********************************************************
* Programa  : dhcpcl                                 	*
* Módulo    : dhcpcl.c                           	*
* Autor     : Moises Martinez Muñoz                 	*
* Autor     : Ignacio Alvarez Santiago       		*
*********************************************************/

#ifndef __LOFERTAS_H__
#define __LOFERTAS_H__

#include <arpa/inet.h>

typedef struct nodoOferta
{
	struct in_addr direccionServidor;
	struct in_addr direccionIP;
	u_long xid;
	struct nodoOferta *sgte;
} nodo;

typedef nodo* lOfertas;

int listaVacia(lOfertas l);
lOfertas ultimoNodo(lOfertas l);
lOfertas seleccionarOferta(lOfertas l, u_long direccion);
struct in_addr obtenerDirServer(lOfertas l);
struct in_addr obtenerDirIP(lOfertas l);
int obtenerXid(lOfertas l);
void insertar(lOfertas *l, struct in_addr direccionServidor, struct in_addr direccionIP, u_long xid);
void eliminar(lOfertas *l);

#endif
