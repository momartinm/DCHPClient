/********************************************************
* Programa  : dhcpcl                                 	*
* Módulo    : dhcpcl.c                           	*
* Autor     : Moises Martinez Muñoz                 	*
* Autor     : Ignacio Alvarez Santiago       		*
*********************************************************/


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "lOfertas.h"

/*******************************************************************************
Esta funcion nos indica si una lista esta vacia.
*******************************************************************************/
int listaVacia(lOfertas l)
{
	return l == NULL;
}

/*******************************************************************************
Esta funcion devuelve el ltimo elemento de una lista de dimesiones.
*******************************************************************************/
lOfertas ultimoNodo(lOfertas l)
{
	while (!listaVacia(l->sgte))
		l = l->sgte;
	return l;
}

/*******************************************************************************
Este metodo almacena una nueva variable indicando el tipo de variable y la linea
en la que sha sido definida esa variable.
*******************************************************************************/
static lOfertas nuevoNodo(struct in_addr direccionServidor, struct in_addr direccionIP, u_long xid)
{
	lOfertas aux;

	aux = (lOfertas) malloc(sizeof(struct nodoOferta));

	aux->direccionServidor  = direccionServidor;
	aux->direccionIP	= direccionIP;
	aux->xid		= xid;
	aux->sgte 		= NULL;
	
	return aux;
}

void insertar(lOfertas *l, struct in_addr direccionServidor, struct in_addr direccionIP, u_long xid)
{
        lOfertas nuevo = nuevoNodo(direccionServidor, direccionIP, xid);

        if (listaVacia(*l))
           *l = nuevo;
        else
            ultimoNodo(*l)->sgte = nuevo;
}


lOfertas seleccionarOferta(lOfertas l, u_long direccion)
{
        struct in_addr ip;
        lOfertas aux;

        if (direccion != 0)
        {
                aux = l;

                while (!listaVacia(aux))
                {
                        ip = obtenerDirIP(aux);

                        if (ip.s_addr == direccion)
                                return aux;
                        else
                                aux = aux->sgte;
                }
        }

        return l;
}

struct in_addr obtenerDirServer(lOfertas l)
{
        return l->direccionServidor;
}

struct in_addr obtenerDirIP(lOfertas l)
{
        return l->direccionIP;
}

int obtenerXid(lOfertas l)
{
        return l->xid;
}

/*******************************************************************************
Este método elimina todos los nodos de una lista de dimensiones.
*******************************************************************************/
void eliminar(lOfertas *l)
{
	lOfertas aux;

	while (!listaVacia(*l))
	{
		aux = *l;
		(*l) = (*l)->sgte;            
		free(aux);
	}
}
