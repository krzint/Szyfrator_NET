/*
 * Net_szyfr.h
 *
 *  Created on: 26-08-2013
 *      Author: Krzysiek
 */

#ifndef NET_SZYFR_H_
#define NET_SZYFR_H_
#include "system.h"
#include "alt_types.h"

void ciph_3des_pot( unsigned char *data, unsigned char *cipher_data,unsigned int length);
void deciph_3des_pot( unsigned char *data, unsigned char *cipher_data,unsigned int length);
void wprowadzenie_adresow_ip_do_3des();
void test_wydajnosci_3des_pot();
struct netif TSE1netif;

//Dlugosc odebranej ramki Ethernetowej (w bajtach)
int pklen;

// Utworzenie ramek odbiorczych
unsigned char rx_frame[1528];
unsigned char rx_frame1[1528];

unsigned char tx_frame[1528];
#endif /* NET_SZYFR_H_ */
