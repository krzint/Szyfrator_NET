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

#endif /* NET_SZYFR_H_ */
