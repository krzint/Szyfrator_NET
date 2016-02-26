/*
 * Net_szyfr.c
 *
 *  Created on: 26-08-2014
 *      Author: Krzysiek
 */

#include <altera_avalon_sgdma.h>
#include <altera_avalon_sgdma_descriptor.h>
#include <altera_avalon_sgdma_regs.h>
#include <stdio.h>
#include "sys/alt_stdio.h"
#include "sys/alt_irq.h"
#include <unistd.h>
#include "Net_szyfr.h"
#include "system.h"
#include "sys/times.h"
#include <altera_avalon_performance_counter.h>
#include <altera_avalon_tse.h>


#include "sys/alt_alarm.h"

#include "lwip/init.h"
#include "lwip/netif.h"
//#include "lwip/dhcp.h"TODO
#include "lwip/tcp.h"
#include "lwip/udp.h"
//#include "lwip/stats.h"TODO
#include "lwip/ip_frag.h"
#include "lwip/ip_addr.h"
#include "netif/etharp.h"
//todo #include "alteraTseEthernetif.h"


void rx_ethernet_isr (void *context);
void rx_ethernet_isr1 (void *context);
void tdes_cryptpot_isr (void *context);
void tdes_decryptpot_isr (void *context);

void init_3des (unsigned int key11,unsigned int key12,unsigned int key21,unsigned int key22,unsigned int key31,unsigned int key32);

void init_3desdecrypt (unsigned int key11,unsigned int key12,unsigned int key21,unsigned int key22,unsigned int key31,unsigned int key32);

void init_3des_pot(unsigned int key11,unsigned int key12,unsigned int key21,unsigned int key22,unsigned int key31,unsigned int key32);

void ciph_3des ( unsigned int data1, unsigned int data2);
void ciph_3des_read ( unsigned int *cdata1, unsigned int *cdata2);
void paczka_szyfrowanie();
void paczka_deszyfrowanie();
void deciph_3des ( unsigned int data1, unsigned int data2);
void deciph_3des_read ( unsigned int *cdata1, unsigned int *cdata2);
void weryfikacja_szyfrowania ();
void weryfikacja_deszyfrowania ();
void test_wydajnosc ();
void przygotowanie_danych();
void przeprowadzenie_szyfrowania_sram();
void przeprowadzenie_deszyfrowania_sram();
void test_wydajnosci_sram();
void wprowadzenie_kluczy();

struct netif* inicjalizacja_netif( struct netif *netif);
unsigned int text_length;
unsigned int result1;
unsigned int result2;



//ramki testowe dla 3DES
unsigned char blok_testowy[1528] = { 0 };
unsigned char blok_wynikow[1528] = { 0 };
//ramki testowe dla deszyfratora 3DES
unsigned char blok_testowy_deszyfracja[1528] = { 0 };
unsigned char blok_wynikow_deszyfracja[1528] = { 0 };




// Utworzenie urzadzen SGDMA
alt_sgdma_dev * sgdma_tx_dev;
alt_sgdma_dev * sgdma_rx_dev;

alt_sgdma_dev * sgdma_tx_dev1;
alt_sgdma_dev * sgdma_rx_dev1;
//Urz¹dzenia SGDMA dla szyfratora 3DES
alt_sgdma_dev * sgdma_in_dev;
alt_sgdma_dev * sgdma_out_dev;
//Urz¹dzenia SGDMA dla deszyfratora 3DES
alt_sgdma_dev * sgdma_in_decrypt_dev;
alt_sgdma_dev * sgdma_out_decrypt_dev;


// Alokacja dekryptorow w pamieci deskryptorow dla TSE
//Dla pierwszego z³¹cza triple speed ethernet:
alt_sgdma_descriptor tx_descriptor		__attribute__ (( section ( ".descriptor_memory" )));
alt_sgdma_descriptor tx_descriptor_end	__attribute__ (( section ( ".descriptor_memory" )));

alt_sgdma_descriptor rx_descriptor  	__attribute__ (( section ( ".descriptor_memory" )));
alt_sgdma_descriptor rx_descriptor_end  __attribute__ (( section ( ".descriptor_memory" )));
//Dla drugiego zlacza triple speed ethernet:
alt_sgdma_descriptor tx_descriptor1		__attribute__ (( section ( ".descriptor_memory1" )));
alt_sgdma_descriptor tx_descriptor_end1	__attribute__ (( section ( ".descriptor_memory1" )));

alt_sgdma_descriptor rx_descriptor1 	__attribute__ (( section ( ".descriptor_memory1" )));
alt_sgdma_descriptor rx_descriptor_end1  __attribute__ (( section ( ".descriptor_memory1" )));


//Alokacja deskryptorów w pamiêci deskryptorów dla szyfratora 3DES
alt_sgdma_descriptor tdesin_descriptor		 __attribute__ (( section ( ".descriptor_memory_3des" )));
alt_sgdma_descriptor tdesin_descriptor_end	 __attribute__ (( section ( ".descriptor_memory_3des" )));

alt_sgdma_descriptor tdesout_descriptor 	 __attribute__ (( section ( ".descriptor_memory_3des" )));
alt_sgdma_descriptor tdesout_descriptor_end  __attribute__ (( section ( ".descriptor_memory_3des" )));

//Alokacja deskryptorów w pamiêci deskryptorów dla szyfratora 3DES
alt_sgdma_descriptor tdesdecryptin_descriptor		__attribute__ (( section ( ".descriptor_memory_3desdecrypt" )));
alt_sgdma_descriptor tdesdecryptin_descriptor_end	__attribute__ (( section ( ".descriptor_memory_3desdecrypt" )));

alt_sgdma_descriptor tdesdecryptout_descriptor 		__attribute__ (( section ( ".descriptor_memory_3desdecrypt" )));
alt_sgdma_descriptor tdesdecryptout_descriptor_end  __attribute__ (( section ( ".descriptor_memory_3desdecrypt" )));






//alokacja deskryptorow do obslugi pamieci SRAM
/*
alt_sgdma_descriptor read_descriptor		__attribute__ (( section ( ".descriptor_memory0" )));
alt_sgdma_descriptor read_descriptor_end	__attribute__ (( section ( ".descriptor_memory0" )));
*/




np_tse_mac *triple = (np_tse_mac*) ETH_TSE_BASE;

np_tse_mac *triple1 = (np_tse_mac*) ETH_TSE1_BASE;

unsigned int p1,p2,p3,p4,p5,p6;
unsigned int p7,p8;
unsigned int p9,p10;
unsigned int  dane[1024]={0};
unsigned int  wyniki[1024]={0};
unsigned int key11=0x01234567,  key12=0x89ABCDEF,  key21=0xFEDCAB89,  key22=0x76543210,  key31=0xF0E1D2C3,  key32=0xB4A59687;








struct pbuf *p;


int main (int argc, char* argv[], char* envp[])
{
	static struct ip_addr   ip_zero = { 0 };
/*
 * Deklaracja adresu MAC w netif( dla wersji z uzyciem pelnego lwIP)
 */
	TSE1netif.hwaddr[0] = 0x11;
	TSE1netif.hwaddr[1] = 0x6E;
	TSE1netif.hwaddr[2] = 0x60;
	TSE1netif.hwaddr[3] = 0x01;
	TSE1netif.hwaddr[4] = 0x0F;
	TSE1netif.hwaddr[5] = 0x02;


printf("Rozpoczecie dzialania programu\n");



	//Otworzenie SGDMA transmitujacego dane do TSE0
	sgdma_tx_dev = alt_avalon_sgdma_open ("/dev/sgdma_tx");
	if (sgdma_tx_dev == NULL) {
		printf ("Error: nie mozna otworzyc scatter-gather dma transmit device dla TSE0\n");
		return -1;
	} else printf ("Otworzono scatter-gather dma transmit device dla TSE0\n");
	//Otworzenie SGDMA odbierajacego dane z TSE0
	sgdma_rx_dev = alt_avalon_sgdma_open ("/dev/sgdma_rx");
	if (sgdma_rx_dev == NULL) {
		printf ("Error:  nie mozna otworzyc scatter-gather dma receive device dla TSE0\n");
		return -1;
	} else printf ("Otworzno scatter-gather dma receive device dla TSE0\n");
	printf ("System uruchomiony\n");
	//Zarejestrowanie wywo³ywania funkcji przy odebraniu danych z TSE0
	alt_avalon_sgdma_register_callback( sgdma_rx_dev, (alt_avalon_sgdma_callback) rx_ethernet_isr, 0x00000014, NULL );
	// Utworzenie odbiorczego deskryptora sgdma
	alt_avalon_sgdma_construct_stream_to_mem_desc( &rx_descriptor, &rx_descriptor_end, (alt_u32 *)rx_frame, 0, 0 );
	// Uruchomienie wykonywania nie blokuj¹cego zapisu z SGDMA TSE0
	alt_avalon_sgdma_do_async_transfer( sgdma_rx_dev, &rx_descriptor );

	//Otworzenie SGDMA transmitujacego dane do TSE1
	alt_avalon_sgdma_do_async_transfer( sgdma_rx_dev1, &rx_descriptor1 );
	sgdma_tx_dev1 = alt_avalon_sgdma_open ("/dev/sgdma_tx1");
	if (sgdma_tx_dev1 == NULL) {
		printf ("Error: nie mozna otworzyc scatter-gather dma transmit device dla TSE1\n");
			return -1;
		} else printf ("Otworzono scatter-gather dma transmit device dla TSE1\n");

	//Otworzenie SGDMA odbierajacego dane z TSE1
	sgdma_rx_dev1 = alt_avalon_sgdma_open ("/dev/sgdma_rx1");
	if (sgdma_rx_dev1 == NULL) {
		printf ("Error:  nie mozna otworzyc scatter-gather dma receive device dla TSE1\n");
		return -1;
	} else printf ("Otworzno scatter-gather dma receive device dla TSE1\n");
	printf ("System uruchomiony\n");
	//Zarejestrowanie wywo³ywania funkcji przy odebraniu danych z TSE1
	alt_avalon_sgdma_register_callback( sgdma_rx_dev1, (alt_avalon_sgdma_callback) rx_ethernet_isr1, 0x00000014, NULL );
	//// Utworzenie odbiorczego deskryptora sgdma
	alt_avalon_sgdma_construct_stream_to_mem_desc( &rx_descriptor1, &rx_descriptor_end1,(alt_u32 *) rx_frame1, 0, 0 );
	// Uruchomienie wykonywania nie blokuj¹cego zapisu z SGDMA TSE1
	alt_avalon_sgdma_do_async_transfer( sgdma_rx_dev1, &rx_descriptor1 );




	//Utworzenie SGDMA dla szyfratora potokowego Triple DES
	sgdma_out_dev = alt_avalon_sgdma_open ("/dev/sgdma_3des_out");
	if (sgdma_out_dev == NULL) {
		printf ("Error: nie mozna otworzyc scatter-gather dma odbieraj¹cego zaszyfrowane dane 3DES\n");
		return -1;
	} else printf ("Otworzono scatter-gather dma source-sink odberaj¹cy zaszyfrowane dane z szyfratora 3DES\n");

	sgdma_in_dev = alt_avalon_sgdma_open ("/dev/sgdma_3des_in");
	if (sgdma_in_dev == NULL) {
		printf ("Error: Nie mozna otworzyc scatter-gather dma przesy³aj¹ce dane do zaszyfrowania do szyfratora 3DES\n");
		return -1;
	} else alt_printf ("Otworzono scatter-gather dma sink-source device wysy³aj¹cy dane do szyfratora 3DES\n");
	// Utworzenie odbiorczego deskryptora sgdma
	alt_avalon_sgdma_construct_stream_to_mem_desc( &tdesout_descriptor, &tdesout_descriptor_end, (alt_u32 *)blok_wynikow, 0, 0 );
	// Uruchomienie wykonywania nie blokuj¹cego zapisu danych z SGDMA szyfratora 3des
	alt_avalon_sgdma_do_async_transfer( sgdma_out_dev, &tdesout_descriptor );


	//Uruchomienie SGDMA dla deszyfratora Triple DES
	sgdma_out_decrypt_dev = alt_avalon_sgdma_open ("/dev/sgdma_3desdecrypt_out");
	if (sgdma_out_decrypt_dev == NULL) {
		printf ("Error: nie mozna otworzyc scatter-gather dma odbieraj¹cego zdeszyfrowane dane 3DES\n");
		return -1;
	} else alt_printf ("Otworzono scatter-gather dma source-sink odberaj¹cy odkodowane dane z deszyfratora 3DES\n");

	sgdma_in_decrypt_dev = alt_avalon_sgdma_open ("/dev/sgdma_3desdecrypt_in");
	if (sgdma_in_decrypt_dev == NULL) {
		printf ("Error: Nie mozna otworzyc scatter-gather dma przesy³aj¹ce dane do zdeszyfrowania do deszyfratora 3DES\n");
		return -1;
	} else printf ("Otworzono scatter-gather dma sink-source device wysy³aj¹cy dane do deszyfratora 3DES\n");

	// Utworzenie odbiorczego deskryptora sgdma
	alt_avalon_sgdma_construct_stream_to_mem_desc( &tdesdecryptout_descriptor,
			&tdesdecryptout_descriptor_end, (alt_u32 *)blok_wynikow_deszyfracja, 0, 0 );
	// Uruchomienie wykonywania nie blokuj¹cego zapisu danych z SGDMA deszyfratora 3des
	alt_avalon_sgdma_do_async_transfer( sgdma_out_decrypt_dev, &tdesdecryptout_descriptor );




	printf ("Cale SGDMA uruchomione\n");

	// adresy bazowe komponentów Triple-speed Ethernet MegaCore
	volatile int * tse = (int *) ETH_TSE_BASE;
	volatile int * tse1 = (int *) ETH_TSE1_BASE;

	// Ustawienie adresu MAC 01-60-6E-11-02-0F na oba moduly TSE
	*(tse + 0x03) = 0x116E6001;
	*(tse + 0x04) = 0x00000F02;
	*(tse1 + 0x03) = 0x116E6001;
	*(tse1 + 0x04) = 0x00000F01;
	printf ("Ustalenie adresu MAC\n");
	//Okreslenie adresow urzadzen PHY do ktorych dostep odbywac sie bedzie przez interfejs MDIO
	*(tse + 0x0F) = 0x10;
	*(tse + 0x10) = 0x11;
	//Okreslenie adresow urzadzen PHY do ktorych dostep odbywac sie bedzie przez interfejs MDIO
	 *(tse1 + 0x0F) = 0x10;
	 *(tse1 + 0x10) = 0x11;
	 // Ustawienie crossoveru dla obu PHY
	 *(tse + 0x94) = 0x4000;
	 *(tse1 + 0x94) = 0x4000;


	 //Uruchomienie crosoveru dla PHY
	  *(tse + 0x90) = *(tse + 0x90) | 0x0060;
	 // Wprowadzenie opoznienia zegara wejsciowego i wyjsciowego
	  *(tse + 0x94) = *(tse + 0x94) | 0x0082;
	  *(tse1 + 0x94) = *(tse1 + 0x94) | 0x0082;

	  // Software reset obu chipow PHY
	  *(tse + 0x80) = *(tse + 0x80) | 0x8000;
		while ( *(tse + 0x80) & 0x8000  )
			;
	 *(tse1 + 0x02) = *(tse1 + 0x02) | 0x2000;
	 while ( *(tse1 + 0x02) & 0x2000  ) ; //sprawdzenie czy reset sie zakonczyl (sw_reset=0)
		 *(tse1 + 0xA0) = *(tse1 + 0xA0) | 0x8000;
 		while ( *(tse1 + 0xA0) & 0x8000  ) 			 ;

		printf("Udany reset obu modulow");
	// Umozliwienie zapisu i odczytu ramek z blednie wyliczonym CRC
	 *(tse + 2) = *(tse + 2) |0x040001F3;
	 *(tse1 + 2) = *(tse1 + 2) |0x040001F3;

	// printf( "send> \n" );
	 text_length = 0;
	// wprowadzenie_kluczy(); //Wprowadzenie wartosci kluczy ktore mialy byc uzywane przy transmisji Ethernet
	 weryfikacja_szyfrowania (); //tutaj ustawione zostaja wartosci kluczy szyfratora 3des
	 //usleep(2500000);
	 weryfikacja_deszyfrowania();//tutaj ustawione zostaja wartosci kluczy deszyfratora 3des
	 // TODO odkomentowac jezeli chce sie przeprowadzic test wydajnosci szyfrowania na ukladzie FPGA
	 test_wydajnosc ();
	test_wydajnosci_sram();
	test_wydajnosci_3des_pot();
	printf("adres udp_Data: %i", &blok_wynikow);
if (ifdecipher_udp==2)
	{
		printf("udp_data");
	}
	wprowadzenie_adresow_ip_do_3des();


	 while(1)
	 {
	 }


	return 0;

}


void rx_ethernet_isr (void *context)
{
	struct netif * netif = &TSE1netif;
	//Poczekanie na zakoñczenie odbioru ramki ethernetowej z³¹czem po³¹czonym z eth_tse
	while (alt_avalon_sgdma_check_descriptor_status(&rx_descriptor) != 0)
		;
	//zapisanie do zmiennej pklen dlugosci odebranej ramki ethernetowej
	pklen = IORD_16DIRECT(&(rx_descriptor.actual_bytes_transferred),0);

	memcpy(tx_frame,rx_frame,pklen);
	p->payload=tx_frame;
	// funkcja lwip ethernet_input obslugujaca ramkê Ethernetow¹
	ethernet_input(p,netif);

	//Wys³anie ramki ethernetowej z³¹czem po³¹czonym z eth_tse1
	alt_avalon_sgdma_construct_mem_to_stream_desc( &tx_descriptor1,
			&tx_descriptor_end1, (alt_u32 *)tx_frame, pklen-4, 0, 1, 1, 0 );
	alt_avalon_sgdma_do_async_transfer( sgdma_tx_dev1, &tx_descriptor1 );
	while (alt_avalon_sgdma_check_descriptor_status(&tx_descriptor1) != 0);

	//Ponowne skonsturowanie deskryptorów odbiorczych z³¹cza eth_tse
	alt_avalon_sgdma_construct_stream_to_mem_desc( &rx_descriptor,
			&rx_descriptor_end, (alt_u32 *)rx_frame, 0, 0 );

	alt_avalon_sgdma_do_async_transfer( sgdma_rx_dev, &rx_descriptor );

	//wyzerowanie pól z d³ugociami bufora lwIP
	p->len=0;
	p->tot_len=0;
}

void rx_ethernet_isr1 (void *context)
{
		struct netif * netif = &TSE1netif;
		//Poczekanie na zakoñczenie odbióru ramki ethernetowej z³¹czem po³¹czonym z eth_tse1
		while (alt_avalon_sgdma_check_descriptor_status(&rx_descriptor1) != 0)
			;
		//dl odebranej ramki
		pklen = IORD_16DIRECT(&(rx_descriptor1.actual_bytes_transferred),0);
		//printf("dlugosc odebranych danych to: %d",pklen);
		memcpy(tx_frame,rx_frame1,pklen);
		p->payload=tx_frame;


		ethernet_input(p,netif);


		alt_avalon_sgdma_construct_mem_to_stream_desc( &tx_descriptor, &tx_descriptor_end, (alt_u32 *)tx_frame, pklen-4, 0, 1, 1, 0 );
		alt_avalon_sgdma_do_async_transfer( sgdma_tx_dev, &tx_descriptor );
		while (alt_avalon_sgdma_check_descriptor_status(&tx_descriptor) != 0);

		alt_avalon_sgdma_construct_stream_to_mem_desc( &rx_descriptor1, &rx_descriptor_end1, (alt_u32 *)rx_frame1, 0, 0 );


		alt_avalon_sgdma_do_async_transfer( sgdma_rx_dev1, &rx_descriptor1 );
		p->len=0;
		p->tot_len=0;


}
/**
 * Wprowadzenie klucza do modulu szyfrujacego Triple DES
 */
void init_3des (unsigned int key11,unsigned int key12,unsigned int key21,unsigned int key22,unsigned int key31,unsigned int key32)
{
	IOWR_32DIRECT (A_3DESCRYPT_0_BASE,0x00000000,key11); //wprowadzenie pierwszej polowy klucza 1

	IOWR_32DIRECT (A_3DESCRYPT_0_BASE,0x00000004,key12); //wprowadzenie drugiej polowy klucza 1

	IOWR_32DIRECT (A_3DESCRYPT_0_BASE,0x00000008,key21);//wprowadzenie pierwszej polowy klucza 2

	IOWR_32DIRECT(A_3DESCRYPT_0_BASE,0x0000000C,key22); //wprowadzenie drugiej polowy klucza 2

	IOWR_32DIRECT ( A_3DESCRYPT_0_BASE,0x00000010,key31);//wprowadzenie pierwszej polowy klucza 3

	IOWR_32DIRECT(A_3DESCRYPT_0_BASE,0x000000014,key32); //wprowadzenie drugiej polowy klucza 3

}
/**
 * Wprowadzenie klucza do modulu deszyfrujacego Triple DES
 */
void init_3desdecrypt (unsigned int key11,unsigned int key12,unsigned int key21,unsigned int key22,unsigned int key31,unsigned int key32)
{
	IOWR_32DIRECT (A_3DESDECRYPT_0_BASE,0x00000000,key11); //wprowadzenie pierwszej polowy klucza 1

	IOWR_32DIRECT (A_3DESDECRYPT_0_BASE,0x00000004,key12);//wprowadzenie drugiej polowy klucza 1

	IOWR_32DIRECT (A_3DESDECRYPT_0_BASE,0x00000008,key21); //wprowadzenie pierwszej polowy klucza 2

	IOWR_32DIRECT(A_3DESDECRYPT_0_BASE,0x0000000C,key22); //wprowadzenie drugiej polowy klucza 2

	IOWR_32DIRECT ( A_3DESDECRYPT_0_BASE,0x00000010,key31);//wprowadzenie pierwszej polowy klucza 3

	IOWR_32DIRECT(A_3DESDECRYPT_0_BASE,0x000000014,key32); //wprowadzenie drugiej polowy klucza 3
}
/**
 * Funkcja realizujaca szyfrowanie z uzyciem modulu Triple DES
 */
void ciph_3des ( unsigned int data1, unsigned int data2)
{
	IOWR_32DIRECT(A_3DESCRYPT_0_BASE,0x00000018,data1); //Wprowadzenie pierwszej polowy danych
	IOWR_32DIRECT(A_3DESCRYPT_0_BASE,0x0000001C,data2); //Wprowadzenie drugiej polowy danych
	IOWR_32DIRECT(A_3DESCRYPT_0_BASE,0x00000024,0xFFFFFFFF); //Ustawienie wartosci rejestru kontrolnego start=1
	IOWR_32DIRECT(A_3DESCRYPT_0_BASE,0x00000024,0x00000000); //Ustawienie wartosci rejestru kontrolnego start=0

}
/**
 * Funkcja realizujaca deszyfrowanie z ucyciem modulu Triple DES
 */
void deciph_3des ( unsigned int data1, unsigned int data2)
{
	IOWR_32DIRECT(A_3DESDECRYPT_0_BASE,0x00000018,data1);//Wprowadzenie pierwszej polowy danych
	IOWR_32DIRECT(A_3DESDECRYPT_0_BASE,0x0000001C,data2);//Wprowadzenie drugiej polowy danych
	IOWR_32DIRECT(A_3DESDECRYPT_0_BASE,0x00000024,0xFFFFFFFF);//Ustawienie wartosci rejestru kontrolnego start=1
	IOWR_32DIRECT(A_3DESDECRYPT_0_BASE,0x00000024,0x00000000); //Ustawienie wartosci rejestru kontrolnego start=0

}
/**
 * Odczytanie zaszyfrowanych danych
 */
void ciph_3des_read ( unsigned int *cdata1, unsigned int *cdata2)
{
	(*cdata1) = IORD_32DIRECT(A_3DESCRYPT_0_BASE,0x00000040); //Odczytanie pierwszej polowy danych
	(*cdata2) = IORD_32DIRECT(A_3DESCRYPT_0_BASE,0x00000044); //Odczytanie drugiej polowy danych


}
/**
 * Odczytanie odszyfrowanych danych
 */
void deciph_3des_read ( unsigned int *cdata1, unsigned int *cdata2)
{
	(*cdata1) = IORD_32DIRECT(A_3DESDECRYPT_0_BASE,0x00000040); //Odczytanie pierwszej polowy danych
	(*cdata2) = IORD_32DIRECT(A_3DESDECRYPT_0_BASE,0x00000044); //Odczytanie drugiej polowy danych


}
/**
 * Funkcja weryfikujaca modul szufrujacy Triple DES dla wektorow i kluczy podanych przez NIST
 */
void weryfikacja_szyfrowania ()
{
	int i=0;
	init_3des(0x01234567,0x89ABCDEF,0x23456789,0xABCDEF01,0x456789AB,0xCDEF0123);//Wprowadzenie kluczy
	init_3des_pot(0x01234567,0x89ABCDEF,0x23456789,0xABCDEF01,0x456789AB,0xCDEF0123);
	ciph_3des(0x54686520,0x71756663); //wprowadzenie wektoru testowego

	blok_testowy[0]=0x54;
	blok_testowy[1]=0x68;
	blok_testowy[2]=0x65;
	blok_testowy[3]=0x20;
	blok_testowy[4]=0x71;
	blok_testowy[5]=0x75;
	blok_testowy[6]=0x66;
	blok_testowy[7]=0x63;

	blok_testowy[8]=0x6B;
	blok_testowy[9]=0x20;
	blok_testowy[10]=0x62;
	blok_testowy[11]=0x72;
	blok_testowy[12]=0x6F;
	blok_testowy[13]=0x77;
	blok_testowy[14]=0x6E;
	blok_testowy[15]=0x20;

	blok_testowy[16]=0x66;
	blok_testowy[17]=0x6F;
	blok_testowy[18]=0x78;
	blok_testowy[19]=0x20;
	blok_testowy[20]=0x6A;
	blok_testowy[21]=0x75;
	blok_testowy[22]=0x6D;
	blok_testowy[23]=0x70;

	blok_testowy[24]=0x54;
	blok_testowy[25]=0x68;
	blok_testowy[26]=0x65;
	blok_testowy[27]=0x20;
	blok_testowy[28]=0x71;
	blok_testowy[29]=0x75;
	blok_testowy[30]=0x66;
	blok_testowy[31]=0x63;


	blok_testowy[32]=0x6B;
	blok_testowy[33]=0x20;
	blok_testowy[34]=0x62;
	blok_testowy[35]=0x72;
	blok_testowy[36]=0x6F;
	blok_testowy[37]=0x77;
	blok_testowy[38]=0x6E;
	blok_testowy[39]=0x20;

	printf("Wynikiem szyfrowania powinien byæ: 0xA826FD8CE53B855F \n");
	ciph_3des_read(&result1,&result2);
	printf("Wynik szyfrowania to: 0x%X%X \n",result1,result2);
	//printf("Adres blok_testowy: %i \n", &blok_testowy);
	//printf("Adres blok_wynikow: %i \n", &blok_wynikow);
	printf("Wynikiem szyfrowania potokowego powinno byæ kolejno: 0xA826FD8CE53B855F , 0xCCE21C8112256FE6, 0x68D5C05DD9B6B900, 0xA826FD8CE53B855F , 0xCCE21C8112256FE6,\n");
	//printf("Wynik szyfrowania potokowego to:  \n");

		i=0;
	ciph_3des_pot(&blok_testowy,&blok_wynikow,40);

	//ciph_3des_pot(&blok_testowy,&blok_wynikow,40);
	//printf("Adres blok_testowy: %x \n",&blok_testowy);
	//printf("Adres blok_testowy: %x \n",&blok_testowy[32]);
	//printf("Adres blok_wynikow: %x \n",&blok_wynikow);
	//ciph_3des_pot(&blok_testowy,&blok_wynikow,40);
	//ciph_3des_pot(&blok_testowy,&blok_wynikow,16);

	printf("Wynik szyfrowania potokowego to:  \n");
	while (i<40)
	{
		if(blok_wynikow[i]>15)
		{
			if(i%8==0)
			{
				printf("\n0x%X",blok_wynikow[i]);
			}
			else
			{
				printf("%X",blok_wynikow[i]);
			}
		}
		else
		{
			if(i%8==0)
			{
				printf("\n0x0%X",blok_wynikow[i]);
			}
			else
			{
				printf("0%X",blok_wynikow[i]);
			}
		}
		i++;
	}
	printf("\n");
}
/**
 * Funkcja weryfikujaca modul deszufrujacy Triple DES dla wektorow i kluczy podanych przez NIST
 */
void weryfikacja_deszyfrowania ()
{
	unsigned int wynik1,wynik2;
	init_3desdecrypt(0x01234567,0x89ABCDEF,0x23456789,0xABCDEF01,0x456789AB,0xCDEF0123);//Wprowadzenie kluczy
	init_3des_decrypt_pot(0x456789AB,0xCDEF0123,0x23456789,0xABCDEF01,0x01234567,0x89ABCDEF);
	deciph_3des(result1,result2); //Wprowadzenie wyniku testu weryfikacji szyfrowania
	printf("Wynikiem deszyfrowania powinien byæ: 0x5468652071756663 \n");
	deciph_3des_read(&wynik1,&wynik2);
	printf("Wynik deszyfrowania to: 0x%X%X \n",wynik1,wynik2);

	blok_testowy_deszyfracja[0]=0xA8;
	blok_testowy_deszyfracja[1]=0x26;
	blok_testowy_deszyfracja[2]=0xFD;
	blok_testowy_deszyfracja[3]=0x8C;
	blok_testowy_deszyfracja[4]=0xE5;
	blok_testowy_deszyfracja[5]=0x3B;
	blok_testowy_deszyfracja[6]=0x85;
	blok_testowy_deszyfracja[7]=0x5F;

	blok_testowy_deszyfracja[8]=0xCC;
	blok_testowy_deszyfracja[9]=0xE2;
	blok_testowy_deszyfracja[10]=0x1C;
	blok_testowy_deszyfracja[11]=0x81;
	blok_testowy_deszyfracja[12]=0x12;
	blok_testowy_deszyfracja[13]=0x25;
	blok_testowy_deszyfracja[14]=0x6F;
	blok_testowy_deszyfracja[15]=0xE6;

	blok_testowy_deszyfracja[16]=0x68;
	blok_testowy_deszyfracja[17]=0xD5;
	blok_testowy_deszyfracja[18]=0xC0;
	blok_testowy_deszyfracja[19]=0x5D;
	blok_testowy_deszyfracja[20]=0xD9;
	blok_testowy_deszyfracja[21]=0xB6;
	blok_testowy_deszyfracja[22]=0xB9;
	blok_testowy_deszyfracja[23]=0x00;

	blok_testowy_deszyfracja[24]=0x68;
	blok_testowy_deszyfracja[25]=0xD5;
	blok_testowy_deszyfracja[26]=0xC0;
	blok_testowy_deszyfracja[27]=0x5D;
	blok_testowy_deszyfracja[28]=0xD9;
	blok_testowy_deszyfracja[29]=0xB6;
	blok_testowy_deszyfracja[30]=0xB9;
	blok_testowy_deszyfracja[31]=0x00;

	blok_testowy_deszyfracja[32]=0xA8;
	blok_testowy_deszyfracja[33]=0x26;
	blok_testowy_deszyfracja[34]=0xFD;
	blok_testowy_deszyfracja[35]=0x8C;
	blok_testowy_deszyfracja[36]=0xE5;
	blok_testowy_deszyfracja[37]=0x3B;
	blok_testowy_deszyfracja[38]=0x85;
	blok_testowy_deszyfracja[39]=0x5F;
	//printf("Adres blok_testowy_deszyfracja: %x \n",&blok_testowy_deszyfracja);
	//printf("Adres blok_wynikow_deszyfracja: %x \n",&blok_wynikow_deszyfracja);

	//deciph_3des_pot(&blok_testowy_deszyfracja,&blok_wynikow_deszyfracja,40);
	deciph_3des_pot(&blok_testowy_deszyfracja,&blok_wynikow_deszyfracja,40);
	//deciph_3des_pot(&blok_testowy_deszyfracja,&blok_wynikow_deszyfracja,24);
	printf("Wynikiem deszyfrowania potokowego powinno byæ kolejno: 0x5468652071756663, 0x6B2062726F776E20, 0x666F78206A756D70, 0x666F78206A756D70, 0x5468652071756663\n");
	printf("Wynik deszyfrowania potokowego to:  ");
	int i=0;
		while (i<40)
		{
			if(blok_wynikow_deszyfracja[i]>15)
			{
				if(i%8==0)
				{
					printf("\n0x%X",blok_wynikow_deszyfracja[i]);
				}
				else
				{
					printf("%X",blok_wynikow_deszyfracja[i]);
				}
			}
			else
			{
				if(i%8==0)
				{
					printf("\n0x0%X",blok_wynikow_deszyfracja[i]);
				}
				else
				{
					printf("0%X",blok_wynikow_deszyfracja[i]);
				}
			}
			i++;
		}
		printf("\n");
}
/**
 * Funkcja testujaca wydajnosc modulow Triple DES przy wykorzystaniu zapisu i odczytu danych na On-Chip Memory
 */
void test_wydajnosc ()
{
 printf ("Test wydajnosci \n");
	PERF_RESET(PERFORMANCE_COUNTER_0_BASE );
	PERF_START_MEASURING(PERFORMANCE_COUNTER_0_BASE);
	int i=0;
	int j=0;
	PERF_BEGIN(PERFORMANCE_COUNTER_0_BASE ,2); //rozpoczecie pracy 2 licznika mierzacego takty zegara
	while(i<512)
	{
		deciph_3des(dane[2*i],dane[2*i+1]);
		j--;
		j++;
		deciph_3des_read(&wyniki[2*i],&wyniki[2*i+1]);
		i++;
	}
	PERF_END(PERFORMANCE_COUNTER_0_BASE ,2); //zakonczenie pracy 2 licznika mierzacego takty zegara
	i=0;
	PERF_BEGIN(PERFORMANCE_COUNTER_0_BASE ,1);//rozpoczecie pracy 1 licznika mierzacego takty zegara
	while(i<512)
	 {
	ciph_3des(dane[2*i],dane[2*i+1]);
	j--;
	j++;
	ciph_3des_read(&wyniki[2*i],&wyniki[2*i+1]);
	i++;
	 }
	PERF_STOP_MEASURING(PERFORMANCE_COUNTER_0_BASE); //zakonczenie pracy wszystkich licznikow
	perf_print_formatted_report((void* )PERFORMANCE_COUNTER_0_BASE,	ALT_CPU_FREQ*2,2,"3Des 32Kbit szyfr","3Des 32Kbit deszyfr"); //generacja raportu
}
/**
 * Przeprowadzenie szyfrowania 4KB danych
 */
void paczka_szyfrowanie()
{	int j=0;
	while(j<512)
	{

		ciph_3des(dane[2*j],dane[2*j+1]);
		j--;
		j++;
		ciph_3des_read(&wyniki[2*j],&wyniki[2*j+1]);
		j++;

	}
}
/**
 * Przeprowadzenie deszyfrowania 4KB danych
 */
void paczka_deszyfrowanie()
{	int j=0;
	while(j<512)
	{

		deciph_3des(dane[2*j],dane[2*j+1]);
		j--;
		j++;
		deciph_3des_read(&wyniki[2*j],&wyniki[2*j+1]);
		j++;

	}
}
/**
 * funkcja generujaca 1MBdanych testowych i zapisujaca je w pamieci SRAM
 */
void przygotowanie_danych()
{
	int k=0;
	int sram_adres=0x200000;
	int j = 0;
	for (j=0 ; j<1024; j++)
	{
		//Generacja wektorow testowych z dokumentacji NIST
		if(j%6==0)
			dane[j]=0x54686520;
		else if(j%6==1)
			dane[j]=0x71756663;
		else if(j%6==2)
			dane[j]=0x6B206272;
		else if(j%6==3)
			dane[j]=0x6F776E20;
		else if(j%6==4)
			dane[j]=0x666F7820;
		else if(j%6==5)
			dane[j]=0x6A756D70;
	}
	//Zapis wektorow testowych do pamieci SRAM
	while(k<256){
	/*alt_avalon_sgdma_construct_mem_to_mem_desc(&read_descriptor,&read_descriptor_end,(alt_u32 *) *dane,(alt_u32*)sram_adres,(alt_u16)4096,0,0);
	alt_avalon_sgdma_do_async_transfer( sgdma_read_3des, &read_descriptor );
	while (alt_avalon_sgdma_check_descriptor_status(&read_descriptor) != 0);*/
	sram_adres+=4096;
	k++;
	}
}

/**
 * Przeprowadzenie szyfrowania 1MB danych w pamieci SRAM oraz zapisanie ich
 */
void przeprowadzenie_szyfrowania_sram()
{	printf("Rozpoczêcie testów szyfrowania 1MB danych metoda iteracyjna \n");
	int k=0;
	int sram_adres_read=0x200000; //adres do odczytu
	int sram_adres_write=sram_adres_read+1048576; //adres do zapisu

	while(k<256)
	{

	paczka_szyfrowanie();

	sram_adres_read+=4096;
	sram_adres_write+=4096;
	k++;
	}

}
/**
 * Przeprowadzenie deszyfrowania 1MB danych w pamieci SRAM oraz zapisanie ich
 */
void przeprowadzenie_deszyfrowania_sram()
{	printf("Rozpoczêcie testów deszyfrowania 1MB danych metoda iteracyjna\n");
	int k=0;
	int sram_adres_read=0x200000; //adres do odczytu
	int sram_adres_write=sram_adres_read+1048576; //adres do zapisu

	while(k<256)
	{

	paczka_deszyfrowanie();

	sram_adres_read+=4096;
	sram_adres_write+=4096;
	k++;
	}

}
/*
 * Test wydajnosci szyfrowania 1MB danych z zapisem i odczytem do pamieci SRAM
 */
void test_wydajnosci_sram()
{
	PERF_RESET(PERFORMANCE_COUNTER_0_BASE );
	PERF_START_MEASURING(PERFORMANCE_COUNTER_0_BASE);
	PERF_BEGIN(PERFORMANCE_COUNTER_0_BASE ,1); //uruchomienie 1 licznia
	przeprowadzenie_szyfrowania_sram();
	PERF_END(PERFORMANCE_COUNTER_0_BASE ,1); //wylaczenie 1 licznika
	PERF_BEGIN(PERFORMANCE_COUNTER_0_BASE ,2); // uruchomienie 2 licznika
	przeprowadzenie_deszyfrowania_sram();
	PERF_STOP_MEASURING(PERFORMANCE_COUNTER_0_BASE); //wylaczenie wszystkich licznikow
	perf_print_formatted_report((void* )PERFORMANCE_COUNTER_0_BASE,	ALT_CPU_FREQ*2,2,"Test szyfr 3DES(1MB)","Test deszyfr 3DES(1MB)");
}
/*
 *Funkcja do wprowadzenia przez uzytkownika kluczy szyfratora i deszyfratora Triple DES
 */
void wprowadzenie_kluczy()
{
	printf("Wprowadz 8 znaków pierwszej polowy klucza 1 w postaci szesnastkowej: ");
	scanf( "%x", &key11 );
	printf("Wprowadz 8 znaków drugiej polowe klucza 1 w postaci szesnastkowej: ");
	scanf( "%x", &key12 );
	printf("Wprowadz  8 znaków pierwszej polowe klucza 2 w postaci szesnastkowej: ");
	scanf( "%x", &key21 );
	printf("Wprowadz 8 znaków druga polowe klucza 2 w postaci szesnastkowej: ");
	scanf( "%x", &key22 );
	printf("Wprowadz pierwsza polowe klucza 3 w postaci szesnastkowej: ");
	scanf( "%x", &key31 );
	printf("Wprowadz 8 znaków drugiej polowe klucza 3 w postaci szesnastkowej: ");
	scanf( "%x", &key32 );

	init_3des(key11,key12,key21,key22,key31,key32); //wprowadzenie kluczy do szyfratora
	init_3desdecrypt(key11,key12,key21,key22,key31,key32); //wprowadzenie kluczy do deszyfratora
	printf ("zainializowano szyfrator\n");

}
/**
 * Wprowadzenie klucza do modulu szyfrujacego Triple DES potokowego
 */
void init_3des_pot (unsigned int key11,unsigned int key12,unsigned int key21,unsigned int key22,unsigned int key31,unsigned int key32)
{
	IOWR_32DIRECT (A_3DESCRYPT_POT_1_BASE,0x00000000,key11); //wprowadzenie pierwszej polowy klucza 1
	//unsigned int iserted_key11 = IORD_32DIRECT(A_3DESCRYPT_POT_1_BASE,0x0000001C);
	IOWR_32DIRECT (A_3DESCRYPT_POT_1_BASE,0x00000004,key12); //wprowadzenie drugiej polowy klucza 1
	//unsigned int iserted_key12 = IORD_32DIRECT(A_3DESCRYPT_POT_1_BASE,0x00000020);
	//printf("Klucz pierwszy: 0x%x%x \n",iserted_key11,iserted_key12);
	IOWR_32DIRECT (A_3DESCRYPT_POT_1_BASE,0x00000008,key21);//wprowadzenie pierwszej polowy klucza 2
	//unsigned int iserted_key21 = IORD_32DIRECT(A_3DESCRYPT_POT_1_BASE,0x00000024);
	IOWR_32DIRECT(A_3DESCRYPT_POT_1_BASE,0x0000000C,key22); //wprowadzenie drugiej polowy klucza 2
	//unsigned int iserted_key22 = IORD_32DIRECT(A_3DESCRYPT_POT_1_BASE,0x00000028);
	//printf("Klucz drugi: 0x%x%x \n",iserted_key21,iserted_key22);
	IOWR_32DIRECT ( A_3DESCRYPT_POT_1_BASE,0x00000010,key31);//wprowadzenie pierwszej polowy klucza 3
	//unsigned int iserted_key31 = IORD_32DIRECT(A_3DESCRYPT_POT_1_BASE,0x0000002C);
	IOWR_32DIRECT(A_3DESCRYPT_POT_1_BASE,0x000000014,key32); //wprowadzenie drugiej polowy klucza 3
	//unsigned int iserted_key32 = IORD_32DIRECT(A_3DESCRYPT_POT_1_BASE,0x00000030);
	//printf("Klucz trzeci: 0x%x%x \n",iserted_key31,iserted_key32);
}
/**
 * Wprowadzenie klucza do modulu  deszyfrujacego Triple DES potokowego
 */
void init_3des_decrypt_pot (unsigned int key11,unsigned int key12,unsigned int key21,unsigned int key22,unsigned int key31,unsigned int key32)
{
	IOWR_32DIRECT (A_3DESDECRYPT_POT_0_BASE,0x00000000,key11); //wprowadzenie pierwszej polowy klucza 1
	//unsigned int iserted_key11 = IORD_32DIRECT(A_3DESDECRYPT_POT_0_BASE,0x0000001C);
	IOWR_32DIRECT (A_3DESDECRYPT_POT_0_BASE,0x00000004,key12); //wprowadzenie drugiej polowy klucza 1
	//unsigned int iserted_key12 = IORD_32DIRECT(A_3DESDECRYPT_POT_0_BASE,0x00000020);
	//printf("Klucz pierwszy: 0x%x%x \n",iserted_key11,iserted_key12);
	IOWR_32DIRECT (A_3DESDECRYPT_POT_0_BASE,0x00000008,key21);//wprowadzenie pierwszej polowy klucza 2
	//unsigned int iserted_key21 = IORD_32DIRECT(A_3DESDECRYPT_POT_0_BASE,0x00000024);
	IOWR_32DIRECT(A_3DESDECRYPT_POT_0_BASE,0x0000000C,key22); //wprowadzenie drugiej polowy klucza 2
	//unsigned int iserted_key22 = IORD_32DIRECT(A_3DESDECRYPT_POT_0_BASE,0x00000028);
	//printf("Klucz drugi: 0x%x%x \n",iserted_key21,iserted_key22);
	IOWR_32DIRECT ( A_3DESDECRYPT_POT_0_BASE,0x00000010,key31);//wprowadzenie pierwszej polowy klucza 3
	//unsigned int iserted_key31 = IORD_32DIRECT(A_3DESDECRYPT_POT_0_BASE,0x0000002C);
	IOWR_32DIRECT(A_3DESDECRYPT_POT_0_BASE,0x000000014,key32); //wprowadzenie drugiej polowy klucza 3
	//unsigned int iserted_key32 = IORD_32DIRECT(A_3DESDECRYPT_POT_0_BASE,0x00000030);
	//printf("Klucz trzeci: 0x%x%x \n",iserted_key31,iserted_key32);
}

/**
 * Funkcja realizujaca szyfrowanie z uzyciem modulu potokowej wersji Triple DES
 */
void ciph_3des_pot ( unsigned char *data, unsigned char *ciph_data, unsigned int length)
{
	//przes³anie danych do zaszyfrowania:
	alt_avalon_sgdma_construct_mem_to_stream_desc( &tdesin_descriptor,
			&tdesin_descriptor_end, (alt_u32 *)data, length, 0, 1, 1, 0 );

	while(alt_avalon_sgdma_do_async_transfer( sgdma_in_dev, &tdesin_descriptor ) != 0)
	{		printf("Zapis do szyfratora 3DES sie nie powiodl\n");	}
	//zapis do pamieci zaszyfrowanych danych:
	alt_avalon_sgdma_construct_stream_to_mem_desc( &tdesout_descriptor,
			&tdesout_descriptor_end, (alt_u32 *)ciph_data, 0, 0 );

	while((alt_avalon_sgdma_do_async_transfer( sgdma_out_dev, &tdesout_descriptor ) != 0));
}

/**
 * Funkcja realizujaca deszyfrowanie z uzyciem modulu potokowej wersji Triple DES
 */
void deciph_3des_pot ( unsigned char *data, unsigned char *deciph_data, unsigned int length)
{
	//przes³anie do zdeszyfrowania:
	alt_avalon_sgdma_construct_mem_to_stream_desc( &tdesdecryptin_descriptor,
			&tdesdecryptin_descriptor_end, (alt_u32 *)data, length, 0, 1, 1, 0 );

	while(alt_avalon_sgdma_do_async_transfer( sgdma_in_decrypt_dev, &tdesdecryptin_descriptor ) != 0) ;
	//zapis do pamieci zdeszyfrowanych danych:
	alt_avalon_sgdma_construct_stream_to_mem_desc( &tdesdecryptout_descriptor,
			&tdesdecryptout_descriptor_end, (alt_u32 *) deciph_data, 0, 0 );

	while(alt_avalon_sgdma_do_async_transfer( sgdma_out_decrypt_dev, &tdesdecryptout_descriptor ) != 0) ;
}




void tdes_cryptpot_isr (void *context)
{




	//printf("tdes_cryptpot_isr \n");
	//while (alt_avalon_sgdma_check_descriptor_status(&tdesin_descriptor) != 0);
	/*while (alt_avalon_sgdma_check_descriptor_status(&tdesout_descriptor) != 0);
	alt_avalon_sgdma_construct_stream_to_mem_desc( &tdesout_descriptor, &tdesout_descriptor_end, (alt_u32 *)blok_wynikow, 0, 0 );

	alt_avalon_sgdma_do_async_transfer( sgdma_out_dev, &tdesout_descriptor );*/

}

void tdes_decryptpot_isr (void *context)
{




	//printf("tdes_decryptpot_isr \n");
	/*while (alt_avalon_sgdma_check_descriptor_status(&tdesdecryptout_descriptor) != 0)
				;
	//printf("deciph_3des_pot: 3 \n");
	alt_avalon_sgdma_construct_stream_to_mem_desc( &tdesdecryptout_descriptor, &tdesdecryptout_descriptor_end, (alt_u32 *) blok_wynikow_deszyfracja, 0, 0 );
	alt_avalon_sgdma_do_async_transfer( sgdma_out_decrypt_dev, &tdesdecryptout_descriptor );
*/
}
/*
 * Funkcja przeprowadzajaca pomiary szyfrowania 1 MB danych
 */
void test_wydajnosci_3des_pot()
{
	printf("Test wydajnosci potokowej realizacji szyfratora i deszyfratora Triple DES \n");
	PERF_RESET(PERFORMANCE_COUNTER_0_BASE );
	PERF_START_MEASURING(PERFORMANCE_COUNTER_0_BASE);
	int i=0;
	int j=0;
	PERF_BEGIN(PERFORMANCE_COUNTER_0_BASE ,2); //rozpoczecie pracy 2 licznika mierzacego takty zegara
	while(i<512)
	{
		ciph_3des_pot(&blok_testowy+2048*i,&blok_testowy+1048576+2048*i,2048);


		i++;
	}
	PERF_END(PERFORMANCE_COUNTER_0_BASE ,2); //zakonczenie pracy 2 licznika mierzacego takty zegara
	i=0;
	PERF_BEGIN(PERFORMANCE_COUNTER_0_BASE ,1);//rozpoczecie pracy 1 licznika mierzacego takty zegara
	while(i<512)
	 {
		deciph_3des_pot(&blok_testowy+2048*i,&blok_testowy+1048576+2048*i,2048);
		i++;
	 }
	PERF_STOP_MEASURING(PERFORMANCE_COUNTER_0_BASE); //zakonczenie pracy wszystkich licznikow
	perf_print_formatted_report((void* )PERFORMANCE_COUNTER_0_BASE,
			ALT_CPU_FREQ*2,2,"3Des_pot 1MB szyfr","3Des_pot 1MB deszyfr"); //generacja raportu

}

void wyswietl_wyniki_sz_dsz()
{	int i = 0;
	printf("Wynik szyfrowania potokowego to:  \n");
		while (i<40)
		{
			if(blok_wynikow[i]>15)
			{
				if(i%8==0)
				{
					printf("\n0x%X",blok_wynikow[i]);
				}
				else
				{
					printf("%X",blok_wynikow[i]);
				}
			}
			else
			{
				if(i%8==0)
				{
					printf("\n0x0%X",blok_wynikow[i]);
				}
				else
				{
					printf("0%X",blok_wynikow[i]);
				}
			}
			i++;
		}
}
void wprowadzenie_adresow_ip_do_3des()
{
	 udp_ciph_ip4_addr1=192;
	 udp_ciph_ip4_addr2=168;
	 udp_ciph_ip4_addr3=0;
	 udp_ciph_ip4_addr4=16;
	 udp_ciph_ip4_port=24;

	 udp_deciph_ip4_addr1=192;
	 udp_deciph_ip4_addr2=168;
	 udp_deciph_ip4_addr3=0;
	 udp_deciph_ip4_addr4=15;
	 udp_deciph_ip4_port=20;

	 ip_ciph_ip4_addr1=192;
	 ip_ciph_ip4_addr2=168;
	 ip_ciph_ip4_addr3=0;
	 ip_ciph_ip4_addr4=10;

	 ip_deciph_ip4_addr1=192;
	 ip_deciph_ip4_addr2=168;
	 ip_deciph_ip4_addr3=0;
	 ip_deciph_ip4_addr4=13;
}
struct netif* inicjalizacja_netif (struct netif *netif)
{

return netif;

}
