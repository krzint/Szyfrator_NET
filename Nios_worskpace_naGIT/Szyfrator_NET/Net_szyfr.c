/*
 * Net_szyfr.c
 *
 *  Created on: 26-08-2013
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
#include "alteraTseEthernetif.h"


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
// Ramka transmisyjna
//unsigned char tx_frame[1024];
/* = {
		0x00,0x00,
		0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
		0x01,0x60,0x6E,0x11,0x02,0x0F,
		0x08,0x00,
		0x45,0x00,0x00,0x46,0x3B,0x26,0x00,0x00,0x80,0x11,0x7E,0x21,0xC0,0xA8,0x00,0x0E,
		0xC0,0xA8,0x00,0x01,0xD6,0x44,0x00,0x35,0x00,0x32,0x54,0xB5,0xC6,0x74,0x01,0x00,
		0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x0D,0x73,0x70,0x6F,0x63,0x2D,0x70,0x6F,
		0x6F,0x6C,0x2D,0x67,0x74,0x6D,0x06,0x6E,0x6F,0x72,0x74,0x6F,0x6E,0x03,0x63,0x6F,
		0x6D,0x00,0xDE,0xFA,0x98,0x1E,'\0'
};*/
// Utworzenie ramek odbiorczych
//unsigned char rx_frame[1024] = { 0 };
unsigned char rx_frame1[1024] = { 0 };

//TODO ramki testowe dla 3DES
unsigned char blok_testowy[1024] = { 0 };
unsigned char blok_wynikow[1024] = { 0 };
//TODO ramki testowe dla deszyfratora 3DES
unsigned char blok_testowy_deszyfracja[1024] = { 0 };
unsigned char blok_wynikow_deszyfracja[1024] = { 0 };



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


//  Zdefiniowanie netif dla lwIP
//struct netif    alteraTseNetif;
/* Base-Structure for all lwIP TSE information TODO do usuniecia */
typedef struct _lwip_tse_info
{
   tse_mac_trans_info mi; /* MAC base driver data. */

   // Location for the SGDMA Descriptors
   alt_sgdma_descriptor *desc;

   // lwIP Ethernetif structure
   struct ethernetif   *ethernetif;

   // Hardware location
   alt_tse_system_info *tse;

} lwip_tse_info;







//TODO zadeklarowac netif
struct pbuf *p;


int main (int argc, char* argv[], char* envp[])
{
	static struct ip_addr   ip_zero = { 0 };
/*
 * Deklaracja netif dla pierwszego zlacza Ethernet TODO zrobiæ to samo ale dla drugiego z³¹cza
 */
	TSE1netif.hwaddr[0] = 0x11;
	TSE1netif.hwaddr[1] = 0x6E;
	TSE1netif.hwaddr[2] = 0x60;
	TSE1netif.hwaddr[3] = 0x01;
	TSE1netif.hwaddr[4] = 0x0F;
	TSE1netif.hwaddr[5] = 0x02;

//dane=0;
	/**
	 * Inicjalizacja danych do szyfrowania
	 */


printf("Rozpoczecie dzialania programu\n");
	//init_3des ( key11,  key12,  key21,  key22,  key31,  key32);

	//lwip_init();
//TODO inicjalizacja netif_add
	if(netif_add(&TSE1netif, &ip_zero, &ip_zero, &ip_zero, TSE1netif.state, ethernetif_init, ethernet_input) == NULL)
		{
		printf( "Fatal error initializing...\n" );
		//for(;;);
		}
	//netif_set_default(&TSE1netif);

	// Initialize Altera TSE in a loop if waiting for a link
	printf("Waiting for link...");
	//while(((struct ethernetif *) TSE1netif.state)->link_alive!=1)
	//	{
		//mSdelay(1000);
	//	putchar('.');
		//tse_mac_init(0, TSE1netif.state);
	//	}
	printf("OK\n");

	//Otworzenie transmitujacego SGDMA dla TSE0
	sgdma_tx_dev = alt_avalon_sgdma_open ("/dev/sgdma_tx");
	if (sgdma_tx_dev == NULL) {
		alt_printf ("Error: nie mozna otworzyc scatter-gather dma transmit device dla TSE0\n");
		return -1;
	} else alt_printf ("Otworzono scatter-gather dma transmit device dla TSE0\n");

	//Otworzenie odbierajacego SGDMA dla TSE0
	sgdma_rx_dev = alt_avalon_sgdma_open ("/dev/sgdma_rx");
	if (sgdma_rx_dev == NULL) {
		alt_printf ("Error:  nie mozna otworzyc scatter-gather dma receive device dla TSE0\n");
		return -1;
	} else alt_printf ("Otworzno scatter-gather dma receive devicedla TSE0\n");
	printf ("System uruchomiony\n");
	alt_avalon_sgdma_register_callback( sgdma_rx_dev, (alt_avalon_sgdma_callback) rx_ethernet_isr, 0x00000014, NULL );

	// Utworzenie odbiorczego deskryptora sgdma
	alt_avalon_sgdma_construct_stream_to_mem_desc( &rx_descriptor, &rx_descriptor_end, (alt_u32 *)rx_frame, 0, 0 );

	alt_avalon_sgdma_do_async_transfer( sgdma_rx_dev, &rx_descriptor );

	// Uruchomienie drugiego SGDMA
	//
	//
	//Otworzenie transmitujacego SGDMA dla TSE1
	alt_avalon_sgdma_do_async_transfer( sgdma_rx_dev1, &rx_descriptor1 );
	sgdma_tx_dev1 = alt_avalon_sgdma_open ("/dev/sgdma_tx1");
	if (sgdma_tx_dev1 == NULL) {
		alt_printf ("Error: nie mozna otworzyc scatter-gather dma transmit device dla TSE1\n");
			return -1;
		} else alt_printf ("Otworzono scatter-gather dma transmit device dla TSE1\n");

	//Otworzenie odbierajacego SGDMA dla TSE1
	sgdma_rx_dev1 = alt_avalon_sgdma_open ("/dev/sgdma_rx1");
	if (sgdma_rx_dev1 == NULL) {
		alt_printf ("Error:  nie mozna otworzyc scatter-gather dma receive device dla TSE1\n");
		return -1;
	} else alt_printf ("Otworzno scatter-gather dma receive devicedla TSE1\n");
	printf ("System uruchomiony\n");

	alt_avalon_sgdma_register_callback( sgdma_rx_dev1, (alt_avalon_sgdma_callback) rx_ethernet_isr1, 0x00000014, NULL );

	//// Utworzenie odbiorczego deskryoptora sgdma
	alt_avalon_sgdma_construct_stream_to_mem_desc( &rx_descriptor1, &rx_descriptor_end1,(alt_u32 *) rx_frame1, 0, 0 );

	// Set up non-blocking transfer of sgdma receive descriptor
	alt_avalon_sgdma_do_async_transfer( sgdma_rx_dev1, &rx_descriptor1 );

	//Uruchomienie trzeciego SGDMA dla szyfratora Triple DES

	//
	sgdma_out_dev = alt_avalon_sgdma_open ("/dev/sgdma_3des_out");
	if (sgdma_out_dev == NULL) {
		alt_printf ("Error: nie mozna otworzyc scatter-gather dma odbieraj¹cego zaszyfrowane dane 3DES\n");
		return -1;
	} else alt_printf ("Otworzono scatter-gather dma source-sink odberaj¹cy zaszyfrowane dane z szyfratora 3DES\n");

	sgdma_in_dev = alt_avalon_sgdma_open ("/dev/sgdma_3des_in");
	if (sgdma_in_dev == NULL) {
		alt_printf ("Error: Nie mozna otworzyc scatter-gather dma przesy³aj¹ce dane do zaszyfrowania do szyfratora 3DES\n");
		return -1;
	} else alt_printf ("Otworzono scatter-gather dma sink-source device wysy³aj¹cy dane do szyfratora 3DES\n");

	//alt_avalon_sgdma_register_callback( sgdma_out_dev, (alt_avalon_sgdma_callback) tdes_cryptpot_isr, 0x00000014, NULL );

			// Utworzenie odbiorczego deskryptora sgdma
	alt_avalon_sgdma_construct_stream_to_mem_desc( &tdesout_descriptor, &tdesout_descriptor_end, (alt_u32 *)blok_wynikow, 0, 0 );

	alt_avalon_sgdma_do_async_transfer( sgdma_out_dev, &tdesout_descriptor );


	//Uruchomienie trzeciego SGDMA dla deszyfratora Triple DES

	//
	sgdma_out_decrypt_dev = alt_avalon_sgdma_open ("/dev/sgdma_3desdecrypt_out");
	if (sgdma_out_decrypt_dev == NULL) {
		alt_printf ("Error: nie mozna otworzyc scatter-gather dma odbieraj¹cego zdeszyfrowane dane 3DES\n");
		return -1;
	} else alt_printf ("Otworzono scatter-gather dma source-sink odberaj¹cy odkodowane dane z deszyfratora 3DES\n");

	sgdma_in_decrypt_dev = alt_avalon_sgdma_open ("/dev/sgdma_3desdecrypt_in");
	if (sgdma_in_decrypt_dev == NULL) {
		alt_printf ("Error: Nie mozna otworzyc scatter-gather dma przesy³aj¹ce dane do zdeszyfrowania do deszyfratora 3DES\n");
		return -1;
	} else alt_printf ("Otworzono scatter-gather dma sink-source device wysy³aj¹cy dane do deszyfratora 3DES\n");

	//alt_avalon_sgdma_register_callback( sgdma_out_dev, (alt_avalon_sgdma_callback) tdes_decryptpot_isr, 0x00000014, NULL );

			// Utworzenie odbiorczego deskryptora sgdma
	alt_avalon_sgdma_construct_stream_to_mem_desc( &tdesdecryptout_descriptor, &tdesdecryptout_descriptor_end, (alt_u32 *)blok_wynikow_deszyfracja, 0, 0 );

	alt_avalon_sgdma_do_async_transfer( sgdma_out_decrypt_dev, &tdesdecryptout_descriptor );




	printf ("Cale SGDMA uruchomione\n");
	/*
	 * weryfikacja_szyfrowania ();
	weryfikacja_deszyfrowania();
	przygotowanie_danych();

	*/
	// adresy bazoweTriple-speed Ethernet MegaCore
	volatile int * tse = (int *) ETH_TSE_BASE;
	//volatile int * tse = (int *) 0x103400;
	volatile int * tse1 = (int *) ETH_TSE1_BASE;
	//volatile int * tse1 = (int *) 0x103000;
	// Ustawienie adresu MAC 01-60-6E-11-02-0F na oba moduly TSE
	*(tse + 0x03) = 0x116E6001;
	*(tse + 0x04) = 0x00000F02;
	*(tse1 + 0x03) = 0x116E6001;
	*(tse1 + 0x04) = 0x00000F01;
	//  Wprowadzenie adresu Mac do netif
/*TODO TO JU¯ jest zrobione wy¿ej
		alteraTseNetif.hwaddr[0] = 0x11;
		alteraTseNetif.hwaddr[1] = 0x6E;
		alteraTseNetif.hwaddr[2] = 0x60;
		alteraTseNetif.hwaddr[3] = 0x01;
		alteraTseNetif.hwaddr[4] = 0x0F;
		alteraTseNetif.hwaddr[5] = 0x02;
*/
	//	alt_tse_mac_set_common_speed(ETH_TSE_BASE,2);
	printf ("Ustalenie adresu MAC\n");
// Okreslenie adresow urzadzen PHY do ktorych dostep odbywac sie bedzie przez interfejs MDIO
	 *(tse + 0x0F) = 0x10;
	*(tse + 0x10) = 0x11;
	//Okreslenie adresow urzadzen PHY do ktorych dostep odbywac sie bedzie przez interfejs MDIO
	 *(tse1 + 0x0F) = 0x10;
	 *(tse1 + 0x10) = 0x11;
	 // Write to register 20 of the PHY chip for Ethernet port 0 to set up line loopback
	 //*(tse + 0x94 ) = 0x4000;
	 // Ustawienie crossoveru dla obu PHY
	// *(tse + 0xA0) = *(tse + 0xA0) | 0x0060;
	/// *(tse1 + 0xB0) = *(tse1 + 0xB0) | 0x0060;
	 *(tse + 0x94) = 0x4000;
	 *(tse1 + 0x94) = 0x4000;


	 //Uruchomienie crosoveru dla PHY
	  *(tse + 0x90) = *(tse + 0x90) | 0x0060;
	 // *(tse1 + 0x90) = *(tse1 + 0x90) | 0x0060;
		//  *(tse1 + 0xB0) = *(tse1 + 0xB0) | 0x0060;
		 // Wprowadzenie opoznienia zegara wejsciowego i wyjsciowego

		///	 *(tse1 + 0xB4) = *(tse1 + 0xB4) | 0x0082;
	  *(tse + 0x94) = *(tse + 0x94) | 0x0082;
	  *(tse1 + 0x94) = *(tse1 + 0x94) | 0x0082;
	 // *(tse + 2) = *(tse + 2) | 0x02000043;
	  // Software reset obu chipow PHY
	  *(tse + 0x80) = *(tse + 0x80) | 0x8000;
		while ( *(tse + 0x80) & 0x8000  )
			;
	//*(tse1 + 0x80) = *(tse1 + 0x80) | 0x8000;
	//			while ( *(tse1 + 0x80) & 0x8000  )
		//			;
			// *(tse + 0x02) = *(tse + 0x02) | 0x2000;
		//	 while ( *(tse + 0x02) & 0x2000  ) ; //sprawdzenie czy reset sie zakonczyl (sw_reset=0)
		 *(tse1 + 0x02) = *(tse1 + 0x02) | 0x2000;
			 while ( *(tse1 + 0x02) & 0x2000  ) ; //sprawdzenie czy reset sie zakonczyl (sw_reset=0)
	 		 *(tse1 + 0xA0) = *(tse1 + 0xA0) | 0x8000;
 		while ( *(tse1 + 0xA0) & 0x8000  ) 			 ;
	 // Umozliwienie zapisu i odczytu oraz przesylania ramek z blednie wyliczonym CRC
		printf("Udany reset obu modulow");
///		 *(tse1 + 2) = *(tse1 + 2) | 0x02000043;
	// *(tse + 2 ) = *(tse + 2) | 0x0000004B;
	 *(tse + 2) = *(tse + 2) |0x040001F3;
	 *(tse1 + 2) = *(tse1 + 2) |0x040001F3;
	 alt_printf( "send> \n" );
	 text_length = 0;
	// wprowadzenie_kluczy(); //Wprowadzenie wartosci kluczy ktore mialy byc uzywane przy transmisji Ethernet
	 weryfikacja_szyfrowania ();
	 //usleep(2500000);
	 weryfikacja_deszyfrowania();
	 /* TODO odkomentowac na sam koniec
	 test_wydajnosc ();
	test_wydajnosci_sram();
	test_wydajnosci_3des_pot();
*/
	wprowadzenie_adresow_ip_do_3des();
	 //wyswietl_wyniki_sz_dsz();
	 //wyswietl_wyniki_sz_dsz();
	 //weryfikacja_szyfrowania ();

	// weryfikacja_deszyfrowania ();
	// weryfikacja_szyfrowania ();
	 //wyswietl_wyniki_sz_dsz();
	//wyswietl_wyniki_sz_dsz();
	/*while (1) {

		char new_char;
	//	tx_frame[16] = '\0';


		while ( (new_char = alt_getchar()) != '\n'  ) {

			if (new_char == 0x08 && text_length > 0) {
				alt_printf( "%c", new_char );
				text_length--;

				// Maintain the terminal character after the text
				tx_frame[16 + text_length] = '\0';

			} else if (text_length < 45) {
				//alt_printf( "%c", new_char );
				unsigned int bajt1, tmp;
				unsigned char bajt2=0x1024000;
				unsigned char szyfr_new_char;


				//szyfr_new_char=IORD(SZYFRXOR_0_BASE,0);
				// Add the new character to the output text
				tx_frame[16 + text_length] = new_char;
				text_length++;
				//printf ("wewnatrz tu	 tu");
				tx_frame[16 + text_length] = '\0';
				//alt_printf( "%c", szyfr_new_char );
			//	printf( "x%2X", new_char);
		//		printf( "x%2X", szyfr_new_char);
			//	printf( "x%2X", bajt2);
			//	printf ("%s", rx_frame);
				//printf( "x%2X", bajt2);
			}
		}
	//	*phy1 = *(tse + 0x2C);
		//printf("Liczba odebranych pakietow: %X",phy1);
		//alt_printf( "\nsend> " );
		//text_length = 0;
		//usleep(2000000);

		//alt_avalon_sgdma_construct_mem_to_stream_desc( &tx_descriptor, &tx_descriptor_end, rx_frame, 90, 0, 1, 1, 0 );
		//alt_avalon_sgdma_do_async_transfer( sgdma_tx_dev, &tx_descriptor );
		//while (alt_avalon_sgdma_check_descriptor_status(&tx_descriptor) != 0)
		//	;
	}
*/

	 while(1)
	 {	//printf("petla while odbieranie i wysylanie");

	//	 while (alt_avalon_sgdma_check_descriptor_status(&rx_descriptor) != 0);

		// printf("petla while odbieranie i wysylanie");

	 }
	 //TODO
	 /*	int j=0;
	 	printf("WYpisanie adresow pamieci dla blok_testowy\n");
	 	while (j<64)
	 	{
	 		printf("blok_testowy %i : %i \n", j,&blok_testowy[j]);
	 		j++;
	 	}
	 	j=0;
	 	printf("WYpisanie adresow pamieci dla blok_wynikow \n");
		while (j<64)
		{
			printf("blok_wynikow %i : %i \n", j,&blok_wynikow[j]);
			j++;
		}
*/
	return 0;

}


void rx_ethernet_isr (void *context)
{
	//int i;
	//DLugosc pakietu

	struct netif * netif = &TSE1netif;
	//lwip_tse_info* tse_ptr = (lwip_tse_info *) context;


	// Wait until receive descriptor transfer is complete
	while (alt_avalon_sgdma_check_descriptor_status(&rx_descriptor) != 0)
		;
	pklen = IORD_16DIRECT(&(rx_descriptor.actual_bytes_transferred),0);
	//printf("dlugosc odebranych danych to: %d",pklen);
	// Clear input line before writing
	//for (i = 0; i < (6 + text_length); i++) {
	//	alt_printf( "%c", 0x08 );		 // 0x1024008 --> backspace
	//}

	// Output received text
//	alt_printf( "receive> %s\n", rx_frame + 16  );
	//i=0;
	// Set up non-blocking transfer of sgdma receive descriptor

	//int speed=alt_tse_mac_get_common_speed( ETH_TSE_BASE);
	//printf("Currents speed:  %i",speed);
	//printf("\n");
	//unsigned int *readtse;
	//*readtse=
	//volatile int * tse = (int *) ETH_TSE_BASE;
	//*(tse + 0x3A)=0x00040000;

	 //printf("Readtse : %i",readtse);
//	printf("\n");
	//		printf("odebrano ramke \n");
			//TODO usunac dla poprawienia wydajnosci
	/*while(i<pklen)
	 {
				alt_printf( "%x", rx_frame[i] );
				i++;// 0x1024008 --> backspaces
				if (rx_frame[i] =='\n')
				{
					i=1024;
				}
			}*/

	memcpy(tx_frame,rx_frame,pklen);
	p->payload=tx_frame;
	//TODO ogarnac to: ethernet_input
	ethernet_input(p,netif);

	// Reprint current input line after the outputs
//	alt_printf( "send> %s", tx_frame + 16 );
	//i=0;
	/*while (i<7)
	{
	tx_frame[i]=0x55;
	i++;
	}
	tx_frame[7]=0xD5;*/
	//TODO zooptymalizowac to uzyc memcpy:
	/*while (i<8)
		{
			tx_frame[i]=0xFF;
			i++;
		}
		tx_frame[0]=0x00;
		tx_frame[1]=0x00;
		tx_frame[8]=0x01;
		tx_frame[9]=0x60;
		tx_frame[10]=0x6E;
		tx_frame[11]=0x11;
		tx_frame[12]=0x02;
		tx_frame[13]=0x0F;*/
/*	while (i<8)
	{
		rx_frame[i]=0xFF;
		i++;
	}
	//TODO ustawienie adresu MAC wychodzacego i przychodzacego mozna wylaczyc, ze wzgledu na uczynienie system "przezroczystym"
	rx_frame[0]=0x00;
	rx_frame[1]=0x00;
	rx_frame[8]=0x01;
	rx_frame[9]=0x60;
	rx_frame[10]=0x6E;
	rx_frame[11]=0x11;
	rx_frame[12]=0x02;
	rx_frame[13]=0x0F;*/
	//Poprawic wartosc pklen na inna
	//tx_frame[12]=0x08;
	//tx_frame[13]=0x00;
	//i=14;
	/*
	while (i <pklen-4)
	{
		tx_frame[i]=rx_frame[i];
		i++;
	}*/

	//tx_frame[88]='\0';
	//TODO uaktualnic wartosc pklen UAKTUALNIONA JEST W INNYM MIEJSCU
	/*
	alt_avalon_sgdma_construct_mem_to_stream_desc( &tx_descriptor1, &tx_descriptor_end1, (alt_u32 *)tx_frame, pklen-4, 0, 1, 1, 0 );
	alt_avalon_sgdma_do_async_transfer( sgdma_tx_dev, &tx_descriptor1 );
	while (alt_avalon_sgdma_check_descriptor_status(&tx_descriptor1) != 0);
*/
	alt_avalon_sgdma_construct_mem_to_stream_desc( &tx_descriptor, &tx_descriptor_end, (alt_u32 *)tx_frame, pklen-4, 0, 1, 1, 0 );
	alt_avalon_sgdma_do_async_transfer( sgdma_tx_dev, &tx_descriptor );
	while (alt_avalon_sgdma_check_descriptor_status(&tx_descriptor) != 0);
	//ff_tx_eop=1;
	alt_avalon_sgdma_construct_stream_to_mem_desc( &rx_descriptor, &rx_descriptor_end, (alt_u32 *)rx_frame, 0, 0 );

	alt_avalon_sgdma_do_async_transfer( sgdma_rx_dev, &rx_descriptor );


	//alt_avalon_sgdma_do_async_transfer( sgdma_rx_dev, &rx_descriptor );

	p->len=0;
	p->tot_len=0;

	printf("\n");
	printf("zakonczono odbior ramki\n");

	// Create new receive sgdma descriptor
	//	alt_avalon_sgdma_construct_stream_to_mem_desc( &rx_descriptor, &rx_descriptor_end, (alt_u32 *)rx_frame, 0, 0 );
}

void rx_ethernet_isr1 (void *context)
{
		int i;
		struct netif * netif = &TSE1netif;
		// Wait until receive descriptor transfer is complete
		while (alt_avalon_sgdma_check_descriptor_status(&rx_descriptor1) != 0)
			;
		printf( "Drugie zlacze odebralo ramke \n" );
		pklen = IORD_16DIRECT(&(rx_descriptor1.actual_bytes_transferred),0);
		printf("dlugosc odebranych danych to: %d",pklen);
		memcpy(tx_frame,rx_frame1,pklen);
		p->payload=tx_frame;

		//TODO ogarnac to: ethernet_input
		ethernet_input(p,netif);

		// Clear input line before writing
	/*	for (i = 0; i < (6 + text_length); i++) {
			alt_printf( "%c", 0x08 );		 // 0x1024008 --> backspace
		}

		// Output received text
	//	alt_printf( "receive> %s\n", rx_frame + 16  );
		i=0;
		while(rx_frame1[i] != NULL)
		 {
					printf( "%c", rx_frame1[i] );
					i++;// 0x1024008 --> backspace
				}
				*/
		// Reprint current input line after the output
		//alt_printf( "send> %s", tx_frame + 16 );

		// Create new receive sgdma descriptor
		alt_avalon_sgdma_construct_mem_to_stream_desc( &tx_descriptor, &tx_descriptor_end, (alt_u32 *)tx_frame, pklen-4, 0, 1, 1, 0 );
		alt_avalon_sgdma_do_async_transfer( sgdma_tx_dev, &tx_descriptor );
		while (alt_avalon_sgdma_check_descriptor_status(&tx_descriptor) != 0);

		alt_avalon_sgdma_construct_stream_to_mem_desc( &rx_descriptor1, &rx_descriptor_end1, (alt_u32 *)rx_frame1, 0, 0 );

		// Set up non-blocking transfer of sgdma receive descriptor
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
	/*alt_avalon_sgdma_construct_mem_to_mem_desc(&read_descriptor,&read_descriptor_end,(alt_u32 *) sram_adres_read,(alt_u32*)*dane,(alt_u16)4096,0,0);
	alt_avalon_sgdma_do_async_transfer( sgdma_read_3des, &read_descriptor );
	while (alt_avalon_sgdma_check_descriptor_status(&read_descriptor) != 0);
	*/
	paczka_szyfrowanie();
	/*alt_avalon_sgdma_construct_mem_to_mem_desc(&read_descriptor,&read_descriptor_end,(alt_u32 *) *wyniki,(alt_u32*)sram_adres_write,(alt_u16)4096,0,0);
	alt_avalon_sgdma_do_async_transfer( sgdma_read_3des, &read_descriptor );
	while (alt_avalon_sgdma_check_descriptor_status(&read_descriptor) != 0);*/
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
	/*alt_avalon_sgdma_construct_mem_to_mem_desc(&read_descriptor,&read_descriptor_end,(alt_u32 *) sram_adres_read,(alt_u32*)*dane,(alt_u16)4096,0,0);
	alt_avalon_sgdma_do_async_transfer( sgdma_read_3des, &read_descriptor );
	while (alt_avalon_sgdma_check_descriptor_status(&read_descriptor) != 0);
	*/
	paczka_deszyfrowanie();
	/*alt_avalon_sgdma_construct_mem_to_mem_desc(&read_descriptor,&read_descriptor_end,(alt_u32 *) *wyniki,(alt_u32*)sram_adres_write,(alt_u16)4096,0,0);
	alt_avalon_sgdma_do_async_transfer( sgdma_read_3des, &read_descriptor );
	while (alt_avalon_sgdma_check_descriptor_status(&read_descriptor) != 0);*/
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
	unsigned int iserted_key11 = IORD_32DIRECT(A_3DESCRYPT_POT_1_BASE,0x0000001C);

	IOWR_32DIRECT (A_3DESCRYPT_POT_1_BASE,0x00000004,key12); //wprowadzenie drugiej polowy klucza 1
	unsigned int iserted_key12 = IORD_32DIRECT(A_3DESCRYPT_POT_1_BASE,0x00000020);
	printf("Klucz pierwszy: 0x%x%x \n",iserted_key11,iserted_key12);

	IOWR_32DIRECT (A_3DESCRYPT_POT_1_BASE,0x00000008,key21);//wprowadzenie pierwszej polowy klucza 2
	unsigned int iserted_key21 = IORD_32DIRECT(A_3DESCRYPT_POT_1_BASE,0x00000024);

	IOWR_32DIRECT(A_3DESCRYPT_POT_1_BASE,0x0000000C,key22); //wprowadzenie drugiej polowy klucza 2
	unsigned int iserted_key22 = IORD_32DIRECT(A_3DESCRYPT_POT_1_BASE,0x00000028);
	printf("Klucz drugi: 0x%x%x \n",iserted_key21,iserted_key22);

	IOWR_32DIRECT ( A_3DESCRYPT_POT_1_BASE,0x00000010,key31);//wprowadzenie pierwszej polowy klucza 3
	unsigned int iserted_key31 = IORD_32DIRECT(A_3DESCRYPT_POT_1_BASE,0x0000002C);

	IOWR_32DIRECT(A_3DESCRYPT_POT_1_BASE,0x000000014,key32); //wprowadzenie drugiej polowy klucza 3
	unsigned int iserted_key32 = IORD_32DIRECT(A_3DESCRYPT_POT_1_BASE,0x00000030);
	printf("Klucz trzeci: 0x%x%x \n",iserted_key31,iserted_key32);
}
/**
 * Wprowadzenie klucza do modulu  deszyfrujacego Triple DES potokowego
 */
void init_3des_decrypt_pot (unsigned int key11,unsigned int key12,unsigned int key21,unsigned int key22,unsigned int key31,unsigned int key32)
{
	IOWR_32DIRECT (A_3DESDECRYPT_POT_0_BASE,0x00000000,key11); //wprowadzenie pierwszej polowy klucza 1
	unsigned int iserted_key11 = IORD_32DIRECT(A_3DESDECRYPT_POT_0_BASE,0x0000001C);

	IOWR_32DIRECT (A_3DESDECRYPT_POT_0_BASE,0x00000004,key12); //wprowadzenie drugiej polowy klucza 1
	unsigned int iserted_key12 = IORD_32DIRECT(A_3DESDECRYPT_POT_0_BASE,0x00000020);
	//printf("Klucz pierwszy: 0x%x%x \n",iserted_key11,iserted_key12);

	IOWR_32DIRECT (A_3DESDECRYPT_POT_0_BASE,0x00000008,key21);//wprowadzenie pierwszej polowy klucza 2
	unsigned int iserted_key21 = IORD_32DIRECT(A_3DESDECRYPT_POT_0_BASE,0x00000024);

	IOWR_32DIRECT(A_3DESDECRYPT_POT_0_BASE,0x0000000C,key22); //wprowadzenie drugiej polowy klucza 2
	unsigned int iserted_key22 = IORD_32DIRECT(A_3DESDECRYPT_POT_0_BASE,0x00000028);
	//printf("Klucz drugi: 0x%x%x \n",iserted_key21,iserted_key22);

	IOWR_32DIRECT ( A_3DESDECRYPT_POT_0_BASE,0x00000010,key31);//wprowadzenie pierwszej polowy klucza 3
	unsigned int iserted_key31 = IORD_32DIRECT(A_3DESDECRYPT_POT_0_BASE,0x0000002C);

	IOWR_32DIRECT(A_3DESDECRYPT_POT_0_BASE,0x000000014,key32); //wprowadzenie drugiej polowy klucza 3
	unsigned int iserted_key32 = IORD_32DIRECT(A_3DESDECRYPT_POT_0_BASE,0x00000030);
	//printf("Klucz trzeci: 0x%x%x \n",iserted_key31,iserted_key32);
}
/**
 * Funkcja realizujaca szyfrowanie z uzyciem modulu potowej wersji Triple DES
 */
void ciph_3des_pot ( unsigned char *data, unsigned char *ciph_data, unsigned int length)
{
		/*alt_avalon_sgdma_construct_stream_to_mem_desc( &tdesout_descriptor, &tdesout_descriptor_end, ciph_data, 0, 0 );
		//printf("tdesout_descriptor: %i \n",tdesout_descriptor);
		//printf("Adres blok blok_wynikow: %i \n",&blok_wynikow );
		 if(alt_avalon_sgdma_do_async_transfer( sgdma_out_dev, &tdesout_descriptor ) != 0)
		  {
			printf("Zapis od szyfratora 3DES do pamieci sie nie powiodl\n");

		  }
*/
	//int i=0;
	/*
	printf("ciph_3des_pot, DANE DO ZASZYFROWANIA: \n");
	while(i<length)
		{

			if(data[i]>15)
					{
						if(i%8==0)
						{
							printf("\n0x%X",data[i]);
						}
						else
						{
							printf("%X",data[i]);
						}
					}
					else
					{
						if(i%8==0)
						{
							printf("\n0x0%X",data[i]);
						}
						else
						{
							printf("0%X",data[i]);
						}
					}

			i++;
		}
	*/
	//printf("ciph_3des_pot: 1 data: %x \n",&data);
	//while (alt_avalon_sgdma_check_descriptor_status(&tdesdecryptout_descriptor) != 0);
	//while (alt_avalon_sgdma_check_descriptor_status(&tdesdecryptin_descriptor) != 0);
	//data+=4;
	alt_avalon_sgdma_construct_mem_to_stream_desc( &tdesin_descriptor, &tdesin_descriptor_end, (alt_u32 *)data, length, 0, 1, 1, 0 );
	//printf("length: %i \n",length);
	//printf("tdesin_descriptor: %i \n",tdesin_descriptor);
	printf("Adres blok testowy: %i \n",data);
	//printf("Adres blok testowy: %i \n",&blok_testowy);
	//printf("Adres blok wynikow: %i \n",ciph_data);
	//printf("tdesin_descriptor_end: %i \n",tdesin_descriptor_end);
	//alt_avalon_sgdma_do_async_transfer( sgdma_in_dev, &tdesin_descriptor ) ;

	while(alt_avalon_sgdma_do_async_transfer( sgdma_in_dev, &tdesin_descriptor ) != 0)
	{
		printf("Zapis do szyfratora 3DES sie nie powiodl\n");

	}

	//while (alt_avalon_sgdma_check_descriptor_status(&tdesin_descriptor) != 0);
	//ff_tx_eop=1;
	//while (alt_avalon_sgdma_check_descriptor_status(&tdesin_descriptor) != 0)
	//	;
	//printf("ciph_3des_pot: 2 \n");

	//printf("ciph_3des_pot: 3 , ciph_data: %x \n",&ciph_data);
	//while (alt_avalon_sgdma_check_descriptor_status(&tdesout_descriptor) != 0)
	//					;
	//printf("tdesout_descriptor: %X \n",&tdesout_descriptor);


	alt_avalon_sgdma_construct_stream_to_mem_desc( &tdesout_descriptor, &tdesout_descriptor_end, (alt_u32 *)ciph_data+4, 0, 0 );
	//alt_avalon_sgdma_do_async_transfer( sgdma_out_dev, &tdesout_descriptor );
	while((alt_avalon_sgdma_do_async_transfer( sgdma_out_dev, &tdesout_descriptor ) != 0))
	{

	}

	//printf("tdesout_descriptor: %i \n",tdesout_descriptor);
	//printf("Adres blok blok_wynikow: %i \n",&blok_wynikow );
	/* if(alt_avalon_sgdma_do_async_transfer( sgdma_out_dev, &tdesout_descriptor ) != 0)
	  {
		printf("Zapis od szyfratora 3DES do pamieci sie nie powiodl\n");

	  }
	// while (alt_avalon_sgdma_check_descriptor_status(&tdesout_descriptor) != 0)
	// 						;
	 i=0;
	 /*	printf("ciph_3des_pot, DANE PO ZASZYFROWANIU: \n");
	 	while(i<length)
	 		{

	 			if(ciph_data[i]>15)
	 					{
	 						if(i%8==0)
	 						{
	 							printf("\n0x%X",ciph_data[i]);
	 						}
	 						else
	 						{
	 							printf("%X",ciph_data[i]);
	 						}
	 					}
	 					else
	 					{
	 						if(i%8==0)
	 						{
	 							printf("\n0x0%X",ciph_data[i]);
	 						}
	 						else
	 						{
	 							printf("0%X",ciph_data[i]);
	 						}
	 					}

	 			i++;
	 		}*/
}

/**
 * Funkcja realizujaca deszyfrowanie z uzyciem modulu potowej wersji Triple DES
 */
void deciph_3des_pot ( unsigned char *data, unsigned char *deciph_data, unsigned int length)
{
	//while (alt_avalon_sgdma_check_descriptor_status(&tdesdecryptout_descriptor) != 0);

	alt_avalon_sgdma_construct_mem_to_stream_desc( &tdesdecryptin_descriptor, &tdesdecryptin_descriptor_end, (alt_u32 *)data, length, 0, 1, 1, 0 );
	//alt_avalon_sgdma_do_async_transfer( sgdma_in_decrypt_dev, &tdesdecryptin_descriptor );
	while(alt_avalon_sgdma_do_async_transfer( sgdma_in_decrypt_dev, &tdesdecryptin_descriptor ) != 0) ;
	//printf("deciph_3des_pot: 1 \n");
	//while (alt_avalon_sgdma_check_descriptor_status(&tdesdecryptin_descriptor) != 0);
	//ff_tx_eop=1;
	//while (alt_avalon_sgdma_check_descriptor_status(&tdesin_descriptor) != 0)
	//	;
	//printf("deciph_3des_pot: 2 \n");
	//while (alt_avalon_sgdma_check_descriptor_status(&tdesdecryptout_descriptor) != 0)
	//			;
	//printf("deciph_3des_pot: 3 \n");
	alt_avalon_sgdma_construct_stream_to_mem_desc( &tdesdecryptout_descriptor, &tdesdecryptout_descriptor_end, (alt_u32 *) deciph_data, 0, 0 );
	//alt_avalon_sgdma_do_async_transfer( sgdma_out_decrypt_dev, &tdesdecryptout_descriptor );
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
	perf_print_formatted_report((void* )PERFORMANCE_COUNTER_0_BASE,	ALT_CPU_FREQ*2,2,"3Des_pot 1MB szyfr","3Des_pot 1MB deszyfr"); //generacja raportu

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
	 udp_ciph_ip4_addr4=7;
	 udp_ciph_ip4_port=0;

	 udp_deciph_ip4_addr1=192;
	 udp_deciph_ip4_addr2=168;
	 udp_deciph_ip4_addr3=0;
	 udp_deciph_ip4_addr4=7;
	 udp_deciph_ip4_port=0;

	 ip_ciph_ip4_addr1=192;
	 ip_ciph_ip4_addr2=168;
	 ip_ciph_ip4_addr3=0;
	 ip_ciph_ip4_addr4=7;

	 ip_deciph_ip4_addr1=192;
	 ip_deciph_ip4_addr2=168;
	 ip_deciph_ip4_addr3=0;
	 ip_deciph_ip4_addr4=7;
}
struct netif* inicjalizacja_netif (struct netif *netif)
{

return netif;

}
