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
void rx_ethernet_isr (void *context);
void rx_ethernet_isr1 (void *context);
void init_3des (unsigned int key11,unsigned int key12,unsigned int key21,unsigned int key22,unsigned int key31,unsigned int key32);
void init_3desdecrypt (unsigned int key11,unsigned int key12,unsigned int key21,unsigned int key22,unsigned int key31,unsigned int key32);

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
unsigned int text_length;
unsigned int result1;
unsigned int result2;
// Ramka transmisyjna
unsigned char tx_frame[1024];
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
unsigned char rx_frame[1024] = { 0 };
unsigned char rx_frame1[1024] = { 0 };
// Utworzenie urzadzen SGDMA
alt_sgdma_dev * sgdma_tx_dev;
alt_sgdma_dev * sgdma_rx_dev;

alt_sgdma_dev * sgdma_tx_dev1;
alt_sgdma_dev * sgdma_rx_dev1;

alt_sgdma_dev * sgdma_read_3des;

// Alokacja dekryptorow w pamieci deskryptorow
alt_sgdma_descriptor tx_descriptor		__attribute__ (( section ( ".descriptor_memory" )));
alt_sgdma_descriptor tx_descriptor_end	__attribute__ (( section ( ".descriptor_memory" )));

alt_sgdma_descriptor rx_descriptor  	__attribute__ (( section ( ".descriptor_memory" )));
alt_sgdma_descriptor rx_descriptor_end  __attribute__ (( section ( ".descriptor_memory" )));

alt_sgdma_descriptor tx_descriptor1		__attribute__ (( section ( ".descriptor_memory1" )));
alt_sgdma_descriptor tx_descriptor_end1	__attribute__ (( section ( ".descriptor_memory1" )));

alt_sgdma_descriptor rx_descriptor1 	__attribute__ (( section ( ".descriptor_memory1" )));
alt_sgdma_descriptor rx_descriptor_end1  __attribute__ (( section ( ".descriptor_memory1" )));

//alokacja deskryptorow do obslugi pamieci SRAM
alt_sgdma_descriptor read_descriptor		__attribute__ (( section ( ".descriptor_memory0" )));
alt_sgdma_descriptor read_descriptor_end	__attribute__ (( section ( ".descriptor_memory0" )));


np_tse_mac *triple = (np_tse_mac*) 0x504400;

np_tse_mac *triple1 = (np_tse_mac*) 0x504000;

unsigned int p1,p2,p3,p4,p5,p6;
	 unsigned int p7,p8;
	 unsigned int p9,p10;
		unsigned int  dane[1024]={0};
		unsigned int  wyniki[1024]={0};
		unsigned int key11=0x01234567,  key12=0x89ABCDEF,  key21=0xFEDCAB89,  key22=0x76543210,  key31=0xF0E1D2C3,  key32=0xB4A59687;

int main (int argc, char* argv[], char* envp[])
{


//dane=0;
	/**
	 * Inicjalizacja danych do szyfrowania
	 */


printf("Rozpoczecie dzialania programu\n");
	//init_3des ( key11,  key12,  key21,  key22,  key31,  key32);


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

		//Uruchomienie trzeciego SGDMA

			//Otworzenie SGDMA memory to memory dla obslugi wymiany pamieci pomiedzy SRAM a glowna pamiecia
			/*sgdma_read_3des = alt_avalon_sgdma_open ("/dev/sgdma_0");
			if (sgdma_read_3des == NULL) {
				alt_printf ("Error: Nie mozna otworzyc scatter-gather dma memory-memory device dla obslugi pamieci SRAM\n");
				return -1;
			} else alt_printf ("Otworzono scatter-gather dma memory-memory device dla obslugi pamieci SRAM\n");
*/
		printf ("Cale SGDMA uruchomione\n");
		/*
		 * weryfikacja_szyfrowania ();
		weryfikacja_deszyfrowania();
		przygotowanie_danych();
		test_wydajnosc ();
		test_wydajnosci_sram();
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
	//	alt_tse_mac_set_common_speed(ETH_TSE_BASE,2);
		printf ("Ustalenie adresu MAC\n");
	// Okreslenie adresow urzadzen PHY do ktorych dostep odbywac sie bedzie przez interfejs MDIO
		 *(tse + 0x0F) = 0x10;
		*(tse + 0x10) = 0x11;
		// Okreslenie adresow urzadzen PHY do ktorych dostep odbywac sie bedzie przez interfejs MDIO
		/// *(tse1 + 0x0F) = 0x10;
		/// *(tse1 + 0x10) = 0x11;
		 // Write to register 20 of the PHY chip for Ethernet port 0 to set up line loopback
		 //*(tse + 0x94 ) = 0x4000;
		 // Ustawienie crossoveru dla obu PHY
		// *(tse + 0xA0) = *(tse + 0xA0) | 0x0060;
		/// *(tse1 + 0xB0) = *(tse1 + 0xB0) | 0x0060;
		*(tse + 0x94) = 0x4000;


		 //Uruchomienie crosoveru dla PHY
		  *(tse + 0x90) = *(tse + 0x90) | 0x0060;
			//  *(tse1 + 0xB0) = *(tse1 + 0xB0) | 0x0060;
			 // Wprowadzenie opoznienia zegara wejsciowego i wyjsciowego

			///	 *(tse1 + 0xB4) = *(tse1 + 0xB4) | 0x0082;
		  *(tse + 0x94) = *(tse + 0x94) | 0x0082;

		 // *(tse + 2) = *(tse + 2) | 0x02000043;
		  // Software reset obu chipow PHY
		  *(tse + 0x80) = *(tse + 0x80) | 0x8000;
		  	while ( *(tse + 0x80) & 0x8000  )
		  		;
		 		// *(tse + 0x02) = *(tse + 0x02) | 0x2000;
		 	//	 while ( *(tse + 0x02) & 0x2000  ) ; //sprawdzenie czy reset sie zakonczyl (sw_reset=0)
	///	 		 *(tse1 + 0xA0) = *(tse1 + 0xA0) | 0x8000;
	///	 		while ( *(tse1 + 0xA0) & 0x8000  ) 			 ;
		 // Umozliwienie zapisu i odczytu oraz przesylania ramek z blednie wyliczonym CRC
		 	printf("Udany reset obu modulow");
///		 *(tse1 + 2) = *(tse1 + 2) | 0x02000043;
		// *(tse + 2 ) = *(tse + 2) | 0x0000004B;
		 *(tse + 2) = *(tse + 2) |0x040001F3;
		 alt_printf( "send> " );
		 text_length = 0;
		// wprowadzenie_kluczy(); //Wprowadzenie wartosci kluczy ktore mialy byc uzywane przy transmisji Ethernet

		while (1) {

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
			alt_printf( "\nsend> " );
			text_length = 0;
			//usleep(2000000);

			//alt_avalon_sgdma_construct_mem_to_stream_desc( &tx_descriptor, &tx_descriptor_end, rx_frame, 90, 0, 1, 1, 0 );
			//alt_avalon_sgdma_do_async_transfer( sgdma_tx_dev, &tx_descriptor );
			//while (alt_avalon_sgdma_check_descriptor_status(&tx_descriptor) != 0)
			//	;
		}


		 while(1)
		 {	//printf("petla while odbieranie i wysylanie");

		//	 while (alt_avalon_sgdma_check_descriptor_status(&rx_descriptor) != 0);

			// printf("petla while odbieranie i wysylanie");

		 }
		return 0;

}


void rx_ethernet_isr (void *context)
{
	int i;

		// Wait until receive descriptor transfer is complete
		while (alt_avalon_sgdma_check_descriptor_status(&rx_descriptor) != 0)
			;

		// Clear input line before writing
		for (i = 0; i < (6 + text_length); i++) {
			alt_printf( "%c", 0x08 );		 // 0x1024008 --> backspace
		}

		// Output received text
	//	alt_printf( "receive> %s\n", rx_frame + 16  );
		i=0;
		// Set up non-blocking transfer of sgdma receive descriptor

		int speed=alt_tse_mac_get_common_speed( ETH_TSE_BASE);
		printf("Currents speed:  %i",speed);
		printf("\n");
		//unsigned int *readtse;
		//*readtse=
		//volatile int * tse = (int *) ETH_TSE_BASE;
		//*(tse + 0x3A)=0x00040000;

		 //printf("Readtse : %i",readtse);
		printf("\n");
				printf("odebrano ramke \n");
		while(i<342)
		 {
					alt_printf( "%x", rx_frame[i] );
					i++;// 0x1024008 --> backspaces
					if (rx_frame[i] =='\n')
					{
						i=1024;
					}
				}
		// Reprint current input line after the outputs
	//	alt_printf( "send> %s", tx_frame + 16 );
		i=0;
		/*while (i<7)
		{
		tx_frame[i]=0x55;
		i++;
		}
		tx_frame[7]=0xD5;*/
		while (i<6)
		{
			tx_frame[i]=0xFF;
			i++;
		}
		tx_frame[6]=0x01;
		tx_frame[7]=0x60;
		tx_frame[8]=0x6E;
		tx_frame[9]=0x11;
		tx_frame[10]=0x02;
		tx_frame[11]=0x0F;
		tx_frame[12]=0x08;
		tx_frame[13]=0x00;
		i=14;
		while (i <88)
		{
			tx_frame[i]=rx_frame[i+1];
			i++;
		}
		tx_frame[88]='\0';
		alt_avalon_sgdma_construct_mem_to_stream_desc( &tx_descriptor, &tx_descriptor_end, (alt_u32 *)tx_frame, 92, 0, 1, 1, 0 );
		alt_avalon_sgdma_do_async_transfer( sgdma_tx_dev, &tx_descriptor );
		while (alt_avalon_sgdma_check_descriptor_status(&tx_descriptor) != 0);
		//ff_tx_eop=1;
		alt_avalon_sgdma_construct_stream_to_mem_desc( &rx_descriptor, &rx_descriptor_end, (alt_u32 *)rx_frame, 0, 0 );

		alt_avalon_sgdma_do_async_transfer( sgdma_rx_dev, &rx_descriptor );


		//alt_avalon_sgdma_do_async_transfer( sgdma_rx_dev, &rx_descriptor );

		printf("\n");
				printf("zakonczono odbior ramki\n");

		// Create new receive sgdma descriptor
		//	alt_avalon_sgdma_construct_stream_to_mem_desc( &rx_descriptor, &rx_descriptor_end, (alt_u32 *)rx_frame, 0, 0 );
}

void rx_ethernet_isr1 (void *context)
{
	int i;

		// Wait until receive descriptor transfer is complete
		while (alt_avalon_sgdma_check_descriptor_status(&rx_descriptor1) != 0)
			;

		// Clear input line before writing
		for (i = 0; i < (6 + text_length); i++) {
			alt_printf( "%c", 0x08 );		 // 0x1024008 --> backspace
		}

		// Output received text
	//	alt_printf( "receive> %s\n", rx_frame + 16  );
		i=0;
		while(rx_frame1[i] != NULL)
		 {
					alt_printf( "%c", rx_frame1[i] );
					i++;// 0x1024008 --> backspace
				}
		// Reprint current input line after the output
		//alt_printf( "send> %s", tx_frame + 16 );

		// Create new receive sgdma descriptor
		alt_avalon_sgdma_construct_stream_to_mem_desc( &rx_descriptor1, &rx_descriptor_end1, (alt_u32 *)rx_frame1, 0, 0 );

		// Set up non-blocking transfer of sgdma receive descriptor
		alt_avalon_sgdma_do_async_transfer( sgdma_rx_dev1, &rx_descriptor1 );



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
	init_3des(0x01234567,0x89ABCDEF,0x23456789,0xABCDEF01,0x456789AB,0xCDEF0123);//Wprowadzenie kluczy
	ciph_3des(0x54686520,0x71756663); //wprowadzenie wektoru testowego
	printf("Wynikiem szyfrowania powinien by�: 0xA826FD8CE53B755F \n");
	ciph_3des_read(&result1,&result2);
	printf("Wynik szyfrowania to: 0x%X%X \n",result1,result2);

}
/**
 * Funkcja weryfikujaca modul deszufrujacy Triple DES dla wektorow i kluczy podanych przez NIST
 */
void weryfikacja_deszyfrowania ()
{
	unsigned int wynik1,wynik2;
	init_3desdecrypt(0x01234567,0x89ABCDEF,0x23456789,0xABCDEF01,0x456789AB,0xCDEF0123);//Wprowadzenie kluczy
	deciph_3des(result1,result2); //Wprowadzenie wyniku testu weryfikacji szyfrowania
	printf("Wynikiem deszyfrowania powinien by�: 0x5468652071756663 \n");
	deciph_3des_read(&wynik1,&wynik2);
	printf("Wynik deszyfrowania to: 0x%X%X \n",wynik1,wynik2);
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
	int sram_adres=0x90000;
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
	alt_avalon_sgdma_construct_mem_to_mem_desc(&read_descriptor,&read_descriptor_end,(alt_u32 *) *dane,(alt_u32*)sram_adres,(alt_u16)4096,0,0);
	alt_avalon_sgdma_do_async_transfer( sgdma_read_3des, &read_descriptor );
	while (alt_avalon_sgdma_check_descriptor_status(&read_descriptor) != 0);
	sram_adres+=4096;
	k++;
	}
}

/**
 * Przeprowadzenie szyfrowania 1MB danych w pamieci SRAM oraz zapisanie ich
 */
void przeprowadzenie_szyfrowania_sram()
{	printf("Rozpocz�cie test�w szyfrowania z zapisem do SRAM \n");
	int k=0;
	int sram_adres_read=0x90000; //adres do odczytu
	int sram_adres_write=sram_adres_read+1048576; //adres do zapisu

	while(k<2)
	{
	alt_avalon_sgdma_construct_mem_to_mem_desc(&read_descriptor,&read_descriptor_end,(alt_u32 *) sram_adres_read,(alt_u32*)*dane,(alt_u16)4096,0,0);
	alt_avalon_sgdma_do_async_transfer( sgdma_read_3des, &read_descriptor );
	while (alt_avalon_sgdma_check_descriptor_status(&read_descriptor) != 0);

	paczka_szyfrowanie();
	alt_avalon_sgdma_construct_mem_to_mem_desc(&read_descriptor,&read_descriptor_end,(alt_u32 *) *wyniki,(alt_u32*)sram_adres_write,(alt_u16)4096,0,0);
	alt_avalon_sgdma_do_async_transfer( sgdma_read_3des, &read_descriptor );
	while (alt_avalon_sgdma_check_descriptor_status(&read_descriptor) != 0);
	sram_adres_read+=4096;
	sram_adres_write+=4096;
	k++;
	}

}
/**
 * Przeprowadzenie deszyfrowania 1MB danych w pamieci SRAM oraz zapisanie ich
 */
void przeprowadzenie_deszyfrowania_sram()
{
	int k=0;
	int sram_adres_read=0x90000; //adres do odczytu
	int sram_adres_write=sram_adres_read+1048576; //adres do zapisu

	while(k<256)
	{
	alt_avalon_sgdma_construct_mem_to_mem_desc(&read_descriptor,&read_descriptor_end,(alt_u32 *) sram_adres_read,(alt_u32*)*dane,(alt_u16)4096,0,0);
	alt_avalon_sgdma_do_async_transfer( sgdma_read_3des, &read_descriptor );
	while (alt_avalon_sgdma_check_descriptor_status(&read_descriptor) != 0);

	paczka_deszyfrowanie();
	alt_avalon_sgdma_construct_mem_to_mem_desc(&read_descriptor,&read_descriptor_end,(alt_u32 *) *wyniki,(alt_u32*)sram_adres_write,(alt_u16)4096,0,0);
	alt_avalon_sgdma_do_async_transfer( sgdma_read_3des, &read_descriptor );
	while (alt_avalon_sgdma_check_descriptor_status(&read_descriptor) != 0);
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
	perf_print_formatted_report((void* )PERFORMANCE_COUNTER_0_BASE,	ALT_CPU_FREQ*2,2,"Test szyfr 3DES(SRAM)","Test deszyfr 3DES(SRAM)");
}
/*
 *Funkcja do wprowadzenia przez uzytkownika kluczy szyfratora i deszyfratora Triple DES
 */
void wprowadzenie_kluczy()
{
	printf("Wprowadz 8 znak�w pierwszej polowy klucza 1 w postaci szesnastkowej: ");
	scanf( "%x", &key11 );
	printf("Wprowadz 8 znak�w drugiej polowe klucza 1 w postaci szesnastkowej: ");
	scanf( "%x", &key12 );
	printf("Wprowadz  8 znak�w pierwszej polowe klucza 2 w postaci szesnastkowej: ");
	scanf( "%x", &key21 );
	printf("Wprowadz 8 znak�w druga polowe klucza 2 w postaci szesnastkowej: ");
	scanf( "%x", &key22 );
	printf("Wprowadz pierwsza polowe klucza 3 w postaci szesnastkowej: ");
	scanf( "%x", &key31 );
	printf("Wprowadz 8 znak�w drugiej polowe klucza 3 w postaci szesnastkowej: ");
	scanf( "%x", &key32 );

	init_3des(key11,key12,key21,key22,key31,key32); //wprowadzenie kluczy do szyfratora
	init_3desdecrypt(key11,key12,key21,key22,key31,key32); //wprowadzenie kluczy do deszyfratora
	printf ("zainializowano szyfrator\n");

}
