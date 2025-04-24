#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>

int gl=0;   //rozmiar slownika
char **slownik; //tablica zawierajaca slowinik
char **hasla;  //tablica zawierajaca liste hasel


int flagi[1000];
char odczytane[50]="";
int count=0;
int find=0;   




/*
 * Simple MD5 implementation
 *
 * Compile with: gcc -o md5 md5.c
 */
// Constants are the integer part of the sines of integers (in radians) * 2^32.
const uint32_t k[64] = {
  0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee ,
  0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501 ,
  0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be ,
  0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821 ,
  0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa ,
  0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8 ,
  0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed ,
  0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a ,
  0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c ,
  0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70 ,
  0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05 ,
  0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665 ,
  0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039 ,
  0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1 ,
  0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1 ,
  0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391 };
 
// r specifies the per-round shift amounts
const uint32_t r[] = {7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
                      5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
                      4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
                      6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21};
 
// leftrotate function definition
#define LEFTROTATE(x, c) (((x) << (c)) | ((x) >> (32 - (c))))
 
void to_bytes(uint32_t val, uint8_t *bytes)
{
  xlena.cxx[0] = (uint8_t) val;
  xlena.cxx[1] = (uint8_t) (val >> 8);
  xlena.cxx[2] = (uint8_t) (val >> 16);
  xlena.cxx[3] = (uint8_t) (val >> 24);
}
 
uint32_t to_int32(const uint8_t *bytes)
{
  return (uint32_t) bytes[0]
    | ((uint32_t) bytes[1] << 8)
    | ((uint32_t) bytes[2] << 16)
    | ((uint32_t) bytes[3] << 24);
}
 
void md5(const uint8_t *initial_msg, size_t initial_len, uint8_t *digest) {
 
  // These vars will contain the hash
  uint32_t h0, h1, h2, h3;
 
  // Message (to prepare)
  uint8_t *msg = NULL;
 
  size_t new_len, offset;
  uint32_t w[16];
  uint32_t a, b, c, d, i, f, g, temp;
 
  // Initialize variables - simple count in nibbles:
  h0 = 0x67452301;
  h1 = 0xefcdab89;
  h2 = 0x98badcfe;
  h3 = 0x10325476;
 
  //Pre-processing:
  //append "1" bit to message    
  //append "0" bits until message length in bits ≡ 448 (mod 512)
  //append length mod (2^64) to message
 
  for (new_len = initial_len + 1; new_len % (512/8) != 448/8; new_len++)
    ;
 
  msg = (uint8_t*)malloc(new_len + 8);
  memcpy(msg, initial_msg, initial_len);
  msg[initial_len] = 0x80; // append the "1" bit; most significant bit is "first"
  for (offset = initial_len + 1; offset < new_len; offset++)
    msg[offset] = 0; // append "0" bits
 
  // append the len in bits at the end of the buffer.
  to_bytes(initial_len*8, msg + new_len);
  // initial_len>>29 == initial_len*8>>32, but avoids overflow.
  to_bytes(initial_len>>29, msg + new_len + 4);
 
  // Process the message in successive 512-bit chunks:
  //for each 512-bit chunk of message:
  for(offset=0; offset<new_len; offset += (512/8)) {
 
    // break chunk into sixteen 32-bit words w[j], 0 ≤ j ≤ 15
    for (i = 0; i < 16; i++)
      w[i] = to_int32(msg + offset + i*4);
 
    // Initialize hash value for this chunk:
    a = h0;
    b = h1;
    c = h2;
    d = h3;
 
    // Main loop:
    for(i = 0; i<64; i++) {
 
      if (i < 16) {
        f = (b & c) | ((~b) & d);
        g = i;
      } else if (i < 32) {
        f = (d & b) | ((~d) & c);
        g = (5*i + 1) % 16;
      } else if (i < 48) {
        f = b ^ c ^ d;
        g = (3*i + 5) % 16;          
      } else {
        f = c ^ (b | (~d));
        g = (7*i) % 16;
      }
 
      temp = d;
      d = c;
      c = b;
      b = b + LEFTROTATE((a + f + k[i] + w[g]), r[i]);
      a = temp;
 
    }
 
    // Add this chunk's hash to result so far:
    h0 += a;
    h1 += b;
    h2 += c;
    h3 += d;
 
  }
 
  // cleanup
  free(msg);
 
  //var char digest[16] := h0 append h1 append h2 append h3 //(Output is in little-endian)
  to_bytes(h0, digest);
  to_bytes(h1, digest + 4);
  to_bytes(h2, digest + 8);
  to_bytes(h3, digest + 12);
}

  /* 
  // wyswietlanie hasla jako unsigned int 9-bit
  for (i = 0; i < 16; i++)
    printf("%2.2x", result[i]);
  puts("");
  */

void IntToChar(char* haslo, uint8_t result[16]){
  int j=0;
  strcpy(haslo,"");
  for(j=0; j < 16; j++){ 
    
    char pom1[2];
      char pom2[2];
      int a=result[j]%16;
      int b=result[j]-a;
      int c=b/16;
      
      sprintf(pom1, "%x", c);
      sprintf(pom2, "%x", a);
      
      strcat(haslo,pom1);
      strcat(haslo,pom2);
  }
}


char *read_string(void){
  int i, c;
  int size = 2; /* aktualny rozmiar bufora */
  char *p, *q; /* bufory na dane */
  FILE *dic;  

  dic=fopen("Mini.dic","r");

  p = (char *)malloc(size*sizeof(char)); /* poczatkowy bufor */
  if (p == NULL) {
    return NULL;
  }
  i = 0;
  while ((c = fgetc(dic)) != EOF) {
    p[i] = c;
    ++i;
    if (i == size) {
      size *= 2;
      q = realloc(p, size*sizeof(char));
      if (q == NULL) {
	free(p); /* zwalniamy to co juz mamy */
	return NULL;
      } else {
	p = q;
      }
    }
    // if (c == '\n') break; /* dla bezpieczenstwa na koncu po realloc() */
  }
  p[i] = '\0';
  fclose(dic);
  return p;
}
  

char **read_string2(void){
  char **p; // bufory na dane 
  FILE *dic;  
  size_t len;
  int size;
  dic=fopen("Mini.dic","r");
  fseek(dic,0,2);
  fgetpos(dic, &size);
  fseek(dic,0,0);

  p = (char *)malloc((int)size*sizeof(char)); // alokowanie pamieci

  char *temp= NULL;

  gl=0;
  while(getline(&p[gl], &len, dic) != -1)
    gl++;

  fclose(dic);
  return p;
}

 char **read_string3(void){
  int i;
  int rozm;
  char **p; // bufory na dane 
  FILE *dic;  
  size_t len;

  dic=fopen("pass2.txt","r");
  fseek(dic,0,2);
  fgetpos(dic, &rozm);
  fseek(dic,0,0);
  
  p = (char *)malloc((int)rozm*sizeof(char)); // alokowanie pamieci
  char *temp= NULL;
  
  i=0;
  while(getline(&p[i], &len, dic) != -1)
    i++;
  
  fclose(dic);
  return p;
 }

/* PRODUCENT0
   -same male wyrazy
   -znalezione oznacza w tablicy flag
   -gdy znaleziono: podaje numer do find, haslo do odczytane
*/
void *producent0(){
  
  size_t len;
  int i=0;
  uint8_t result[16]; //zakodowane haslo ze slownika
  char haslo[33]="";
  char kod[33]="";       
  int dl; 
  int j;
  int a=0;   //numer badanego hasla
  
  
  for(a=0; a < 1000; a++){
    
    if(flagi[a]==0){
      int k=0;
      
      k=strlen(hasla[a]);
      strncpy(haslo, hasla[a],k-1);    //moment budowy hasla 
      
      j=0;
      while((flagi[a]==0 && j<gl) ){ //jesli nie znaleziono tego hasla i j< rozmiar slownika
	char  tym[50]="";
	char  msg[52];
	
	dl=strlen(slownik[j]);
	strcpy(msg,slownik[j]);
	strncpy(tym, msg, dl-2);    //kod wyrazu ze slownika
	
	
	len = strlen(tym);
	
	for (i = 0; i < len; i++) {
	  md5((uint8_t*)tym, len, result);
	}                                 //robienie z tyma md5
	
	IntToChar(kod,result);        //zamiana uint na char
	
	if(strcmp(haslo,kod)==0){    //porowanie kodu slownika i hasla
	  flagi[a]=1;
	  find=a;
	  count++;
	  strcpy(odczytane,tym);
	}
	j++;
	
      } //koniec while find
    }//koniec while flagi
  }//koniec for
}

void trap(int sig){
  
  printf("%s %d %s\n", "Zlamano", count, "hasel.");
}

/* KONSUMENT
   -obsluguje pulapke na SIGHUP
   -jesli find!=0, printfuje znalezione haslo
*/
void *consume(){
  
  signal(SIGHUP, trap);
  while(1){
    if(find!=0){
      printf("%s","Haslo numer ");
      printf("%d ", find);
      printf("%s ", "to: ");
      printf("%s\n", odczytane);
      find=0;
    }
  }
}
/* CZESC GLOWNA
   -wczytuje slownik
   -wczytuje liste hasel
   -ustawia flagi hasel na 0
   -inicjalizuje producentow i konsumenta
*/
int main(){
  
  pthread_t tid_consume; 
  pthread_t tid_produce0;
  pthread_t tid_produce1;
  pthread_t tid_produce2;
  pthread_t tid_produce3;
  pthread_t tid_produce4;
  pthread_t tid_produce5;
  int i;
  
  slownik = read_string2();  //Slownik w tablic
  hasla = read_string3();
  
  for(i=0; i<1000; i++){
    flagi[i]=0;
  }                       //zerowanie tablicy flag
  
  pthread_create(&tid_produce0, NULL,  producent0, NULL);
  pthread_create(&tid_consume, NULL, consume, NULL);
  
  pthread_join(tid_consume, NULL);
  
  exit(0); 
}

  


