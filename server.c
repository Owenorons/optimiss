#include <stdlib.h>
#include <unistd.h> /*FOR USING FORK for at a time send and receive messages*/

#include <errno.h>    /*USING THE ERROR LIBRARY FOR FINDING ERRORS*/
#include <malloc.h> /*FOR MEMORY ALLOCATION */

#include <string.h> /*using fgets funtions for geting input from user*/

#include <arpa/inet.h> /*for using ascii to network bit*/

#include <sys/socket.h> /*for creating sockets*/

#include <sys/types.h> /*for using sockets*/

#include <netinet/in.h> /* network to asii bit */

#include <resolv.h> /*server to find out the runner's IP address*/

#include "openssl/ssl.h" /*using openssl function's and certificates and configuring them*/

#include "openssl/err.h" /* helps in finding out openssl errors*/

#include <stdio.h> /*standard i/o*/

#define FAIL -1 /*for error output == -1 */
#define TABLE_SIZE 20000
#define BUFFER 1024 /*buffer for reading messages*/
#define BUFFSIZE 2048
#define SERVER_BACKLOG 100
/**datastruct**/
typedef struct{
	struct sockaddr_in address;
	int sd;
	int uid;
    SSL *ssl;
	char name[32];
	char rna_start_msg[BUFFSIZE];
} client_t;
/**hashtable datastruct**/
typedef struct entry_t {
    char *key;
    char *value;
    struct entry_t *next;
} entry_t;

/**hashtable entry strct**/
typedef struct {
    entry_t **entries;
} hash_t;
/**this transform work to uppercase**/
 char *struppr(char *str){
     char * strup = str;
     
      for(int i=0; strup[i]!='\0'; i++){
						if(strup[i]>='a' && strup[i]<='z'){
							strup[i]= strup[i] - 32;
						}
					
					}
						return strup;		
               }
    /**this count how many CC and GG in  codon
     * to help perform optimisation**/
  int countGCC(char *codon){
  int count = 0;
  char * codonn = struppr(codon);
     for (int i = 0; i < strlen(codonn); i++)
     {
         if(codonn[i] =='G' || codonn[i] =='C'){
             count++;
         }
         /* code */
     }
     

  return count;
 }
/**hash the key**/
unsigned int hash(const char *key) {
    unsigned long int value = 0;
    unsigned int i = 0;
    unsigned int key_len = strlen(key);

    // do several rounds of multiplication
    for (; i < key_len; ++i) {
        value = value * 37 + key[i];
    }

    // make sure value is 0 <= value < TABLE_SIZE
    value = value % TABLE_SIZE;

    return value;
}
entry_t *ht_pair(const char *key, const char *value) {
    // allocate the entry
    entry_t *entry = malloc(sizeof(entry_t) * 1);
    entry->key = malloc(strlen(key) + 1);
    entry->value = malloc(strlen(value) + 1);

    // copy the key and value in place
    strcpy(entry->key, key);
    strcpy(entry->value, value);

    // next starts out null but may be set later on
    entry->next = NULL;

    return entry;
}
/**create a hashtable**/
hash_t *ht_create(void) {
    // allocate table
    hash_t *hashtable = malloc(sizeof(hash_t) * 1);

    // allocate table entries
    hashtable->entries = malloc(sizeof(entry_t*) * TABLE_SIZE);

    // set each to null (needed for proper operation)
    int i = 0;
    for (; i < TABLE_SIZE; ++i) {
        hashtable->entries[i] = NULL;
    }

    return hashtable;
}
/**set hashtable**/
void ht_set(hash_t *hashtable, const char *key, const char *value) {
    unsigned int slot = hash(key);

    // try to look up an entry set
    entry_t *entry = hashtable->entries[slot];

    // no entry means slot empty, insert immediately
    if (entry == NULL) {
        hashtable->entries[slot] = ht_pair(key, value);
        return;
    }

    entry_t *prev;

    // walk through each entry until either the end is
    // reached or a matching key is found
    while (entry != NULL) {
        // check key
        if (strcmp(entry->key, key) == 0) {
            // match found, replace value
            free(entry->value);
            entry->value = malloc(strlen(value) + 1);
            strcpy(entry->value, value);
            return;
        }

        // walk to next
        prev = entry;
        entry = prev->next;
    }

    // end of chain reached without a match, add new
    prev->next = ht_pair(key, value);
}
/**search hashtable to return the value**/
char *ht_get(hash_t *hashtable, const char *key) {
    unsigned int slot = hash(key);

    // try to find a valid slot
    entry_t *entry = hashtable->entries[slot];

    // no slot means no entry
    if (entry == NULL) {
        return NULL;
    }

    // walk through each entry in the slot, which could just be a single thing
    while (entry != NULL) {
        // return value if found
        if (strcmp(entry->key, key) == 0) {
            return entry->value;
        }

        // proceed to next key if available
        entry = entry->next;
    }

    // reaching here means there were >= 1 entries but no key match
    return NULL;
}
char *ht_getkey(hash_t *hashtable, const char *key) {
    unsigned int slot = hash(key);

    // try to find a valid slot
    entry_t *entry = hashtable->entries[slot];

    // no slot means no entry
    if (entry == NULL) {
        return NULL;
    }

    // walk through each entry in the slot, which could just be a single thing
    while (entry != NULL) {
        // return value if found
        if (strcmp(entry->key, key) == 0) {
            return entry->key;
        }

        // proceed to next key if available
        entry = entry->next;
    }

    // reaching here means there were >= 1 entries but no key match
    return NULL;
}

/**process codon**/
char *processCondo(char *codon){
	char *result = codon;
		
	 char fileBuff[TABLE_SIZE];
    hash_t *ht = ht_create();
 

    FILE* fp = fopen("codon-aminoacid.csv", "r");
    if(fp == NULL){
        perror("error file opening failed");
        exit(EXIT_FAILURE);
    }
    
    fgets(fileBuff,TABLE_SIZE, fp);
    
    while(!feof(fp)){
        char *token;
        token = strtok(fileBuff, ",");
      
        ht_set(ht, token, &fileBuff[4]);
        fgets(fileBuff,sizeof(fileBuff), fp);
    }

		char gccCount = countGCC(result);
		char *aminoAcid = ht_get(ht, result);

		if(aminoAcid != NULL){
		
		for(int i =0; i <TABLE_SIZE; i++){
				entry_t *entri = ht->entries[i];
				if(entri == NULL){
					continue;
				}
				
				int cmp = strcmp(aminoAcid, entri->value);
				if(cmp == 0){
					int countgc =countGCC(entri->key);
					if(gccCount > countgc){
						countgc = gccCount;
						result = entri->key;
					}

						if(entri->next == NULL){
					  break;
				}
				    entri = entri->next;
				}

			
		}
      
			
		}

 
return result;
}
/*validates codon*/
int validate_string(char *baseString){			
  if(baseString==NULL){
    return 1;
  }
  for(int i = 0; baseString[i] != '\0'; i+=1)
  {
    if(
      baseString[i] != 'T' &&
      baseString[i] != 'C' &&
      baseString[i] != 'A' &&
      baseString[i] != 'G'
    )
    {
      return 0;
    }
  }
  return 1;
}
/* *****************/

int OpenListener(int port)

{
    int sd;

    struct sockaddr_in addr; /*creating the sockets*/

    sd = socket(PF_INET, SOCK_STREAM, 0);

    bzero(&addr, sizeof(addr)); /*free output the garbage space in memory*/

    addr.sin_family = AF_INET; /*getting ip address form machine */

    addr.sin_port = htons(port); /* converting host bit to n/w bit */

    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sd, (struct sockaddr *)&addr, sizeof(addr)) != 0) /* assiging the ip address and port*/

    {

        perror("can't bind port"); /* reporting error using errno.h library */

        abort(); /*if error will be there then abort the process */
    }

    if (listen(sd, 10) != 0) /*for listening to max of 10 clients in the queue*/

    {

        perror("Can't configure listening port"); /* reporting error using errno.h library */

        abort(); /*if erroor will be there then abort the process */
    }

    return sd;
}

int isRoot() /*for checking if the root user is executing the server*/

{

    if (getuid() != 0)

    {

        return 0;
    }

    else

    {

        return 1; /* if root user is not executing report must be user */
    }
}

SSL_CTX *InitServerCTX(void) /*creating and setting up ssl context structure*/

{
//    const SSL_METHOD *method;

    SSL_CTX *SSL_ctx;

    OpenSSL_add_all_algorithms(); /* load & register all cryptos, etc. */

    SSL_load_error_strings(); /* load all error messages */
   

    const SSL_METHOD *method;
    method= TLS_server_method();
    SSL_ctx =SSL_CTX_new(method);

SSL_CTX *SSL_CTX_new(const SSL_METHOD *method);
 int SSL_CTX_up_ref(SSL_CTX *ctx);
    if (SSL_ctx == NULL)

    {

        ERR_print_errors_fp(stderr);

        abort();
    }

    return SSL_ctx;
}

void LoadCertificates(SSL_CTX *ctx, char *CertFile, char *KeyFile) /* to load a certificate into an SSL_CTX structure*/

{

    /* set the local certificate from CertFile */

    if (SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0)

    {

        ERR_print_errors_fp(stderr);

        abort();
    }

    /* set the private key from KeyFile (may be the same as CertFile) */

    if (SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0)

    {

        ERR_print_errors_fp(stderr);

        abort();
    }

    /* verify private key */

    if (!SSL_CTX_check_private_key(ctx))

    {

        fprintf(stderr, "Private key does not match the public certificaten");

        abort();
    }
}

void ShowCerts(SSL *ssl) /*show the ceritficates to client and match them*/

{
    X509 *cert;

    char *line;

    cert = SSL_get_peer_certificate(ssl); /* Get certificates (if available) */

    if (cert != NULL)

    {

        printf("Server certificates: \n\t");

        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);

        printf("Server: %s \n\t", line); /*server certifcates*/

        free(line);

        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);

        printf("client: %s \n\t", line); /*client certificates*/

        free(line);

        X509_free(cert);
    }

    else

        printf("No certificates.\n");
}
/* Server the connection */
void Servlet(SSL *ssl) {
    char buf[BUFFSIZE];

    int sd, bytes;

    char input[BUFFER];
    char optbuff[BUFFER];
    
    pid_t c_pid;
   char *optimiseCodon;

       

          
/* check if SSL-protocol is accepted */
     if (SSL_accept(ssl) == FAIL) 

        ERR_print_errors_fp(stderr);

    else{
     ShowCerts(ssl); /* get any certificates */

        /*Fork system call is used to create a new process*/

        c_pid = fork();

        if (c_pid == 0){

            while (1){

             /* get request and read message from server*/

                if ((bytes = SSL_read(ssl, buf, sizeof(buf)))> 0){                                      
                        struppr(buf);
                        printf("\n From client: %s", buf);
                        /* dpass RNA into and optimise codon */
                        optimiseCodon= processCondo(buf);
                        sprintf(optbuff, "%s \n", optimiseCodon);
                   /* write encrypted message */
                  SSL_write(ssl, optbuff, strlen(optbuff));

                  bzero(optbuff, BUFFER);
                  
                }else

                    ERR_print_errors_fp(stderr);
            } 
                  
        }

        else{

            while (1){
                printf("\nMessage to client: ");
             
                fgets(input, BUFFER, stdin); 
               /* return message to reply to client*/
                SSL_write(ssl, input, strlen(input));
            }
        }
    }
/* get socket connection */
    sd = SSL_get_fd(ssl); 
/* free SSL  */
    SSL_free(ssl); 
 /* close socket connection */
    close(sd);
}

int main(int argc, char *argv[]) {
    SSL_CTX *ctx;

    int server;

    char *portnum;
 
    if (argc != 2){
   /*send the usage guide if less arg*/
        printf("Usage: %s n", argv[0]); 

        exit(0);
    }
/*load encryption and hash algo's in ssl*/
    SSL_library_init(); 
    portnum = argv[1];
 /* initialize SSL */
    ctx = InitServerCTX();
 /* load certs */
    LoadCertificates(ctx, "mycert.pem", "mycert.pem");
 /* create server socket */
    server = OpenListener(atoi(portnum));
 /*socket for server*/
    struct sockaddr_in addr;

    socklen_t len = sizeof(addr);

    SSL *ssl;
/*setting 5 clients at a time to queue*/
    listen(server, 5); 
     printf("waiting on connections....\n");
     /* accept connection as usual */
    int client = accept(server, (struct sockaddr *)&addr, &len); 
	
    printf("Connection: %s:%dn", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port)); /*printing connected client information*/
     /* get new SSL state with context */
    ssl = SSL_new(ctx);
   /* set connection socket to SSL */
    SSL_set_fd(ssl, client);
   /* service connection */
    Servlet(ssl); 
  /* close socket */
    close(server); 
  /* free context */
    SSL_CTX_free(ctx); 
}
