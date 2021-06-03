#include <errno.h> 
#include <stdio.h> 
#include <unistd.h> 
#include <malloc.h> 
#include <string.h> 
#include <sys/socket.h>
#include <resolv.h> 
#include <netdb.h>
#include <openssl/ssl.h> 
#include <openssl/err.h> 
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h> 
#define FAIL -1 
#define BUFFER 2050 
#define FAIL -1 /*for error output == -1 */
/*buffer for reading messages*/
#define BUFFER 2050 

 /*the function is use to open the socket connection*/
int OpenConnection(const char *hostname, int port)

{
    int sd;

    struct hostent *host;

    struct sockaddr_in addr; /*creating the sockets*/

    if ((host = gethostbyname(hostname)) == NULL)

    {

        perror(hostname);

        abort();
    }

    sd = socket(PF_INET, SOCK_STREAM, 0); /* setting the connection as tcp it creates endpoint for connection */

    bzero(&addr, sizeof(addr));

    addr.sin_family = AF_INET;

    addr.sin_port = htons(port);

    addr.sin_addr.s_addr = *(long *)(host->h_addr);

    if (connect(sd, (struct sockaddr *)&addr, sizeof(addr)) != 0) /*initiate a connection on a socket*/

    {

        close(sd);

        perror(hostname);

        abort();
    }

    return sd;
}
 /*creating and setting up ssl context structure*/
SSL_CTX *InitCTX(void)
{
    const SSL_METHOD *method;

    SSL_CTX *ctx;

    OpenSSL_add_all_algorithms(); /* Load cryptos, et.al. */

    SSL_load_error_strings(); /* Bring in and register error messages */

    method = TLS_client_method(); /* Create new client-method instance */

    ctx = SSL_CTX_new(method); /* Create new context */

    if (ctx == NULL){

        ERR_print_errors_fp(stderr);

        abort();
    }

    return ctx;
}
/*show the ceritficates to server and match 
them but here we are not using any client certificate*/
void ShowCerts(SSL *ssl) {
    X509 *cert;

    char *line;

    cert = SSL_get_peer_certificate(ssl); /* get the server's certificate */

    if (cert != NULL)

    {

        printf("Server certificates:\n");

        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);

        printf("Subject: %s\n \t", line);

        free(line); /* free the allocated space pointer */

        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);

        printf("\n Issuer: %s\n\t", line);

        free(line); /* free the malloc'ed string */

        X509_free(cert); /* free the malloc'ed certificate copy */
    }

    else

        printf("Info: No client certificates configured. \n");
}
 char *struppr(char *str){
     char * strup = str;
     
      for(int i=0; strup[i]!='\0'; i++){
						if(strup[i]>='a' && strup[i]<='z'){
							strup[i]= strup[i] - 32;
						}
					
					}
						return strup;			
              
 }
int validate_string(char *baseString)
{

  				
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
int main(int argc, char *argv[]){
    SSL_CTX *ctx;

    int server;

    SSL *ssl;

    char buf[BUFFER];
     char tokbuff[BUFFER];

    char input[BUFFER];
    // char startRNA[100] = "Start RNA";

    int bytes;

    char *hostname, *portnum;
   

    pid_t cpid; /* fork variable*/

    if (argc < 2){

        printf("usage: %s <hostname> <port> <file>", argv[0]);

        exit(0);
    }
/*load encryption and hash algo's in ssl*/
    SSL_library_init(); 
    hostname = argv[1];
    portnum = argv[2];
     
    ctx = InitCTX();
/*call open connection function by
hostname and port number in */
    server = OpenConnection(hostname, atoi(portnum)); 
/* create new SSL connection  */
    ssl = SSL_new(ctx); 
 /* attach the socket */
    SSL_set_fd(ssl, server);
    
               /* perform the connection */
                if (SSL_connect(ssl) == FAIL) /* perform the connection */

                    ERR_print_errors_fp(stderr);

                else

                {

        printf("Connected with %s encryption", SSL_get_cipher(ssl));
                   /* get any certs */
                    ShowCerts(ssl);

                   
                  
                    cpid = fork();

                    /*Fork new process*/

                    if (cpid == 0){
                       
                        while (1){         
                            /* open and read encrypted message from server*/
                            bytes = SSL_read(ssl, buf, sizeof(buf));
                            if (bytes > 0){

                                printf("\nFrom Server: %s", buf);
                              
                                bzero(buf, sizeof(buf));
                            }

                            else

                                ERR_print_errors_fp(stderr);
                        }
                    }

                    else{
                 /* if use enter codon file this will read data to server*/
                          if(argv[3] != NULL){
                              /* open file*/   
                                FILE* fp= fopen(argv[3], "r");
                                if (fp == NULL){
                                    perror(" File fail to Open");
                                    exit(EXIT_FAILURE);
                                }                       
                                char *token;
                                        fgets(tokbuff, sizeof(tokbuff), fp);
                                        
                                        token=strtok(tokbuff, " , ");
                                        
                                        if(!validate_string(token)){
                                        fprintf(stderr,"Invalid RNA\n");                                                    
                                        exit(1);
                                        
                                        }
                                      /* encrypt send message to server */     
                                     SSL_write(ssl, tokbuff, BUFFER);
                                     bzero(tokbuff, sizeof(tokbuff)); 
                                     /*close file*/
                                     fclose(fp);  
                            }
                        while (1){  
                          
                           bzero(input, sizeof(input)); 
                            
                              printf("\nEnter RNA: ");
                            
                             scanf("%s", input);
                             fflush(stdin);
                            if (strlen(input) < 3 || strlen(input) >=4){
                                    printf("RNA must be 3 characters.\n");
                                    exit(1);
                                }
                                /* transform input to upper*/
                             struppr(input);
                             if(!validate_string( input)){
                             fprintf(stderr,"Invalid RNA\n");
                             exit(1);	
                             }
						     /* encrypt send message to server */   				
                            SSL_write(ssl, input, BUFFER); 
                           
                        }
                         bzero(input, sizeof(input));
             
                    }
                /* free connection  */
              SSL_free(ssl);
     }
     /* close socket */
       close(server); 
    /* release context */
        SSL_CTX_free(ctx); 

        return 0;
}