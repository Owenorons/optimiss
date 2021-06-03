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
#define FAIL -1 
#define BUFFER 2050 

/*the function is use to open the socket connection*/
int OpenConnection(const char *hostname, int port){

    int sd;
    struct hostent *host;

/*creating the sockets*/
    struct sockaddr_in addr; 

    if ((host = gethostbyname(hostname)) == NULL){

        perror(hostname);

        abort();

    }

/* setting the connection as tcp it creates endpoint for connection */
    sd = socket(PF_INET, SOCK_STREAM, 0); 
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = *(long *)(host->h_addr);

 /*initiate a connection on a socket*/

    if (connect(sd, (struct sockaddr *)&addr, sizeof(addr)) != 0){

       close(sd);

        perror(hostname);

        abort();

    }

/* return socket connection if successful*/
    return sd;

}

 
/*creating and setting up ssl context structure*/
SSL_CTX *InitCTX(void) {
 SSL_METHOD *method;

    SSL_CTX *ctx;
    OpenSSL_add_all_algorithms(); /* Load cryptos, et.al. */

    SSL_load_error_strings(); /* Bring in and register error messages */
 
    method = TLS_client_method(); /* Create new client-method instance */

    ctx = SSL_CTX_new(method); /* Create new context */

    if (ctx == NULL)

    {

        ERR_print_errors_fp(stderr);

        abort();

    }

    return ctx;

}

 
/*show the ceritficates to server and match 
them but here we are not using any client certificate*/
void ShowCerts(SSL *ssl){

    X509 *cert;

    char *line;
    /* get the server's certificate */
    cert = SSL_get_peer_certificate(ssl); 

    if (cert != NULL){

        printf("Server certificates:n");

        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
      printf("Subject: %sn", line);
       free(line); /* free the malloc'ed string */
       line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %sn", line);
        free(line); /* free the malloc'ed string */
        X509_free(cert); /* free the malloc'ed certificate copy */

    }

    else
      printf("Info: No client certificates configured.n");

}

 

int main(int argc, char *argv[]){

    SSL_CTX *ctx;
    int server;
    SSL *ssl;
    char buf[1024];
    char input[BUFFER];
    int bytes;
    char buf[BUFFER];
    char tokbuff[BUFFER];
    char *hostname, *portnum;

    pid_t cpid; /* fork variable*/
    if (argc < 2){
       printf("usage: %s n", argv[0]);
      exit(0);

    }

    SSL_library_init(); /*load encryption and hash algo's in ssl*/

    hostname = argv[1];
    portnum = argv[2];
    ctx = InitCTX();
    server = OpenConnection(hostname, atoi(portnum)); /*converting ascii port to interger */
    ssl = SSL_new(ctx); /* create new SSL connection state */
    SSL_set_fd(ssl, server); /* attach the socket descriptor */

    if (SSL_connect(ssl) == FAIL) /* perform the connection */
        ERR_print_errors_fp(stderr);
    else{
        printf("Connected with %s encryptionn", SSL_get_cipher(ssl));
        ShowCerts(ssl);
        /* get any certs */
        cpid = fork();
        /*Fork system call is used to create a new process*/
        if (cpid == 0){

               if(argv[3] != NULL){
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
                                        
                                     SSL_write(ssl, tokbuff, BUFFER);
                                     bzero(tokbuff, sizeof(tokbuff)); 
                                     fclose(fp);  
                            }  
          while (1){
            printf("\n Enter RNA");
                fgets(input, BUFFER, stdin);
                if (strlen(input) < 3 || strlen(input) >=4){
                                    printf("RNA must be 3 characters.\n");
                                    exit(1);
                                }
                             struppr(input);
                             if(!validate_string( input)){
                             fprintf(stderr,"Invalid RNA\n");
                             exit(1);	
                             }
                SSL_write(ssl, input, strlen(input)); /* encrypt & send message */

            }

        }else{
            while (1){

                bytes = SSL_read(ssl, buf, sizeof(buf)); /* get request */


                if (bytes > 0){

                    buf[bytes] = 0;

                    printf("\n From Server: %s\n", buf);

                }

            }

        } 

        SSL_free(ssl); /* release connection state */

    }

    close(server); /* close socket */

    SSL_CTX_free(ctx); /* release context */

    return 0;

}

 