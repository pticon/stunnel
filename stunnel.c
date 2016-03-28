#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <signal.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/queue.h>


/* TODO
 * add snoop option (in a define)
 * add daemon option with a pid file
 * add address to bind
 * handle Ipv6
 * handle 6to4 and 4to6
 * add bufferlen option
 * add more options for crypto features (force TLSv1.2, etc...)
 */


/* Hardcoded values
 */
#define PROGNAME    "stunnel"
#define BUFFERLEN   (1024 * 1024)
#define TIMEOUT     60L


/* Default options
 */
#define CERTFILE    "cert.pem"
#define KEYFILE     "key.pem"
#define LISTENPORT  4433
#define BACKLOG     1
#define TUNNELIP    INADDR_LOOPBACK
#define TUNNELPORT  8080


/* Program's structures
 */
typedef struct tunnel
{
    uint32_t    addr;
    uint16_t    port;
} tunnel_t;


typedef struct options
{
    char        *certfile;
    char        *keyfile;
    uint16_t    listenport;
    int         backlog;
    long        timeout;
    tunnel_t    tunnel;
    uint8_t     verbose:1;
} options_t;


typedef struct conn
{
    int                 client;
    SSL_CTX             *ctx;
    struct sockaddr_in  *addr;
    tunnel_t            *tunnel;
    long                timeout;
    uint8_t             verbose:1;
} conn_t;


/* Global variables
 */
static volatile int forever = 1;
static volatile int sock = -1;


/* Macro convenience
 */
#define HANDLE_PTHREAD_ERR(err, msg)        \
    do                                      \
    {                                       \
        errno = err;                        \
        perror(msg);                        \
    } while(0)

#define ARRAY_SIZE(a)   (sizeof((a))/sizeof((a)[0]))

#define VERBOSE(v, ...)                     \
    do                                      \
    {                                       \
        if ( (v) )                          \
            fprintf(stderr, __VA_ARGS__);   \
    } while ( 0 )

#define COPY_TO_FROM(to, from, field)       \
    (to)->field = (from)->field;

#define CLOSE_SOCKET(s)                     \
    do                                      \
    {                                       \
        if ( s != -1 )                      \
        {                                   \
            close(s);                       \
            s = -1;                         \
        }                                   \
    } while ( 0 )                           \

#define ADDR_TO_STR(addr)                   \
    ({                                      \
        struct in_addr  ina;                \
        ina.s_addr = htonl(addr);           \
        inet_ntoa(ina);                     \
    })

#define SET_SOCK_NON_BLOCKING(s)            \
    do                                      \
    {                                       \
        fcntl(s, F_SETFL, O_NONBLOCK);      \
    } while ( 0 )                           \


/* Functions
 */
static void signal_handler(int sig)
{
    fprintf(stderr, "Signal caught...\n");
    switch ( sig )
    {
        case SIGINT:
        case SIGTERM:
        fprintf(stderr, "Signal %d: end loop\n", sig);
        forever = 0;
        CLOSE_SOCKET(sock);
        break;

        default:
        fprintf(stderr, "Signal %d is not handled\n", sig);
        break;
    }
}


static int set_signal_handler(void)
{
    size_t                  i;
    static const int const  sig_array [] =
    {
        SIGINT,
        SIGTERM,
    };

    for ( i = 0 ; i < ARRAY_SIZE(sig_array) ; i++ )
        if ( signal(sig_array[i], signal_handler) == SIG_ERR )
            return -1;

    return 0;
}


static void usage(const char * prog)
{
    fprintf(stderr, "usage: %s [options]\n", prog);
    fprintf(stderr, "options:\n");
    fprintf(stderr, "\t-h                : display this and exit\n");
    fprintf(stderr, "\t-c <certfile.pem> : specify the certificate file (default: %s)\n", CERTFILE);
    fprintf(stderr, "\t-k <keyfile.pem>  : specify the key file (default: %s)\n", KEYFILE);
    fprintf(stderr, "\t-p <port>         : specify the listen port (default: %u)\n", LISTENPORT);
    fprintf(stderr, "\t-b <backlog>      : specify the maximum length to which the queue of pending connections (default: %u)\n", BACKLOG);
    fprintf(stderr, "\t-t <ip:port>      : specify the tunneling binding (default: %s:%02d)\n", ADDR_TO_STR(TUNNELIP), TUNNELPORT);
    fprintf(stderr, "\t-T <timeout>      : specify the timeout to close connection (default: %ld)\n", TIMEOUT);
    fprintf(stderr, "\t-v                : verbose mode\n");
    fprintf(stderr, "\nexample: tunneling a HTTP server on port 80 through SSL on port 443\n");
    fprintf(stderr, "\t %s -p 443 -t 127.0.0.1:80\n", prog);
}


static inline int is_valid_port(const unsigned long port)
{
    if ( port > 0 && port < 0xffff )
        return 1;

    return 0;
}


static int parse_tunnel(char *str, tunnel_t *tunnel)
{
    char    *token;

    if ( (token = strtok(str, ":")) == NULL )
    {
        fprintf(stderr, "No Ip and port found for tunnel\n");
        return -1;
    }

    if ( (tunnel->addr = (const uint32_t) inet_network(token)) == -1 )
    {
        fprintf(stderr, "Invalid IP address %s\n", token);
        return -1;
    }

    if ( (token = strtok(NULL, ":")) == NULL )
    {
        fprintf(stderr, "No port found for tunnel\n");
        return -1;
    }

    tunnel->port = strtoul(token, NULL, 10);
    if ( !is_valid_port(tunnel->port) )
    {
        fprintf(stderr, "Invalid tunnel port\n");
        return -1;
    }

    return 0;
}


static int parse_options(int argc, char *argv[], options_t *options)
{
    int     c;

    /* Default options
     */
    options->certfile = CERTFILE;
    options->keyfile = KEYFILE;
    options->listenport = LISTENPORT;
    options->backlog = BACKLOG;
    options->verbose = 0;
    options->tunnel.addr = TUNNELIP;
    options->tunnel.port = TUNNELPORT;

    while ( (c = getopt(argc, argv, "hc:k:p:b:t:T:v")) != -1 )
    {
        switch ( c )
        {
            case 'h':
            usage(PROGNAME);
            return -1;

            case 'c':
            options->certfile = optarg;
            break;

            case 'k':
            options->keyfile = optarg;
            break;

            case 'p':
            options->listenport = strtoul(optarg, NULL, 10);
            if ( !is_valid_port(options->listenport) )
            {
                fprintf(stderr, "Invalid listen port %d\n", options->listenport);
                return -1;
            }
            break;

            case 'b':
            if ( (options->backlog = strtoul(optarg, NULL, 10)) <= 0 )
            {
                fprintf(stderr, "Invalid backlog %d\n", options->backlog);
                return -1;
            }
            break;

            case 't':
            if ( parse_tunnel(optarg, &options->tunnel) )
                return -1;
            break;

            case 'T':
            if ( (options->timeout = strtoul(optarg, NULL, 10)) <= 0 )
            {
                fprintf(stdout, "Invalid timeout options %ld\n", options->timeout);
                return -1;
            }
            break;

            case 'v':
            options->verbose = 1;
            break;

            default:
            fprintf(stderr, "Invalid options %c\n", (const char) c);
            return -1;
        }
    }

    if ( (argc -= optind) )
    {
        fprintf(stderr, "No argument needed\n");
        return -1;
    }

    return 0;
}


static void init_openssl(void)
{
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}


static SSL_CTX *create_ctx(void)
{
    const SSL_METHOD    *method;

    method = SSLv23_server_method();

    return SSL_CTX_new(method);
}


static int configure_ctx(SSL_CTX *ctx, const char *cert, const char *key)
{
    //SSL_CTX_set_ecdh_auto(ctx, 1);

    if ( SSL_CTX_use_certificate_file(ctx, cert, SSL_FILETYPE_PEM) < 0 )
        return -1;

    if ( SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) < 0 )
        return -1;

    return 0;
}


static int init_pthread(pthread_attr_t *attr, const int backlog)
{
    if ( pthread_attr_init(attr) < 0 )
        return -1;

    if ( pthread_attr_setdetachstate(attr, PTHREAD_CREATE_JOINABLE) != 0 )
        return -1;

    return 0;
}


/* FIXME
 * handle IPv6
 */
static int create_socket(const uint16_t port, const int backlog)
{
    int                 s;
    struct sockaddr_in  addr;
    const int           yes = 1;

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if ( (s = socket(AF_INET, SOCK_STREAM, 0)) < 0 )
        return -1;

    if ( setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) != 0 )
        return -1;

    if ( bind(s, (const struct sockaddr *) &addr, sizeof(addr)) < 0 )
        return -1;

    if ( listen(s, backlog) < 0 )
        return -1;

    return s;
}


static int from_ssl_to_clear(SSL *ssl, int clear, void *buffer, size_t len, const int v)
{
    int     rlen,
            ret,
            redo;

    do
    {
        redo = 0;

        if ( (rlen = SSL_read(ssl, buffer, len)) > 0 )
        {
            VERBOSE(v, "\nSSL READ: %.*s", rlen, (const char *)buffer);

            if ( (ret = send(clear, buffer, rlen, 0)) > 0 )
                return 0;

            perror("send");
            return -1;
        }

        VERBOSE(v, "\nssl read (%d)\n", rlen);
        switch ( SSL_get_error(ssl, rlen) )
        {
            case SSL_ERROR_NONE:
            VERBOSE(v, "No real error => continue\n");
            return 0;

            case SSL_ERROR_ZERO_RETURN:
            VERBOSE(v, "Disconnected peer => break\n");
            return -1;

            /* SSL_read() could want to write too
             * It must be repeated with the same arguments.
             */
            case SSL_ERROR_WANT_READ:
            case SSL_ERROR_WANT_WRITE:
            VERBOSE(v, "Want read => continue\n");
            redo = 1;
            break;

            default:
            VERBOSE(v, "Unknown error => break\n");
            return -1;
        }
    } while ( redo && forever );

    return 0;
}


static int from_clear_to_ssl(int clear, SSL *ssl, void *buffer, size_t len, const int v)
{
    int     rlen,
            ret,
            redo;

    if ( (rlen = read(clear, buffer, len)) == 0 )
    {
        /* FIN close
         */
        VERBOSE(v, "\nClient closes connection\n");
        return -1;
    }

    if ( rlen < 0 )
    {
        /* recv error
         */
        VERBOSE(v, "\nClient closes connection (2) %d\n", rlen);
        perror("recv");

        return -1;
    }

    VERBOSE(v, "\nSSL WRITE: %.*s", rlen, (const char *)buffer);

    do
    {
        redo = 0;

        if ( (ret = SSL_write(ssl, buffer, rlen)) > 0 )
            return 0;

        switch ( SSL_get_error(ssl, ret) )
        {
            case SSL_ERROR_NONE:
            VERBOSE(v, "No real error => continue\n");
            return 0;

            case SSL_ERROR_ZERO_RETURN:
            VERBOSE(v, "Disconnected peer => break\n");
            return -1;

            /* SSL_write() could want to read too.
             * It must be repeated with the same arguments.
             */
            case SSL_ERROR_WANT_READ:
            case SSL_ERROR_WANT_WRITE:
            VERBOSE(v, "Want read => continue\n");
            redo = 1;
            break;

            default:
            VERBOSE(v, "Unknown error => break\n");
            return -1;
        }
    } while ( redo && forever );

    return -1;
}


static int tunnel_data(SSL *ssl, const tunnel_t *tunnel, const long timeout, const int v)
{
    char                buffer[BUFFERLEN];
    int                 srv,
                        ret;
    struct sockaddr_in  sin;

    if ( (srv = socket(AF_INET, SOCK_STREAM, 0)) < 0 )
    {
        perror("socket");
        return -1;
    }

    sin.sin_family = AF_INET;
    sin.sin_port = htons(tunnel->port);
    sin.sin_addr.s_addr = htonl(tunnel->addr);

    if ( connect(srv, (const struct sockaddr*) &sin, sizeof(sin)) != 0 )
    {
        perror("connect");
        return -1;
    }

    SET_SOCK_NON_BLOCKING(srv);
    SET_SOCK_NON_BLOCKING(SSL_get_fd(ssl));

    VERBOSE(v, "Start tunneling data...");

    ret = 0;

    while ( forever )
    {
        fd_set          set;
        struct timeval  tv =
        {
            timeout,
            0
        };

        FD_ZERO(&set);
        FD_SET(SSL_get_fd(ssl), &set);
        FD_SET(srv, &set);

        if ( select(srv + 1, &set, NULL, NULL, &tv) == 0 )
        {
            perror("select");
            ret = -1;
            break;
        }

        /* Request
         */
        if ( FD_ISSET(SSL_get_fd(ssl), &set) )
        {
            if ( from_ssl_to_clear(ssl, srv, buffer, sizeof buffer, v) )
                break;
        }

        /* Response
         */
        if ( FD_ISSET(srv, &set) )
        {
            if ( from_clear_to_ssl(srv, ssl, buffer, sizeof buffer, v) )
                break;
        }
    }

    if ( shutdown(srv, 0) )
        perror("shutdown");

    /* Flush the buffer
     */
    while ( read(srv, buffer, sizeof(buffer)) != 0 )
        ;

    close(srv);

    return ret;
}


static void copy_to_conn(conn_t *conn, const int client, SSL_CTX *ctx, struct sockaddr_in *addr, options_t *options)
{
    conn->client = client;
    conn->ctx = ctx;
    conn->addr = addr;
    conn->tunnel =  &options->tunnel;
    COPY_TO_FROM(conn, options, verbose);
    COPY_TO_FROM(conn, options, timeout);
}


static void *connection_handler(void *arg)
{
    conn_t      *conn = (conn_t *) arg;
    SSL         *ssl;
    char        buffer[1024];

    VERBOSE(conn->verbose, "New client connection %s:%u\n", inet_ntoa(conn->addr->sin_addr), htons(conn->addr->sin_port));

    ssl = SSL_new(conn->ctx);
    if ( SSL_set_fd(ssl, conn->client) != 1 )
    {
        perror("SSL_set_fd");
        goto error;
    }

    if ( SSL_accept(ssl) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        goto error;
    }

    if ( tunnel_data(ssl, conn->tunnel, conn->timeout, conn->verbose) )
    {
        fprintf(stderr, "Tunnel data failed\n");
        goto error;
    }

error:
    VERBOSE(conn->verbose, "End client connection %s:%u\n", inet_ntoa(conn->addr->sin_addr), htons(conn->addr->sin_port));

    SSL_set_shutdown(ssl, SSL_SENT_SHUTDOWN|SSL_RECEIVED_SHUTDOWN);
    SSL_free(ssl);
    if ( shutdown(conn->client, 2) )
        perror("shutdown");

    while ( read(conn->client, buffer, sizeof buffer) > 0 );

    close(conn->client);

    pthread_exit(NULL);;
}


static void cleanup_openssl(void)
{
    EVP_cleanup();
}


int main(int argc, char *argv[])
{
    options_t       options;
    SSL_CTX         *ctx = NULL;
    pthread_attr_t  pthread_attr;
    int             ret;

    /* Init
     */
    if ( parse_options(argc, argv, &options) )
        return -1;

    init_openssl();
    VERBOSE(options.verbose, "Create SSL context\n");
    if ( (ctx = create_ctx()) == NULL )
    {
        perror("Unable to create SSL context");
        goto error;
    }

    VERBOSE(options.verbose, "Use certfile %s and keyfile %s\n", options.certfile, options.keyfile);
    if ( configure_ctx(ctx, options.certfile, options.keyfile) != 0 )
    {
        perror("Unable to configure SSL context");
        goto error;
    }

    VERBOSE(options.verbose, "Create %d threads\n", options.backlog);
    if ( (ret = init_pthread(&pthread_attr, options.backlog)) != 0 )
    {
        HANDLE_PTHREAD_ERR(ret, "init pthread");
        goto error;
    }

    VERBOSE(options.verbose, "Bind port %u\n", options.listenport);
    if ( (sock = create_socket(options.listenport, options.backlog)) < 0 )
    {
        perror("Socket error");
        goto error;
    }

    if ( set_signal_handler() )
    {
        perror("signal");
        goto error;
    }

    /* Main loop
     */
    while ( forever )
    {
        struct sockaddr_in  addr;
        socklen_t           addrlen = sizeof(addr);
        int                 client;
        pthread_t           thread;
        conn_t              conn;

        VERBOSE(options.verbose, "Waiting for client connection\n");
        if ( (client = accept(sock, (struct sockaddr *) &addr, &addrlen)) < 0 )
        {
            if ( sock != -1 )
                perror("Accept");
            break;
        }

        copy_to_conn(&conn, client, ctx, &addr, &options);

        if ( (ret = pthread_create(&thread, &pthread_attr, connection_handler, &conn)) != 0 )
        {
            HANDLE_PTHREAD_ERR(ret, "pthread create");
            continue;
        }
    }

    /* Clean up
     */
    pthread_attr_destroy(&pthread_attr);
    SSL_CTX_free(ctx);
    CLOSE_SOCKET(sock);
    cleanup_openssl();
    pthread_exit(NULL);

    return 0;

error:
    SSL_CTX_free(ctx);
    CLOSE_SOCKET(sock);
    ERR_print_errors_fp(stderr);
    cleanup_openssl();

    return -1;
}
