/*
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 * 
 * You should have received a copy of the GNU General Public License along
 * with this program. If not, see <https://www.gnu.org/licenses/>. 
 */
#include <sys/select.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <termios.h>
#include <unistd.h>
#include <fcntl.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/certs_test.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/types.h>

typedef WOLFSSL_METHOD* (*wolf_creator_fun)();

static WOLFSSL* create_client(WOLFSSL_CTX** ctx, char* suite, int setSuite);
static WOLFSSL* create_server(WOLFSSL_CTX** ctx, char* suite, int setSuite);

static int tls_established(WOLFSSL *ssl);
static int tls_client();
static int tls_server();

static int cb_recv(WOLFSSL *ssl, char *buf, int sz, void *ctx);
static int cb_send(WOLFSSL *ssl, char *buf, int sz, void *ctx);

static ssize_t write_all(int fd, const void* buf, size_t size);
static int read_wait(int fd, int timeout);
static int read_wont_block(int fd);

static void configure_tty(int fd);
static int open_tty(const char* device);
static int create_pty();

static const char* get_env_val(const char* var, const char* default_val);

#define LOCAL_CERT (get_env_val("TTY_LOCAL_KEY", "/etc/ttytls/local-cert.pem"))
#define LOCAL_KEY  (get_env_val("TTY_LOCAL_KEY", "/etc/ttytls/local-key.pem"))
#define PEER_CERT (get_env_val("TTY_PEER_CERT", "/etc/ttytls/peer-cert.pem"))

// file descriptor of the TTY transmitting/receiving ciphertext
static int fd_tty = -1;
// file descriptor of the PTY transmitting/receiving plaintext
static int fd_pty = -1;

static char buffer[1024];
static char err[80];

static int timeout = -1;
static speed_t baud_rate = B115200;

const char* get_env_val(const char* var, const char* default_val)
{
    const char* val = getenv(var);
    if (val != NULL)
    {
        return val;
    }
    else
    {
        return default_val;
    }
}

int read_wait(int fd, int timeout)
{
    fd_set rd_fds;
    FD_ZERO(&rd_fds);
    FD_SET(fd, &rd_fds);

    int nfds = fd + 1;

    struct timeval tv =
    {
        .tv_sec = timeout,
        .tv_usec = 0
    };

    return select(nfds, &rd_fds, NULL, NULL, timeout < 0 ? NULL : &tv);
}

int read_wont_block(int fd)
{
    return read_wait(fd, 0);
}

int cb_recv(WOLFSSL *ssl, char *buf, int sz, void *ctx)
{
    (void) ssl;
    (void) ctx;

    int block = read_wont_block(fd_tty);
    if (block > 0)
    {
        return (int)read(fd_tty, buf, (size_t)sz);
    }
    else if (block < 0)
    {
        return WOLFSSL_CBIO_ERR_GENERAL;
    }
    else
    {
        return WOLFSSL_CBIO_ERR_WANT_READ;
    }
}

int cb_send(WOLFSSL *ssl, char *buf, int sz, void *ctx)
{
    (void) ssl;
    (void) ctx;

    return (int)write(fd_tty, buf, (size_t)sz);
}

void flush_tty(int fd)
{
    tcflush(fd, TCIOFLUSH);

    while (read_wont_block(fd) > 0)
    {
        read(fd, buffer, sizeof(buffer));
    }
}

void configure_tty(int fd)
{
    struct termios termarg;

    memset(&termarg, 0, sizeof(termarg));
    cfmakeraw(&termarg);

    termarg.c_cflag |=  (CRTSCTS | CREAD);

    termarg.c_cc[VMIN] = 1;
    termarg.c_cc[VTIME] = 0;

    cfsetspeed(&termarg, baud_rate);

    tcsetattr(fd, TCSANOW, &termarg);
    flush_tty(fd);
}

int open_tty(const char* device)
{
    int fd;

    fd = open(device, O_RDWR | O_NOCTTY);
    if (fd < 0)
    {
        return -1;
    }

    configure_tty(fd);
    return fd;
}

int create_pty()
{
    return open_tty("/dev/ptmx");
}

WOLFSSL* create_wolf_ssl(wolf_creator_fun fun, WOLFSSL_CTX** ctx, const char* suite, int set_suite)
{
    WOLFSSL* ssl;
    int ret = -1;

    *ctx = wolfSSL_CTX_new(fun());
    if (*ctx == NULL)
    {
        fprintf(stderr, "Error in setting server ctx\n");
        return NULL;
    }

    ret = wolfSSL_CTX_use_certificate_file(*ctx, LOCAL_CERT, SSL_FILETYPE_PEM);
    if (ret != SSL_SUCCESS)
    {
        fprintf(stderr, "trouble loading local cert file\n");
        return NULL;
    }

    ret = wolfSSL_CTX_use_PrivateKey_file(*ctx, LOCAL_KEY, SSL_FILETYPE_PEM);
    if (ret != SSL_SUCCESS)
    {
        fprintf(stderr, "trouble loading local key file\n");
        return NULL;
    }

    ret = wolfSSL_CTX_load_verify_locations(*ctx, PEER_CERT, 0);
    if (ret != SSL_SUCCESS)
    {
        fprintf(stderr, "Failed to load peer cert file\n");
        return NULL;
    }

    if (set_suite == 1)
    {
        ret = wolfSSL_CTX_set_cipher_list(*ctx, suite);
        if (ret != SSL_SUCCESS)
        {
            fprintf(stderr, "ret = %d\n", ret);
            fprintf(stderr, "Error: can't set cipher\n");
            wolfSSL_CTX_free(*ctx);
            return NULL;
        }
    }
    else
    {
        (void) suite;
    }

    wolfSSL_SetIORecv(*ctx, cb_recv);
    wolfSSL_SetIOSend(*ctx, cb_send);

    ssl = wolfSSL_new(*ctx);
    if (ssl == NULL)
    {
        fprintf(stderr, "issue when creating ssl\n");
        wolfSSL_CTX_free(*ctx);
        return NULL;
    }

    wolfSSL_set_fd(ssl, fd_tty);

    return ssl;
}

WOLFSSL* create_server(WOLFSSL_CTX** ctx, char* suite, int set_suite)
{
    return create_wolf_ssl(wolfTLSv1_3_server_method, ctx, suite, set_suite);
}

WOLFSSL* create_client(WOLFSSL_CTX** ctx, char* suite, int set_suite)
{
    return create_wolf_ssl(wolfTLSv1_3_client_method, ctx, suite, set_suite);
}

ssize_t write_all(int fd, const void* buf, size_t len)
{
    size_t written = 0;
    const char* char_buf = (const char*)buf;

    while (written < len)
    {
        ssize_t ret = write(fd, char_buf + written, len - written);
        if (ret < 0)
        {
            return -1;
        }

        written += ret;
    }

    return written;
}

int tls_established(WOLFSSL* ssl)
{
    fd_pty = create_pty();
    if (fd_pty < 0)
    {
        return 1;
    }

    fprintf(stderr, "Connected\n");

    unlockpt(fd_pty);
    printf("%s\n", ptsname(fd_pty));
    fflush(stdout);

    int loop = 1;
    int ret = 0;
    while (loop)
    {
        fd_set rd_fds;
        FD_ZERO(&rd_fds);

        FD_SET(fd_pty, &rd_fds);
        FD_SET(fd_tty, &rd_fds);

        int nfds = (fd_pty > fd_tty ? fd_pty : fd_tty) + 1;

        struct timeval tv =
        {
            .tv_sec = timeout,
            .tv_usec = 0
        };

        ret = select(nfds, &rd_fds, NULL, NULL, timeout > 0 ? &tv : NULL);
        if (ret < 0)
        {
            fprintf(stderr, "Error calling select\n");
            ret = 1;
            loop = 0;
            break;
        }
        else if (ret == 0)
        {
            fprintf(stderr, "Timeout\n");
            ret = 0;
            loop = 0;
            break;
        }

        int error;

        if (FD_ISSET(fd_pty, &rd_fds))
        {
            do
            {
                int pty_read = read(fd_pty, buffer, sizeof(buffer));
                if (pty_read > 0)
                {
                    ret = wolfSSL_write(ssl, buffer, pty_read);
                    error = wolfSSL_get_error(ssl, 0);
                    if (ret != pty_read)
                    {
                        if (error != SSL_ERROR_WANT_READ &&
                            error != SSL_ERROR_WANT_WRITE)
                        {
                            fprintf(stderr, "SSL Write failed ret = %d err = %d (%s)\n",
                                    ret, error, wolfSSL_ERR_error_string(error, err));
                            ret = 1;
                            loop = 0;
                            break;
                        }
                    }
                }
                else if (pty_read < 0)
                {
                    perror("PTY read failed");
                    ret = 1;
                    loop = 0;
                    break;
                }
            }
            while(read_wont_block(fd_pty) > 0);
        }

        if (FD_ISSET(fd_tty, &rd_fds))
        {
            do
            {
                ret = wolfSSL_read(ssl, buffer, sizeof(buffer));
                error = wolfSSL_get_error(ssl, 0);
                if (ret < 0)
                {
                    if (error != SSL_ERROR_WANT_READ &&
                        error != SSL_ERROR_WANT_WRITE)
                    {
                        fprintf(stderr, "SSL Read failed ret = %d err = %d (%s)\n",
                                ret, error, wolfSSL_ERR_error_string(error, err));
                        ret = 1;
                        loop = 0;
                        break;
                    }
                }
                else if (ret > 0)
                {
                    if (write_all(fd_pty, buffer, ret) != ret)
                    {
                        perror("PTY write failed");
                        ret = 1;
                        loop = 0;
                        break;
                    }
                }
            }
            while (wolfSSL_pending(ssl) > 0);
        }
    }

    close(fd_pty);

    return ret;
}

int tls_server()
{
    WOLFSSL* ssl = NULL;
    WOLFSSL_CTX* ctx = NULL;

    ssl = create_server(&ctx, "let-wolfssl-decide", 0);
    if (ssl == NULL)
    {
        wolfSSL_CTX_free(ctx);
        return 1;
    }

    fprintf(stderr, "Waiting for connection\n");

    int ret = SSL_FAILURE;
    while (ret != SSL_SUCCESS)
    {
        int error;

        ret = wolfSSL_accept(ssl);
        error = wolfSSL_get_error(ssl, 0);
        if (ret != SSL_SUCCESS)
        {
            if (error != SSL_ERROR_WANT_READ &&
                error != SSL_ERROR_WANT_WRITE)
            {
                wolfSSL_free(ssl);
                wolfSSL_CTX_free(ctx);
                fprintf(stderr,
                        "server ssl accept failed ret = %d error = %d (%s)\n",
                        ret, error, wolfSSL_ERR_error_string(error, err));
                return 1;
            }

            int connect_wait = read_wait(fd_tty, timeout);
            if (connect_wait < 0)
            {
                perror("Error trying to accept");
                wolfSSL_free(ssl);
                wolfSSL_CTX_free(ctx);
                return 1;
            }
            else if (connect_wait == 0)
            {
                fprintf(stderr, "Timeout\n");
                wolfSSL_free(ssl);
                wolfSSL_CTX_free(ctx);
                return 1;
            }
        }
    }

    ret = tls_established(ssl);

    wolfSSL_shutdown(ssl);
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);

    return ret;
}

int tls_client()
{
    WOLFSSL* ssl = NULL;
    WOLFSSL_CTX* ctx = NULL;

    ssl = create_client(&ctx, "let-wolfssl-decide", 0);
    if (ssl == NULL)
    {
        wolfSSL_CTX_free(ctx);
        return 1;
    }

    fprintf(stderr, "Trying to connect\n");

    int ret = SSL_FAILURE;
    while (ret != SSL_SUCCESS)
    {
        int error;

        ret = wolfSSL_connect(ssl);
        error = wolfSSL_get_error(ssl, 0);
        if (ret != SSL_SUCCESS)
        {
            if (error != SSL_ERROR_WANT_READ &&
                error != SSL_ERROR_WANT_WRITE)
            {
                fprintf(stderr, "Could not connect ret = %d error = %d (%s)\n",
                        ret, error, wolfSSL_ERR_error_string(error, err));
                wolfSSL_free(ssl);
                wolfSSL_CTX_free(ctx);
                return 1;
            }

            int connect_wait = read_wait(fd_tty, timeout);
            if (connect_wait < 0)
            {
                perror("Error trying to connect");
                wolfSSL_free(ssl);
                wolfSSL_CTX_free(ctx);
                return 1;
            }
            else if (connect_wait == 0)
            {
                fprintf(stderr, "Timeout\n");
                wolfSSL_free(ssl);
                wolfSSL_CTX_free(ctx);
                return 1;
            }
        }
    }

    ret = tls_established(ssl);

    wolfSSL_shutdown(ssl);
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);

    return ret;
}

/* ttyTLS.c
 *
 * This program initializes a TLS connection on top of a TTY
 * and provides a PTY which can be used by other applications
 * to communicate over this TTY using that TLS connection once
 * it has been established. This can be useful to eg. secure all
 * traffic sent over a serial port or modem device. One obvious
 * use case would be to run pppd on the PTY generated by this
 * program, as a way to encrypt all network traffic sent between
 * two devices
 *
 * The program can either be configured to listen for a TLS
 * session initialized on the other side of the TTY or initiate
 * a TLS session to a listener on the other side.
 *
 * The path to the PTY is output to standard output. This can be
 * useful to calling scripts to eg. set up symlinks.
 */
int main(int argc, char* argv[])
{
    if (argc < 2)
    {
        fprintf(stderr, "usage: ttyTLS [-l] [-b <baud rate>] [-t <timeout>] <tty>");
        return 1;
    }

    int is_server = 0;
    char c = 0;
    while ((c = getopt(argc, argv, "lb:t:")) != -1)
    {
        switch(c)
        {
        case 'l':
            is_server = 1;
            break;
        case 'b':
            switch(atoi(optarg))
            {
            case 9600:
                baud_rate = B9600;
                break;
            case 19200:
                baud_rate = B19200;
                break;
            case 38400:
                baud_rate = B38400;
                break;
            case 57600:
                baud_rate = B57600;
                break;
            case 115200:
                baud_rate = B115200;
                break;
            case 230400:
                baud_rate = B230400;
                break;
            default:
                fprintf(stderr, "Valid baud rates: 9600|19200|38400|57600|115200|230400\n");
                return 1;
            }
            break;
        case 't':
            timeout = atoi(optarg);
            if (timeout <= 0)
            {
                fprintf(stderr, "Timeout must be > 0\n");
                return 1;
            }
            break;
        }
    }

    fd_tty = open_tty(argv[optind]);
    if (fd_tty < 0)
    {
        fprintf(stderr, "Error opening tty\n");
    }

    wolfSSL_Init();

    int ret = 0;
    if (is_server)
    {
        fprintf(stderr, "Starting TLS Server\n");
        ret = tls_server(argv[optind]);
    }
    else
    {
        fprintf(stderr, "Starting TLS Client\n");
        ret = tls_client(argv[optind]);
    }

    wolfSSL_Cleanup();

    close(fd_tty);
    return 0;
}
