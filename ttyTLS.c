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

int cb_recv(WOLFSSL *ssl, char *buf, int sz, void *ctx)
{
    (void) ssl;
    (void) ctx;

    return (int)read(fd_tty, buf, (size_t)sz);
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

    fd_set rd_fds;
    FD_ZERO(&rd_fds);

    FD_SET(fd, &rd_fds);

    struct timeval tv;
    memset(&tv, 0, sizeof(tv));

    if (select(2, &rd_fds, NULL, NULL, &tv) > 0)
    {
        read(fd, buffer, sizeof(buffer));
    }
}

/*
 * Taken from:
 * https://tldp.org/HOWTO/Serial-Programming-HOWTO/x115.html
 */
void configure_tty(int fd)
{
    struct termios termarg;

    memset(&termarg, 0, sizeof(termarg));
    // "rawer" option from socat + flow control
    termarg.c_iflag = 0;
    termarg.c_oflag = 0;
    termarg.c_lflag = 0;
    termarg.c_cflag = (CRTSCTS | CS8);
    termarg.c_cc[VMIN] = 1;
    termarg.c_cc[VTIME] = 0;

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
        fd_set wr_fds;
        FD_ZERO(&wr_fds);

        FD_SET(fd, &wr_fds);

        if (select(fd + 1, NULL, &wr_fds, NULL, NULL) < 0)
        {
            return -1;
        }

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

    int ret = 0;
    while (1)
    {
        fd_set rd_fds;
        FD_ZERO(&rd_fds);

        FD_SET(fd_pty, &rd_fds);
        FD_SET(fd_tty, &rd_fds);

        int nfds = (fd_pty > fd_tty ? fd_pty : fd_tty) + 1;

        struct timeval timeout =
        {
            .tv_sec = 0,
            .tv_usec = 50000
        };

        if (select(nfds, &rd_fds, NULL, NULL, &timeout) < 0)
        {
            fprintf(stderr, "Error calling select\n");
            ret = 1;
            break;
        }

        int error;

        if (FD_ISSET(fd_pty, &rd_fds))
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
                        break;
                    }
                }
            }
            else if (pty_read < 0)
            {
                perror("PTY read failed");
                ret = 1;
                break;
            }
        }

        if (FD_ISSET(fd_tty, &rd_fds))
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
                    break;
                }
            }
            else if (ret > 0)
            {
                if (write_all(fd_pty, buffer, ret) != ret)
                {
                    perror("PTY write failed");
                    ret = 1;
                    break;
                }
            }
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

    int ret = SSL_FAILURE;
    while (ret != SSL_SUCCESS)
    {
        int error;

        fprintf(stderr, "Waiting for connection\n");

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

    int ret = SSL_FAILURE;
    while (ret != SSL_SUCCESS)
    {
        int error;

        fprintf(stderr, "Trying to connect\n");

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
        fprintf(stderr, "usage: ttyTLS [-l] <tty>");
    }

    int is_server = 0;
    for (int i = 1; i < argc; ++i)
    {
        if (strcmp(argv[i], "-l") == 0)
        {
            is_server = 1;
        }
    }

    fd_tty = open_tty(argv[argc - 1]);
    if (fd_tty < 0)
    {
        fprintf(stderr, "Error opening tty\n");
    }

    wolfSSL_Init();

    int ret = 0;
    if (is_server)
    {
        fprintf(stderr, "Starting TLS Server\n");
        ret = tls_server(argv[argc - 1]);
    }
    else
    {
        fprintf(stderr, "Starting TLS Client\n");
        ret = tls_client(argv[argc - 1]);
    }

    wolfSSL_Cleanup();
    return 0;
}
