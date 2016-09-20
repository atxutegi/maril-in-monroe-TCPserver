/**
 * *****************************************************************************
 * Copyright 2016-2017 University of the Basque Country (UPV/EHU)
 *
 * Code adaptation and development based on
 * https://github.com/alladin-IT/open-rmbt/tree/master/RMBTServer
 *
 * This code includes an adaptation and simplication of the software developed at:
 * alladin-IT GmbH (https://alladin.at/),
 * Rundfunk und Telekom Regulierungs-GmbH (RTR-GmbH) (https://www.rtr.at/)
 * and Specure GmbH (https://www.specure.com/).
 *
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *****************************************************************************
 */

#define _POSIX_C_SOURCE 200809L
#define _BSD_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <signal.h>
#include <syslog.h>

#include <pwd.h>
#include <grp.h>

#include <sys/mman.h>
#include <sys/time.h>

#include <time.h>

#include <pthread.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <poll.h>
#include <arpa/inet.h>

#include "config.h"

#include <openssl/ssl.h>
#include <openssl/err.h>
    
static pthread_mutex_t *lockarray;
#define MY_SOCK BIO*
#define my_organic_write BIO_write
#define my_organic_read BIO_read

#define BACKSPACE '\n'
#define DOWNLOAD "DOWNLOAD"
#define REQUESTFRAME "REQUESTFRAME"
#define UPLOAD "UPLOAD"
#define UPTESTING "UPTESTING"
#define PING "PING"
#define PONG "PONG\n"
#define ACK "ACK"
#define ACK_SERVER "ACK\n"
#define WAITING "WAITING FOR COMMAND\n"
#define ERROR "ERROR\n"
#define FIN "FIN"
#define FINACK "FINACK\n"

volatile int accept_queue[ACCEPT_QUEUE_MAX_SIZE];
volatile int accept_queue_listen_idx[ACCEPT_QUEUE_MAX_SIZE];
volatile int accept_queue_size, accept_queue_start = 0;
pthread_mutex_t accept_queue_mutex = PTHREAD_MUTEX_INITIALIZER;

pthread_cond_t accept_queue_not_empty = PTHREAD_COND_INITIALIZER;
pthread_cond_t accept_queue_not_full = PTHREAD_COND_INITIALIZER;

volatile int do_shutdown = 0;

struct listen
{
    struct sockaddr_in6 sockaddr;
    int sock;
} *listens;
int num_listens;

struct thread_info
{
    pthread_t thread_id;
    int thread_num;
} *thread_infos;

// char *pidfile = NULL;

int num_threads = DEFAULT_NUM_THREADS;

char *total_random;
long random_size;

long page_size;

void print_help()
{
	printf("--- maril ---\n"
			"command line arguments:\n\n"
			" -l     listen on (IP and) port;\n\n"
			" -t     number of worker threads to run for handling connections (default: %d)\n\n"
			" -d     fork into background as daemon (no argument)\n\n"
			"-l option is required\n",
			DEFAULT_NUM_THREADS);
}

void syslog_and_print(FILE *fp, int priority, const char *format, ...)
{
    int len = strlen(format);
    char format_nl[len + 2];
    strncpy(format_nl, format, len);
    format_nl[len] = '\n';
    format_nl[len + 1] = '\0';
    
    va_list va1;
    va_start(va1, format);
    vfprintf(fp, format_nl, va1);
    va_end(va1);
}

ssize_t my_write(MY_SOCK fd, const void *buf, size_t count) {
    return my_organic_write(fd,buf,count);
}

ssize_t my_read(MY_SOCK b, void *buf, size_t count) {
    return my_organic_read(b,buf,count);
}


int my_readline(MY_SOCK sock, const char *buf, int size)
{
    const char *buf_ptr = buf;
    int size_remain = size;
    int r;
    char *nl_ptr = NULL;
    
    do
    {
        r = my_read(sock, (void*)buf_ptr, size_remain);
        if (r > 0)
        {
            nl_ptr = memchr(buf_ptr, BACKSPACE, r);
            buf_ptr += r;
            size_remain -= r;
        }
    }
    while (r > 0 && nl_ptr == NULL && size_remain > 0);
    if (size_remain <= 0)
        return -1;
    if (nl_ptr != NULL)
        *nl_ptr = '\0';
    return  buf_ptr - buf;
}

void fill_ts(struct timespec *time_result)
{
    int clock;
    
    clock = clock_gettime(CLOCK_MONOTONIC, time_result);
    if (clock == -1)
    {
        syslog(LOG_ERR, "error during clock_gettime: %m");
        exit(EXIT_FAILURE);
    }
}

long long ts_diff(struct timespec *start)
{
    struct timespec end;
    fill_ts(&end);
    
    if ((end.tv_nsec-start->tv_nsec)<0)
    {
        start->tv_sec = end.tv_sec-start->tv_sec-1;
        start->tv_nsec = 1000000000ull + end.tv_nsec-start->tv_nsec;
    }
    else
    {
        start->tv_sec = end.tv_sec-start->tv_sec;
        start->tv_nsec = end.tv_nsec-start->tv_nsec;
    }
    return start->tv_nsec + (long long)start->tv_sec * 1000000000ull;
}

long long ts_diff_preserve(struct timespec *start)
{
    struct timespec end;
    fill_ts(&end);
    
    if ((end.tv_nsec-start->tv_nsec)<0)
    {
        end.tv_sec = end.tv_sec-start->tv_sec-1;
        end.tv_nsec = 1000000000ull + end.tv_nsec-start->tv_nsec;
    }
    else
    {
        end.tv_sec = end.tv_sec-start->tv_sec;
        end.tv_nsec = end.tv_nsec-start->tv_nsec;
    }
    return end.tv_nsec + (long long)end.tv_sec * 1000000000ull;
}

void do_bind()
{
    int true = 1;
    
    int i;
    for (i = 0; i < num_listens; i++)
    {
        if ((listens[i].sock = socket(AF_INET6, SOCK_STREAM, 0)) == -1)
        {
            syslog(LOG_ERR, "error during socket: %m");
            exit(EXIT_FAILURE);
        }
        
        if (setsockopt(listens[i].sock, SOL_SOCKET, SO_REUSEADDR, &true, sizeof (int)) == -1)
        {
            syslog(LOG_ERR, "error during setsockopt SO_REUSEADDR: %m");
            exit(EXIT_FAILURE);
        }
        
        /* set receive timeout */
        struct timeval timeout;
        timeout.tv_sec = TIMEOUT;
        timeout.tv_usec = 0;
        if (setsockopt(listens[i].sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof (timeout)) == -1)
        {
            syslog(LOG_ERR, "error during setsockopt SO_RCVTIMEO: %m");
            exit(EXIT_FAILURE);
        }
        
        /* set send timeout */
        if (setsockopt(listens[i].sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof (timeout)) == -1)
        {
            syslog(LOG_ERR, "error during setsockopt SO_SNDTIMEO: %m");
            exit(EXIT_FAILURE);
        }
        
        char ip[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &listens[i].sockaddr.sin6_addr, ip, sizeof(ip));
        if (bind(listens[i].sock, (const struct sockaddr *) &listens[i].sockaddr, sizeof(*listens)) == -1)
        {
            syslog(LOG_ERR, "error while binding on [%s]:%d: %m", ip, ntohs(listens[i].sockaddr.sin6_port));
            exit(EXIT_FAILURE);
        }
        
        if (listen(listens[i].sock,LISTENNING) == -1)
        {
            syslog(LOG_ERR, "error during listen: %m");
            exit(EXIT_FAILURE);
        }
        syslog(LOG_INFO, "listening on [%s]:%d", ip, ntohs(listens[i].sockaddr.sin6_port));
    }
}

void unbind()
{
    syslog(LOG_DEBUG, "closing sockets");
    int i;
    for (i = 0; i < num_listens; i++)
    {
        close(listens[i].sock);
    }
}

void accept_loop()
{
    struct pollfd poll_array[num_listens];
    int i;
    for (i = 0; i < num_listens; i++)
    {
        poll_array[i].fd = listens[i].sock;
        poll_array[i].events = POLLIN;
    }
    
    syslog(LOG_INFO, "ready for connections");
    
    /* accept loop */
    while (! do_shutdown)
    {
        /* poll */
        int r = poll(poll_array, num_listens, -1);
        if (r == -1)
        {
            if (errno != EINTR)
                syslog(LOG_ERR, "error during poll: %m");
            continue;
        }
	syslog(LOG_INFO, "BEFORE FOR");
        for (i = 0; i < num_listens; i++)
        {
	    syslog(LOG_INFO, "BEFORE IF");
            if ((poll_array[i].revents & POLLIN) != 0)
            {
                /* accept */
                int socket_descriptor = accept(listens[i].sock, NULL, NULL);
                
                /* if valid socket descriptor */
		syslog(LOG_INFO, "BEFORE IF 2");
                if (socket_descriptor >= 0)
                {
                    /* lock */
                    pthread_mutex_lock(&accept_queue_mutex);
                    
                    /* wait until queue not full anymore */
                    while (! do_shutdown && accept_queue_size == ACCEPT_QUEUE_MAX_SIZE)
                        pthread_cond_wait(&accept_queue_not_full, &accept_queue_mutex);
                    
                    if (do_shutdown)
                        return;
                    
                    /* add socket descriptor to queue */
                    int idx = (accept_queue_start + accept_queue_size++) % ACCEPT_QUEUE_MAX_SIZE;
                    accept_queue[idx] = socket_descriptor;
                    accept_queue_listen_idx[idx] = i;
                    
                    /* if queue was empty, signal a thread to start looking for the socket descriptor */
                    if (accept_queue_size > 0)
                        pthread_cond_signal(&accept_queue_not_empty);
                    
                    /* unlock */
                    pthread_mutex_unlock(&accept_queue_mutex);
                }
            }
        }
    }
}

const char *base64(const char *input, int ilen, char *output, int *olen)
{
    BIO *bmem, *b64;
    BUF_MEM *bptr;
    
    b64 = BIO_new(BIO_f_base64());
    bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);
    BIO_write(b64, input, ilen);
    BIO_flush(b64);
    BIO_get_mem_ptr(b64, &bptr);
    
    if (bptr->length > *olen)
    {
        BIO_free_all(b64);
        return NULL;
    }
    else
    {
        memcpy((void *)output, bptr->data, bptr->length);
        output[bptr->length - 1]='\0';
        *olen = bptr->length;
        BIO_free_all(b64);
        return output;
    }
}

int check_passphrase(int thread_num, const char *uuid)
{
    char msg[128]="158f-43cb-912-191-fdf2-5b76-bca-4ef0";
    if (strncmp(uuid, msg, sizeof(msg)) == 0)
    	return 0;
    else
	return 1;
}


void write_err(MY_SOCK sock)
{
    my_write(sock, ERROR, sizeof(ERROR)-1);
    //printf("sending ERR\n");
}

void handle_connection(int thread_num, MY_SOCK sock)
{
    /************************/
    
    char buf1[FRAMESIZE];
    char buf2[FRAMESIZE];
    char buf3[FRAMESIZE];
    char buf4[FRAMESIZE];
    int r, s;
    FILE *fp;
    fp=fopen("outputServer.txt", "a");
    
    r = my_readline(sock, buf1, sizeof (buf1));
    if (r <= 0) {
        syslog(LOG_INFO, "initialization error: %d %d", r, (int) ERR_get_error());
        ERR_print_errors_fp(stdout);
        return;
    }
    r = sscanf((char*)buf1, "PASSPHRASE %36[0-9a-f-]", buf2);
    if (r != 1)
    {
    	syslog(LOG_ERR, "Thread %d: syntax error on passphrase: \"%s\"", thread_num, buf1);
        return;
    }
    
    if (CHECK_PASSPHRASE)
    {
        if (check_passphrase(thread_num, buf2))
        {
        	syslog(LOG_ERR, "Thread %d: passphrase was not accepted", thread_num);
            return;
        }

        syslog(LOG_INFO, "Thread %d: valid passphrase; uuid: %s", thread_num, buf2);
    }
    else
    	syslog(LOG_INFO, "Thread %d: passphrase NOT CHECKED; uuid: %s", thread_num, buf2);
  

    my_write(sock, ACK_SERVER, sizeof(ACK_SERVER)-1);
    r = snprintf(buf1, sizeof(buf1), "FRAMESIZE %d\n", FRAMESIZE);
    if (r <= 0) return;
    s = my_write(sock, buf1, r);
    if (r != s) return;
    
    for (;;)
    {
        my_write(sock, WAITING, sizeof(WAITING)-1);
        int r = my_readline(sock, buf1, sizeof(buf1));
        if (r <= 0)
            return;
        
        int elements = sscanf((char*)buf1, "%50s %12[^\n]", buf2, buf3);
        
        /***** DOWNLOAD *****/
        if (elements == 2 && strncmp((char*)buf2, DOWNLOAD, sizeof(DOWNLOAD)) == 0)
        {
            int seconds;
            r = sscanf((char*)buf3, "%12d", &seconds);
            if (r != 1 || seconds <=0 || seconds > MAX_DURATION)
                write_err(sock);
            else
            {
                long long maxnsec = (long long)seconds * 1000000000ull;
                
                /* start time measurement */
                struct timespec timestamp;
                fill_ts(&timestamp);
                
                /* TODO: start at random place? */
                char *random_ptr = total_random;
                //unsigned char null = 0x00;
                //unsigned char ff = 0xff;
                long long diffnsec;
                unsigned long total_bytes = 0;
                
                //char debugrandom[frame];
                //memset(debugrandom, 0, sizeof(debugrandom));

		syslog_and_print(fp, LOG_INFO,"Max %lld nsec", maxnsec); //NQAS
                syslog_and_print(fp, LOG_INFO,"Download phase"); //NQAS

                do
                {
                    if (random_ptr + FRAMESIZE >= (total_random + random_size))
                        random_ptr = total_random;
                    
                    memcpy(buf4, random_ptr, FRAMESIZE);
                    
                    diffnsec = ts_diff_preserve(&timestamp);
                    if (diffnsec >= maxnsec)
                        buf4[FRAMESIZE - 1] = 0xff; // signal last package
                    else
                        buf4[FRAMESIZE - 1] = 0x00;
                    
                    r = my_write(sock, buf4, FRAMESIZE);
                    
                    total_bytes += r;
                    random_ptr += FRAMESIZE;

                    syslog_and_print(fp, LOG_INFO,"TIME(nsec) \t %lld \t DATA(bytes) \t %lld", diffnsec, total_bytes); //NQAS

                }
                while (diffnsec < maxnsec && r > 0);
                
                //printf("TIME reached, %lu bytes sent.\n", total_bytes);
                
                if (r <= 0)
                    write_err(sock);
                else
                {
                    int r = my_readline(sock, buf1, sizeof(buf1));
                    if (r <= 0)
                        return;
                    
                    /* end time measurement */
                    long long nsecs_total = ts_diff(&timestamp);
                    
                    if (strncmp((char*)buf1, ACK, sizeof(ACK)) == 0)
                    {
                        //print_speed(nsecs_total, total_bytes);
                        r = snprintf((char*)buf3, sizeof(buf3), "TIME(nsec) \t %lld \t TOTALDATA(bytes) \t %ld", nsecs_total, total_bytes);
                        if (r <= 0) return;
                        s = my_write(sock, buf3, r);
                        if (r != s) return;
                    }
                    else
                        write_err(sock);
                }
            }
        }
        /***** REQUESTFRAME *****/
        else if (elements == 2 && strncmp((char*)buf2, REQUESTFRAME, sizeof(REQUESTFRAME)) == 0)
        {
            int frames;
            r = sscanf((char*)buf3, "%12d", &frames);
            if (r != 1 || frames <=0 || frames > MAX_FRAMES)
                write_err(sock);
            else
            {
                
                /* start time measurement */
                struct timespec timestamp;
                fill_ts(&timestamp);
                
                int s;
                /* TODO: start at random place? */
                char *random_ptr = total_random; 
                unsigned char null = 0x00;
                unsigned char ff = 0xff;
                unsigned long total_bytes = 0;
                
                int frames_sent = 0;

                do
                {
                    if (random_ptr + FRAMESIZE >= (total_random + random_size))
                        random_ptr = total_random;
                    
                    r = my_write(sock, random_ptr, FRAMESIZE - 1);
                    if (++frames_sent >= frames)
                        s = my_write(sock, &ff, 1); // signal last package
                    else
                        s = my_write(sock, &null, 1);
                    total_bytes += r + s;
                    random_ptr += FRAMESIZE;
                }
                while (frames_sent < frames && r > 0 && s > 0);
                
                if (r <= 0 || s <= 0)
                    write_err(sock);
                else
                {
                    int r = my_readline(sock, buf1, sizeof(buf1));
                    if (r <= 0)
                        return;
                    
                    /* end time measurement */
                    long long nsecs_total = ts_diff(&timestamp);
                    
                    if (strncmp((char*)buf1, ACK, sizeof(ACK)) == 0)
                    {
                        //print_speed(nsecs_total, total_bytes);
                        r = snprintf((char*)buf3, sizeof(buf3), "TIME %lld\n", nsecs_total);
                        if (r <= 0) return;
                        s = my_write(sock, buf3, r);
                        if (r != s) return;
                    }
                    else
                        write_err(sock);
                }
            }
        }
        /***** UPLOAD *****/
        else if (elements == 1 && (strncmp((char*)buf2, UPLOAD, sizeof(UPLOAD)) == 0 || strncmp((char*)buf2, UPTESTING, sizeof(UPTESTING)) == 0))
        {
            int printIntermediateResult = strncmp((char*)buf2, UPLOAD, sizeof(UPLOAD)) == 0;
            
            my_write(sock, ACK_SERVER, sizeof(ACK_SERVER)-1);
            
            /* start time measurement */
            struct timespec timestamp;
            fill_ts(&timestamp);
            
            unsigned char last_byte = 0;
            long total_read = 0;
            long long diffnsec;
            long long last_diffnsec = -1;
            //long frames = 0;

            syslog_and_print(fp, LOG_INFO,"Upload phase"); //NQAS

            do
            {
               r = my_read(sock, buf4, sizeof(buf4));
               if (r > 0)
               {
                   int pos_last = FRAMESIZE - 1 - (total_read % FRAMESIZE);
                   if (r > pos_last)
                       last_byte = buf4[pos_last];
                   total_read += r;
               }
               
               if (printIntermediateResult)
               {
                   diffnsec = ts_diff_preserve(&timestamp);
                   //if (++frames % 10 == 0)
                   if (last_diffnsec == -1 || (diffnsec - last_diffnsec > 1e5))
                   {
                       last_diffnsec = diffnsec;
                       syslog_and_print(fp, LOG_INFO,"TIME \t %lld \t BYTES \t %ld", diffnsec, total_read); //NQAS
                       s = snprintf((char*)buf3, sizeof(buf3), "TIME %lld BYTES %ld\n", diffnsec, total_read);
                       if (s <= 0) return;
				r = my_write(sock, buf3, s);
                       if (r != s) return;
                   }
               }
            }
            while (r > 0 && last_byte != 0xff);
            long long nsecs = ts_diff(&timestamp);
            if (r <= 0)
                write_err(sock);
            else
            {
                //print_speed(nsecs, total_read);
                
                syslog_and_print(fp, LOG_INFO,"TIME \t %lld", nsecs); //NQAS
                
                r = snprintf((char*)buf3, sizeof(buf3), "TIME %lld\n", nsecs);
                if (r <= 0) return;
                s = my_write(sock, buf3, r);
                if (r != s) return;
            }
        }
        /***** FIN *****/
        else if (strncmp((char*)buf2, FIN, sizeof(FIN)) == 0)
        {
            my_write(sock, FINACK, sizeof(FINACK)-1);
            return;
        }
        /***** PING *****/
        else if (elements == 1 && strncmp((char*)buf2, PING, sizeof(PING)) == 0)
        {
            /* start time measurement */
            struct timespec timestamp;
            fill_ts(&timestamp);
            
            my_write(sock, PONG, sizeof(PONG)-1);
            int r = my_readline(sock, buf1, sizeof(buf1));
            if (r <= 0)
                return;
            
            /* end time measurement */
            long long nsecs = ts_diff(&timestamp);
            
            if (strncmp((char*)buf1, ACK, sizeof(ACK)) != 0)
                write_err(sock);
            else
            {
                r = snprintf((char*)buf3, sizeof(buf3), "TIME %lld\n", nsecs);
                if (r <= 0) return;
                s = my_write(sock, buf3, r);
                if (r != s) return;
                
                //print_milsecs(nsecs);
            }
        }
        else
            write_err(sock);
    
        /************************/
    }
    fclose(fp);
}

static void *worker_thread_main(void *arg)
{
    struct thread_info *tinfo = arg;
    int thread_num = tinfo->thread_num;
    while (! do_shutdown)
    {
        /* lock */
        pthread_mutex_lock(&accept_queue_mutex);
        
        /* wait until something in queue */ 
        while (! do_shutdown && accept_queue_size == 0)
            pthread_cond_wait(&accept_queue_not_empty, &accept_queue_mutex);
        
        if (do_shutdown)
        {
            pthread_mutex_unlock(&accept_queue_mutex);
            return NULL;
        }
        
        /* get from queue */
        accept_queue_size--;
        int idx = accept_queue_start++;
        int socket_descriptor = accept_queue[idx];
        if (accept_queue_start == ACCEPT_QUEUE_MAX_SIZE)
            accept_queue_start = 0;
        
        /* if queue was full, send not_full signal */
        if (accept_queue_size + 1 == ACCEPT_QUEUE_MAX_SIZE)
            pthread_cond_signal(&accept_queue_not_full);
        
        /* unlock */
        pthread_mutex_unlock(&accept_queue_mutex);
        
        struct sockaddr_in6 addr;
        socklen_t addrlen = sizeof(addr);
        int r = getsockname(socket_descriptor, (struct sockaddr *) &addr, &addrlen);
        if (r == -1)
        {
            syslog(LOG_ERR, "Thread %d: error during getsockname: %m", thread_num);
            continue;
        }
        
        r = getpeername(socket_descriptor, (struct sockaddr *) &addr, &addrlen);
        if (r == -1)
        {
            syslog(LOG_ERR, "Thread %d: error during getpeername: %m", thread_num);
            continue;
        }
        int peer_port = ntohs(addr.sin6_port);
        
        char buf[128];
        if (inet_ntop(AF_INET6, &addr.sin6_addr, buf, sizeof(buf)) == NULL)
        {
            syslog(LOG_ERR, "Thread %d: error during inet_ntop: %m", thread_num);
            continue;
        }
        syslog(LOG_INFO, "Thread %d: connection from: [%s]:%d", thread_num, buf, peer_port);
        
        
        BIO *sock;
        sock = BIO_new(BIO_s_fd());
        BIO_set_fd(sock, socket_descriptor, BIO_CLOSE);
        
	handle_connection(thread_num, sock);
        
        syslog(LOG_INFO, "Thread %d: closing connection", thread_num);

        BIO_free(sock);
    }
    
    return NULL;
}

void start_threads()
{
    int i;
    
    syslog(LOG_INFO, "starting %d worker threads", num_threads);
    
    thread_infos = calloc(num_threads, sizeof(struct thread_info));
    if (thread_infos == NULL)
    {
        syslog(LOG_ERR, "error during calloc: %m");
        exit(EXIT_FAILURE);
    }
    
    for (i = 0; i < num_threads; i++)
    {
        thread_infos[i].thread_num = i;
        int rc = pthread_create(&thread_infos[i].thread_id, NULL, &worker_thread_main, &thread_infos[i]);
        if (rc != 0)
        {
            errno = rc;
            syslog(LOG_ERR, "error during pthread_create: %m");
            exit(EXIT_FAILURE);
        }
    }
}

void stop_threads()
{
    int i;
    
    syslog(LOG_INFO, "stopping worker threads...");
    
    if (! do_shutdown)
    {
        syslog(LOG_ERR, "stop_threads() called but !do_shutdown");
        exit(EXIT_FAILURE);
    }
    
    pthread_cond_broadcast(&accept_queue_not_empty);
    
    for (i = 0; i < num_threads; i++)
    {
        pthread_join(thread_infos[i].thread_id, NULL);
    }
    syslog(LOG_INFO, "all worker threads stopped.");
}

void mmap_random()
{
    syslog(LOG_DEBUG, "opening random file");
    int fd = open("random", O_RDONLY);
    if (fd == -1)
    {
        syslog(LOG_ERR, "error while opening random file: %m");
        exit(EXIT_FAILURE);
    }
    
    struct stat stat_data;
    
    int rc = fstat(fd, &stat_data);
    if (rc == -1)
    {
        syslog(LOG_ERR, "error during fstat random: %m");
        exit(EXIT_FAILURE);
    }
    
    if (!S_ISREG (stat_data.st_mode))
    {
        syslog(LOG_ERR, "random is not a regular file");
        exit(EXIT_FAILURE);
    }
    
    random_size = stat_data.st_size;
    
    syslog(LOG_DEBUG, "mmapping random file");
    total_random = mmap(NULL, stat_data.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (total_random == MAP_FAILED)
    {
        syslog(LOG_ERR, "error during mmap random: %m");
        exit(EXIT_FAILURE);
    }
    
    if (close(fd) == -1)
    {
        syslog(LOG_ERR, "error while closing random: %m");
        exit(EXIT_FAILURE);
    }
    
    syslog(LOG_DEBUG, "reading random file");
    /* read whole mmapped file to force caching */
    char buf[FRAMESIZE];
    char *ptr = total_random;
    long read;
    for (read = 0; read < random_size; read+=sizeof(buf))
    {
        memcpy(buf, ptr, sizeof(buf));
        ptr+=sizeof(buf);
    }
    // TODO: handle if not multiple of buf
}

void term_handler(int signum)
{
    do_shutdown = 1;
}


int main(int argc, char **argv)
{
    openlog("maril", LOG_CONS | LOG_PID | LOG_NDELAY, LOG_DAEMON);
    
    int _fork = 0;
    
    num_listens = 0;
    listens = NULL;
    
    char buf[48];
    char buf2[16];
    int port;
    
    int c;
    int i;
    int matched;
    while ((c = getopt (argc, argv, "l:t:dDw")) != -1)
        switch (c)
        {
        case 'l':
            matched = sscanf(optarg, "[%47[0-9.a-fA-F:]]:%d", buf, &port); /* ipv6 syntax */
            if (matched != 2)
            {
                matched = sscanf(optarg, "%15[0-9.]:%d", buf2, &port); /* ipv4 syntax */
                if (matched == 2)
                    snprintf(buf, sizeof(buf), "::ffff:%s", buf2); /* convert to ipv4 mapped ipv6 */
            }
            if (matched != 2)
            {
                matched = sscanf(optarg, "*:%d", &port);
                if (matched != 1)
                    matched = sscanf(optarg, "[*]:%d", &port);
                if (matched != 1)
                    matched = sscanf(optarg, "%d", &port);
            }
            
            if (matched != 1 && matched != 2)
            {
                syslog(LOG_ERR, "could not parse option -%c: \"%s\"", c, optarg);
                print_help();
                return EXIT_FAILURE;
            }
            
            i = num_listens++;
            listens = realloc(listens, num_listens * sizeof(*listens));
            memset(&listens[i], 0, sizeof(*listens));
            listens[i].sockaddr.sin6_family = AF_INET6;
            listens[i].sockaddr.sin6_port = htons(port);
            if (matched == 1)
                listens[i].sockaddr.sin6_addr = in6addr_any;
            else
            {
                if (1 != inet_pton(AF_INET6, buf, &listens[i].sockaddr.sin6_addr))
                {
                    syslog(LOG_ERR, "could not parse ip: \"%s\"", buf);
                    print_help();
                    return EXIT_FAILURE;
                }
            }
            break;
            
        case 't': /* threads */
            sscanf(optarg, "%d", &num_threads);
            break;
            
        case 'd':
            _fork = 1;
            break;
            
	case '?':
        	print_help();
            return EXIT_FAILURE;
            break;
        
        default:
            abort();
        }
    
    if (num_listens == 0)
    {
        syslog(LOG_ERR, "need at least one listen (-l) argument!");
        print_help();
        return EXIT_FAILURE;
    }
    
    if (num_threads <= 0)
    {
        syslog(LOG_ERR, "number of threads (-t) must be positive!");
        print_help();
        return EXIT_FAILURE;
    }
    
    if (_fork)
    {
        syslog(LOG_INFO, "forking deamon");
        
        pid_t pid = fork();
        if (pid == -1)
        {
            syslog(LOG_CRIT, "fork failed");
            return EXIT_FAILURE;
        }
        if (pid > 0)
            return EXIT_SUCCESS; // exit parent
        setsid(); // new session
    }
    
    setlogmask(LOG_UPTO(LOG_INFO));

	syslog(LOG_INFO, "starting...");
	
        
    struct sigaction action;
    memset(&action, 0, sizeof(struct sigaction));
    action.sa_handler = term_handler;
    sigaction(SIGTERM, &action, NULL);
    sigaction(SIGINT, &action, NULL);
    
    action.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &action, NULL);
	
    page_size = sysconf(_SC_PAGE_SIZE);
	
    mmap_random();
	
		
    do_bind();
    
    start_threads();
   
    accept_loop();
    
    syslog(LOG_INFO, "shutdown..");
    
    unbind();
    
    stop_threads();
    
    free(thread_infos);
    thread_infos = NULL;
    free(lockarray);
    lockarray = NULL;
    free(listens);
    listens = NULL;
    
    syslog(LOG_INFO, "exiting.");
    closelog();
    
    return EXIT_SUCCESS;
} /* end main() */

