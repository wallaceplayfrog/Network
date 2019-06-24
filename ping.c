#include "ping.h"            

struct proto	proto_v4 = { proc_v4, send_v4, NULL, NULL, 0, IPPROTO_ICMP };

#ifdef	IPV6
struct proto	proto_v6 = { proc_v6, send_v6, NULL, NULL, 0, IPPROTO_ICMPV6 };
#endif

int	datalen = 56;		/* data that goes with ICMP echo request */
int maxdatalen = 65507;

int main(int argc, char **argv)
{
        int c;
        struct addrinfo	*ai;

        opterr = 0;		/* don't want getopt() writing to stderr */
        while ( (c = getopt(argc, argv, "vhbt:qc:i:s:nd")) != -1) {
                switch (c) {
                case 'v':
                        verbose++;
                        break;

                case 'h':
                        help();
                        break;
                case 'b':
                        broadcast = 1;
                        break;
                case 't':
                        ttlcount = atoi(optarg);
                        if (ttlcount < 1)
                                err_quit("错误的输入");
                        printf("time to live %d\n", ttlcount);
                        break;
                case 'c':
                        pingtimes = atoi(optarg);
                        if (pingtimes < 0)
                                err_quit("错误的输入");
                        printf("ping %d times\n", pingtimes);
                        break;
                case 'i':
                        time_lag = atoi(optarg);
                        if (time_lag < 0)
                                err_quit("错误的输入");
                        printf("\n时间间隔 %d s\n", time_lag);
                        break;
                case 'q':
                        printf("quiet mode. ctrl+c to stop\n");
                        quietmode = 1;
                        break;
                case 's':
                        datalen = atoi(optarg);
                        if (datalen < 0)
                                err_quit("错误的输入");
                        if (datalen > maxdatalen)
                                err_quit("packet size %d is too large. Maximum is %d", datalen, maxdatalen);
                        break;
                case 'n':
                        justnumber = 1;
                        break;
                case 'd':
                        sodebug = 1;
                        break;
                case '?':
                        err_quit("unrecognized option: %c", c);
                }
        }

        /*optind指向argv中未解释的参数的第一个*/
        if (optind != argc-1)
                err_quit("usage: ping [ -v ] <hostname>");
        host = argv[optind]; //格式正确时，argv[optind]为主机地址

        pid = getpid();
        signal(SIGALRM, sig_alrm); //为SIGALRM建立信号处理程序
/*这里开始处理主机名参数*/
        ai = host_serv(host, NULL, 0, 0); /*addrinfo结构链表*/
        if (broadcast)
                printf("WARNING: pinging broadcast address\n");
        printf("ping %s (%s): %d data bytes\n", ai->ai_canonname,
                   Sock_ntop_host(ai->ai_addr, ai->ai_addrlen), datalen);

                /* 根据协议初始化4initialize according to protocol */
        if (ai->ai_family == AF_INET) {
                pr = &proto_v4;
#ifdef	IPV6
        } else if (ai->ai_family == AF_INET6) {
                pr = &proto_v6;
                if (IN6_IS_ADDR_V4MAPPED(&(((struct sockaddr_in6 *)
                                                                 ai->ai_addr)->sin6_addr)))
                        err_quit("cannot ping IPv4-mapped IPv6 address");
#endif
        } else
                err_quit("unknown address family %d", ai->ai_family);

        pr->sasend = ai->ai_addr;
        pr->sarecv = calloc(1, ai->ai_addrlen);
        pr->salen = ai->ai_addrlen;
/*readloop处理分组*/
        readloop();

        exit(0);
}

void help(){
        printf("Usage: ping \
[-aAbBdDfhLnOqrRUvV64] [-c count] [-i interval] [-I interface]\n \
\t\t[-m mark] [-M pmtudisc_option] [-l preload] [-p pattern] [-Q tos]\n \
\t\t[-s packetsize] [-S sndbuf] [-t ttl] [-T timestamp_option]\n \
\t\t[-w deadline] [-W timeout] [hop1 ...] destination\n\
Usage: ping -6 \
[-aAbBdDfhLnOqrRUvV] [-c count] [-i interval] [-I interface]\n \
\t\t[-l preload] [-m mark] [-M pmtudisc_option]\n \
\t\t[-N nodeinfo_option] [-p pattern] [-Q tclass] [-s packetsize]\n \
\t\t[-S sndbuf] [-t ttl] [-T timestamp_option] [-w deadline]\n \
\t\t[-W timeout] destination\n");
}

/*中断并输出汇总信息*/
void Stop(){
        int i = 0;
        float sum = 0, max = rttmatrix[0], min = rttmatrix[0], avg = 0;
        for (i;i<nrecv;i++){
                if (rttmatrix[i] > max)
                        max = rttmatrix[i];
                if (rttmatrix[i] < min)
                        min = rttmatrix[i];
                sum += rttmatrix[i];
        }
        avg = sum/nrecv;
        printf("\n--- %s ping statistics ---\n", Sock_ntop_host(pr->sarecv, pr->salen));
        printf("%u packets transmitted, %d received, %0.0f%% packet loss\n", nsent, nrecv, 1.0*(nsent-nrecv)/nsent*100);
        printf("rtt min/avg/max = %.3f/%.3f/%.3f/ ms\n", min, avg, max);
        close(sockfd);
        exit(0);
}

/*剥去ICMP报头*/
void
proc_v4(char *ptr, ssize_t len, struct timeval *tvrecv)
{
        int				hlen1, icmplen;
        double			rtt;
        struct ip		*ip;
        struct icmp		*icmp;
        struct timeval	*tvsend;

        /*求ip报头长度，即ip报头长度标志乘4，头长度指明头中包含的4字节
         *的个数。可接受的最小值是5，最大值是15*/
        ip = (struct ip *) ptr;		/* start of IP header */
        hlen1 = ip->ip_hl << 2;		/* length of IP header */

        icmp = (struct icmp *) (ptr + hlen1);	/*越过ip报头,指向ICMP报头*//* start of ICMP header */
        if ( (icmplen = len - hlen1) < 8) /*len - hlen1为ICMP报头及ICMP数据报的总长度*/
                err_quit("icmplen (%d) < 8", icmplen);/*小于ICMP报头长度则不合理*/

        if (icmp->icmp_type == ICMP_ECHOREPLY) {
                if (icmp->icmp_id != pid) /*确保所接收的是发送的ICMP的回应*/
                        return;			/* not a response to our ECHO_REQUEST */
                if (icmplen < 16)
                        err_quit("icmplen (%d) < 16", icmplen);

                tvsend = (struct timeval *) icmp->icmp_data;
                tv_sub(tvrecv, tvsend);/*接收和发送的时间差*/
                rtt = tvrecv->tv_sec * 1000.0 + tvrecv->tv_usec / 1000.0;/*以毫秒为单位计算rtt*/

                /*显示相关信息*/
                if (!quietmode){
                        if (justnumber)
                                printf("%d bytes from %s : seq=%u, ttl=%d, rtt=%.3f ms\n",
                                        icmplen, Sock_ntop_host(pr->sarecv, pr->salen),
                                        icmp->icmp_seq, ip->ip_ttl, rtt);
                        else
                                printf("%d bytes from %s(%s) : seq=%u, ttl=%d, rtt=%.3f ms\n",
                                        icmplen, Sock_ntop_host(pr->sarecv, pr->salen), Sock_ntop_host(pr->sarecv, pr->salen),
                                        icmp->icmp_seq, ip->ip_ttl, rtt);
                        
                }
                rttmatrix[icmp->icmp_seq] = rtt;                
                nrecv = icmp->icmp_seq + 1; // 统计接收数

        } else if (verbose) {
                printf("  %d bytes from %s: type = %d, code = %d\n",
                                icmplen, Sock_ntop_host(pr->sarecv, pr->salen),
                                icmp->icmp_type, icmp->icmp_code);
        } 
}

void
proc_v6(char *ptr, ssize_t len, struct timeval* tvrecv)
{
#ifdef	IPV6
        int					hlen1, icmp6len;
        double				rtt;
        struct ip6_hdr		*ip6;
        struct icmp6_hdr	*icmp6;
        struct timeval		*tvsend;

        /*
        ip6 = (struct ip6_hdr *) ptr;		// start of IPv6 header 
        hlen1 = sizeof(struct ip6_hdr);
        if (ip6->ip6_nxt != IPPROTO_ICMPV6)
                err_quit("next header not IPPROTO_ICMPV6");

        icmp6 = (struct icmp6_hdr *) (ptr + hlen1);
        if ( (icmp6len = len - hlen1) < 8)
                err_quit("icmp6len (%d) < 8", icmp6len);
        */        

        icmp6=(struct icmp6_hdr *)ptr;  
        if((icmp6len=len)<8)                    //len-40
                err_quit("icmp6len (%d) < 8", icmp6len);


        if (icmp6->icmp6_type == ICMP6_ECHO_REPLY) {
                if (icmp6->icmp6_id != pid)
                        return;			/* not a response to our ECHO_REQUEST */
                if (icmp6len < 16)
                        err_quit("icmp6len (%d) < 16", icmp6len);

                tvsend = (struct timeval *) (icmp6 + 1);
                tv_sub(tvrecv, tvsend);
                rtt = tvrecv->tv_sec * 1000.0 + tvrecv->tv_usec / 1000.0;

                printf("%d bytes from %s: seq=%u, hlim=%d, rtt=%.3f ms\n",
                                icmp6len, Sock_ntop_host(pr->sarecv, pr->salen),
                                icmp6->icmp6_seq, ip6->ip6_hlim, rtt);

        } else if (verbose) {
                printf("  %d bytes from %s: type = %d, code = %d\n",
                                icmp6len, Sock_ntop_host(pr->sarecv, pr->salen),
                                icmp6->icmp6_type, icmp6->icmp6_code);
        }
#endif	/* IPV6 */
}

/*校验和算法*/
unsigned short
in_cksum(unsigned short *addr, int len)
{
        int                             nleft = len;
        int                             sum = 0;
        unsigned short  *w = addr;
        unsigned short  answer = 0;

        /*
         * Our algorithm is simple, using a 32 bit accumulator (sum), we add
         * sequential 16 bit words to it, and at the end, fold back all the
         * carry bits from the top 16 bits into the lower 16 bits.
         */
        /* 把ICMP报头二进制数据以2字节为单位累加起来*/
        while (nleft > 1)  {
                sum += *w++;
                nleft -= 2;
        }
        /*若ICMP报头为奇数个字节，会剩下最后一字节。把最后一个字节视为一个2字节数据
        的高字节，这个2字节数据的低字节为0，继续累加*/

                /* 4mop up an odd byte, if necessary */
        if (nleft == 1) {
                *(unsigned char *)(&answer) = *(unsigned char *)w ;
                sum += answer;
        }

                /* 4add back carry outs from top 16 bits to low 16 bits */
        sum = (sum >> 16) + (sum & 0xffff);     /* add hi 16 to low 16 */
        sum += (sum >> 16);                     /* add carry */
        answer = ~sum;                          /* truncate to 16 bits */
        return(answer);
}

void
send_v4(void)
{
        int			len;
        struct icmp	*icmp;

        icmp = (struct icmp *) sendbuf;
        icmp->icmp_type = ICMP_ECHO;
        icmp->icmp_code = 0;
        icmp->icmp_id = pid;
        icmp->icmp_seq = nsent++;
        gettimeofday((struct timeval *) icmp->icmp_data, NULL);/*记录发送时间*/

        len = 8 + datalen;		/* checksum ICMP header and data */
        icmp->icmp_cksum = 0;
        icmp->icmp_cksum = in_cksum((u_short *) icmp, len);/*校验算法*/

        sendto(sockfd, sendbuf, len, 0, pr->sasend, pr->salen);
}

void
send_v6()
{
#ifdef	IPV6
        int					len;
        struct icmp6_hdr	*icmp6;

        icmp6 = (struct icmp6_hdr *) sendbuf;
        icmp6->icmp6_type = ICMP6_ECHO_REQUEST;
        icmp6->icmp6_code = 0;
        icmp6->icmp6_id = pid;
        icmp6->icmp6_seq = nsent++;
        gettimeofday((struct timeval *) (icmp6 + 1), NULL);

        len = 8 + datalen;		/* 8-byte ICMPv6 header */

        sendto(sockfd, sendbuf, len, 0, pr->sasend, pr->salen);
                /* kernel calculates and stores checksum for us */
#endif	/* IPV6 */
}

void
readloop(void)
{
        int				size;
        char			recvbuf[BUFSIZE];
        socklen_t		len;
        ssize_t			n;
        struct timeval	tval;
        int yes = 1;
        /*创建套接口*/
        sockfd = socket(pr->sasend->sa_family, SOCK_RAW, pr->icmpproto);
        setuid(getuid());		/* don't need special permissions any more */

        size = 60 * 1024;       /* OK if setsockopt fails */
        //设置套接口缓冲区大小
        setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));

        /* -t  ******************** */
        if (ttlcount)
                setsockopt(sockfd,IPPROTO_IP, IP_TTL, &ttlcount, sizeof(ttlcount));
        /* -b */
        if (broadcast)
                setsockopt(sockfd, SOL_SOCKET, SO_BROADCAST, &yes, sizeof(yes));
        /* -d */
        if (sodebug)
                setsockopt(sockfd, SOL_SOCKET, SO_DEBUG, &yes, yes);

        sig_alrm(SIGALRM);		/*发送第一个分组 send first packet */

        //读取返回给ICMP原始套接口的每个分组
        for ( ; ; ) {
                len = pr->salen;
                n = recvfrom(sockfd, recvbuf, sizeof(recvbuf), 0, pr->sarecv, &len);
                //小于0时返回错误
                if (n < 0) {
                        if (errno == EINTR)
                                continue;
                        else
                                err_sys("recvfrom error");
                }
                //记录收到分组的时间
                gettimeofday(&tval, NULL);
                //调用proc来处理这些分组
                (*pr->fproc)(recvbuf, n, &tval);
                /*中断*/
                signal(SIGINT, Stop);
                /* -c */
                if (pingtimes)
                        if (nrecv == pingtimes)
                                Stop();
        }
}

void
sig_alrm(int signo)
{
        (*pr->fsend)();

        /* -i */
        if (time_lag){
                alarm(time_lag);
                return;
        }
        alarm(1);
        return;         /* 可能会中断接收probably interrupts recvfrom() */
}

/*计算接收和发送的时间差*/
void
tv_sub(struct timeval *out, struct timeval *in)
{
        if ( (out->tv_usec -= in->tv_usec) < 0) {	/* out -= in */
                --out->tv_sec;
                out->tv_usec += 1000000;
        }
        out->tv_sec -= in->tv_sec;
}




char *
sock_ntop_host(const struct sockaddr *sa, socklen_t salen)
{
    static char str[128];               /* Unix domain is largest */

        switch (sa->sa_family) {
        case AF_INET: {
                struct sockaddr_in      *sin = (struct sockaddr_in *) sa;

                if (inet_ntop(AF_INET, &sin->sin_addr, str, sizeof(str)) == NULL)
                        return(NULL);
                return(str);
        }

#ifdef  IPV6
        case AF_INET6: {
                struct sockaddr_in6     *sin6 = (struct sockaddr_in6 *) sa;

                if (inet_ntop(AF_INET6, &sin6->sin6_addr, str, sizeof(str)) == NULL)
                        return(NULL);
                return(str);
        }
#endif

#ifdef  HAVE_SOCKADDR_DL_STRUCT
        case AF_LINK: {
                struct sockaddr_dl      *sdl = (struct sockaddr_dl *) sa;

                if (sdl->sdl_nlen > 0)
                        snprintf(str, sizeof(str), "%*s",
                                         sdl->sdl_nlen, &sdl->sdl_data[0]);
                else
                        snprintf(str, sizeof(str), "AF_LINK, index=%d", sdl->sdl_index);
                return(str);
        }
#endif
        default:
                snprintf(str, sizeof(str), "sock_ntop_host: unknown AF_xxx: %d, len %d",
                                 sa->sa_family, salen);
                return(str);
        }
    return (NULL);
}

char *
Sock_ntop_host(const struct sockaddr *sa, socklen_t salen)
{
        char    *ptr;

        if ( (ptr = sock_ntop_host(sa, salen)) == NULL)
                err_sys("sock_ntop_host error");        /* inet_ntop() sets errno */
        return(ptr);
}

/*返回指针，指向由其中ai_next成员串联起来的addrinfo结构链表*/
struct addrinfo *
host_serv(const char *host, const char *serv, int family, int socktype)
{
        int                             n;
        struct addrinfo hints, *res;

        bzero(&hints, sizeof(struct addrinfo));
        hints.ai_flags = AI_CANONNAME;  /*指定如何来处理地址和名字*//* always return canonical name */
        hints.ai_family = family;        /*指定地址族*/       /* AF_UNSPEC, AF_INET, AF_INET6, etc. */
        hints.ai_socktype = socktype;   /*指定套接字的类型*//* 0, SOCK_STREAM, SOCK_DGRAM, etc. */

        if ( (n = getaddrinfo(host, serv, &hints, &res)) != 0)
                return(NULL);
        return(res);    /* return pointer to first on linked list */
}
/* end host_serv */

static void err_doit(int errnoflag, int level, const char *fmt, va_list ap)
{
        int             errno_save, n;
        char    buf[MAXLINE];

        errno_save = errno;             /* value caller might want printed */
#ifdef  HAVE_VSNPRINTF
        vsnprintf(buf, sizeof(buf), fmt, ap);   /* this is safe */
#else
        vsprintf(buf, fmt, ap);                                 /* this is not safe */
#endif
        n = strlen(buf);
        if (errnoflag)
                snprintf(buf+n, sizeof(buf)-n, ": %s", strerror(errno_save));
        strcat(buf, "\n");

        if (daemon_proc) {
                syslog(level, buf);
        } else {
                fflush(stdout);         /* in case stdout and stderr are the same */
                fputs(buf, stderr);
                fflush(stderr);
        }
        return;
}


/* Fatal error unrelated to a system call.
 * Print a message and terminate. */

void err_quit(const char *fmt, ...)
{
        va_list         ap;

        va_start(ap, fmt);
        err_doit(0, LOG_ERR, fmt, ap);
        va_end(ap);
        exit(1);
}

/* Fatal error related to a system call.
 * Print a message and terminate. */

void
err_sys(const char *fmt, ...)
{
        va_list         ap;

        va_start(ap, fmt);
        err_doit(1, LOG_ERR, fmt, ap);
        va_end(ap);
        exit(1);
}
