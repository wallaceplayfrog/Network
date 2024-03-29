#include 	<netinet/in_systm.h>
#include	<netinet/ip.h>
#include	<netinet/ip_icmp.h>
#include	<netinet/icmp6.h>
#include	<netinet/ip6.h>
#include	<sys/types.h>	/* basic system data types */
#include	<sys/socket.h>	/* basic socket definitions */
#include	<sys/time.h>	/* timeval{} for select() */
#include	<time.h>		/* timespec{} for pselect() */
#include	<netinet/in.h>	/* sockaddr_in{} and other Internet defns */
#include	<arpa/inet.h>	/* inet(3) functions */
#include	<netdb.h>
#include	<signal.h>
#include	<stdio.h>
#include	<stdlib.h>
#include	<string.h>
#include	<errno.h>
#include 	<pwd.h>
#include	<unistd.h>
#include	<sys/un.h>		/* for Unix domain sockets */
#include	<sys/ioctl.h>
#include	<net/if.h>
#include <stdarg.h>
#include <syslog.h>
#ifdef  HAVE_SOCKADDR_DL_STRUCT
# include       <net/if_dl.h>
#endif

#define IPV6

#define BUFSIZE		1500
#define MAXLINE         4096

/* globals */
char	 recvbuf[BUFSIZE];/*收到返回的数据放入recvbuf中*/
char	 sendbuf[BUFSIZE];/*对这个缓冲区内容的更改结果，作为生成的ICMP数据包*/

float rttmatrix[BUFSIZ];
int pingtimes; /* -c 参数，ping的次数*/
int quietmode = 0; /* 0关闭安静模式，1开启安静模式*/
float time_lag = 1; /* -i 时间间隔*/
int ttlcount; /* -t time to live */
int broadcast; /* -b */
int justnumber; /* -n */
int sodebug; /* -d */
int deadline; /* -w */
int sndbuf; /* -S */
int time_out; /* -W */
int flood; /* -f */
int perload = 1; /* -l */
int audio; /* -a */
int auto_time; /* -A */

int    datalen;	/* #bytes of data, following ICMP header */
char	*host;
int	 nsent;			/* add 1 for each sendto() */
int  nrecv = 0;

pid_t pid;			/* our PID */
int	 sockfd;
int	 verbose;
int    daemon_proc;            /* set nonzero by daemon_init() */

/* function prototypes */
void	 proc_v4(char *, ssize_t, struct timeval *);
void	 proc_v6(char *, ssize_t, struct timeval *);
void	 send_v4(void);
void	 send_v6(void);
void	 readloop(void);
void	 sig_alrm(int);
void	 tv_sub(struct timeval *, struct timeval *);
void   Stop();
void   help();

char * Sock_ntop_host(const struct sockaddr *sa, socklen_t salen);
struct addrinfo* host_serv(const char *host, const char *serv, int family, int socktype);
static void err_doit(int errnoflag, int level, const char *fmt, va_list ap);
void err_quit(const char *fmt, ...);
void err_sys(const char *fmt, ...);

struct proto {
  void	 (*fproc)(char *, ssize_t, struct timeval *);
  void	 (*fsend)(void);
  struct sockaddr  *sasend;	/* sockaddr{} for send, from getaddrinfo */
  struct sockaddr  *sarecv;	/* sockaddr{} for receiving */
  socklen_t	    salen;		/* length of sockaddr{}s */
  int	   	    icmpproto;	/* IPPROTO_xxx value for ICMP */
} *pr;

