#ifndef _HTTPD_H_
#define _HTTPD_H_

#define  OK 200
#define  BADREQ 400
#define  UNAUTH 401
#define  NOTFOUND 404

struct http_req_head_t;

struct http_req_head_t
{
	char method[8];
	char path[256];
	char ver[10];
	char host[128];
	char auth[128];
	int contentsize;	
};

A_INT32  httpd_init(A_UINT16 port);

A_UINT16  http_get_req_line(struct conn * conn);

#endif
