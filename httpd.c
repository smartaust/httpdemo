#include "qcom_common.h"
#include "socket_api.h"
#include "utils.h"
#include "select_api.h"
#include "board.h"
#include "socket.h"
#include "socat.h"
#include "httpd.h"

char sendbuf[BUFSIZ];

char recvbuf[BUFSIZ];

char tempbuf[BUFSIZ];

struct http_req_head_t req_head; 

static const A_CHAR Base64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

char error401[] ={
"<html>\
<HEAD><TITLE>401 Unauthorized</TITLE></HEAD>\n\
<BODY><H1>401 Unauthorized</H1>\nYour client doesn't have permission to get the page.\
</html>"
};

char error400[]=
{"<html>\
<HEAD><TITLE>400 Bad Request</TITLE></HEAD>\n\
<BODY><H1>400 Bad Request</H1>\
</html>"
};

static void make_respond_msg(A_INT16 code,char *mothed)
{
	assert(strlen(mothed)>0);

	bzero(tempbuf,sizeof(tempbuf));

	if(!strcmp(mothed,"GET"))
	{
		if(code == OK)
		{
			snprintf(tempbuf,sizeof(tempbuf),
			"<html>"
			"<form action = \" \" method = \"POST\">"
			"<table>"
			"<tr><td>server fqdn:</td><td><input type = \"text\" name = \"fqdn\" value = \"%s\"/></td></tr>"
			"<tr><td>service port:</td><td><input type = \"text\" name = \"port\" value = \"%d\" /></td></tr>"
			"<tr><td>SSID:</td><td><input type = \"text\" name = \"ssid\" value = \"%s\" /></td></tr>"	
			"<tr><td>password:</td><td><input type = \"text\" name = \"password\" value = \"%s\" /> </td></tr>"
			"<tr><td>adminname:</td><td><input type = \"text\" name = \"username\" value = \"%s\"/> </td></tr>"
			"<tr><td>admintoken:</td><td><input type = \"text\" name = \"usertoken\"value =\"%s\"/></td></tr>"
			"<tr> <td></td><td><input type = \"submit\" value=\"Modify\"/></td></tr>"
			"</table>"
			"</form>"
			"</html>",sysargs.conn.fqdn,sysargs.conn.port
				 ,sysargs.iwconfig.ssid,sysargs.iwconfig.passphrase
				 ,sysargs.board.username,sysargs.board.passcode);
	
			snprintf(sendbuf,BUFSIZ,"HTTP/1.1 200 OK\r\n"
						"Content-Length:%d\r\n"
						"Content-Type:text/html\r\n\r\n"
						"%s",strlen(tempbuf),tempbuf);
		}
		else if(code == UNAUTH)
		{
			snprintf(sendbuf,BUFSIZ,"HTTP/1.1 401 Unauthorized\r\n"
						"WWW-Authenticate:Basic realm = \"Authorize\"\r\n"
						"Content-Length:%d\r\n"
						"Content-Type:text/html\r\n\r\n"
						"%s",strlen(error401),error401);

		}

		else if(code == NOTFOUND)
		{
			
			snprintf(sendbuf,BUFSIZ,"HTTP/1.1 404 Not Found\r\n"
						"Content-Type:text/html\r\n\r\n");
		}
	}

	else if(!strcmp(mothed,"POST"))
	{
			snprintf(tempbuf,sizeof(tempbuf),
			"<html>"
			"<body>"
			"<h1>Modify OK!!</h1>"
			"</body>"
			"<table>"
			"<tr><td>server fqdn:</td><td><input type = \"text\" name = \"fqdn\" value = \"%s\" readonly = \"true\"style=\"background-color:grey\"/> </td></tr>"		
			"<tr><td>service port:</td><td><input type = \"text\" name = \"port\" value = \"%d\" readonly = \"true\"style=\"background-color:grey\"/> </td></tr>"		
			"<tr><td>SSID:</td><td><input type = \"text\" name = \"ssid\" value = \"%s\" readonly = \"true\"style=\"background-color:grey\"/> </td></tr>"		
			"<tr><td>password:</td><td><input type = \"text\" name = \"password\" value = \"%s\" readonly = \"true\"style=\"background-color:grey\"/> </td></tr>"		
			"<tr><td>adminname:</td><td><input type = \"text\" name = \"username\" value = \"%s\" readonly = \"true\"style=\"background-color:grey\"/> </td></tr>"		
			"<tr><td>admintoken:</td><td><input type = \"text\" name = \"usertoken\" value = \"%s\" readonly = \"true\"style=\"background-color:grey\"/> </td></tr>"		
			"</table>"
			"</html>",sysargs.conn.fqdn,sysargs.conn.port
				 ,sysargs.iwconfig.ssid,sysargs.iwconfig.passphrase
				 ,sysargs.board.username,sysargs.board.passcode);
	
			snprintf(sendbuf,BUFSIZ,"HTTP/1.1 200 OK\r\n"
						"Content-Length:%d\r\n"
						"Content-Type:text/html\r\n\r\n"
						"%s",strlen(tempbuf),tempbuf);

	}
	else 
	{
		
		if(code == BADREQ)
		{
			snprintf(sendbuf,BUFSIZ,"HTTP/1.1 400 Bad Request\r\n"
						"Content-Length:%d\r\n"
						"Content-Type:text/html\r\n\r\n"
						"%s",strlen(error400),error400);
		}
	}	
}

static void base64_encode(const char *src,char *dst)
{
	A_INT32 i=0;

    	char *p=dst;

    	int d=strlen(src)-3;
   
	for(i=0;i<=d;i+=3)
    	{
        	*p++=Base64[((*(src+i))>>2)&0x3f];
       		*p++=Base64[(((*(src+i))&0x3)<<4)+((*(src+i+1))>>4)];
        	*p++=Base64[((*(src+i+1)&0xf)<<2)+((*(src+i+2))>>6)];
        	*p++=Base64[(*(src+i+2))&0x3f];
    	}
    
	if((strlen(src)-i)==1)
    	{
       		*p++=Base64[((*(src+i))>>2)&0x3f];
       	 	*p++=Base64[((*(src+i))&0x3)<<4];
        	*p++='=';
        	*p++='=';
    	}
 
   	if((strlen(src)-i)==2)
    	{
        	*p++=Base64[((*(src+i))>>2)&0x3f];
        	*p++=Base64[(((*(src+i))&0x3)<<4)+((*(src+i+1))>>4)];
      	 	*p++=Base64[((*(src+i+1)&0xf)<<2)];
        	*p++='=';
   	 }
   	 *p='\0';	
}
	
A_INT32 httpd_init(A_UINT16 port)
{
	bzero((char *)&req_head,sizeof(struct http_req_head_t));

	return init_tcp_srv(port);
}

static A_UINT16 strtoint16(char * str)
{
	A_UINT16 temp =0;

	if(str == NULL)
		return 0;
	else 
	{
		while(*str != '\0')
		{
			if(*str > '9'||*str < '0')
				return 0;
			else 
				temp = temp*10 + (*str - '0');
			str++;
		}
		return temp;
	}

}
static void parahandle(char *buf)
{
	char *head;
	char *tail;
	char temp[100] = {0};

	printf("%s \n",buf);
	strncpy(temp,buf,10);
	head = qcom_strstr(buf,"fqdn=");
	tail = qcom_strstr(head,"&");
	bzero(temp,sizeof(temp));
	memcpy(temp,head+5,tail-head-5);
	printf("fqdn: %s\n",temp);

	strcpy(sysargs.conn.fqdn,temp);

	head = qcom_strstr(buf ,"port=");
	tail = qcom_strstr(head,"&");
	bzero(temp,sizeof(temp));
	memcpy(temp,head+5,tail-head-5);
	printf("port : %s\n",temp);

	sysargs.conn.port = strtoint16(temp);

	printf("sys port:%d\n",sysargs.conn.port);

	head = qcom_strstr(buf ,"ssid=");
	tail = qcom_strstr(head,"&");
	bzero(temp,sizeof(temp));
	memcpy(temp,head+5,tail-head-5);
	printf("ssid : %s\n",temp);

	strncpy(sysargs.iwconfig.ssid,temp,31);

	head = qcom_strstr(buf ,"password=");
	tail = qcom_strstr(head,"&");
	bzero(temp,sizeof(temp));
	memcpy(temp,head+9,tail-head-9);

	printf("passcode : %s\n",temp);
	strcpy(sysargs.iwconfig.passphrase,temp);

	head = qcom_strstr(buf ,"username=");
	tail = qcom_strstr(head,"&");
	bzero(temp,sizeof(temp));
	memcpy(temp,head+9,tail-head-9);
	printf("username: %s\n",temp);
	strcpy(sysargs.board.username,temp);

	head = qcom_strstr(buf ,"usertoken=");
	bzero(temp,sizeof(temp));
	memcpy(temp,head+10,strlen(head) -10);
	printf("usertoken: %s\n",temp);
	strcpy(sysargs.board.passcode,temp);
}

static A_UINT16 auth_test(char * buf)
{	
	bzero(sendbuf,sizeof(sendbuf));

	snprintf(sendbuf,sizeof(sendbuf),"%s:%s",sysargs.board.username ,sysargs.board.passcode);

	bzero(tempbuf,sizeof(tempbuf));

	base64_encode(sendbuf,tempbuf);

	if(!strcmp(buf,tempbuf))
	{
		return 0;
	}	
	else 
		return 1;

}

static void http_respond(A_INT32 fd,struct http_req_head_t *req_head)
{
	int ret;

	bzero(sendbuf,BUFSIZ);

	bzero(recvbuf,BUFSIZ);

	if(req_head->contentsize != 0)
	{
		bzero(sendbuf,sizeof(recvbuf));

		qcom_recv(fd,recvbuf ,sizeof(recvbuf),0);
	}

	if(!memcmp(req_head->method,"GET",strlen("GET")))	
	{
		bzero(sendbuf,BUFSIZ);
		
		if(strcmp(req_head->path,"/"))
		{
			make_respond_msg(NOTFOUND,"GET");

		}

		if(0 == strlen(req_head->auth))
		{
			make_respond_msg(UNAUTH,"GET");
		}
		else
		{
			if(auth_test(req_head->auth))
			{
				make_respond_msg(UNAUTH,"GET");
			}
			else 
			{
				 make_respond_msg(OK,"GET");
			}
		}
		
	}
	else if(!memcmp(req_head->method,"POST",strlen("POST")))
	{	
		if(req_head->contentsize != 0)
		{
			parahandle(recvbuf);
		}
		make_respond_msg(OK,"POST");
			
		ret =	qcom_send(fd ,sendbuf ,strlen(sendbuf),0);

		sysargs.iwconfig.mode = QCOM_WLAN_DEV_MODE_STATION;
			
		sysargs.conn.mode = CONN_MODE_CLI;

		sys_commit();

		qcom_sys_reset();
	}
	else
	{
		snprintf(sendbuf,BUFSIZ,"HTTP/1.1 400 Bad Request\r\n"
					"Content-Length:%d\r\n"
					"Content-Type:text/html\r\n\r\n"
					"%s",strlen(error400),error400);
	
			//404 not found		
	}

	ret =	qcom_send(fd ,sendbuf ,strlen(sendbuf),0);
	LOG("ret : %d",ret);
	bzero((A_CHAR *)req_head,sizeof(struct http_req_head_t));
}

void http_req_handle(int fd,struct http_req_head_t *req_head)
{
	printf("method:%s\npath:%s\nversion:%s\nhost:%s\n",req_head->method,req_head->path,req_head->ver,req_head->host);

	printf("content length:%d\n",req_head->contentsize);
	
	http_respond(fd,req_head);
}

A_UINT16 http_get_req_line(struct conn * conn)
{

	if(!strncmp("POST",conn->buf,strlen("POST")))
	{
		sscanf(conn->buf,"%s %s %s\r\n",req_head.method,req_head.path,req_head.ver);
	}

	if(!strncmp("GET",conn->buf,strlen("GET")))
	{
		sscanf(conn->buf,"%s %s %s\r\n",req_head.method,req_head.path,req_head.ver);
	}
			
	if(!strncmp("Host",conn->buf,strlen("Host")))
	{
		sscanf(conn->buf,"Host:%s\r\n",req_head.host);
	}

	if(!strncmp("Authorization",conn->buf,strlen("Authorization")))
	{
		sscanf(conn->buf,"Authorization: Basic %s\r\n",req_head.auth);
	}

	if(!strncmp("Content-Length",conn->buf,strlen("Content-Length")))
	{
		sscanf(conn->buf,"Content-Length:%d\r\n",&req_head.contentsize);
	}

	if(!memcmp("\r\n",conn->buf ,2))
	{
		printf("head end flag fd:%d\n",conn->chann.fd);
		http_req_handle(conn->chann.fd,&req_head);
		return 1;
	}

	return 0;
	
	//need add conn handle code here //add your code here
}
