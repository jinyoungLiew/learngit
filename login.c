/*
*/
#include<stdio.h> //printf
#include<string.h>    //strlen
#include<sys/socket.h>    //socket
#include<arpa/inet.h> //inet_addr

#define SEND_BUFF_LEN 100*1024*1024 
#define FRAME_NBR 3 

int mfptp_pack_string(char *src, char *buf, int max_len);
int senddata(int fd, char *buf,char *,int dlen);

unsigned char send_buf[SEND_BUFF_LEN] = {0};
// 每帧2M
//unsigned char data[FRAME_NBR][10*1024*1024];
unsigned char data[FRAME_NBR][1024];

int main(int argc , char *argv[])
{
    int sock;
    struct sockaddr_in server;
    unsigned char message[1024*1024*8] , server_reply[2000];
     

	char voice[] = "qiang fang you she xiang tou";

    //Create socket
    sock = socket(AF_INET , SOCK_STREAM , 0);
    if (sock == -1)
    {
        printf("Could not create socket");
    }
    puts("Socket created");
     
    //server.sin_addr.s_addr = inet_addr("192.168.1.15");
    server.sin_addr.s_addr = inet_addr("127.0.0.1");
    server.sin_family = AF_INET;
    server.sin_port = htons( 6990 );
 
    //Connect to remote server
    if (connect(sock , (struct sockaddr *)&server , sizeof(server)) < 0)
    {
        perror("connect failed. Error");
        return 1;
    }
     
    puts("Connected\n");
    int len = mfptp_pack_string(argv[1],message,512);
	if (len < 0)
	{
		printf("mfptp_pack_string error\n");
		len = 0;
	}
    int ret;
     
    //keep communicating with server
    while(1)
    {
        printf("Enter message : ");
        //scanf("%s" , message);
         
        //Send some data
        if( (ret = send(sock , message , len , 0)) < 0)
        {
            puts("Send failed");
            return 1;
        }
        printf("发送出去的数据长度是%d\n",ret);
        int i =0;
        for(i=0;i<ret;i++){
            printf("%x ",message[i]);
        }
        printf("\n");
         
        //Receive a reply from the server
        if((ret=recv(sock , server_reply , 2000 , 0)) < 0)
        {
            puts("recv failed");
            break;
        }
         
        printf("Server reply : %d\n",ret);
        printf("登录成功，准备好接收微薄\n");
        break;
    }
	
		#if 1 
		// 发送数据
		int senddata_len = senddata(sock,send_buf,voice,sizeof(voice) - 1);	

		int i =0;
		for (i = 0; i < senddata_len; i++)
			printf(" %x ",send_buf[i]);
		printf("\n");
		#endif

	//package
	int packages = 3;
	while(packages >0)
	{
		printf("现在，第%d包：\n",3 - packages + 1);
		int more = 1;
		//帧
		for (i = 0; i < FRAME_NBR; i++)
		{
			//最后一帧
			if (i == FRAME_NBR - 1)
				more = 0;
			// 帧数组初始化;
			memset(data[i],'a'+i,sizeof(data[i]));

		    senddata_len +=	senddata_multi_frame(sock,send_buf + senddata_len ,data[i],/*strlen(data[i])*/sizeof(data[i]),more);
			printf("senddata_len = %d\n",senddata_len);

		}
		printf("第%d包打包完成：\n",3 - packages + 1);

		packages--;
	}
	//数据打包完毕，一起发送
		printf("发送3包数据\n");
		int alldata = send(sock,send_buf,senddata_len,0);
		printf("send %d data\n",alldata);
		#if 0
		for (i = 0; i < alldata; i++)
		{
			if (i % 20 == 0)
				printf("\n");
			printf("0x%02x ",send_buf[i]);
		}
		printf("\n");
		#endif

    sleep(1000);
    close(sock);
    return 0;
}
int mfptp_pack_string(char *src, char *buf, int max_len)
{
        int ret = -1;
        buf[0] ='#';
        buf[1] ='M';
        buf[2] ='F';
        buf[3] ='P';
        buf[4] ='T';
        buf[5] ='P';
        buf[6] =0x10; /* 版本*/
        buf[7] =0x00; /*压缩、加密*/
        buf[8] =0x04; /* REP */
        buf[9] =0x01; /* 包个数*/ // 3包
        buf[10]=0x00; /* FP_CONTROL  */

        if(NULL != src){
                int len = strlen(src);
                if(len>255){
                        len = 255;
                }
                buf[11]=len;
                memcpy(&buf[12], src, len);
                ret = len+12;
        }
        return ret;
}
/*功能: 打包一帧数据
 *参数：buf --- 发送缓冲区
 *      data---发送数据
 *      data_len---发送数据长度,小于buf缓冲区长度
 *      more---是否有下一个帧数据
 *返回值：打包好的帧的数据长度
 **/
int mfptp_pack_frames_with_hdr( char *buf,char *data, int data_len,int more)
{
        int ret = -1;
        buf[0] ='#';
        buf[1] ='M';
        buf[2] ='F';
        buf[3] ='P';
        buf[4] ='T';
        buf[5] ='P';
        buf[6] =0x10; /* 版本*/
        buf[7] =0x00; /*压缩、加密*/
        buf[8] =0x04; /* REP */
        buf[9] = 0x3; /* 包个数*/

        if(0!=more){
            buf[10]=0x04; /* FP_CONTROL----低4位高两位  */
		}else{
            buf[10]=0x00;
        }

        unsigned char *p=(unsigned char *)&data_len;

        if(data_len<=255){
            buf[11]=data_len;

			memcpy(&buf[12],data,data_len);

            ret = data_len+12;
        }else if(data_len<=65535){
            buf[11]=*(p+1);
            buf[12]=*(p);
            buf[10]=buf[10] | 0x01; /* FP_CONTROL 低4为低两位 1--->2 */

			memcpy(&buf[13],data,data_len);
            ret = data_len+13;
        }else{
            buf[11]=*(p+2);
            buf[12]=*(p+1);
            buf[13]=*(p);
            buf[10]=buf[10]|0x02; /* FP_CONTROL  低4位低两位2--->3*/

			memcpy(&buf[14],data,data_len);
            ret = data_len+14;
        }
	
        return ret;
}
/*
 *功能：发送一帧数据，保证dlen小于buf缓冲区大小，具体怎么保证，上层处理
 *
 *
 **/
int  senddata(int fd, char *buf,char *data,int dlen)
{
	
    int ret; 
	//1. 先发一个数据包
	
	int	more = 1;
        int len = mfptp_pack_frames_with_hdr(buf,data,dlen,more);
		
#if 0
        printf("sending data =%d\n",len);
        if( (ret = send(fd, buf , len, 0)) < 0)
        {

            puts("Send failed");
			return len;
        }
#endif

       // printf("振作%d\n",ret);
		return len;


}
int  senddata_multi_frame(int fd, char *buf,char *data,int dlen,int more)
{
	
    int ret; 
	//1. 先发一个数据包
	
        int len = mfptp_pack_frames_no_hdr(buf,data,dlen,more);
#if 0		
        printf("sending data =%d\n",len);
        if( (ret = send(fd, buf , len, 0)) < 0)
        {

            puts("Send failed");
			return len;
        }

#endif
        //printf("多帧%d\n",ret);
		return len;


}
int mfptp_pack_frames_no_hdr(char *buf,char *data, int data_len,int more)
{
        int ret = -1;
        if(0!=more){
            buf[0]=0x04; /* FP_CONTROL----低4位高两位  */ }else{
            buf[0]=0x00;
        }
		printf("本帧长度%d 0x%x\n",data_len,data_len);
	
        unsigned char *p=(unsigned char *)&data_len;

        if(data_len<=255){
            buf[1]=data_len;

			memcpy(&buf[2],data,data_len);

            ret = data_len+2;
        }else if(data_len<=65535){
            buf[1]=*(p+1);
            buf[2]=*(p);
            buf[0]=buf[0] | 0x01; /* FP_CONTROL 低4为低两位 1--->2 */

			memcpy(&buf[3],data,data_len);
            ret = data_len+3;
        }else if (data_len <= 16777215){
            buf[1]=*(p+2);
            buf[2]=*(p+1);
            buf[3]=*(p);
            buf[0]=buf[0]|0x02; /* FP_CONTROL  低4位低两位2--->3*/

			memcpy(&buf[4],data,data_len);
            ret = data_len+4;
        }else {
			printf("一帧大于16M,len = %d\n",data_len);
            buf[1]=*(p+3);
            buf[2]=*(p+2);
            buf[3]=*(p+1);
			buf[4] = *(p);
            buf[0]=buf[0]|0x03; /* FP_CONTROL  低4位低两位2--->3*/

			memcpy(&buf[5],data,data_len);
            ret = data_len+5;
		
		}
        return ret;
}
