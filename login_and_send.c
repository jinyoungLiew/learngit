/******
 *
 *文件：测试登录和发送数据
 *
 *
 *
 */

#include<stdio.h> //printf
#include<string.h>    //strlen
#include<sys/socket.h>    //socket
#include<arpa/inet.h> //inet_addr

#define SEND_BUFF_LEN 1460
#define PACK_NBR 10

char send_buf[1024*1024*8]  = {0}, server_reply[2000] = {0};
char data[11] = "helloworld";

int packages = 0;// 包索引

int frames = 10;// 帧个数
int frame_index = 0;//帧索引
/*
 *功能：打包字符串
 *参数：src---字符串参数
 		buf---发送缓存区
		max_len---发送缓冲区大小
 *返回值：打包后的数据产长度
 *
 **/
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
        buf[9] =0x01; /* 包个数*/
        buf[10]=0x00; /* FP_CONTROL  */

        if(NULL != src){
            int len = strlen(src);

			if (len > max_len){
				printf("需要打包的字符串太长\n");

				return -1;
			}
             buf[11]=len;
             memcpy(&buf[12], src, len);
             ret = len+12;
        }else {
			printf("打包数据为空\n");
		}

        return ret;
}


/*功能: 打包一帧数据
 *参数：buf --- 发送缓冲区
 		buf_index---buf索引
 *      data---发送数据
 *      data_len---发送数据长度,小于buf缓冲区长度
 *      more---是否有下一个帧数据
 *返回值：打包好的帧的数据长度
 **/
int mfptp_pack_frames_with_hdr( char *buf,int buf_index,char *data, int data_len,int more)
{
        int ret = -1;
        buf[buf_index] ='#';
        buf[buf_index + 1] ='M';
        buf[buf_index + 2] ='F';
        buf[buf_index + 3] ='P';
        buf[buf_index + 4] ='T';
        buf[buf_index + 5] ='P';
        buf[buf_index + 6] =0x10; /* 版本*/
        buf[buf_index + 7] =0x00; /*压缩、加密*/
        buf[buf_index + 8] =0x04; /* REP */
        buf[buf_index + 9] = 0x1; /* 包个数*/

        if(0!=more){
            buf[buf_index + 10]=0x04; /* FP_CONTROL----低4位高两位  */
		}else{
            buf[buf_index + 10]=0x00;
        }

        unsigned char *p=(unsigned char *)&data_len;

        if(data_len<=255){
            buf[ buf_index + 11]=data_len;

			//memcpy(&buf[12],data,data_len);

            ret = data_len+12;
        }else if(data_len<=65535){
            buf[buf_index + 11]=*(p+1);
            buf[buf_index + 12]=*(p);
            buf[buf_index + 10]=buf[buf_index + 10] | 0x01; /* FP_CONTROL 低4为低两位 1--->2 */

			//memcpy(&buf[13],data,data_len);
            ret = data_len+13;
        }else{
            buf[buf_index + 11]=*(p+2);
            buf[buf_index + 12]=*(p+1);
            buf[buf_index + 13]=*(p);
            buf[buf_index + 10]=buf[buf_index + 10]|0x02; /* FP_CONTROL  低4位低两位2--->3*/

			//memcpy(&buf[14],data,data_len);
            ret = data_len+14;
        }
	
        return ret;
}
/*功能: 控制打包一帧数据
 *参数：buf --- 发送缓冲区
 		buf_index---recv 缓存区索引
 *      data---发送数据
 *      data_len---发送数据长度,小于buf缓冲区长度
 *      more---是否有下一个帧数据
 *返回值：打包好的帧的数据长度
 **/
int mfptp_pack_frames_no_hdr(char buf,int buf_index,int data, char data_len, int more)
{
        int ret = -1;
        if(0!=more){
            buf[buf_index]=0x04; /* FP_CONTROL  */
        }else{
            buf[buf_index]=0x00;
        }
		

        unsigned char *p=(unsigned char *)&data_len;
        if(data_len<=255){
            buf[buf_index + 1]=data_len;
            ret = data_len + 2;
        }else if(len<=65535){
            buf[buf_index]=buf[buf_index] | 0x01; /* FP_CONTROL  */
            buf[buf_index + 1]=*(p+1);
            buf[buf_index + 2]=*(p);
            ret = data_len+3;
        }else{
            buf[buf_index] = buf[buf_index] | 0x02; /* FP_CONTROL  */
            buf[buf_index + 1]=*(p+2);
            buf[buf_index + 2]=*(p+1);
            buf[buf_index + 3]=*(p);
            ret = data_len+4;
        }
        return ret;
}
/********
 *功能：打包数据，发送
 *
 *
 *
 */

void pack_and_send_data(int sockfd, char *src,int src_len,char * buf, int buf_len)
{
	int more;
	
	for (packages = 0; packages < PACK_NBR; packages ++){
		more = 1;
		// 处理帧	
		for (frame_index = 0; frame_index < frames; frame_index ++){
			//打包第index 帧数据 共（index + 1）* 100字节
			if ((packages == 0)&& (frame_index == 0)){

				buf_index = mfptp_pack_frames_with_hdr(buf,buf_index,src,src_len,more);	

			}else {
				if (frames == 9)
					more = 0;
				mfptp_pack_frames_no_hdr(buf,buf_index,src,src_len,more);			
			}
		}
	}

}

int main()
{
    int sock;
    struct sockaddr_in server;
     
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
    int len = mfptp_pack_string(argv[1],send_buf,512);
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
        printf("登录成功，准备好发送数据\n");
        break;
    }

	// 发送数据
	pack_and_send_data(int fd,send_buf,sizeof(send_buf));
    sleep(1000);
    close(sock);
    return 0;
}
