/*
*
*/

#include "mfptp_parser_machine.h"
#include <unistd.h>

/*  FP_Control的长度 */
#define FP_CONTROL_SIZE                 (0x01)
#define FP_CONTROL_LOW01_BITS_MASK      (0x03)
#define FP_CONTROL_LOW23_BITS_MASK      (0x0C)

#define MFPTP_BURST_HEADER_LEN          (0x0A)
#define MFPTP_BURST_HEADER_START        (0x00)
#define MFPTP_BURST_HEADER_VERSION      (0x07)
#define MFPTP_BURST_HEADER_DATA_MODE    (0x08)
#define MFPTP_BURST_HEADER_SOCKET_MODE  (0x09) 
#define MFPTP_BURST_HEADER_PACKAGES     (0x0A)
#define MFPTP_BURST_FRAME_START         (0x0B)



#define GET_LOW01_BITS(ctrl) (ctrl&FP_CONTROL_LOW01_BITS_MASK)
#define GET_LOW23_BITS(ctrl) ((ctrl&FP_CONTROL_LOW23_BITS_MASK)>>2)

#define PTR_MOVE(len) do {	\
	offset += len;	\
	p_status->doptr += len;\
}while(0)

#define ELSE_RETURN(x) else{\
	return x;\
}

#define CHECK_SIZE(a, b) do{		\
	if ( (a) + (b) > usr->recv.get_size ){	\
		if (p_status->step == MFPTP_PARSE_PACKAGE && p_status->index > 0){      \
			            if((a) + (b) > MAX_REQ_SIZE){ \
	                                int    left_len  = MAX_REQ_SIZE - (a); \
			                char  *left_data = ptr + offset; \
	                                char  *begin     = ptr + p_parser->pos_frame_start; \
	                                if(left_len<=0){ \
					        usr->recv.get_size = 0;    \
		                                p_parser->packages -= (p_status->index -1);        \
		                                p_status->index = 0;    \
		                                p_status->doptr -= length_over;        \
					        length_over = 0;	\
						return p_status->step;\
	                                 }else{ \
					        while(left_len--){ \
						        printf("-%c",*left_data); \
						        *begin++ = *left_data++; \
					        } \
					        usr->recv.get_size -= length_over;    \
		                                p_parser->packages -= (p_status->index -1);        \
		                                p_status->index = 0;    \
		                                p_status->doptr -= length_over;        \
					        length_over = 0;	\
	                                }\
			             }\
		}	\
		return p_status->step;\
	}\
} while(0)
/*      名    称: mfptp_pack_string
 *	功    能: 把字符串打包成mfptp格式数据,单包单帧
 *	参    数: src, 要打包的字符串首地址
 *	          buf, 输出的mfptp帧保存在这个起始地址上,空间由调用者在调用前分配
 *	          max_len, buf指向内存空间的长度,
 *	          这个长度至少应该等于包头长度+帧头长度+字符串的长度,否则打包会失败
 *	返 回 值:  -1, 失败;  0成功。
 *	修    改: 新生成函数l00167671 at 2015/2/28
 */
int mfptp_pack_string(char *src, char *buf, int max_len)
{
	int ret = -1;
        int i = 0;
	buf[0] ='#';
	buf[1] ='M';
	buf[2] ='F';
	buf[3] ='P';
	buf[4] ='T';
	buf[5] ='P';
	buf[6] =0x01; /* 版本*/
	buf[7] =0x00; /*压缩、加密*/
	buf[8] =0x04; /* REP */
	buf[9] =0x01; /* 包个数*/
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
        x_printf(D,"发送了%d个字节\n",ret);
        for(i=0;i<ret;i++){
            if(isgraph(buf[i])){
                    x_printf(D,"%c ",buf[i]);
            }else{
                    x_printf(D,"%x ",buf[i]);
            }
        }

	return ret;
}
/*	名   	称: mfptp_pack_login_ok
 *	功	能: 生成登录认证成功的应答消息帧
 *	参	数: buf, 存储消息帧的首地址
 *	            len, 续传长度
 *	            usr, 用户
 *	返  回  值: 应答消息帧的长度
 *	修      改: 新生成函数l00167671 at 2015/5/7
*/
int mfptp_pack_login_ok(char *buf, int len, struct user_info *usr)
{
        int ret = -1;
        int i = 0;
        int network_len = htonl(len);
        printf("............len=%d\n",len);
        buf[0] ='#';
        buf[1] ='M';
        buf[2] ='F';
        buf[3] ='P';
        buf[4] ='T';
        buf[5] ='P';
        buf[6] =0x01; /* 版本*/
        buf[7] =0x00; /*压缩、加密*/
        buf[8] =0x00; /* PAIR_METHOD */
        buf[9] =0x01; /* 包个数*/
        buf[10]=0x00; /* FP_CONTROL  */
        buf[11]=0x01; /* 帧长度 */
        buf[12]=0x01; /* 成功 */

        /* 续传长度 */
        memcpy((void *)&buf[13], (void *)&network_len, sizeof(network_len));

        #define  SECRET_KEY_LEN    (16)
        #define  PACKAGE_HDR_LEN   (10)

        /* 密钥 */
        memcpy((void *)&buf[17], usr->key, SECRET_KEY_LEN);
        
        /* 响应帧的长度 */
        buf[11] = 0x01 + sizeof(network_len) + SECRET_KEY_LEN;
        
        /* 包头长度+帧头长度+成功标识长度+续传数据位置长度+密钥长度*/
        return PACKAGE_HDR_LEN + 2 + 1 + sizeof(network_len)+SECRET_KEY_LEN;
}
/*	名   	称: mfptp_register_callback
 *	功	能: 设置回调函数
 *	参	数:
 *	返  回  值: 无
 *	修      改: 新生成函数l00167671 at 2015/2/28
*/
void mfptp_register_callback(struct user_info* usr, mfptp_callback_func fun)
{
	usr->mfptp_info.parser.func = fun;
}
void mfptp_init_parser_info(struct mfptp_parser_info *p_info)
{
    p_info->parser.compress         = 0;
    p_info->parser.encrypt          = 0;
	p_info->parser.func             = NULL;
	p_info->parser.method           = 0;
	p_info->parser.packages         = 0;
	p_info->parser.sub_version      = 0;
	p_info->parser.version          = 0;

	p_info->status.package.complete = true;
	p_info->status.package.frames   = 0;

    p_info->status.packages_index = 0;// add by liujinyang
	p_info->status.mfptp_header = NULL;
}
/////////////////////////////////////////////////////FSM PARSE/////////////////////////////////////////////

#define FREE_MEM(a) do{ \
	mem_free((a));      \
	(a) = NULL;         \
}while(0)

/*
 *1. readn
 *
 *
 */
int recvn(int fd, char *vptr, int n)
{
   int  nleft;
   int  nread;
   char *ptr = vptr;
   nleft = n;

   while( nleft > 0){
       if ( (nread = read(fd,ptr,nleft) ) < 0 ){
		   if (errno == EINTR)
				nread = 0;
	        else            // 中间某次读失败，返回已经读到的字符
	  		    return -1 
	   }else if (nread == 0) // 缓冲区无数据可读
		   break;

	   nleft -= nread;
	   ptr += nread;
   }
   return (n - nleft);// >= 0
}


/*
 *1. 接收数据，返回发生事件
 *2. 事件有先后顺序,可以根据当前状态可能发生的事件来控制,故传入参数state,来做一次控制
 *3. 事件即是一种准备好数据的状态，行为即是解析数据
 *
 */
RECV_EV recv_ev(struct user_info* usr, FSM_STATE state)
{
	struct mfptp_status* p_status = &(usr->mfptp_info.status);
    int recv_n;
	int  fp_size_len;

	// 当前的状态，决定了可能的状态
	switch(state)
	{
		// 初始状态，要去判断头----#MFPTP
	    case INIT_STATE:
			if (p_status->recv_bytes == 0){
				char *header = (char *)mem_get(10);
			    // usr 里面添加一个指针指向头,然后使其指向header指向的内存
				p_status->mfptp_header = header;
			}
		    recv_n = recv(usr->sfd, (p_status->mfptp_header + p_status->recv_bytes), (10 - p_status->recv_bytes),0);	
			// 失败的话，设置事件无效，状态不变
			if (recv_n < (10 - p_status->recv_bytes) ){
				if(recv_n < 0){//-1 
					if(errno == EAGAIN ||errno == EINTR){
						return RETRY_EV;
					}
					p_status->recv_bytes = 0;
				//	FREE_MEM(p_status->mfptp_header);
					return OFFLINE_EV;
				}else if (recv_n == 0){
					p_status->recv_bytes = 0;//当一个事件结束的时候，复位记录该事件的进度标志。
				//	FREE_MEM(p_status->mfptp_header);
					return OFFLINE_EV;
				}else{
					// 读了部分数据，接下来要继续读
					p_status->recv_bytes += recv_n;
					return RETRY_EV;
				}
			}
			p_status->recv_bytes = 0;//当一个事件结束的时候，复位记录事件的进度标志。
			// 判断header
			if (strncmp(header,"#MFPTP",6) == 0){
				return HEAD_EV;
			}else {
				// 数据不对的情况下，先释放内存，然后重新接收等待
				FREE_MEM(p_status->mfptp_header);
				return RETRY_EV;
			}
			break;
			// 以下三种状态下，可能发生的事件是一样的，故判断方法也是一样的
		case HEAD_STATE:
		case FRAME_STATE:
	    case DEAL_PACK_STATE:
			//head state 需要读两次，一次FP_control,一次是FP_size
			// 1. fp_control
			if (p_status->recv_bytes == 0){
				char fp_control;
				recv_n = recv(usr->sfd,&fp_conctrol,sizeof(fp_control), 0);
				if (recv_n < sizeof(fp_control))
				{
					if (recv_n < 0){// -1
						if(errno == EAGAIN ||errno == EINTR){
							return RETRY_EV;
						}
						return OFFLINE_EV;
					}else {// 0
						return OFFLINE_EV;
					}
				}
				p_status->recv_bytes += 1;
				/* fp_control的最低2位表示f_size字段占据的长度*/
				fp_size_len = GET_LOW01_BITS(fp_control) + 1; 
				/* fp_control的第2、3位表示package是否结束,只有0和1两个取值*/
				p_status->package.complete = GET_LOW23_BITS(fp_control);
			}
			// 2. FP_size
			  	if(p_status->recv_bytes == 1){
					static char tmp[4] = {0};// 最大4个字节,定义成static , 续传或者重读使用.
			  	}	
				recv_n = recv(usr->sfd, (tmp + p_status->recv_bytes),(fp_size_len - p_status->recv_bytes), 0);
				if (recv_n < (fp_size_len - p_status->recv_bytes))
				{
					if (recv_n < 0){
						if(errno == EAGAIN ||errno == EINTR){
							return RETRY_EV;
						}
						p_status->recv_bytes = 0;
						return OFFLINE_EV;
					}else if(recv_n == 0){
						p_status->recv_bytes = 0;
						return OFFLINE_EV;	
					} else{
						p_status->recv_bytes += recv_n;
						return RETRY_EV;
					}
				}
				/* 取出数据长度，本长度低地址字节表示高位*/
				int frame_size = 0;
				int i;
				for (i = 0; i < fp_size_len; i++){
					frame_size += *(tmp + i) << (8 * (fp_size_len - 1 -i));
				}
				// reset
				p_status->recv_bytes += recv_n;
				memset(tmp,0,sizeof(tmp));
						
			// 3. 获取内存，存放帧
			if (p_status->recv_bytes == (1 + fp_size_len)){
			 	char *frame_ptr = mem_get(frame_size);
				p_status->mfptp_frame = frame_ptr;
			}	
			recv_v = recv(usr->sfd,( p_status->mfptp_frame + p_status->recv_bytes),( frame_size - p_status->recv_bytes), 0);
			if (recv_v < (frame_size - p_status->recv_bytes)){
				if (recv_n < 0){
					if(errno == EAGAIN ||errno == EINTR){
						return RETRY_EV;
					}
					p_status->recv_bytes = 0;
					return OFFLINE_EV;
				}else if(recv_n == 0){
					p_status->recv_bytes = 0;
					return OFFLINE_EV;	
				} else{
					p_status->recv_bytes += recv_n;
					return RETRY_EV;
				}
			}
			//一帧的数据收完,放进packages中
			p_status->recv_bytes = 0;
			p_status->package.frames++;
			// 帧太多，无效
			if (p_status->package.frames > MAX_FRAMES_PER_PACKAGE){
				return	INVALID_EV; 
			}
			// 心跳包直接丢弃
		    if (usr->mfptp_info.parser.method!=HEARTBEAT_METHOD) {
                p_status->package.ptrs[p_status->package.frames - 1] = frame_ptr;
                p_status->package.dsizes[p_status->package.frames - 1] = frame_size;
            }else{
                p_status->package.frames--;
			}	
			// 判断包事件,两种可能:一个包完成，一次请求结束
			if (p_status->package.complete == 0){  
				
				p_status->packages_index++;
				// 一次请求结束
				if(p_status->packages_index == usr->mfptp_info.parser.packages)
					return ALL_PACK_EV;
				return SINGLE_PACK_EV;
			}
			return FRAME_EV;
			break;
		case OVER_STATE:
			
			break;
		default:
			break;
	}
}


/*
 *1. 解析head,返回解析状态
 *
 *
 *
 **/
int mfptp_parse_head(struct user_info* usr)
{
	assert(NULL != usr);
	//取得头结构指针，然后解析
	struct mfptp_parser * p_parser = &(usr->mfptp_info.parser);
    struct mfptp_status * p_status = &(usr->mfptp_info.status);	
	
	assert(NULL != p_status->mfptp_header);

	char * ptr = p_status->mfptp_header;
    int offset = 6;           // 解析头部数据
                                
    /* 版本信息 */
	p_parser->version = (uint8_t)(*(ptr + offset) >> 4); 	
	p_parser->sub_version = (uint8_t)(*(ptr + offset) << 4);
    p_parser->sub_version = p_parser->sub_version >> 4;	
    
	offset++;
    /* 加密和压缩信息 */
	p_parser->compress =  (uint8_t)(*(ptr + offset) >> 4);	
	p_parser->encrypt = (uint8_t)(*(ptr + offset) << 4);
	p_parser->encrypt = p_parser->encrypt >> 4;		
    
	offset++;
    /* 方法信息 */
	p_parser->method = (uint8_t)(*(ptr + offset));

	if (p_parser->compress > 0x3 || p_parser->encrypt > 0x3 || p_parser->method > 0x9){
    	x_printf(E, "异常啊\n"); 
		// 继续接收
        return MFPTP_PARSE_ILEGAL;
	}
                                
    if(p_parser->method == HEARTBEAT_METHOD){
        x_printf(D,"心跳\n"); 
		// 心跳不能直接返回，而应该retry
		return MFPTP_PARSE_HEARTBEAT;
    }
	offset++;
    /* 包数信息 */
	p_parser->packages = (uint8_t)(*(ptr + offset));
	if (p_parser->packages == 0){
		// 只有头，没有数据
		return MFPTP_PARSE_NODATA;
	}

	// head ---end
	return MFPTP_PARSE_PACKAGE;
}

/*
 *1. 解析frame
 *
 *
 *
 *
 */
 void mfptp_parse_frame(struct user_info* usr)
{

}

/*
 *1. 一个包完成，回调
 *
 *
 *
 **/
void  mfptp_parse_package(struct user_info* usr)
{
	struct mfptp_parser * p_parser = &(usr->mfptp_info.parser);
    struct mfptp_status * p_status = &(usr->mfptp_info.status);	
	int i = 0;

	/*-接收完成一个包后调用回调函数，心跳包直接丢弃,不调用回调函数-*/
	if (p_parser->func&&p_parser->method!=HEARTBEAT_METHOD)
		p_parser->func(usr);
	// 释放内存，链表循环释放
    for (i = 0; i < p_status->packages.frames; i++){
		mem_free(p_status->package.ptrs[i]);
		p_status->package.ptrs[i] = NULL;
		p_status->package.dsizes[i] = 0;
	}	
	//包 reset
	memset(&(p_status->package), 0, sizeof(struct mfptp_package));
}
	
	
/*
 *1. 接收数据和解析全部放在这里面做
 *2. 抽离事件
 *
 *
 *
 *
 **/

/* 数据接受解析全部在这一个函数里面处理*/
int mfptp_parse(struct user_info* usr)
{
	assert(usr);
	struct mfptp_parser* p_parser = &(usr->mfptp_info.parser);
	struct mfptp_status* p_status = &(usr->mfptp_info.status);
	int ret;

	//设置初始状态以及事件,static变量
	static FSM_STATE state = INIT_STATE;
	RECV_EV ev = INVALID_EV;
	for( ; ;){
    //监听事件,考虑何时跳出循环，事件判断结束-----libev一次循环结束
	//不跳出循环的为正常事件，事件到了需要做一些处理的
		ev = recv_ev(usr,state);

		//只要是非出口事件发生了，说明了一件事:数据收到
		//对于header的状态，有可能出现一些不合法的数据,这个时候就会抛弃数据，重置状态
		switch(ev){
			case HEAD_EV:
			// 根据状态，执行动作，切换状态
				ret = mfptp_parse_head(usr);
				// 头解析完毕就要释放临时的内存,这跟解析帧不一样，帧是直接把帧内存挂上去的，够一个包然后统一释放
				FREE_MEM(p_status->mfptp_header);
				//非法或者心跳，释放内存，从新接收
				if ( (ret == MFPTP_PARSE_ILEGAL) || (ret == MFPTP_PARSE_HEARTBEAT)){
					state = INIT_STATE;	
				
				}else if ( ret == MFPTP_PARSE_NODATA )	// 没有数据，登录验证包
					state = HEAD_STATE;
					return MFPTP_PARSE_OVER;
					//head---end
				}
				else if ( ret == MFPTP_PARSE_PACKAGE)// 继续判断后续帧事件
					state = HEAD_STATE;
				break;
			case FRAME_EV:
			// 只有在下面三种状态下才可能发生帧事件
			// 在该状态下，行为切换状态，帧已经在事件判断的过程中放进usr->p_status->packages
				if (state == HEAD_EV)
					state = FRAME_STATE;
				else if (state == FRAME_STATE)
					;// 状态不变
				else if (state == DEAL_PACK_STATE)
					state = FRAME_STATE;
				
				break;
			case SINGLE_PACK_EV:
				// 一个包完成，回调
			    mfptp_parse_package(usr);	
				state = DEAL_PACK_STATE;
				break;
				//一次请求结束，设置为初始状态
			case ALL_PACK_EV:
				mfptp_parse_package(usr);
				state = INIT_STATE;
		
				return MFPTP_PARSE_OVER;
				break;
				/*下面几个事件是出口*/

			case INVALID_EV://一种情况，#MFPTP不对
				//无效事件，未离线，跳出循环
				state = INIT_STATE;
			//	return MFPTP_PARSE_ILEGAL;// illegal
				break;

			case RETRY_EV:
				// 跳出循环,retry
				// 状态保持不变
				return MFPTP_PARSE_RETRY;
				break;
			case OFFLINE_EV:
				// 跳出循环,离线,续传功能
				//state = INIT_STATE;
				return MFPTP_PARSE_OFFLINE;
				break;

			default:
				break;
		}
    }
}                         




/* 名      称: mfptp_pack_frames_with_hdr
 * 功      能: 序列化一个mfptp协议头到缓冲区中
 * 参      数: dst,添加包头后的数据写入到该地址
               ver,版本号more
               sk_type,socket类型标识数据类型
               pkt_cnt,数据包的个数
 * 返  回  值: 序列化头部后的长度
 * 修      改: 新生成函数l00167671 at 2015/2/28
*/                                                             
int mfptp_pack_hdr(char *dst, int ver, int sk_type, int pkt_cnt)
{
        dst[0] ='#';
        dst[1] ='M';
        dst[2] ='F';
        dst[3] ='P';
        dst[4] ='T';
        dst[5] ='P';
        dst[6] =ver;     /* 版本*/
        dst[7] =0x00;    /* 压缩、加密*/
        dst[8] =sk_type; /* PUSH */
        dst[9] =pkt_cnt; /* 包个数*/
        
        /* 当前头部长度为10,魔鬼数字*/
        return 10;
}
/* 名      称: mfptp_pack_frames_with_hdr
 * 功      能: 把src指向的长度为len的数据打包成符合mfptp协议的数据包
 * 参      数: src, 指向要打包的数据; len, 要打包数据的长度; 
               dst,添加包头后的数据写入到该地址
               more,非零表示有后续帧，零表示无后续帧
 * 返  回  值: 序列化后的数据长度
 * 修      改: 新生成函数l00167671 at 2015/2/28
*/                                                             
int mfptp_pack_frames_with_hdr(char *src, int len, char *dst, int more)
{
        int ret = -1;
        dst[0] ='#';
        dst[1] ='M';
        dst[2] ='F';
        dst[3] ='P';
        dst[4] ='T';
        dst[5] ='P';
        dst[6] =0x01; /* 版本*/
        dst[7] =0x00; /* 压缩、加密*/
        dst[8] =0x08; /* PUSH */
        dst[9] = 0x1; /* 包个数*/
        if(0!=more){
            dst[10]=0x04; /* FP_CONTROL  */
        }else{
            dst[10]=0x00;
        }

        unsigned char *p=(unsigned char *)&len;
        if(len<=255){
            dst[11]=len;
            memcpy(dst+12,src,len);
            ret = len+12;
        }else if(len<=65535){
            dst[11]=*(p+1);
            dst[12]=*(p);
            dst[10]=dst[10] | 0x01; /* 设置FP_CONTROL  */
            memcpy(dst+13,src,len);
            ret = len+13;
        }else{
            dst[11]=*(p+2);
            dst[12]=*(p+1);
            dst[13]=*(p);
            dst[10]=dst[10]|0x02; /* 设置FP_CONTROL  */
            memcpy(dst+14,src,len);
            ret = len+14;
        }
        return ret;
}
                                                             
int mfptp_pack_frame(char *src, int len, char *dst, int more)
{
        int ret = -1;
        if(0!=more){
            dst[0]=0x04; /* 设置FP_CONTROL  */
        }else{
            dst[0]=0x00; /* 设置FP_CONTROL */
        }

        unsigned char *p=(unsigned char *)&len;
        if(len<=255){
            dst[1]=len;
            memcpy(dst+2,src,len);
            ret = len+2;
        }else if(len<=65535){
            dst[0]=dst[0] | 0x01; /* FP_CONTROL  */
            dst[1]=*(p+1);
            dst[2]=*(p);
            memcpy(dst+3,src,len);
            ret = len+3;
        }else{
            dst[0]=dst[0]|0x02; /* FP_CONTROL  */
            dst[1]=*(p+2);
            dst[2]=*(p+1);
            dst[3]=*(p);
            memcpy(dst+4,src,len);
            ret = len+4;
        }
        return ret;
}

