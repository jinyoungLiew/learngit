/*
*
*/

#include "mfptp_parser.h"
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

#define FSM 1
#if 0 
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

void mfptp_init_parser_info(struct mfptp_parser_info *p_info)
{
        p_info->parser.compress         = 0;
        p_info->parser.encrypt          = 0;
	p_info->parser.func             = NULL;
	p_info->parser.method           = 0;
	p_info->parser.packages         = 0;
	p_info->parser.pos_frame_start  = 0;
	p_info->parser.sub_version      = 0;
	p_info->parser.version          = 0;
	p_info->status.index            = 0;
	p_info->status.package.complete = true;
	p_info->status.package.frames   = 0;
	p_info->status.step             = 0;
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

#endif
/////////////////////////////////////////////////////FSM PARSE/////////////////////////////////////////////

// debug
// by 刘金阳 @ 2015/6/11 
char * mem_get(int size)
{
	char * ptr  = malloc(size);
	return ptr;
}

void mem_free(char * ptr)
{
	free(ptr);
}

/*
 *功 能：一次请求结束，重新设置mfptp_parse_info
 *参 数：p_info---用户结构体 指针
 *返回值：void
 *修 改: 新生成函数 by 刘金阳 @ 2015/6/9
 **/
void mfptp_reset_parser_info(struct user_info *p_info)
{
	memcpy(&(p_info->mfptp_info),0,sizeof(p_info->mfptp_info));

	// 下面这两个数据域比较特殊，需要重置
	p_info->mfptp_info.status.state = INIT_STATE;
	p_info->mfptp_info.status.package.complete = true;
}

/*
 *功 能：初始化状态机，设置状态机状态为INIT_STATE
 *参 数：usr---用户结构体指针
 *返回值：void
 *修 改: 新生成函数 by 刘金阳 @ 2015/6/9
 *
 **/
void fsm_init(struct user_info *usr)
{
	move_to_state(usr,INIT_STATE);
}

/*
 *功 能：设置状态机状态
 *参 数: usr--用户结构体指针
 *       new_state--要设置的成的状态
 *返回值：void
 *修 改: 新生成函数 by 刘金阳 @ 2015/6/9
 */
void move_to_state(struct user_info* usr, FSM_STATE new_state)
{
	usr->mfptp_info.status.state = new_state;
}


/*
 *功 能：尝试获取头事件,如果事件未发生，设置偏移量，事件发生，偏移量赋值0
 *       header_offset--- 
 *参 数: usr--用户结构体指针
 *返回值：EV_OK---事件发生
 *        EV_CONTENT_ERR--严重错误
 *        EV_NOT_HAPPENED--事件未发生
 *修 改: 新生成函数 by 刘金阳 @ 2015/6/9
 */
int got_header_ev(struct user_info* usr, char *buf, int len)
{
	assert(NULL != usr);

	struct mfptp_parser * p_parser = &(usr->mfptp_info.parser);
    struct mfptp_status * p_status = &(usr->mfptp_info.status);	

	const char *header = "#MFPTP";
	//recv 缓冲区 index
	int offset = p_status->recv_buf_index;

	// (10 - p_status->header_offset)  ------剩余的字符数量
	int remain = 10 - p_status->header_offset;
	/**
	 *测试极端情况：#MFPTP一个字符一个字符达到
	 */

	//1, 先内存拷贝
    if ((len - offset) >= remain){
		/*进入该条件，则数据长度够，下一步判断内容,而且只进入一次，要么ok,要么错误*/
		x_printf(D,"header_offset = %d,recv_buf offset = %d\n",p_status->header_offset,offset);
		memcpy(p_status->mfptp_header + p_status->header_offset, buf + offset, remain);	
#if 1
		printf("recv buf\n");	
		// for debug
		int i;
		for (i = offset; i< offset + 6; i++){
			printf(" %x ",buf[i]);	
		}
		printf("\n");
		printf("header buffer\n");
		for (i = p_status->header_offset; i < p_status->header_offset + 6; i++){
			printf("%x ",(p_status->mfptp_header)[i]);	
		}
		printf("\n");
#endif
		p_status->header_offset += remain;
		/* 包的前6个字节必须是"#MFPTP" */
		if (strncmp(buf + offset, header, 6) != 0 ){		
			x_printf(E,"非法协议 remain = %d\n",remain);
			return EV_CONTENT_ERR;	 
		}else{
			p_status->recv_buf_index += remain;
		x_printf(D,"%s ok\n",__func__);
			return EV_OK;
		}
	}else{
		/*长度不够,只做拷贝,最终还是走到上面的if条件里面去*/
	    memcpy(p_status->mfptp_header + p_status->header_offset, buf + offset, (len - offset));	
	    p_status->header_offset += (len - offset);	
		p_status->recv_buf_index += (len - offset);
		
		return EV_NOT_HAPPENED;	
#if 0
		if (p_status->header_offset > 5){
			// 拷贝部分
			if (strncmp(buf + offset,header,6) != 0){
				x_printf(E,"非法协议\n");	
				return EV_CONTENT_ERR;
			}else{
				//偏移
				p_status->recv_buf_index += (len - offset);
				return EV_NOT_HAPPENED;	
			}
		}else {
			if (strncmp(buf+offset, header,(p_status->header_offset > 6 ? 6:p_status->header_offset)) != 0){
				x_printf(E,"非法协议\n");
				return EV_CONTENT_ERR;	 
			}else {
				p_status->recv_buf_index += (len - offset);
				return EV_NOT_HAPPENED;	
			}
		}
#endif
	}
}

/**
 *功 能：尝试回去FP_control字段，获取后，事件发生
 *参 数：usr---用户结构体指针
 *       buf---recv 缓冲区
 *       len---缓冲区长度
 *返回值：EV_OK---事件发生
 *        EV_NOT_HAPPENED---事件未发生
 *修 改: 新生成函数 by 刘金阳 @ 2015/6/10
 */
int got_FP_control_ev(struct user_info* usr, char * buf, int len)
{
	assert(NULL != usr);
    struct mfptp_status * p_status = &(usr->mfptp_info.status);	
	
	// p_status->recv_buf_index 指向FP_control	
	x_printf(D,"p_status->recv_buf_index = %d\n",p_status->recv_buf_index);
	if(len >= p_status->recv_buf_index){
		//FP_control 一个字节
		p_status->FP_control = *(buf + p_status->recv_buf_index);
		p_status->recv_buf_index += 1;
		x_printf(D,"FP_control = %d\n",p_status->FP_control);
		x_printf(D,"%s ok\n",__func__);
		return EV_OK;
	}else{
		return EV_NOT_HAPPENED;
	}
	
}

/**
 *功 能: 尝试获取FP_size，如事件未发生，需要设置FP_size_offset
 *参 数：usr---用户结构体指针
 *       buf---recv 缓冲区
 *       len---缓冲区长度
 *返回值：EV_OK---事件发生
 *        EV_NOT_HAPPENED---事件未发生
 *修 改: 新生成函数 by 刘金阳 @ 2015/6/10
 */
int got_FP_size_ev(struct user_info* usr, char * buf, int len)
{
	assert(NULL != usr);
    struct mfptp_status * p_status = &(usr->mfptp_info.status);	
	
	int offset = p_status->recv_buf_index;
	
	int remain = p_status->fp_size_len - p_status->FP_size_offset;
	x_printf(D,"offset 应该是 11 offset = %d\n",p_status->recv_buf_index);
	x_printf(D,"帧长度所占用字节:%d, remain = %d\n",p_status->fp_size_len,remain);
	// 下面条件进入一次
	if ((len - offset) >= remain){
		memcpy(p_status->FP_size + p_status->FP_size_offset,buf + offset, remain);
		x_printf(D,"p_status->FP_size[0] = %d\n",p_status->FP_size[0]);
		p_status->FP_size_offset += remain;
		p_status->recv_buf_index += remain;

		x_printf(D,"%s ok\n",__func__);
		return EV_OK;	
	}else {
		memcpy(p_status->FP_size + p_status->FP_size_offset, buf + offset,(len - offset));	
		p_status->FP_size_offset += (len - offset);
		p_status->recv_buf_index += (len - offset);
		return EV_NOT_HAPPENED;
	}

}

/**
 *功 能: 尝试获取帧数据，根据帧长度来判断，如事件未发生，需要设置frame_offset
 *参 数：usr---用户结构体指针
 *       buf---recv 缓冲区
 *       len---缓冲区长度
 *返回值：EV_OK---事件发生
 *        EV_NOT_HAPPENED---事件未发生
 *修 改: 新生成函数 by 刘金阳 @ 2015/6/10
 */
int got_frame_data_ev(struct user_info* usr, char * buf, int len)
{
	assert(NULL != usr);
    struct mfptp_status * p_status = &(usr->mfptp_info.status);	

	int frame_length = p_status->frame_len;

	int offset = p_status->recv_buf_index;
	int remain = frame_length - p_status->frame_offset;
	// 帧数据全部得到以后才存到package里面，否则就只是暂存指针
	
	x_printf(D,"frame_length = %d, remain = %d\n",frame_length,remain);
	//分配内存
	if (NULL == p_status->frame_data){
		p_status->frame_data = mem_get(frame_length);
		p_status->frame_offset = 0;
		p_status->package.frames += 1;
	}
	if ( (len - offset) >= remain){
		memcpy(p_status->frame_data + p_status->frame_offset,buf + offset,remain);
		p_status->recv_buf_index += remain;
		p_status->frame_offset += remain;
		
		x_printf(D,"%s ok\n",__func__);
		return EV_OK;
	}else{
		memcpy(p_status->frame_data + p_status->frame_offset,buf + offset, (len - offset));	
		p_status->recv_buf_index += (len - offset);
		p_status->frame_offset += (len - offset);
		 
		return EV_NOT_HAPPENED;
	}
	
}

/**
 *功 能：解析FP_control字段，取出complete,fp_size_len字段
 *参 数：usr---用户结构体指针
 *返回值：void
 *修 改: 新生成函数 by 刘金阳 @ 2015/6/9
 */
void mfptp_parse_FP_control(struct user_info * usr)
{
	assert(NULL != usr);
    struct mfptp_status * p_status = &(usr->mfptp_info.status);	
	
	int fp_control = p_status->FP_control;
	x_printf(D,"fp_control = %d\n",fp_control);
	/* fp_control的最低2位表示f_size字段占据的长度*/
	p_status->fp_size_len = GET_LOW01_BITS(fp_control) + 1; 
	/* fp_control的第2、3位表示package是否结束,只有0和1两个取值*/
	p_status->package.complete = GET_LOW23_BITS(fp_control);

	p_status->FP_control = 0;

}
/**
 *功 能：解析FP_size字段，取出帧长度字段
 *参 数：usr---用户结构体指针
 *返回值：void
 *修 改: 新生成函数 by 刘金阳 @ 2015/6/9
 */
void mfptp_parse_FP_size(struct user_info *usr){

	assert(NULL != usr);
    struct mfptp_status * p_status = &(usr->mfptp_info.status);	

	char *ptr = p_status->FP_size;
	int fp_size = p_status->fp_size_len;
	int i = 0;
	x_printf(D,"*ptr = %d\n",*ptr);
	x_printf(D,"fp_size %d\n",fp_size);
	for (i = 0; i < fp_size; i++){
		p_status->frame_len += *(ptr + i) << (8 * (fp_size - 1 -i));
	}
	x_printf(D,"frame len = %d\n",p_status->frame_len);
	// 解析完 reset
	memset(p_status->FP_size,0,4);
	p_status->FP_size_offset = 0;
	p_status->fp_size_len = 0;

}

/**
 *功 能：解析一帧数据,主要放进package中
 *参 数：usr---用户结构体指针
 *返回值：void
 *修 改: 新生成函数 by 刘金阳 @ 2015/6/9
 */
void mfptp_parse_frame(struct user_info *usr){
	assert(NULL != usr);
    struct mfptp_status * p_status = &(usr->mfptp_info.status);	

	p_status->package.dsizes[p_status->package.frames - 1] = p_status->frame_len;
	p_status->package.ptrs[p_status->package.frames - 1] = p_status->frame_data;

	p_status->frame_len = 0;
	p_status->frame_data = NULL;

}

/*
 *功 能：必须是事件发生以后，解析head,返回解析状态
 *参 数：usr---用户结构体指针
 *返回值: header 解析的状态
 *        MPTPT_PARSE_OVER---心跳包的时候
 *        MFPTP_PARSE_ILEGAL---压缩，解密方式等错误,解析出来包数错误
 *        MFPTP_PARSE_PACKAGE---header解析正常
 *修 改: 新生成函数 by 刘金阳 @ 2015/6/9
 *
 **/
int mfptp_parse_head(struct user_info* usr)
{
	assert(NULL != usr);

	struct mfptp_parser * p_parser = &(usr->mfptp_info.parser);
    struct mfptp_status * p_status = &(usr->mfptp_info.status);	
	char *ptr = p_status->mfptp_header;
	int offset = 0;
#if 0
	/* 包的前6个字节必须是"#MFPTP" */
		if (strncmp(ptr, "#MFPTP", 6) != 0 ){		
			x_printf(E,"非法协议\n");
			return MFPTP_PARSE_ILEGAL;	 
		}
#endif
		// 首先，通过偏移六个字节，去除#MFPTP这几个字节
		offset += 6;
        /* 版本信息 */
		p_parser->version = (uint8_t)(*(ptr + offset) >> 4); 	
		p_parser->sub_version = (uint8_t)(*(ptr + offset) << 4);
		p_parser->sub_version = p_parser->sub_version >> 4;	

        offset += 1; 
        /* 加密和压缩信息 */
		p_parser->compress =  (uint8_t)(*(ptr + offset) >> 4);	
		p_parser->encrypt = (uint8_t)(*(ptr + offset) << 4);
		p_parser->encrypt = p_parser->encrypt >> 4;		

	    offset += 1;	
        /* 方法信息 */
		p_parser->method = (uint8_t)(*(ptr + offset));

		if (p_parser->compress > 0x3 || p_parser->encrypt > 0x3 || p_parser->method > 0x9){
            x_printf(E, "异常,加密和压缩等信息不合法\n"); 
			return MFPTP_PARSE_ILEGAL;
		}
                                
        if(p_parser->method == HEARTBEAT_METHOD){
            x_printf(D,"心跳包\n"); 
            return MFPTP_PARSE_OVER;
        }

		offset += 1;
        /* 包数信息 */
		p_parser->packages = (uint8_t)(*(ptr + offset));

		if (p_parser->packages == 0){
			x_printf(E,"MFPTP_PARSE_NODATA\n");
			return MFPTP_PARSE_ILEGAL;
		}
				
		x_printf(D," parse header over!\n");
       // p_status->package.frames = 0;

		//header 处理结束，相关变量重置
		memset(p_status->mfptp_header,0,sizeof(p_status->mfptp_header));
		p_status->header_offset = 0;

		//只要不返回该值，全部上抛，返回该值，则设置状态机状态，继续其他事件
		return MFPTP_PARSE_PACKAGE;
}

/*
 *功 能： 接收完成一个包后调用回调函数，心跳包直接丢弃,不调用回调函数
 *        然后需要清理整个包结构
 *参 数： usr---用户信息结构体
 *返回值：void
 *修 改: 新生成函数 by 刘金阳 @ 2015/6/9
 **/
void  mfptp_parse_package(struct user_info* usr)
{
	struct mfptp_parser * p_parser = &(usr->mfptp_info.parser);
    struct mfptp_status * p_status = &(usr->mfptp_info.status);	
	int i = 0;

	/*-接收完成一个包后调用回调函数，心跳包直接丢弃,不调用回调函数-*/
	if (p_parser->func/*&&p_parser->method!=HEARTBEAT_METHOD*/)
	{
#if 1 
		int index = 0;
		for (index = 0; index < usr->mfptp_info.status.package.dsizes[p_status->package.frames -1]; index++)
			printf(" %x ",*(usr->mfptp_info.status.package.ptrs[p_status->package.frames-1] + index ));
		printf("\n");
#endif
		x_printf(D,"包解析结束，回调\n");
		p_parser->func(usr);
	}else{
		x_printf(E,"回调函数为空\n");
		// 暂时先这样处理一下，如果进入这里，则需要看log
	}

	x_printf(D,"回调结束\n");
	// 释放内存，链表循环释放
    for (i = 0; i < p_status->package.frames; i++){
		mem_free(p_status->package.ptrs[i]);
		p_status->package.ptrs[i] = NULL;
		p_status->package.dsizes[i] = 0;
	}	
	//包---reset
	p_status->package.complete = true;
	p_status->package.frames = 0;

	p_status->frame_data = NULL;
	p_status->frame_len = 0;
	p_status->frame_offset = 0;

}

/*
 *功 能：状态机---根据状态，若发生了某些事件，则进行相应的行为
 *参 数：usr---用户信息
 *       buf---recv 缓冲区
 *       len---recv缓冲区长度
 *返回值：
 *        MPTPT_PARSE_OVER---心跳包或者一次请求结束
 *        MFPTP_PARSE_ILEGAL---压缩，解密方式等错误,解析出来包数错误
 *修 改: 新生成函数 by 刘金阳 @ 2015/6/9
 **/	
int mfptp_parse_fsm(struct user_info* usr, char * buf, int len)
{
	assert(NULL != usr);
	
	struct mfptp_parser* p_parser = &(usr->mfptp_info.parser);
	struct mfptp_status* p_status = &(usr->mfptp_info.status);
	
	//FSM_STATE state = p_status->state;
	int got_ev_ret;
	int parse_ret;
    for( ; ;)	
	{
		switch(p_status->state){
			case INIT_STATE:
				got_ev_ret = got_header_ev(usr,buf,len);
				if (EV_OK == got_ev_ret){
					//action
					parse_ret = mfptp_parse_head(usr);	
					if (MFPTP_PARSE_PACKAGE != parse_ret){
						return parse_ret;// 抛到上层处理	
					}else{
						move_to_state(usr,GOT_HEADER_STATE);	
					}
				}else if (EV_NOT_HAPPENED == got_ev_ret){

					//这种情况是缓冲区数据解析完毕，需要记录控制信息
					return MFPTP_PARSE_CONTINUE;

				}else if (EV_CONTENT_ERR == got_ev_ret){

					x_printf(E,"协议内容错误，严重错误");
				    return MFPTP_PARSE_ILEGAL;		
				}

				break;
			case GOT_HEADER_STATE:
				got_ev_ret = got_FP_control_ev(usr,buf,len);
				if (EV_OK == got_ev_ret){

					mfptp_parse_FP_control(usr);
				    move_to_state(usr,GOT_FP_control_STATE);			
				}else {
					return MFPTP_PARSE_CONTINUE;		
				}

				break;
			case GOT_FP_control_STATE:
				got_ev_ret = got_FP_size_ev(usr,buf,len);
				if (EV_OK == got_ev_ret){
					mfptp_parse_FP_size(usr);		
					move_to_state(usr,GOT_FP_size_STATE);
				}else {
					return MFPTP_PARSE_CONTINUE;		
				}
				break;
			case GOT_FP_size_STATE:
				got_ev_ret = got_frame_data_ev(usr,buf,len);
				if (EV_OK == got_ev_ret){
					mfptp_parse_frame(usr);		
					move_to_state(usr,GOT_FRAME_DATA_STATE);
				}else {
					return MFPTP_PARSE_CONTINUE;		
				}
				break;
			case GOT_FRAME_DATA_STATE:
				// 先写下代码，然后再看看能抽象不
				// 1. 先判断是否是一个包
				if (p_status->package.complete == 0){

					x_printf(D,"一个包完成\n");	
					p_status->package_index++;
					mfptp_parse_package(usr);
					
					// 一起请求结束
					if (p_status->package_index == p_parser->packages){
						move_to_state(usr,OVER_STATE);
					}else {
						// 下一帧
						move_to_state(usr,GOT_FP_control_STATE);
					}
				}
				break;

			case OVER_STATE:
				x_printf(D,"一次请结束\n");
			//	move_to_state(INIT_STATE);
			    mfptp_reset_parser_info(usr);
				return MFPTP_PARSE_OVER;
				break;
		}
	}

}



#if 0
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
#endif
