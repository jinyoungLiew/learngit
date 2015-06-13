#pragma once 


#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>
#include "mfptp_def.h"
#include <ev.h>
#include <arpa/inet.h>

#include "list.h"
#include "net_cache.h"
#include "rbtree.h"
#include "mfptp_api.h"


#ifndef bool
#define bool int
#endif

#ifndef true 
#define true 1
#endif


#ifndef false
#define false 0
#endif


#define MFPTP_PARSER_TEST (0xff)

#define MFPTP_PARSE_NODATA (-2)	/*-return this value, no package data-*/
#define MFPTP_PARSE_ILEGAL (-1)	/*-return this value, now the data's not legal mfptp protocol-*/
#define MFPTP_PARSE_INIT 0	/*-this will not return, but represent parse is not start-*/
#define MFPTP_PARSE_HEAD 1	/*-return this value, now the data's head is not over,wait more data; if not return value, now step is parsing header-*/
#define MFPTP_PARSE_PACKAGE 2	/*-return this value, now the data's not over, wait more package data; if not return value, now step is parsing package-*/
#define MFPTP_PARSE_OVER 3	/*-return this value, now the data is parsed over-*/
#define MFPTP_PARSE_MOREDATA 4	/*-return this value, more data ,bigger than buffer-*/

#define MFPTP_PARSE_RETRY 5 // add by liujinyang
#define MFPTP_PARSE_OFFLINE 6
#define MFPTP_PARSE_HEARTBEAT 7
/* 状态定义------5个状态*/
typedef enum{
	INIT_STATE ,
	HEAD_STATE ,
	FRAME_STATE ,
	DEAL_PACK_STATE ,
	OVER_STATE ,
}FSM_STATE;

/*事件定义*/
typedef enum {
	INVALID_EV,// 错误事件,状态不变
	HEAD_EV,
	FRAME_EV,
	SINGLE_PACK_EV,
	ALL_PACK_EV,
	RETRY_EV,// 事件部分来了，但不齐全,需要记录已经读到的字节
	OFFLINE_EV,// 用户要下线了
}RECV_EV;

enum COMPRESSION_FORMAT_TYPE{
	NO_COMPRESSION = 	0x0,
	ZIP_COMPRESSION = 	0x1,
	GZIP_COMPRESSION = 	0x2,
};

enum ENCRYPTION_FORMAR_TYPE{
	NO_ENCRYPTION = 	0x0,
	IDEA_ENCRYPTION = 	0x1,
	AES_ENCRYPTION = 	0x2,
}; 


enum WORK_METHOD{
	PAIR_METHOD      = 0x00,
	PUB_METHOD       = 0x01,
	SUB_METHOD       = 0x02,
	REQ_METHOD       = 0x03,
	REP_METHOD       = 0x04,
	DEALER_METHOD    = 0x05,
	ROUTER_METHOD    = 0x06,
	PULL_METHOD      = 0x07,
	PUSH_METHOD      = 0x08,
	HEARTBEAT_METHOD = 0x09,
        INVALID_METHOD   = 0x10
};


typedef void* (*mfptp_callback_func)(void *);

struct mfptp_parser{
	//bool head_parse;	/*-if package if whole parse-*/
	short version;
	short sub_version;
	uint8_t  method;
	uint8_t compress;
	uint8_t encrypt;
	uint8_t packages;	/*-package counts to parse-*/
	mfptp_callback_func func;	/*-callback function-*/
};

/*-each whole data maybe have several packages-*/
/*-each package have serveral frames-*/

#define MAX_FRAMES_PER_PACKAGE 10

struct mfptp_package{
	bool complete;
	int frames;	
	int dsizes[MAX_FRAMES_PER_PACKAGE];	/*-data size, all size is :fsize + dsize + 1, 1 is control size-*/
	char *ptrs[MAX_FRAMES_PER_PACKAGE];	/*-data start pointer-*/
};

struct mfptp_status{
//	int step;	/*-parse step-*/
//	int index;	/*-parsing package index, start 1-*/
//	int doptr;	/*-pointer now pos-*/

    char *mfptp_header;	
	char *mfptp_frame;// 临时指针指向frame数据,当全局变量使用
	int package_index;// 当前包是第几个包
    int recv_bytes;
	int recv_buf_index;


        int sharp_pos;  /* 记录每个包开始的#的位置, 主要是为了计算续传的位置*/
	struct mfptp_package package;	
};

struct mfptp_parser_info{
	struct mfptp_parser parser;
	struct mfptp_status status;
};

struct user_info {
	rb_node node; 
	WORKER_PTHREAD *processor;
	/*whenever can't clean when reset user_info*/
	/***base attribute***/
	int sfd;
        int old_sfd;
	int port;
        /* 终端崩溃后重启无法续传， 引入force_login字段标志是否需要续传 */
        int force_login; /* 此标志为1表示不需要续传， 0表示需要续传*/
	char szAddr[ INET_ADDRSTRLEN ];		/* 255.255.255.255 */
	char who[64];
        char key[16];     /* 加密密钥，使用128bit长度*/
	

	/*should clean when reset user_info*/
	/***ev***/
	ev_io i_watcher;
	ev_io o_watcher;
	/***R***/
	struct net_cache recv;

	/***W***/
	struct net_cache send;
	
	struct mfptp_parser_info mfptp_info;
	
	/****S***/
	enum {
		NO_AUTH = 0,
		IS_AUTH = 1,
	} auth_status;				/*io dispose*/
	int control;				/*cmd dispose*/

};

void mfptp_register_callback(struct user_info* usr, mfptp_callback_func fun);
void mfptp_init_parser_info(struct mfptp_parser_info *p_info);
int mfptp_parse(struct user_info* usr);
/* 名      称: mfptp_pack_frames_with_hdr
 * 功      能: 把src指向的长度为len的数据打包成符合mfptp协议的数据包
 * 参      数: src, 指向要打包的数据; len, 要打包数据的长度; 
               dst,添加包头后的数据写入到该地址
               more,非零表示有后续帧，零表示无后续帧
 * 返  回  值: 序列化后的数据长度
 * 修      改: 新生成函数l00167671 at 2015/2/28
*/
int mfptp_pack_frames_with_hdr(char *src, int len, char *dst, int more);
int mfptp_pack_hdr(char *dst, int ver, int sk_type, int pkt_cnt);
int mfptp_pack_frame(char *src, int len, char *buf, int more);
