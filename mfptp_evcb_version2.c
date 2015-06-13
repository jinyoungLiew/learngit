/*
 * a simple server use libev
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <pthread.h>
#include <semaphore.h>
#include <assert.h>

#include "mfptp_evcb.h"
#include "mfptp_api.h"
#include "net_cache.h"
#include "mfptp_parser.h"
#include "mfptp_def.h"
#include "mfptp_callback.h"
#include "rbtree.h"
#include "basic_type.h"
#include "mfptp_users_rbtree.h"

/* test */
static struct timeval g_dbg_time;

extern int G_WORKER_COUNTS;
extern MASTER_PTHREAD g_master_pthread;
extern WORKER_PTHREAD *g_worker_pthread;

extern struct mfptp_settings g_mfptp_settings;
extern struct data_node *g_data_pool;

static struct linger g_quick_linger = {
	.l_onoff = 1,
	.l_linger = 0
};
static struct linger g_delay_linger = {
	.l_onoff = 1,
	.l_linger = 1
};
rb_root user_tree = RB_ROOT ;

/********************************************************/
static void _mfptp_timeout_cb(struct ev_loop *loop, ev_timer *w, int revents);
static void _mfptp_recv_cb(struct ev_loop *loop, ev_io *w, int revents);
 void _mfptp_send_cb(struct ev_loop *loop, ev_io *w, int revents);
/********************************************************/
static void mfptp_dispatch_task(struct user_info *p_info)
{
	unsigned int idx = 0;
	int stp = 0;
	int mul = 1;
	WORKER_PTHREAD *p_worker = NULL;
	/*dispath to a hander thread*/
	idx = 0;//mfptp_hash( p_info->who ) % G_WORKER_COUNTS;
	p_worker = &g_worker_pthread[ idx ];
	p_info->processor = p_worker;
#ifdef USE_PIPE
DISPATCH_LOOP:
	if ( write(p_worker->pfds[1], (char *)&p_info, sizeof(uintptr_t *)) != sizeof(uintptr_t *) ){
		if ( 0 == ((++ stp) % (mul * SERVER_BUSY_ALARM_FACTOR)) ){
			mul ++;
			x_printf(S, "recv worker thread is too busy!\n");
		}
		goto DISPATCH_LOOP;
	}
#else
	CQ_ITEM *p_item = &p_info->recv_item;

	cq_push( &(p_worker->qlist) , p_item);
	ev_async_send(p_worker->loop, &(p_worker->async_watcher));//TODO
#endif

}




static void _mfptp_pass_cb(struct ev_loop *loop, ev_io *w, int revents)
{
	x_out_time(&g_dbg_time);

	struct user_info *p_info = w->data;


	int ret = net_send(&p_info->send, w->fd, &p_info->control);
	if ( ret >= 0 ){
		if (ret > 0){
			x_printf(D, "-> no all\n");
			return;
		}
		else{
			x_printf(D, "-> is all\n");
		}
	}
	cache_free( &p_info->send );
	p_info->control = X_DONE_OK;
	ev_io_stop(loop,  w);
        int active = ev_is_active(w);
	mfptp_dispatch_task(p_info);
	return;
P_BROKEN:
	cache_free( &p_info->send );
	ev_io_stop(loop, w);
	close(w->fd);
	free(p_info);

	return;
}
static void * callback_auth( void *data )
{
	struct user_info          *puser    =  (struct user_info *)data;
	struct mfptp_status       *p_status =  &puser->mfptp_info.status;
	int                        cnt      =  p_status->package.frames;	

	if( (REQ_METHOD == puser->mfptp_info.parser.method) && (1 == cnt)){
		int len = MFPTP_UID_MAX_LEN;
		if(p_status->package.dsizes[0] < MFPTP_UID_MAX_LEN){
			len = p_status->package.dsizes[0];
		}
		memcpy(puser->who,p_status->package.ptrs[0],len);
		puser->who[len] = 0;
	}else{
		memcpy(puser->who, MFPTP_INVALID_UID, MFPTP_INVALID_UID_LEN);
		puser->who[MFPTP_INVALID_UID_LEN] = 0;
	}
	
	return NULL;
}

static void _mfptp_auth_cb(struct ev_loop *loop, ev_io *w, int revents)
{
	char temp[MAX_DEF_LEN] = {0};
	struct user_info *p_info = w->data;
        int continution_index = 0;
	int ret = net_recv(&p_info->recv, w->fd, &p_info->control);

	x_out_time(&g_dbg_time);
        
	if(ret > 0){
                x_printf(D, "接收到的数据长度:%d\n",p_info->recv.get_size);
                int i =0;
		do {
			/*no more memory*/
			if (p_info->control == X_MALLOC_FAILED){
				//TODO
				goto A_BROKEN;
			}
			/*data too large*/
			if (p_info->control == X_DATA_TOO_LARGE) {
				//TODO
				goto A_BROKEN;
			}
			/* parse recive data */
			if ( MFPTP_PARSE_OVER != mfptp_parse(p_info) ){//FIXME
				/*data not all,go on recive*/
				return;
			}else{
                                /* 协议分析状态初始化 */
                                //mfptp_init_parser_info(&(p_info->mfptp_info));
                        }
			p_info->auth_status ++;
			if( 0 == strncmp(p_info->who, MFPTP_INVALID_UID, MFPTP_UID_MAX_LEN)){
				/* 登陆失败 */
			}else{
			    /* 登陆成功 */
	                        ev_io_stop(loop, w);
                                p_info->who[15] = 0;
                                
                                if( p_info->force_login == 1){
                                    rb_remove_user(&user_tree, p_info);
                                }

				/* 插入到红黑树中*/
				if(rb_insert_user(&user_tree, p_info) == TRUE){
                                    mfptp_init_parser_info(&(p_info->mfptp_info));
                                    mfptp_register_callback(p_info, mfptp_drift_out_callback);
                                    continution_index = 0;
                                }else{
                                    /* 插入失败表示该用户记录还未被删除，查找到该用户*/
                                    p_info  = rb_search_user(&user_tree,p_info->who);

                                    /* 该用户的fd已经在新连接中从新生成, 需要从新设置*/
                                    p_info->old_sfd = p_info->sfd;
                                    x_printf(D, "以前的fd=%d, 新来的fd=%d\n",p_info->sfd,w->fd);
                                    p_info->sfd = w->fd;

                                    if(0 == p_info->mfptp_info.status.sharp_pos ){
                                        continution_index = 0;
                                    }else{
                                        continution_index = p_info->recv.get_size - p_info->mfptp_info.status.sharp_pos ;
                                    }
                                }
 
                                x_printf(D, "用户%s: 上线了\n", p_info->who);
                                topo_set_user_data(p_info->who, (void *)p_info);
                                /* 插入成功给用户回复OK */
                                if(1){
                                        printf("continution_index=%d\n", continution_index);
                                }
                                int len = mfptp_pack_login_ok(temp, continution_index, p_info);
                                x_printf(D, "验证成功 %d\n\n",len);
                                if(len>0){
                                        cache_add(&p_info->send, temp, len);
                                        ev_io *p_watcher = &(p_info->o_watcher);
		                        ev_io_stop(loop, p_watcher);
                                        p_watcher->data = p_info;
                                        ev_io_init(p_watcher, _mfptp_pass_cb, p_info->sfd, EV_WRITE);
                                        ev_io_start(loop, p_watcher);
                                }else{
                                        /* 异常处理*/
                                }

			}
		}while(0);
	}
	else if(ret ==0){/* socket has closed when read after */
		x_printf(D, "remote socket closed!socket fd: %d\n",w->fd);
		setsockopt(w->fd, SOL_SOCKET, SO_LINGER, (const char *)&g_quick_linger, sizeof(g_quick_linger));
		goto A_BROKEN;
	}
	else{
		if(errno == EAGAIN ||errno == EWOULDBLOCK){
			return;
		}
		else{/* socket is going to close when reading */
			x_printf(D, "ret :%d ,close socket fd : %d\n",ret,w->fd);
			setsockopt(w->fd, SOL_SOCKET, SO_LINGER, (const char *)&g_quick_linger, sizeof(g_quick_linger));
			goto A_BROKEN;
		}
	}
	//cache_free( &p_info->recv );
	ev_io_stop(loop,  w);

	//ev_io *p_watcher = &(p_info->o_watcher);
	//p_watcher->data = p_info;
	//ev_io_init(p_watcher, _mfptp_pass_cb, w->fd, EV_WRITE);
	//ev_io_start(loop, p_watcher);
	/* it will quickly run into  _mfptp_pass_cb() when socket is not broken */
	return;
A_BROKEN:
	cache_free( &p_info->recv );
	ev_io_stop(loop, w);
	close(w->fd);
	free(p_info);

	return;
}

void mfptp_accept_cb(struct ev_loop *loop, ev_io *w, int revents)
{
	int newfd;

	/*accept*/
	struct sockaddr_in sin;
	socklen_t addrlen = sizeof(struct sockaddr);
	while ((newfd = accept(w->fd, (struct sockaddr *)&sin, &addrlen)) < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			/* these are transient, so don't log anything. */
			continue; 
		}
		else {
			x_printf(D, "accept error.[%s]\n", strerror(errno));
			return;
		}
	}
        x_printf(D, "one connection, from %s:%d..\n",inet_ntoa(sin.sin_addr),ntohs(sin.sin_port));
	if (newfd >= MAX_LIMIT_FD){
		x_printf(D, "error : this fd (%d) too large!\n", newfd);
		send(newfd, FETCH_MAX_CNT_MSG, strlen(FETCH_MAX_CNT_MSG), 0);
		//setsockopt(newfd, SOL_SOCKET, SO_LINGER, (const char *)&g_delay_linger, sizeof(g_delay_linger));
		close(newfd);
		return;
	}//FIXME how to message admin
	x_out_time(&g_dbg_time);
	/*set status*/
	fcntl(newfd, F_SETFL, fcntl(newfd, F_GETFL) | O_NONBLOCK);

	/*set the new connect*/
	struct user_info *p_info = calloc(1, sizeof(struct user_info));
        p_info->mfptp_info.status.doptr    = 0;
        mfptp_init_parser_info(&(p_info->mfptp_info));
	if (p_info){
		cache_init( &p_info->recv );
		cache_init( &p_info->send );
		fsm_init(p_info);// by 刘金阳 @ 2015/6/11

		p_info->sfd = newfd;
                p_info->old_sfd = -1;
		p_info->port = ntohs(sin.sin_port);
                mfptp_set_user_secret_key(p_info->key);
		inet_ntop(AF_INET, &sin.sin_addr, p_info->szAddr, INET_ADDRSTRLEN);
		p_info->auth_status = NO_AUTH;
		//TODO add timeout
		ev_io *p_watcher = &(p_info->i_watcher);
		p_watcher->data = p_info;
		mfptp_register_callback(p_info, mfptp_auth_callback);
		ev_io_init(p_watcher, _mfptp_auth_cb, newfd, EV_READ);
		ev_io_start(loop, p_watcher);
	}else{
		//TODO
	}
}




static int fetch_link_work_task(WORKER_PTHREAD *p_worker, struct ev_loop *loop)
{
	CQ_ITEM *item = cq_pop( &(p_worker->qlist) );

	if (item != NULL) {
		struct user_info *p_info = item->data;
		ev_io *p_watcher = &(p_info->i_watcher);
		p_watcher->data = p_info;
		ev_io_init(p_watcher, _mfptp_recv_cb, p_info->sfd, EV_READ);
		ev_io_start(loop, p_watcher);
		return 1;
	}
	return 0;
}

#ifdef USE_PIPE
static int fetch_pipe_work_task(WORKER_PTHREAD *p_worker, struct ev_loop *loop)
{
	struct user_info *p_info = NULL;
	int n = read(p_worker->pfds[0], (char *)&p_info, sizeof(uintptr_t *));
	assert( (n == -1) || (n == sizeof(uintptr_t *)) );
	if (n == sizeof(uintptr_t *)){
		ev_io *p_watcher = &(p_info->i_watcher);
                if(MFPTP_INVALID_FD != p_info->old_sfd){
		    ev_io_stop(loop, p_watcher);
                }
		p_watcher->data = p_info;
		ev_io_init(p_watcher, _mfptp_recv_cb, p_info->sfd, EV_READ);
		ev_io_start(loop, p_watcher);
		return 0;
	}
	return 1;
}

static int fetch_weibo_pipe_work_task(WORKER_PTHREAD *p_worker, struct ev_loop *loop)
{
	struct user_info *p_info = NULL;
	int n = read(p_worker->weibo_pfds[0], (char *)&p_info, sizeof(uintptr_t *));
	if (n == sizeof(uintptr_t *)){
		ev_io *p_watcher = &(p_info->o_watcher);
		p_watcher->data = p_info;
		int active = ev_is_active(p_watcher);
                if(!active){
		        ev_io_init(p_watcher, _mfptp_send_cb, p_info->sfd, EV_WRITE);
		        ev_io_start(loop, p_watcher);
                }
		return 0;
	}
	return 1;
}

#define MAX_TASK_FETCH_DEPTH		25
void mfptp_fetch_cb(struct ev_loop *loop, ev_io *w, int revents)
{
	WORKER_PTHREAD *p_worker = (WORKER_PTHREAD *)(w->data);
	int i = 0;
	while( !!fetch_pipe_work_task(p_worker, loop) && (++i <= MAX_TASK_FETCH_DEPTH) ){};
}
void mfptp_weibo_fetch_cb(struct ev_loop *loop, ev_io *w, int revents)
{
	WORKER_PTHREAD *p_worker = (WORKER_PTHREAD *)(w->data);
	int i = 0;
	while( !!fetch_weibo_pipe_work_task(p_worker, loop) && (++i <= MAX_TASK_FETCH_DEPTH) ){};
}

void mfptp_check_cb(struct ev_loop *loop, ev_check *w, int revents)
{
	int idx = 0;
	WORKER_PTHREAD *p_worker = (WORKER_PTHREAD *)(w->data);
	while( !!fetch_link_work_task(p_worker, loop) ){ 
		idx++;
	}
	if (idx == 0){
		fetch_pipe_work_task(p_worker, loop);
	}
}
#else
void mfptp_async_cb(struct ev_loop *loop, ev_async *w, int revents)
{
	WORKER_PTHREAD *p_worker = (WORKER_PTHREAD *)(w->data);
	fetch_link_work_task(p_worker, loop);
}

void mfptp_check_cb(struct ev_loop *loop, ev_check *w, int revents)
{
	WORKER_PTHREAD *p_worker = (WORKER_PTHREAD *)(w->data);
	while( !!fetch_link_work_task(p_worker, loop) ){ }
}
#endif

////////////////////////////////////////////////////////////////////////
//*recv 拿到外面来做
//
//
//
//*
///////////////////////////////////////////////////////////////////////

static void _mfptp_recv_cb(struct ev_loop *loop, ev_io *w, int revents)
{
	struct user_info *p_info = w->data;

     int parse_ret ;
#if 1// add by liujinyang
	int ret = 0;
	char temp[MAX_DEF_LEN] = {0};
	
	ret = recv(w->fd, temp, MAX_DEF_LEN, 0);
	x_printf(D, "%d     recv size : %d\n", w->fd, ret);

    if(ret ==0){/* socket has closed when read after */
		x_printf(D, "remote socket closed!socket fd: %d\n",w->fd);
		setsockopt(w->fd, SOL_SOCKET, SO_LINGER, (const char *)&g_quick_linger, sizeof(g_quick_linger));
		goto R_BROKEN;
	}
	else if (ret < 0){
		if(errno == EAGAIN ||errno == EWOULDBLOCK){
			return;
		}
		else{/* socket is going to close when reading */
			x_printf(D, "ret :%d ,close socket fd : %d\n",ret,w->fd);
			setsockopt(w->fd, SOL_SOCKET, SO_LINGER, (const char *)&g_quick_linger, sizeof(g_quick_linger));
			goto R_BROKEN;
		}
	}

	printf("recv data:\n");
	int i = 0;
	for (i = 0; i< ret; i++){
		printf(" %x",temp[i]);	
	}
	printf("\n");
	//状态机初始化---创建一个用户的时候初始化
	//fsm_init(p_info);

    //初始化recv_buf_index---buf数组的偏移量	
	p_info->mfptp_info.status.recv_buf_index = 0;

	// 如果还有数据再重启状态机,状态不变
    while((ret  - p_info->mfptp_info.status.recv_buf_index) > 0){
        x_printf(D, "_recv_buf_index =  %d -- 读取到消息\n",p_info->mfptp_info.status.recv_buf_index);
		// start fsm
        parse_ret = mfptp_parse_fsm(p_info,temp,ret);	

        if (MFPTP_PARSE_OVER == parse_ret){//心跳包或者一次请求结束,如果buf还有数据，则再次开启状态机

			x_printf(D,"心跳包或者一次请求结束\n");

		}else if(MFPTP_PARSE_CONTINUE == parse_ret) {
			//其他返回值，抛给libev
			//break;	
			return;
		}
		else {
			x_printf(E,"状态机出错\n");
			break;
		}
	}
	return;

R_BROKEN:
	// offline 考虑续传
    x_printf(D, "用户%s: 离线了\n", p_info->who);
	ev_io_stop(loop, &p_info->i_watcher);
	ev_io_stop(loop, &p_info->o_watcher);
	return;

#else
	int ret = net_recv(&p_info->recv, w->fd, &p_info->control);
        
	x_out_time(&g_dbg_time);
	//错误检测
	if(ret > 0){
		if (p_info->control < X_DONE_OK){
			goto R_BROKEN;
		}
                x_printf(D, "_mfptp_recv_cb %d -- 读取到消息\n",ret);
		/* parse recive data */
                parse_ret=mfptp_parse(p_info);	
                if (MFPTP_PARSE_OVER == parse_ret){
                        x_printf(D, "_mfptp_recv_cb -- 读取到消息分析完毕\n");
                        mfptp_init_parser_info(&(p_info->mfptp_info));
                        mfptp_register_callback(p_info, mfptp_drift_out_callback);
                }

		if (p_info->control == X_PARSE_ERROR){
			goto R_BROKEN;
		}
	}
	else if(ret ==0){/* socket has closed when read after */
		x_printf(D, "remote socket closed!socket fd: %d\n",w->fd);
		setsockopt(w->fd, SOL_SOCKET, SO_LINGER, (const char *)&g_quick_linger, sizeof(g_quick_linger));
		goto R_BROKEN;
	}
	else{
		if(errno == EAGAIN ||errno == EWOULDBLOCK){
			return;
		}
		else{/* socket is going to close when reading */
			x_printf(D, "ret :%d ,close socket fd : %d\n",ret,w->fd);
			setsockopt(w->fd, SOL_SOCKET, SO_LINGER, (const char *)&g_quick_linger, sizeof(g_quick_linger));
			goto R_BROKEN;
		}
	}
	return;

R_BROKEN:
	switch( p_info->control ){
		case X_MALLOC_FAILED:
			x_printf(D, "NO MORE MEMORY!\n");
			break;
		case X_DATA_TOO_LARGE:
			x_printf(D, "DATA TOO LARGE!\n");
			break;
	}
	//clean rbtree
        x_printf(D, "用户%s: 离线了\n", p_info->who);
	//rb_remove_user(&user_tree, p_info->who);
	//cache_free( &p_info->recv );//TODO clean all
	//cache_free( &p_info->send );//TODO clean all
	//close(w->fd);
	ev_io_stop(loop, &p_info->i_watcher);
	ev_io_stop(loop, &p_info->o_watcher);

	//free(p_info);

#endif
	return;
}



void _mfptp_send_cb(struct ev_loop *loop, ev_io *w, int revents)
{
	x_out_time(&g_dbg_time);
	struct user_info *p_info = w->data;

	int ret = net_send(&p_info->send, w->fd, &p_info->control);
	if ( ret >= 0 ){
		if (ret > 0){
			x_printf(D, "-> no all\n");
			// TODO 数据前移
			return;
		}
		else{
			x_printf(D, "-> is all\n");
			if ( p_info->control != X_DONE_OK ){
				goto S_BROKEN;
			}
		}
	}
	cache_free( &p_info->send );
	p_info->control = X_DONE_OK;
	ev_io_stop(loop,  w);
        //fprintf(stderr,"stop stop stop stop stop\n");
	return;
S_BROKEN:
	//clean rbtree
	//rb_remove_user(&user_tree, p_info->who);
	//cache_free( &p_info->recv );//TODO clean all
	//cache_free( &p_info->send );//TODO clean all
	//close(w->fd);
	ev_io_stop(loop, &p_info->i_watcher);
	ev_io_stop(loop, &p_info->o_watcher);

	//free(p_info);
	return;
}

static void _mfptp_timeout_cb(struct ev_loop *loop, ev_timer *w, int revents)
{
}


void mfptp_update_cb(struct ev_loop *loop, ev_timer *w, int revents)
{
	int space = get_overplus_time();
	if (0 == space){
		x_printf(S, "update ...\n");

		/*reget timer*/
		space = get_overplus_time();
	}
	/*reset timer*/
	ev_timer_stop( loop, w );
	ev_timer_init( w, mfptp_update_cb, space, 0. );
	ev_timer_start( loop, w );
}

void mfptp_signal_cb (struct ev_loop *loop, ev_signal *w, int revents)
{
	x_printf(D, "get a signal\n");
	if(w->signum == SIGQUIT){
		//TODO free pool buff
		ev_signal_stop( loop, w );
		ev_break (loop, EVBREAK_ALL);
	}
}
