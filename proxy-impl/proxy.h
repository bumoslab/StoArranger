/*
 * SSLsplit - transparent and scalable SSL/TLS interception
 * Copyright (c) 2009-2014, Daniel Roethlisberger <daniel@roe.ch>
 * All rights reserved.
 * http://www.roe.ch/SSLsplit
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice unmodified, this list of conditions, and the following
 *    disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef PROXY_H
#define PROXY_H

#include "opts.h"
#include "attrib.h"
#include <pthread.h>

#define PXY_CONN_CTX_INIT_SIZE 20
typedef struct proxy_ctx proxy_ctx_t;
struct pxy_conn_ctx;
typedef struct pxy_conn_ctx pxy_conn_ctx_t;

typedef struct pxy_conn_ctx_wrapper{
	struct pxy_conn_ctx* ctx;
//	struct pxy_conn_ctx_wrapper* prev;
	struct pxy_conn_ctx_wrapper* next;
}pxy_wrapper_t;

typedef struct gbuff{
	pthread_mutex_t lock;
#if 0
	struct pxy_conn_ctx** ctx_list;
#endif
	struct pxy_conn_ctx_wrapper* ctx_list_head;
	struct pxy_conn_ctx_wrapper* ctx_list_end;
	size_t size;
}gbuff_t;
gbuff_t* global_ctx_buff;

void global_list_append(struct pxy_conn_ctx* ctx);
struct pxy_conn_ctx* global_list_remove();
proxy_ctx_t * proxy_new(opts_t *) NONNULL(1) MALLOC;
void proxy_run(proxy_ctx_t *) NONNULL(1);
void proxy_free(proxy_ctx_t *) NONNULL(1);
void reqbuff_fini();
void reqbuff_init();
void reqbuff_reinit();
void pxy_myconn_setup(pxy_conn_ctx_t*);

#endif /* !PROXY_H */

/* vim: set noet ft=c: */
