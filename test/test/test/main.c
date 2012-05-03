//
//  main.c
//  test
//
//  Created by Zening Qu on 4/17/12.
//  Copyright (c) 2012 REMAP/UCLA. All rights reserved.
//

#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>
#include <stdarg.h>
#include <strings.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <pthread.h>


#include <ccn/ccn.h>
#include <ccn/sync.h>
#include <ccn/uri.h>
#include <ccn/charbuf.h>
#include <ccn/digest.h>
#include <ccn/fetch.h>
#include <ccn/seqwriter.h>

#include "SyncActions.h"
#include "SyncBase.h"
#include "SyncHashCache.h"
#include "SyncNode.h"
#include "SyncPrivate.h"
#include "SyncRoot.h"
#include "SyncUtil.h"
#include "SyncTreeWorker.h"
#include "IndexSorter.h"


#include "main.h"

#define MAX_READ_LEN 1000000
#define DEFAULT_CMD_TIMEOUT 6000
#define TIMEOUT 10
#define INTEROP_BUFFER_SIZE 8192

static char* TOPO = "/ndn/broadcast/cqs/game0/scene0";
static char* PREFIX = "/ndn/ucla.edu/apps/cqs/game0/scene0";

char *
hex_string(unsigned char *s, size_t l)
{
    const char *hex_digits = "0123456789abcdef";
    char *r;
    int i;
    r = calloc(1, 1 + 2 * l);
    for (i = 0; i < l; i++) {
        r[2*i] = hex_digits[(s[i]>>4) & 0xf];
        r[1+2*i] = hex_digits[s[i] & 0xf];
    }
    return(r);
}

int hex_value(char c)
{
    if (0 == isxdigit(c)) return (-1);
    if (c >= '0' && c <= '9') return (c - '0');
    return (10+tolower(c) - 'a');
}

void PutToBuffer(char* name, char* content);
int
sync_cb(struct ccns_handle *h,
        struct ccn_charbuf *lhash,
        struct ccn_charbuf *rhash,
        struct ccn_charbuf *name)
{
    printf("sync_cb\n");
    //PutToBuffer("sync_cb", "got called");
    
    char *hexL;
    char *hexR;
    struct ccn_charbuf *uri = ccn_charbuf_create();
    ccn_uri_append(uri, name->buf, name->length, 1);
    if (lhash == NULL || lhash->length == 0) {
        hexL = strdup("none");
    } else
        hexL = hex_string(lhash->buf, lhash->length);
    if (rhash == NULL || rhash->length == 0) {
        hexR = strdup("none");
    } else
        hexR = hex_string(rhash->buf, rhash->length);
    printf("%s\n", ccn_charbuf_as_string(uri));
    
    //PutToBuffer("sync_cb is reading from repo", ccn_charbuf_as_string(uri));
    
    ReadFromRepo(ccn_charbuf_as_string(uri));
    free(hexL);
    free(hexR);
    ccn_charbuf_destroy(&uri);
    return(0);
}


int WriteSlice(struct ccn* h, char* p, char* t)
{
    
    int res;
    struct ccns_slice *slice;
    struct ccn_charbuf *prefix = ccn_charbuf_create();
    struct ccn_charbuf *roothash = NULL;
    struct ccn_charbuf *topo = ccn_charbuf_create();
    int timeout = 10*1000;
    unsigned i, j, n;
    
    ccn_name_init(prefix);
    ccn_name_init(topo);
    
    // case 'p':
    if (0 > ccn_name_from_uri(prefix, p)) 
    {
        printf("Prefix Not Right.\n");
        return -1;
    }
    // case 'r':
    char* temp = "";
    n = strlen(temp);
    if (n == 0) {
        roothash = ccn_charbuf_create();
    }
    if ((n % 2) != 0)
    {
        printf("Roothash must be even.\n");
        return -1;
    }
    roothash = ccn_charbuf_create_n(n / 2);
    for (i = 0; i < (n / 2); i++) {
        j = (hex_value(temp[2*i]) << 4) | hex_value(temp[1+2*i]);
        ccn_charbuf_append_value(roothash, j, 1);
    }
    
    // case 't':
    if (0 > ccn_name_from_uri(topo, t)) 
    {
        printf("Topo not correct.\n");
        return -1;
    }
                
    // case 'w':
    timeout = TIMEOUT;
    if (timeout < -1) 
    {
        printf("Timeout cannot be less than -1");
        return -1;
    }
    timeout *= 1000;
    
    
    
    slice = ccns_slice_create();
    ccns_slice_set_topo_prefix(slice, topo, prefix);
    
    res = ccns_write_slice(h, slice, prefix);
    
    ccns_slice_destroy(&slice);
    
    return res;
}

int WatchOverRepo(struct ccn* h, char* p, char* t)
{
    int res;
    struct ccns_slice *slice;
    struct ccns_handle *ccns;
    struct ccn_charbuf *prefix = ccn_charbuf_create();
    struct ccn_charbuf *roothash = NULL;
    struct ccn_charbuf *topo = ccn_charbuf_create();
    int timeout = 10*1000;
    unsigned i, j, n;
    
    ccn_name_init(prefix);
    ccn_name_init(topo);
    
    // case 'p':
    if (0 > ccn_name_from_uri(prefix, p)) 
    {
        printf("Prefix Not Right.\n");
        return -1;
    }
    // case 'r':
    char* temp = "";
    n = strlen(temp);
    if (n == 0) {
        roothash = ccn_charbuf_create();
    }
    if ((n % 2) != 0)
    {
        printf("Roothash must be even.\n");
        return -1;
    }
    roothash = ccn_charbuf_create_n(n / 2);
    for (i = 0; i < (n / 2); i++) {
        j = (hex_value(temp[2*i]) << 4) | hex_value(temp[1+2*i]);
        ccn_charbuf_append_value(roothash, j, 1);
    }
    
    // case 't':
    if (0 > ccn_name_from_uri(topo, t)) 
    {
        printf("Topo not correct.\n");
        return -1;
    }
    
    // case 'w':
    timeout = TIMEOUT;
    if (timeout < -1) 
    {
        printf("Timeout cannot be less than -1");
        return -1;
    }
    timeout *= 1000;
    
    
    
    
    slice = ccns_slice_create();
    ccns_slice_set_topo_prefix(slice, topo, prefix);
    
    ccns = ccns_open(h, slice, &sync_cb, roothash, NULL);
    
    // ccns_close(&ccns, NULL, NULL);
    
    ccns_slice_destroy(&slice);
    
    
    return res;
}

struct SyncTestParms {
    struct SyncBaseStruct *base;
    struct SyncRootStruct *root;
    int mode;
    int mark;
    int digest;
    int scope;
    int syncScope;
    int life;
    int sort;
    int bufs;
    int verbose;
    int resolve;
    int segmented;
    int noDup;
    int noSend;
    int blockSize;
    char *inputName;
    char *target;
    int nSplits;
    int *splits;
    struct timeval startTime;
    struct timeval stopTime;
    intmax_t fSize;
};

struct MaxN
{
    int max_n;
    int timestamp;
};

struct Transform
{
    int instanceID;
    int px;
    int py;
    int pz;
    int rx;
    int ry;
    int rz;
    int timestamp;
};

struct ContentStruct {
    struct SyncTestParms *parms;
    struct ccn_charbuf *nm;
    struct ccn_charbuf *cb;
    struct ccn *ccn;
    off_t bs;
    off_t fSize;
    FILE *file;
    //
    char* type; // MaxN, Transform
    struct MaxN * maxn;
    struct Transform * transform;
    struct ccn_charbuf * resultbuf;
    struct ccn_parsed_ContentObject *pcobuf;
    struct ccn_indexbuf *compsbuf;
    char* value;
    //
    unsigned char *segData;
    int nSegs;
    int stored;
    struct ccn_charbuf *template;
};


static int64_t
segFromInfo(struct ccn_upcall_info *info) {
	// gets the current segment number for the info
	// returns -1 if not known
	if (info == NULL) return -1;
	const unsigned char *ccnb = info->content_ccnb;
	struct ccn_indexbuf *cc = info->content_comps;
	if (cc == NULL || ccnb == NULL) {
		// go back to the interest
		cc = info->interest_comps;
		ccnb = info->interest_ccnb;
		if (cc == NULL || ccnb == NULL) return -1;
	}
	int ns = cc->n;
	if (ns > 2) {
		// assume that the segment number is the last component
		int start = cc->buf[ns - 2];
		int stop = cc->buf[ns - 1];
		if (start < stop) {
			size_t len = 0;
			const unsigned char *data = NULL;
			ccn_ref_tagged_BLOB(CCN_DTAG_Component, ccnb, start, stop, &data, &len);
			if (len > 0 && data != NULL) {
				// parse big-endian encoded number
				// TBD: where is this in the library?
				if (data[0] == CCN_MARKER_SEQNUM) {
                    int64_t n = 0;
                    int i = 0;
                    for (i = 1; i < len; i++) {
                        n = n * 256 + data[i];
                    }
                    return n;
                }
			}
		}
	}
	return -1;
}

struct SyncTestParms* SetParameter()
{
    struct SyncTestParms parmStore;
    struct SyncTestParms *parms = &parmStore;
    struct SyncBaseStruct *base = SyncNewBase(NULL, NULL, NULL);
    
    memset(parms, 0, sizeof(parmStore));
    
    parms->mode = 1;
    parms->scope = 1;
    parms->syncScope = 2;
    parms->life = 4;
    parms->bufs = 4;
    parms->blockSize = 4096;
    parms->base = base;
    parms->resolve = 1;
    
    
    return parms;
}

/*
char* Buffer(char mode, char* name, char* content)
{
    static char InteropBF[INTEROP_BUFFER_SIZE];
    static int mutex = 0;
    
    if (mode == 'w') {
        while (mutex>0);
        mutex++;
        strcat(InteropBF, name);
        strcat(InteropBF, ",");
        strcat(InteropBF, content);
        strcat(InteropBF, ",");
        char temp[INTEROP_BUFFER_SIZE];
        strcpy(temp, InteropBF);
        mutex--;
        return temp;
    }
    else if(mode == 'r')
    {
        char temp[INTEROP_BUFFER_SIZE];
        while (mutex>0);
        mutex++;
        strcpy(temp, InteropBF);
        strcpy(InteropBF, "");
        mutex--;
        return temp;
    }
}
 
 */


static char InteropBF[INTEROP_BUFFER_SIZE];
static int mutex = 0;
struct bufnode
{
    char* name;
    char* content;
    struct bufnode *next;
};

struct bufnode* bufhead = NULL;
struct bufnode* buftail = NULL;
// for the c code to put its message in buffer
void PutToBuffer(char* name, char* content)
{
    struct bufnode *temp = malloc(sizeof(struct bufnode));
    temp->name = malloc(256);
    temp->content = malloc(256);
    strcpy(temp->name,name);
    strcpy(temp->content,content);
    temp->next = NULL;
    
    if (bufhead == NULL && buftail == NULL) {
        bufhead = temp;
        buftail = temp;
    }
    else if(bufhead != NULL && buftail != NULL){
        buftail->next = temp;
        buftail = temp;
    }
    else {
        printf("Put to buffer error.\n");
    }
    
    
    /*
    while (mutex>0);
    mutex++;
    strcat(InteropBF, name);
    strcat(InteropBF, ",");
    strcat(InteropBF, content);
    strcat(InteropBF, ",");
    printf("Interop Buffer: %s\n", InteropBF);
    mutex--;
     */
    
}

// for the C# code to poll and read from C
int ReadFromBuffer(struct bufnode* temp)
{
    if (bufhead != NULL && buftail != NULL) {
        temp->name = bufhead->name;
        temp->content = bufhead->content;
        temp->next = NULL;
        if (bufhead == buftail) {
            bufhead = NULL;
            buftail = NULL;
        }
        else {
            bufhead = bufhead->next;
        }
        
        return 0;
    }
    else if(bufhead == NULL && buftail == NULL)
    {
        return 1;
    }
    else {
        return -1;
    }
    
    /*
    while (mutex>0);
    mutex++;
    strcpy(*temp, InteropBF);
    // memcpy(temp, InteropBF, INTEROP_BUFFER_SIZE);
    strcpy(InteropBF, "");
    mutex--;
    return temp;
     */
}

int testbuffer(int time)
{
    while (1) {
        char* name = "sync_cb,got called,sync_cb is reading from repo,ccnx:/ndn/ucla.edu/apps/cqs/game0/scene0/0/-401085/%FD%04%F9%Fsync_cb,got called,sync_cb is reading from repo,ccnx:/ndn/ucla.edu/apps/cqs/game0/scene0/0/-401085/%FD%04%F9%FA%B9%ED%D9/%00/%28%19%EC%B1d%2A%B7%AFGa%E6%1CF%C2i3%C7I%CDJ.o%A2%83%A5%8Eu%1B%A4%D6h%E5,ccnx:/ndn/ucla.edu/apps/cqs/game0/scene0/0/-401085/%FD%04%F9%FA%B9%ED%D9/%00/%28%19%EC%B1d%2A%B7%AFGa%E6%1CF%C2i3%C7I%CDJ.o%A2%83%A5%8Eu%1B%A4%D6h%E5,sync_cb,got called,sync_cb is reading from repo,ccnx:/ndn/ucla.edu/apps/cqs/game0/scene0/0/-401085/%FD%04%F9%FA%B9%ED%D9/%00/%28%19%EC%B1d%2A%B7%AFGa%E6%1CF%C2i3%C7I%CDJ.o%A2%83%A5%8Eu%1B%A4%D6h%E5,ccnx:/ndn/ucla.edu/apps/cqs/game0/scene0/0/-401085/%FD%04%F9%FA%B9%ED%D9/%00/%28%19%EC%B1d%2A%B7%AFGa%E6%1CF%C2i3%C7I%CDJ.o%A2%83%A5%8Eu%1B%A4%D6h%E5,sync_cb,got called,sync_cb is reading from repo,ccnx:/ndn/ucla.edu/apps/cqs/game0/scene0/0/-401085/%FD%04%F9%FA%B9%ED%D9/%00/%28%19%EC%B1d%2A%B7%AFGa%E6%1CF%C2i3%C7I%CDJ.o%A2%83%A5%8Eu%1B%A4%D6h%E5,ccnx:/ndn/ucla.edu/apps/cqs/game0/scene0/0/-401085/%FD%04%F9%FA%B9%ED%D9/%00/%28%19%EC%B1d%2A%B7%AFGa%E6%1CF%C2i3%C7I%CDJ.o%A2%83%A5%8Eu%1B%A4%D6h%E5,sync_cb,got called,sync_cb is reading from repo,ccnx:/ndn/ucla.edu/apps/cqs/game0/scene0/0/-401085/%FD%04%F9%FA%B9%ED%D9/%00/%28%19%EC%B1d%2A%B7%AFGa%E6%1CF%C2i3%C7I%CDJ.o%A2%83%A5%8Eu%1B%A4%D6h%E5,ccnx:/ndn/ucla.edu/apps/cqs/game0/scene0/0/-401085/%FD%04%F9%FA%B9%ED%D9/%00/%28%19%EC%B1d%2A%B7%AFGa%E6%1CF%C2i3%C7I%CDJ.o%A2%83%A5%8Eu%1B%A4%D6h%E5,";
        char* content = "ABCDEFGsync_cb,got called,sync_cb is reading from repo,ccnx:/ndn/ucla.edu/apps/cqs/game0/scene0/0/-401085/%FD%04%F9%FA%B9%ED%D9/%00/%28%19%EC%B1d%2A%B7%AFGa%E6%1CF%C2i3%C7I%CDJ.o%A2%83%A5%8Eu%1B%A4%D6h%E5,ccnx:/ndn/ucla.edu/apps/cqs/game0/scene0/0/-401085/%FD%04%F9%FA%B9%ED%D9/%00/%28%19%EC%B1d%2A%B7%AFGa%E6%1CF%C2i3%C7I%CDJ.o%A2%83%A5%8Eu%1B%A4%D6h%E5,sync_cb,got called,sync_cb is reading from repo,ccnx:/ndn/ucla.edu/apps/cqs/game0/scene0/0/-401085/%FD%04%F9%FA%B9%ED%D9/%00/%28%19%EC%B1d%2A%B7%AFGa%E6%1CF%C2i3%C7I%CDJ.o%A2%83%A5%8Eu%1B%A4%D6h%E5,ccnx:/ndn/ucla.edu/apps/cqs/game0/scene0/0/-401085/%FD%04%F9%FA%B9%ED%D9/%00/%28%19%EC%B1d%2A%B7%AFGa%E6%1CF%C2i3%C7I%CDJ.o%A2%83%A5%8Eu%1B%A4%D6h%E5,sync_cb,got called,sync_cb is reading from repo,ccnx:/ndn/ucla.edu/apps/cqs/game0/scene0/0/-401085/%FD%04%F9%FA%B9%ED%D9/%00/%28%19%EC%B1d%2A%B7%AFGa%E6%1CF%C2i3%C7I%CDJ.o%A2%83%A5%8Eu%1B%A4%D6h%E5,ccnx:/ndn/ucla.edu/apps/cqs/game0/scene0/0/-401085/%FD%04%F9%FA%B9%ED%D9/%00/%28%19%EC%B1d%2A%B7%AFGa%E6%1CF%C2i3%C7I%CDJ.o%A2%83%A5%8Eu%1B%A4%D6h%E5,sync_cb,got called,sync_cb is reading from repo,ccnx:/ndn/ucla.edu/apps/cqs/game0/scene0/0/-401085/%FD%04%F9%FA%B9%ED%D9/%00/%28%19%EC%B1d%2A%B7%AFGa%E6%1CF%C2i3%C7I%CDJ.o%A2%83%A5%8Eu%1B%A4%D6h%E5,ccnx:/ndn/ucla.edu/apps/cqs/game0/scene0/0/-401085/%FD%04%F9%FA%B9%ED%D9/%00/%28%19%EC%B1d%2A%B7%AFGa%E6%1CF%C2i3%C7I%CDJ.o%A2%83%A5%8Eu%1B%A4%D6h%E5,sync_cb,got called,sync_cb is reading from repo,ccnx:/ndn/ucla.edu/apps/cqs/game0/scene0/0/-401085/%FD%04%F9%FA%B9%ED%D9/%00/%28%19%EC%B1d%2A%B7%AFGa%E6%1CF%C2i3%C7I%CDJ.o%A2%83%A5%8Eu%1B%A4%D6h%E5,ccnx:/ndn/ucla.edu/apps/cqs/game0/scene0/0/-401085/%FD%04%F9%FA%B9%ED%D9/%00/%28%19%EC%B1d%2A%B7%AFGa%E6%1CF%C2i3%C7I%CDJ.o%A2%83%A5%8Eu%1B%A4%D6h%E5,sync_cb,got called,sync_cb is reading from repo,ccnx:/ndn/ucla.edu/apps/cqs/game0/scene0/0/-401085/%FD%04%F9%FA%B9%ED%D9/%00/%28%19%EC%B1d%2A%B7%AFGa%E6%1CF%C2i3%C7I%CDJ.o%A2%83%A5%8Eu%1B%A4%D6h%E5,ccnx:/ndn/ucla.edu/apps/cqs/game0/scene0/0/-401085/%FD%04%F9%FA%B9%ED%D9/%00/%28%19%EC%B1d%2A%B7%AFGa%E6%1CF%C2i3%C7I%CDJ.o%A2%83%A5%8Eu%1B%A4%D6h%E5,";
        PutToBuffer(name, content);
        sleep(time);
    }
    return 0;
}

static enum ccn_upcall_res WriteCallBack(struct ccn_closure *selfp,
                                    enum ccn_upcall_kind kind,
                                    struct ccn_upcall_info *info)
{
    printf("Write Call Back\n");
    struct ccn *h = info->h;
    
    struct ContentStruct *sfd = selfp->data;
    enum ccn_upcall_res ret = CCN_UPCALL_RESULT_OK;
    switch (kind) {
        case CCN_UPCALL_FINAL:
            printf("CCN_UPCALL_FINAL\n");
            free(selfp);
            
            break;
        case CCN_UPCALL_INTEREST: {
            printf("CCN_UPCALL_INTEREST\n");
            
            int64_t seg = segFromInfo(info);
            if (seg < 0) seg = 0;
            struct ccn_charbuf *uri = ccn_charbuf_create();
            ccn_uri_append(uri, sfd->nm->buf, sfd->nm->length, 0);
            char *str = ccn_charbuf_as_string(uri);
            ret = CCN_UPCALL_RESULT_INTEREST_CONSUMED;
            if (seg >= 0 && seg < sfd->nSegs) {
                struct ccn_charbuf *name = SyncCopyName(sfd->nm);
                struct ccn_charbuf *cb = ccn_charbuf_create();
                struct ccn_charbuf *cob = ccn_charbuf_create();
                off_t bs = sfd->bs;
                off_t pos = seg * bs;
                off_t rs = sfd->fSize - pos;
                if (rs > bs) rs = bs;
                
                ccn_charbuf_reserve(cb, rs);
                cb->length = rs;
                char *cp = ccn_charbuf_as_string(cb);
                
                int res = 0;
                //cp = sfd->type;
                strcpy(cp, sfd->value);
                
                if (res >= 0) {
                    struct ccn_signing_params sp = CCN_SIGNING_PARAMS_INIT;
                    const void *cp = NULL;
                    size_t cs = 0;
                    sp.type = CCN_CONTENT_DATA;
                    cp = (const void *) cb->buf;
                    cs = cb->length;
                    sp.template_ccnb = sfd->template;
                    
                    if (seg+1 == sfd->nSegs) sp.sp_flags |= CCN_SP_FINAL_BLOCK;
                    ccn_name_append_numeric(name, CCN_MARKER_SEQNUM, seg);
                    res |= ccn_sign_content(sfd->ccn,
                                            cob,
                                            name,
                                            &sp,
                                            cp,
                                            rs);
                    if (sfd->parms->digest) {
                        // not sure if this generates the right hash
                        struct ccn_parsed_ContentObject pcos;
                        ccn_parse_ContentObject(cob->buf, cob->length,
                                                &pcos, NULL);
                        ccn_digest_ContentObject(cob->buf, &pcos);
                        if (pcos.digest_bytes > 0)
                            res |= ccn_name_append(name, pcos.digest, pcos.digest_bytes);
                    }
                    res |= ccn_put(sfd->ccn, (const void *) cob->buf, cob->length);
                    
                    if (res < 0) {
                        printf("seg %d, %s",
                                       (int) seg,
                                       str);
                        return -1;
                    }
                    
                    // update the tracking
                    unsigned char uc = sfd->segData[seg];
                    if (uc == 0) {
                        uc++;
                        sfd->stored++;
                    } else {
                        if (sfd->parms->noDup) {
                            printf("ERROR in storeHandler, duplicate segment request, seg %d, %s\n",
                                    (int) seg, str);
                        }
                        if (uc < 255) uc++;
                    }
                    sfd->segData[seg] = uc;
                }
                
                ccn_charbuf_destroy(&name);
                ccn_charbuf_destroy(&cb);
                ccn_charbuf_destroy(&cob);
                ccn_set_run_timeout(h, 0);
            }
            ccn_charbuf_destroy(&uri);
                        
            break;
        }
        default:
            ret = CCN_UPCALL_RESULT_ERR;
            printf("CCN_UPCALL_RESULT_ERR\n");
            break;
    }
    
    return ret;

}

void WriteToRepo(char* dst, char* value)
{
    struct ccn* ccn = GetHandle();
    // set sync parameters
    struct SyncTestParms* parms = SetParameter();
    
    
    int bs = parms->blockSize;

    int res = 0;
        
    struct ccn_charbuf *cb = ccn_charbuf_create();
    struct ccn_charbuf *nm = ccn_charbuf_create();
    struct ccn_charbuf *cmd = ccn_charbuf_create();
    
    res = ccn_name_from_uri(nm, dst);
    if (res < 0) {
        printf("ccn_name_from_uri failed\n");
    }
    ccn_create_version(ccn, nm, CCN_V_NOW, 0, 0);
    
    struct ContentStruct *Data = NEW_STRUCT(1, ContentStruct);
    Data->parms = parms;
    Data->file = NULL;
    Data->bs = bs;
    Data->nm = nm;
    Data->cb = cb;
    Data->ccn = ccn;
    Data->fSize = sizeof(struct Transform);
    Data->nSegs = (Data->fSize + bs -1) / bs;
    Data->segData = NEW_ANY(Data->nSegs, unsigned char);
    
    Data->value= value;
    
    struct ccn_parsed_ContentObject pcobuf = {0};
    Data->pcobuf = &pcobuf;
    
    struct ccn_charbuf *resultbuf = NULL;
    resultbuf = ccn_charbuf_create();
    Data->resultbuf = resultbuf;
    
    {
        // make a template to govern the timestamp for the segments
        // this allows duplicate segment requests to return the same hash
        const unsigned char *vp = NULL;
        ssize_t vs;
        SyncGetComponentPtr(nm, SyncComponentCount(nm)-1, &vp, &vs);
        if (vp != NULL && vs > 0) {
            Data->template = ccn_charbuf_create();
            ccnb_element_begin(Data->template, CCN_DTAG_SignedInfo);
            ccnb_append_tagged_blob(Data->template, CCN_DTAG_Timestamp, vp, vs);
            ccnb_element_end(Data->template);
        } else 
            printf("create template failed\n");
    }

    struct ccn_charbuf *template = SyncGenInterest(NULL,
                                                   1,
                                                   4,
                                                   -1, -1, NULL);
    
    struct ccn_closure *action = NEW_STRUCT(1, ccn_closure);
    action->p = WriteCallBack;
    
    action->data = Data;
    
    // fire off a listener
    res = ccn_set_interest_filter(ccn, nm, action);
    ccn_charbuf_append_charbuf(cmd, nm);
    ccn_name_from_uri(cmd, "%C1.R.sw");
    
    // struct ccn_charbuf *uri = ccn_charbuf_create();
    // ccn_uri_append(uri, cmd->buf, cmd->length, 1);
    // printf("before nounce: %s\n", ccn_charbuf_as_string(uri));
    
    ccn_name_append_nonce(cmd);
    
    // struct ccn_charbuf *u = ccn_charbuf_create();
    // ccn_uri_append(u, cmd->buf, cmd->length, 1);
    // printf("after nounce: %s\n", ccn_charbuf_as_string(u));   
    
    res = ccn_express_interest(ccn,
                         cmd,
                         action,
                         template);
    ccn_run(ccn, -1);
    
}

// return 0 for verified
// return 1 for unverified
static unsigned char rawbuf[8801];
int VerifySig()
{
    int res;
    ssize_t size;
    struct ccn_parsed_ContentObject obj = {0};
    struct ccn_parsed_ContentObject *co = &obj;
    struct ccn_indexbuf *comps = ccn_indexbuf_create();
    struct ccn_keystore *keystore;
    char *home = getenv("HOME");
    char *keystore_suffix = "/.ccnx/.ccnx_keystore";
    char *keystore_name = NULL;

    const void *verification_pubkey = NULL;
    
    if (home == NULL) {
        printf("Unable to determine home directory for keystore\n");
        exit(1);
    }
    keystore_name = calloc(1, strlen(home) + strlen(keystore_suffix) + 1);
    
    strcat(keystore_name, home);
    strcat(keystore_name, keystore_suffix);
    
    keystore = ccn_keystore_create();
    if (0 != ccn_keystore_init(keystore, keystore_name, "Th1s1sn0t8g00dp8ssw0rd.")) {
        printf("Failed to initialize keystore\n");
        exit(1);
    }
    verification_pubkey = ccn_keystore_public_key(keystore);

//    size = strlen(rawbuf);
    size = sizeof(rawbuf);
    res = ccn_parse_ContentObject(rawbuf, size, co, comps);
    if (res < 0) {
        printf("not a ContentObject\n");
    }
    if (co->offset[CCN_PCO_B_KeyLocator] != co->offset[CCN_PCO_E_KeyLocator]) {
        struct ccn_buf_decoder decoder;
        struct ccn_buf_decoder *d =
        ccn_buf_decoder_start(&decoder,
                              rawbuf + co->offset[CCN_PCO_B_Key_Certificate_KeyName],
                              co->offset[CCN_PCO_E_Key_Certificate_KeyName] - co->offset[CCN_PCO_B_Key_Certificate_KeyName]);
        
        printf("[has KeyLocator: ");
        if (ccn_buf_match_dtag(d, CCN_DTAG_KeyName)) printf("KeyName] ");
        if (ccn_buf_match_dtag(d, CCN_DTAG_Certificate)) printf("Certificate] ");
        if (ccn_buf_match_dtag(d, CCN_DTAG_Key)) printf("Key] ");
    }
    
    res = ccn_verify_signature(rawbuf, size, co, verification_pubkey);
    
    if (res != 1) {
        printf("Signature failed to verify\n");
        strcpy(rawbuf, "");
        return -1;
    } else {
        printf("Verified\n");
        strcpy(rawbuf, "");
        return 0;
    } 
    
}

static enum ccn_upcall_res ReadCallBack(struct ccn_closure *selfp,
                                         enum ccn_upcall_kind kind,
                                         struct ccn_upcall_info *info)
{
    printf("Read Call Back\n");
    struct ContentStruct *sfd = selfp->data;
    enum ccn_upcall_res ret = CCN_UPCALL_RESULT_OK;
    
    
    
    switch (kind) {
        case CCN_UPCALL_CONTENT:
            printf("CCN_UPCALL_CONTENT\n");
            // printf("%s\n", info->content_ccnb);
            
            
            if (sfd->resultbuf != NULL) {
                sfd->resultbuf->length = 0;
                ccn_charbuf_append(sfd->resultbuf,
                                   info->content_ccnb, info->pco->offset[CCN_PCO_E]);
            }
            if (sfd->pcobuf != NULL)
                memcpy(sfd->pcobuf, info->pco, sizeof(*sfd->pcobuf));
            
            // just for debug
            unsigned char* ptr = NULL;
            size_t length;
            ptr = sfd->resultbuf->buf;
            length = sfd->resultbuf->length;
            ccn_content_get_value(ptr, length, sfd->pcobuf, &ptr, &length);
            printf("%s\n", ptr);
            
            
            // verify signature 1
            // strcpy(rawbuf, info->content_ccnb);
            // int res = VerifySig();
            // printf("*content_ccnb* Verify Sig returns %d\n", res);
            // verify signature 2
            // strcpy(rawbuf, info->pco);
            // res = VerifySig();
            // printf("*pco* Verify Sig returns %d\n", res);
            
            break;
        case CCN_UPCALL_CONTENT_BAD:
            printf("CCN_UPCALL_CONTENT_BAD\n");
            break;
        case CCN_UPCALL_INTEREST_TIMED_OUT:
            printf("CCN_UPCALL_INTEREST_TIMED_OUT\n");
            break;
        case CCN_UPCALL_FINAL:
            printf("CCN_UPCALL_FINAL\n");
        
            break;
        default:
            break;
    }
    
    ccn_set_run_timeout(info->h, 0);
    return ret;
}

struct ccn* GetHandle();
void ReadFromRepo(char* dst)
{
    
    struct ccn *ccn = GetHandle();
    
    int res = 0;
    
    struct ccn_charbuf *nm = ccn_charbuf_create();

    res = ccn_name_from_uri(nm, dst);
    if (res < 0) {
        printf("ccn_name_from_uri failed\n");
        printf("while parsing name %s\n", dst);
        printf("-- by ReadFromRepo\n");
    }
    
    
    struct ContentStruct *Data = NEW_STRUCT(1, ContentStruct);
    Data->resultbuf = ccn_charbuf_create();
    struct ccn_parsed_ContentObject pcos;
    Data->pcobuf = &pcos;
    Data->compsbuf = NULL;
    
    
    
    struct ccn_charbuf *template = SyncGenInterest(NULL,
                                                   1,
                                                   4,
                                                   -1, -1, NULL);
    
    struct ccn_closure *action = NEW_STRUCT(1, ccn_closure);
    action->p = ReadCallBack;
    
    action->data = Data;
    
    
    res = ccn_express_interest(ccn,
                               nm,
                               action,
                               template);
    ccn_run(ccn, -1);
    
    unsigned char* ptr = NULL;
    size_t length;
    ptr = Data->resultbuf->buf;
    length = Data->resultbuf->length;
    ccn_content_get_value(ptr, length, Data->pcobuf, &ptr, &length);
    
    struct ccn_charbuf *uri = ccn_charbuf_create();
    ccn_uri_append(uri, nm->buf, nm->length, 1);
    printf("%s\n", ccn_charbuf_as_string(uri));
    printf("%s\n", ptr);
    
    PutToBuffer(ccn_charbuf_as_string(uri), ptr);
        
    // printf("Interop Buffer: %s\n", ReadFromBuffer());
    
    
    ccn_destroy(&ccn);
    return;
    
}


struct ccn* GetHandle()
{
    struct ccn *ccn = NULL;
    ccn = ccn_create();
    if (ccn_connect(ccn, NULL) == -1) {
        printf("could not connect to ccnd.\n");
    }
    return ccn;
}

int main(int argc, const char * argv[])
{
    struct ccn *h = GetHandle();
    
    // Write Slice to Repo
    int res = WriteSlice(h, PREFIX, TOPO);
    // printf("%d\n", res);
    
    WatchOverRepo(h, PREFIX, TOPO);
    

    // Write to repo
   // WriteToRepo(h, PREFIX, "2,34,21,22");
    // ccn_run(h, 100);
    
    ccn_run(h, -1);
    // Read from repo
    // printf("%s", ReadFromRepo(h, PREFIX));
}

