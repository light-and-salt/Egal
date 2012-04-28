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


int
sync_cb(struct ccns_handle *h,
        struct ccn_charbuf *lhash,
        struct ccn_charbuf *rhash,
        struct ccn_charbuf *name)
{
    printf("sync_cb\n");
    
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
    printf("%s %s %s\n", ccn_charbuf_as_string(uri), hexL, hexR);
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

void WriteToRepo(struct ccn* ccn, char* dst, char* value)
{
    // set sync parameters
    struct SyncTestParms* parms = SetParameter();
    
    
    int bs = parms->blockSize;

    int res = 0;
        
    struct ccn_charbuf *cb = ccn_charbuf_create();
    struct ccn_charbuf *nm = ccn_charbuf_create();
    struct ccn_charbuf *cmd = ccn_charbuf_create();
    
    res = ccn_name_from_uri(nm, dst);
    if (res < 0) {
        printf("ccn_name_from_uri failed");
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
    ccn_name_append_nonce(cmd);
    
    res = ccn_express_interest(ccn,
                         cmd,
                         action,
                         template);
    
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

char* ReadFromRepo(char* dst)
{
    
    
    int res = 0;
    struct ccn *ccn = NULL;
    ccn = ccn_create();
    if (ccn_connect(ccn, NULL) == -1) {
        printf("could not connect to ccnd.\n");
    }
    
    struct ccn_charbuf *nm = ccn_charbuf_create();

    res = ccn_name_from_uri(nm, dst);
    if (res < 0) {
        printf("ccn_name_from_uri failed");
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
    
    
    

    // just for debug
    unsigned char* ptr = NULL;
    size_t length;
    ptr = Data->resultbuf->buf;
    length = Data->resultbuf->length;
    ccn_content_get_value(ptr, length, Data->pcobuf, &ptr, &length);
    // printf("%s\n", ptr);
    
    return ptr;
    
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
    WriteToRepo(h, PREFIX, "9876543210123456789");
    ccn_run(h, -1);
    
    // Read from repo
    // printf("%s", ReadFromRepo(PREFIX));
}

