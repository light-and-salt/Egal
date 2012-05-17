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

static char* TOPO = "ccnx:/ndn/broadcast/cqs/game0/scene0";
static char* PREFIX = "ccnx:/ndn/ucla.edu/apps/cqs/game0/scene0";

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

struct StateStruct {
    struct SyncTestParms *parms;
    struct ccn_charbuf *nm;
    struct ccn_charbuf *cb;
    struct ccn *ccn;
    off_t bs;
    off_t fSize;
    FILE *file;
    //
    struct ccn_closure * closure;
    struct ccn_charbuf * resultbuf;
    struct ccn_parsed_ContentObject *pcobuf;
    struct ccn_indexbuf *compsbuf;
    char* value;
    int valuesize;
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
}

// for the C# code to poll and read from C
struct bufnode* ReadFromBuffer()
{
    if (bufhead != NULL && buftail != NULL) {
        // temp->name = bufhead->name;
        // temp->content = bufhead->content;
        // temp->next = NULL;
        struct bufnode* temp = bufhead;
        if (bufhead == buftail) {
            bufhead = NULL;
            buftail = NULL;
        }
        else {
            bufhead = bufhead->next;
        }
        
        return temp;
    }
    else if(bufhead == NULL && buftail == NULL)
    {
        return NULL;
    }
    else {
        return NULL;
    }
}

int testbuffer(int time)
{
    while (1) {
        char* name = "";
        char* content = "";
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


static intmax_t last_time = -1;
static intmax_t max_time = 68719476736; // this is (2^48-1)/4096
static struct ccn_charbuf * last_name = NULL;
static struct ccn_charbuf * max_name = NULL;

// reads byte array (big endian) and length
// returns time stamp in seconds
intmax_t GetTimeStamp(unsigned char* data, size_t length)
{
    if(length!=6)
    {
        return -1;
    }
    
    int i = 0;
    intmax_t result = ((uint64_t)data[0] << 40) |
    ((uint64_t)data[1] << 32) |
    ((uint64_t)data[2] << 24) |
    ((uint64_t)data[3] << 16) |
    ((uint64_t)data[4] << 8)  |
    ((uint64_t)data[5] << 0);
    intmax_t time = result/4096;
    
    
    // printf("%d\n", time);
    return time;
    
}

int UpdateFencePoints(intmax_t last_time, struct ccn_upcall_info *info )
{
    struct ccn_indexbuf *comps;
    int matched_comps = 0;
    const unsigned char *ccnb = NULL;
    size_t ccnb_size = 0;
    struct ccn_charbuf * comp = NULL;
    
    ccnb = info->content_ccnb;
    ccnb_size = info->pco->offset[CCN_PCO_E];
    comps = info->content_comps;
    matched_comps = info->pi->prefix_comps;
    
    // last timestamp
    comp = ccn_charbuf_create();
    ccn_name_init(comp);
    if (matched_comps + 1 == comps->n) {
        /* Reconstruct the implicit content digest component */
        ccn_digest_ContentObject(ccnb, info->pco);
        ccn_name_append(comp, info->pco->digest, info->pco->digest_bytes);
    }
    else {
        ccn_name_append_components(comp, ccnb,
                                   comps->buf[matched_comps],
                                   comps->buf[matched_comps + 1]);
    }
    last_name = comp;
    
    // max timestamp
}

static enum ccn_upcall_res AskCallBack(struct ccn_closure *selfp,
                                        enum ccn_upcall_kind kind,
                                        struct ccn_upcall_info *info)
{
    printf("Ask Call back\n");
    struct StateStruct *sfd = selfp->data;
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
            // if (sfd->pcobuf != NULL)
            //    memcpy(sfd->pcobuf, info->pco, sizeof(*sfd->pcobuf));
            
            // print content
            unsigned char* ptr = NULL;
            size_t length;
            ptr = sfd->resultbuf->buf;
            length = sfd->resultbuf->length;
            ccn_content_get_value(ptr, length, info->pco, &ptr, &length);
                        
            size_t begin = info->pco->offset[CCN_PCO_B_Timestamp];
            size_t end = info->pco->offset[CCN_PCO_E_Timestamp];
            
            size_t timelength = end - begin + 1;
            unsigned char* timestamp = malloc(timelength);
            
            // parse timestamp
            ccn_ref_tagged_BLOB(CCN_DTAG_Timestamp, 
                                info->content_ccnb, 
                                begin,
                                end,
                                &timestamp, 
                                &timelength);

            intmax_t ts = GetTimeStamp(timestamp, timelength);
            
            UpdateFencePoints(ts, info);
            printf("%s <%d>\n", ptr, ts);
            
            break;
        case CCN_UPCALL_CONTENT_BAD:
            printf("CCN_UPCALL_CONTENT_BAD\n");
            break;
        case CCN_UPCALL_INTEREST_TIMED_OUT:
            printf("CCN_UPCALL_INTEREST_TIMED_OUT\n");
            break;
        case CCN_UPCALL_FINAL:
            printf("CCN_UPCALL_FINAL\n");
            free(sfd);
            free(selfp);
            break;
        default:
            break;
    }
    
     // ccn_set_run_timeout(info->h, 0);
    
    return ret;
}


struct ccn_charbuf* GenMyTemplate(struct ccn* h)
{
    int ans;
    struct ccn_charbuf *templ = NULL;
    int i;
    // struct ccn_traversal *data = get_my_data(selfp);
    
    templ = ccn_charbuf_create();
    ccn_charbuf_append_tt(templ, CCN_DTAG_Interest, CCN_DTAG);
    ccn_charbuf_append_tt(templ, CCN_DTAG_Name, CCN_DTAG);
    ccn_charbuf_append_closer(templ); /* </Name> */
    
    if(last_name!=NULL)
    {
        printf("Generating new fence points.\n");
        
        ccn_charbuf_append_tt(templ, CCN_DTAG_Exclude, CCN_DTAG);
        
        // EXCLUDE_LOW
        ccn_charbuf_append_tt(templ, CCN_DTAG_Any, CCN_DTAG);
        ccn_charbuf_append_closer(templ);
        
        // First Timestamp
        // ccn_create_version(h, templ, CCN_V_REPLACE, 0, 0*1000);
        // ccn_charbuf_append_tt(templ, CCN_DTAG_Component, CCN_DTAG);
        // ccnb_append_timestamp_blob(templ, CCN_MARKER_VERSION, last_time, last_time*1000000000);
        // ccn_charbuf_append_closer(templ); /* </Component> */
        ccn_charbuf_append(templ, last_name->buf + 1, last_name->length - 2);
        
        /*
        // Second Timestamp
        // ccn_create_version(h, templ, CCN_V_NESTOK, 1, 1*1000000000);
        ccn_charbuf_append_tt(templ, CCN_DTAG_Component, CCN_DTAG);
        ccnb_append_timestamp_blob(templ, CCN_MARKER_VERSION, max_time, max_time*1000000000);
        ccn_charbuf_append_closer(templ);
        // and what is max_time? the end of time? ... &&& ~~~ @@@ *** %%% ### !!!
        
        // EXCLUDE_HIGH
        ccn_charbuf_append_tt(templ, CCN_DTAG_Any, CCN_DTAG);
        ccn_charbuf_append_closer(templ);
        */
                
        ccn_charbuf_append_closer(templ); /* </Exclude> */
    }

    ccnb_tagged_putf(templ, CCN_DTAG_ChildSelector, "%d", 1);

    ccnb_tagged_putf(templ, CCN_DTAG_Scope, "%d", 2);
    
    ccn_charbuf_append_closer(templ); /* </Interest> */
    return templ;
}

void AskForState(struct ccn* ccn, char* name, int timeout)
{
    // struct ccn* ccn = GetHandle();
    
    // set sync parameters
    struct SyncTestParms* parms = SetParameter();
        
    int res = 0;
    
    struct ccn_charbuf *nm = ccn_charbuf_create();
        
    // for this function, dst should be like
    // ccnx:/ndn/ucla.edu/apps/cqs/car/scene0/objID/state
    res = ccn_name_from_uri(nm, name);
    if (res < 0) {
        printf("ccn_name_from_uri failed\n");
    }
    
    struct StateStruct *State = NEW_STRUCT(1, StateStruct);
    State->nm = nm;
    State->ccn = ccn;
    State->resultbuf = ccn_charbuf_create();
    
    struct ccn_parsed_ContentObject pcobuf = {0};
    State->pcobuf = &pcobuf;
    
    struct ccn_charbuf *template = GenMyTemplate(ccn);
    
    struct ccn_closure *action = NEW_STRUCT(1, ccn_closure);
    action->p = AskCallBack;
    
    action->data = State;
    
    
    res = ccn_express_interest(ccn,
                               nm,
                               action,
                               template);
    //ccn_run(ccn, timeout);
    //ccn_destroy(&ccn);
    
}


struct StateBuffer
{
    char* state;
    int statelens;
};

static struct StateBuffer* PtrToStateBuffer = NULL;
int WriteToStateBuffer(char* state, int statelens)
{
    // this is for C# to write to the State Buffer
    if (PtrToStateBuffer == NULL) {
        PtrToStateBuffer = malloc(sizeof(struct StateBuffer));
        PtrToStateBuffer->state = malloc(statelens);
        PtrToStateBuffer->statelens = malloc(sizeof(int));
        PtrToStateBuffer->statelens = statelens;
            }
    strcpy(PtrToStateBuffer->state, state);
}

char* ReadStateBuffer()
{
    return PtrToStateBuffer->state;
}

int ReadStateLens()
{
    return PtrToStateBuffer->statelens;
}

static enum ccn_upcall_res PublishState(struct ccn_closure *selfp,
                                        enum ccn_upcall_kind kind,
                                        struct ccn_upcall_info *info)
{
    printf("Publishing state...\n");
    struct ccn *h = info->h;
    
    struct StateStruct *sfd = selfp->data;
    enum ccn_upcall_res ret = CCN_UPCALL_RESULT_OK;
    switch (kind) {
        case CCN_UPCALL_FINAL:
            printf("CCN_UPCALL_FINAL\n");
            // free(selfp);
            
            break;
        case CCN_UPCALL_INTEREST: {
            printf("CCN_UPCALL_INTEREST\n");
            
            struct ccn_charbuf *uri = ccn_charbuf_create();
            ccn_uri_append(uri, sfd->nm->buf, sfd->nm->length, 0);
            char *str = ccn_charbuf_as_string(uri);
            ret = CCN_UPCALL_RESULT_INTEREST_CONSUMED; // maybe not like this
            
            
            struct ccn_charbuf *name = SyncCopyName(sfd->nm); // need to do sth to the name 
            ccn_create_version(h, name, CCN_V_NOW, 0, 0); // very good, haha -- CQ
            
            struct ccn_charbuf *cb = ccn_charbuf_create(); // cb is content buffer
            struct ccn_charbuf *cob = ccn_charbuf_create();
            
            int rs = ReadStateLens();
            ccn_charbuf_reserve(cb, rs);
            cb->length = rs;
            char *ptr = ccn_charbuf_as_string(cb);
            
            if (PtrToStateBuffer == NULL) {
                return -1;
            }                    
            strcpy(ptr, PtrToStateBuffer->state);
            
            // start signing ...
            struct ccn_signing_params sp = CCN_SIGNING_PARAMS_INIT;
            const void *cp = NULL;
            size_t cs = 0;
            sp.type = CCN_CONTENT_DATA;
            cp = (const void *) cb->buf;
            cs = cb->length;
            
            // I think I am going to need a different template
            // since timestamp is in the template
            sp.template_ccnb = SyncGenInterest(NULL,
                                               2,
                                               4,
                                               -1, -1, NULL);

            
            sp.sp_flags |= CCN_SP_FINAL_BLOCK;
            ccn_name_append_numeric(name, CCN_MARKER_SEQNUM, 0);
            ccn_sign_content(sfd->ccn,
                             cob,
                             name,
                             &sp,
                             cp,
                             rs);
            // is hash required?
            // not sure... just leave it here
            
            if (1) {
                // not sure if this generates the right hash
                struct ccn_parsed_ContentObject pcos;
                ccn_parse_ContentObject(cob->buf, cob->length,
                                        &pcos, NULL);
                ccn_digest_ContentObject(cob->buf, &pcos);
                if (pcos.digest_bytes > 0)
                    ccn_name_append(name, pcos.digest, pcos.digest_bytes);
            }
            
            
            ccn_put(sfd->ccn, (const void *) cob->buf, cob->length);
            
            
            ccn_charbuf_destroy(&name);
            ccn_charbuf_destroy(&cb);
            ccn_charbuf_destroy(&cob);
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

void RegisterInterestFilter(struct ccn* ccn, char* name)
{
    int res = 0;
    struct ccn_charbuf *nm = ccn_charbuf_create();
    res = ccn_name_from_uri(nm, name);
    if (res < 0) {
        printf("ccn_name_from_uri failed\n");
    }
    // ccn_create_version(ccn, nm, CCN_V_NOW, 0, 0);
    
    
    struct StateStruct *State = NEW_STRUCT(1, StateStruct);
    State->ccn = ccn;
    State->nm = nm;

    struct ccn_closure *action = NEW_STRUCT(1, ccn_closure);
    action->p = PublishState;
    action->data = State;

    ccn_set_interest_filter(ccn, nm, action);
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


static enum ccn_upcall_res TestCallBack(struct ccn_closure *selfp,
                                       enum ccn_upcall_kind kind,
                                       struct ccn_upcall_info *info)
{
    struct StateStruct *sfd = selfp->data;
    enum ccn_upcall_res ret = CCN_UPCALL_RESULT_OK;
    
    switch (kind) {
        case CCN_UPCALL_CONTENT:
            printf("CCN_UPCALL_CONTENT\n");
               
            if (sfd->resultbuf != NULL) {
                sfd->resultbuf->length = 0;
                ccn_charbuf_append(sfd->resultbuf,
                                   info->content_ccnb, info->pco->offset[CCN_PCO_E]);
            }
            
            // print content
            unsigned char* ptr = NULL;
            size_t length;
            ptr = sfd->resultbuf->buf;
            length = sfd->resultbuf->length;
            ccn_content_get_value(ptr, length, info->pco, &ptr, &length);
            
            size_t begin = info->pco->offset[CCN_PCO_B_Timestamp];
            size_t end = info->pco->offset[CCN_PCO_E_Timestamp];
            
            size_t timelength = end - begin + 1;
            unsigned char* timestamp = malloc(timelength);
            
            // parse timestamp
            ccn_ref_tagged_BLOB(CCN_DTAG_Timestamp, 
                                info->content_ccnb, 
                                begin,
                                end,
                                &timestamp, 
                                &timelength);
            
            intmax_t ts = GetTimeStamp(timestamp, timelength);
            
            UpdateFencePoints(ts, info);
            printf("%s <%d>\n", ptr, ts);
            
            
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
    return ret;
}
void TestHandle(struct ccn * ccn, char* name)
{
    struct ccn_charbuf *nm = ccn_charbuf_create();
    ccn_name_from_uri(nm, name);

    struct StateStruct *State = NEW_STRUCT(1, StateStruct);
    State->nm = nm;
    State->ccn = ccn;
    State->resultbuf = ccn_charbuf_create();
    struct ccn_parsed_ContentObject pcobuf = {0};
    State->pcobuf = &pcobuf;
    struct ccn_closure *action = NEW_STRUCT(1, ccn_closure);
    action->p = TestCallBack;
    action->data = State;
    
    struct ccn_charbuf *template = GenMyTemplate(ccn);
    
    ccn_express_interest(ccn,
                         nm,
                         action,
                         template);
}

int main(int argc, const char * argv[])
{
    
    // Write Slice to Repo
    // int res = WriteSlice(h, PREFIX, TOPO);
    // printf("%d\n", res);
    
    // WatchOverRepo(h, PREFIX, TOPO);
    

    // Write to repo
    // WriteToRepo(h, PREFIX, "2,34,21,22");
    // ccn_run(h, 100);
    
    // this shall be called from C#
    // here is just for debug
    WriteToStateBuffer("zening", 10);
    
    char* other = "ccnx:/ndn/ucla.edu/apps/cqs/car/scene0/lioncub/state";
    char* me = "ccnx:/ndn/ucla.edu/apps/cqs/car/scene0/zening/state";
    struct ccn *h = GetHandle();
    RegisterInterestFilter(h, me);
    
    while (1) {
        //struct ccn *hh = GetHandle();
        AskForState(h, me, 1000);
        ccn_run(h, 1000);
        //ccn_run(hh, 1000);

    }
    
    
    /*
    struct ccn *h = GetHandle();
    while (1) {
        TestHandle(h, other);
        ccn_run(h, 1000);
    }
    */               
    
    // Read from repo
    // printf("%s", ReadFromRepo(h, PREFIX));
}

