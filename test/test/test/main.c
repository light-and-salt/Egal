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

void
usage(char *prog)
{
    fprintf(stderr,
            "%s [-t topo-uri] [-p prefix-uri] [-r roothash-hex] [-w timeout-secs]\n"
            "   topo-uri and prefix-uri must be CCNx URIs.\n"
            "   roothash-hex must be an even number of hex digits "
            "representing a valid starting root hash.\n"
            "   timeout-secs is the time, in seconds that the program "
            "should monitor sync activity.\n"
            "       or -1 to run until interrupted.\n", prog);
    exit(1);
}

int
sync_cb(struct ccns_handle *h,
        struct ccn_charbuf *lhash,
        struct ccn_charbuf *rhash,
        struct ccn_charbuf *name)
{
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


void WriteSlice()
{
    int opt;
    int res;
    struct ccn *h;
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
    if (0 > ccn_name_from_uri(prefix, PREFIX)) 
        printf("Prefix Not Right.\n");
    
    // case 'r':
    char* temp = "00";
    n = strlen(temp);
    if (n == 0) {
        roothash = ccn_charbuf_create();
    }
    if ((n % 2) != 0)
        printf("Roothash must be even.\n");
    roothash = ccn_charbuf_create_n(n / 2);
    for (i = 0; i < (n / 2); i++) {
        j = (hex_value(temp[2*i]) << 4) | hex_value(temp[1+2*i]);
        ccn_charbuf_append_value(roothash, j, 1);
    }
    
    // case 't':
    if (0 > ccn_name_from_uri(topo, TOPO)) 
        printf("Topo not correct.\n");
                
    // case 'w':
    timeout = TIMEOUT;
    if (timeout < -1) 
        printf("Timeout cannot be less than -1");
    timeout *= 1000;
    
    
    
    
    h = ccn_create();
    res = ccn_connect(h, NULL);
    slice = ccns_slice_create();
    ccns_slice_set_topo_prefix(slice, topo, prefix);
    
    ccns_write_slice(h, slice, prefix);
    
    ccns_slice_destroy(&slice);
    ccn_destroy(&h);
    

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
    int MaxN;
    int instanceID;
    int px;
    int py;
    int pz;
    int rx;
    int ry;
    int rz;
    //
    unsigned char *segData;
    int nSegs;
    int stored;
    struct ccn_charbuf *template;
};

/*
static enum ccn_upcall_res
storeHandler(struct ccn_closure *selfp,
             enum ccn_upcall_kind kind,
             struct ccn_upcall_info *info) {
    struct storeFileStruct *sfd = selfp->data;
    enum ccn_upcall_res ret = CCN_UPCALL_RESULT_OK;
    switch (kind) {
        case CCN_UPCALL_FINAL:
            free(selfp);
            break;
        case CCN_UPCALL_INTEREST: {
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
                
                // fill in the contents
                int res = fseeko(sfd->file, pos, SEEK_SET);
                if (res >= 0) {
                    res = fread(cp, rs, 1, sfd->file);
                    if (res < 0) {
                        char *eMess = strerror(errno);
                        fprintf(stderr, "ERROR in fread, %s, seg %d, %s\n",
                                eMess, (int) seg, str);
                    }
                } else {
                    char *eMess = strerror(errno);
                    fprintf(stderr, "ERROR in fseeko, %s, seg %d, %s\n",
                            eMess, (int) seg, str);
                }
                
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
                        return noteErr("seg %d, %s",
                                       (int) seg,
                                       str);
                    } else if (sfd->parms->verbose) {
                        if (sfd->parms->mark) putMark(stdout);
                        struct ccn_charbuf *nameUri = ccn_charbuf_create();
                        ccn_uri_append(nameUri, name->buf, name->length, 0);
                        char *nameStr = ccn_charbuf_as_string(nameUri);
                        fprintf(stdout, "put seg %d, %s\n",
                                (int) seg,
                                nameStr);
                        ccn_charbuf_destroy(&nameUri);
                    }
                    
                    // update the tracking
                    unsigned char uc = sfd->segData[seg];
                    if (uc == 0) {
                        uc++;
                        sfd->stored++;
                    } else {
                        if (sfd->parms->noDup) {
                            fprintf(stderr,
                                    "ERROR in storeHandler, duplicate segment request, seg %d, %s\n",
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
            break;
    }
    return ret;
}

*/

/*
static int
putContent(char *src) {
    // stores the src file to the dst file (in the repo)
    
    char *dst = PREFIX;
    
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
    parms->segmented = 1;
    
    
    struct stat myStat;
    int res = stat(src, &myStat);
    if (res < 0) {
        perror("putFile, stat failed");
        return -1;
    }
    off_t fSize = myStat.st_size;
    
    if (fSize == 0) {
        return noteErr("putFile, stat failed, empty src");
    }
    FILE *file = fopen(src, "r");
    if (file == NULL) {
        perror("putFile, fopen failed");
        return -1;
    }
    
    
    int res = 0;
    struct ccn *ccn = NULL;
    ccn = ccn_create();
    if (ccn_connect(ccn, NULL) == -1) {
        return noteErr("putFile, could not connect to ccnd");
    }
    struct ccn_charbuf *cb = ccn_charbuf_create();
    struct ccn_charbuf *nm = ccn_charbuf_create();
    struct ccn_charbuf *cmd = ccn_charbuf_create();
    int bs = parms->blockSize;
    
    res = ccn_name_from_uri(nm, dst);
    if (res < 0) {
        return noteErr("putFile, ccn_name_from_uri failed");
    }
    ccn_create_version(ccn, nm, CCN_V_NOW, 0, 0);
    
    struct ContentStruct *sfData = NEW_STRUCT(1, ContentStruct);
    sfData->parms = parms;
    sfData->file = NULL;
    sfData->bs = bs;
    sfData->nm = nm;
    sfData->cb = cb;
    sfData->ccn = ccn;
    sfData->fSize = 0;
    sfData->nSegs = (sfData->fSize + bs -1) / bs;
    sfData->segData = NEW_ANY(sfData->nSegs, unsigned char);
    
    {
        // make a template to govern the timestamp for the segments
        // this allows duplicate segment requests to return the same hash
        const unsigned char *vp = NULL;
        ssize_t vs;
        SyncGetComponentPtr(nm, SyncComponentCount(nm)-1, &vp, &vs);
        if (vp != NULL && vs > 0) {
            sfData->template = ccn_charbuf_create();
            ccnb_element_begin(sfData->template, CCN_DTAG_SignedInfo);
            ccnb_append_tagged_blob(sfData->template, CCN_DTAG_Timestamp, vp, vs);
            ccnb_element_end(sfData->template);
        } else return noteErr("putFile, create store template failed");
    }
    
    struct ccn_charbuf *template = SyncGenInterest(NULL,
                                                   parms->scope,
                                                   parms->life,
                                                   -1, -1, NULL);
    struct ccn_closure *action = NEW_STRUCT(1, ccn_closure);
    action->p = storeHandler;
    action->data = sfData;
    
    parms->fSize = fSize;
    
    // fire off a listener
    res = ccn_set_interest_filter(ccn, nm, action);
    if (res < 0) {
        return noteErr("putFile, ccn_set_interest_filter failed");
    }
    ccn_run(ccn, 40);
    // initiate the write
    // construct the store request and "send" it as an interest
    ccn_charbuf_append_charbuf(cmd, nm);
    ccn_name_from_uri(cmd, "%C1.R.sw");
    ccn_name_append_nonce(cmd);
    
    if (parms->verbose && parms->mode != 0) {
        struct ccn_charbuf *uri = SyncUriForName(nm);
        if (parms->mark) putMark(stdout);
        fprintf(stdout, "put init, %s\n",
                ccn_charbuf_as_string(uri));
        ccn_charbuf_destroy(&uri);
    }
    gettimeofday(&parms->startTime, 0);
    ccn_get(ccn, cmd, template, DEFAULT_CMD_TIMEOUT, NULL, NULL, NULL, 0);
    ccn_charbuf_destroy(&template);
    if (res < 0) {
        return noteErr("putFile, ccn_get failed");
    }
    
    // wait for completion
    while (sfData->stored < sfData->nSegs) {
        ccn_run(ccn, 2);
    }
    
    gettimeofday(&parms->stopTime, 0);
    
    res = ccn_set_interest_filter(ccn, nm, NULL);
    if (res < 0) {
        return noteErr("putFile, ccn_set_interest_filter failed (removal)");
    }
    ccn_run(ccn, 40);
    
    ccn_charbuf_destroy(&sfData->template);
    free(sfData->segData);
    free(sfData);
    ccn_destroy(&ccn);
    fclose(file);
    ccn_charbuf_destroy(&cb);
    ccn_charbuf_destroy(&cmd);
    ccn_charbuf_destroy(&nm);
    
    formatStats(parms);
    
    if (res > 0) res = 0;
    return res;
}
*/

struct SimpleStruct
{
    int x;
    int y;
    int z;
};

static enum ccn_upcall_res callback(struct ccn_closure *selfp,
                                    enum ccn_upcall_kind kind,
                                    struct ccn_upcall_info *info)
{
    printf("Call Back!\n");
    
    struct SimpleStruct *sfd = selfp->data;
    enum ccn_upcall_res ret = CCN_UPCALL_RESULT_OK;
    switch (kind) {
        case CCN_UPCALL_FINAL:
            printf("CCN_UPCALL_FINAL\n");
            free(selfp);
            break;
        case CCN_UPCALL_INTEREST: {
            printf("CCN_UPCALL_INTEREST\n");
            /*
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
                
                // fill in the contents
                int res = fseeko(sfd->file, pos, SEEK_SET);
                if (res >= 0) {
                    res = fread(cp, rs, 1, sfd->file);
                    if (res < 0) {
                        char *eMess = strerror(errno);
                        fprintf(stderr, "ERROR in fread, %s, seg %d, %s\n",
                                eMess, (int) seg, str);
                    }
                } else {
                    char *eMess = strerror(errno);
                    fprintf(stderr, "ERROR in fseeko, %s, seg %d, %s\n",
                            eMess, (int) seg, str);
                }
                
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
                        return noteErr("seg %d, %s",
                                       (int) seg,
                                       str);
                    } else if (sfd->parms->verbose) {
                        if (sfd->parms->mark) putMark(stdout);
                        struct ccn_charbuf *nameUri = ccn_charbuf_create();
                        ccn_uri_append(nameUri, name->buf, name->length, 0);
                        char *nameStr = ccn_charbuf_as_string(nameUri);
                        fprintf(stdout, "put seg %d, %s\n",
                                (int) seg,
                                nameStr);
                        ccn_charbuf_destroy(&nameUri);
                    }
                    
                    // update the tracking
                    unsigned char uc = sfd->segData[seg];
                    if (uc == 0) {
                        uc++;
                        sfd->stored++;
                    } else {
                        if (sfd->parms->noDup) {
                            fprintf(stderr,
                                    "ERROR in storeHandler, duplicate segment request, seg %d, %s\n",
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
             */
            break;
        }
        default:
            ret = CCN_UPCALL_RESULT_ERR;
            printf("CCN_UPCALL_RESULT_ERR\n");
            break;
    }
    return ret;

}

void ExpressInterest()
{
    char* dst = PREFIX;
    int res = 0;
    struct ccn *ccn = NULL;
    ccn = ccn_create();
    if (ccn_connect(ccn, NULL) == -1) {
        printf("could not connect to ccnd.\n");
    }
    
    struct ccn_charbuf *cb = ccn_charbuf_create();
    struct ccn_charbuf *nm = ccn_charbuf_create();
    struct ccn_charbuf *cmd = ccn_charbuf_create();
    
    res = ccn_name_from_uri(nm, dst);
    if (res < 0) {
        printf("ccn_name_from_uri failed");
    }
    ccn_create_version(ccn, nm, CCN_V_NOW, 0, 0);
    
    struct ccn_charbuf *template = SyncGenInterest(NULL,
                                                   1,
                                                   4,
                                                   -1, -1, NULL);
    
    struct ccn_closure *action = NEW_STRUCT(1, ccn_closure);
    action->p = callback;
    struct SimpleStruct *Data = NEW_STRUCT(1, SimpleStruct);
    Data->x = 10;
    Data->y = 20;
    Data->z = 30;
    action->data = Data;
    
    // fire off a listener
    res = ccn_set_interest_filter(ccn, nm, action);
    printf("%d\n", res);
    ccn_charbuf_append_charbuf(cmd, nm);
    ccn_name_from_uri(cmd, "%C1.R.sw");
    ccn_name_append_nonce(cmd);
    
    res = ccn_express_interest(ccn,
                         cmd,
                         action,
                         template);
    ccn_run(ccn, -1);
    
}

int main(int argc, const char * argv[])
{

    // Write Slice
    // WriteSlice();
    
    ExpressInterest();
    // Write MaxN to repo
    
    // Get Space
    
    // Write TimeStamp To Repo
    
    // Read From Repo
    
    printf("Hello, World!\n");
    return 0;
}

