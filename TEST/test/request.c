//
//  request.c
//  TEST
//
//  Created by Zening Qu on 6/13/13.
//  Copyright (c) 2013 Zening Qu. All rights reserved.
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <ccn/bloom.h>
#include <ccn/ccn.h>
#include <ccn/charbuf.h>
#include <ccn/uri.h>

enum ccn_upcall_res RequestCallBack(
                             struct ccn_closure *selfp,
                             enum ccn_upcall_kind kind,
                             struct ccn_upcall_info *info  /** details about the event */
                             )
{
    switch (kind) {
        case CCN_UPCALL_CONTENT_UNVERIFIED:
        case CCN_UPCALL_CONTENT:
            printf("CCN_UPCALL_CONTENT\n");
            
            // *** Get Content Value *** //
            unsigned char* content_ptr;
            size_t content_length = 0;
            ccn_content_get_value(info->content_ccnb, 0, info->pco, &content_ptr, &content_length);
            printf("Content Value: %s\n\n", content_ptr);
            
            // *** Get Content Name *** //
            struct ccn_charbuf *c = ccn_charbuf_create();
            size_t ccnb_size = info->pco->offset[CCN_PCO_E];
            ccn_uri_append(c, info->content_ccnb, ccnb_size, 0);
            printf("Content name: %s\n", ccn_charbuf_as_string(c));
            
            break;
                        
        case CCN_UPCALL_FINAL:
            printf("CCN_UPCALL_FINAL\n");
            ccn_set_run_timeout(info->h, 0);
            free(selfp);
            break;
            
        default:
            break;
    }
    
    return CCN_UPCALL_RESULT_OK;
}
/*
int main()
{
    struct ccn* ccn = NULL;
    ccn = ccn_create();
    if (ccn_connect(ccn, NULL) == -1) {
        printf("could not connect to ccnd.\n");
    }
    
    struct ccn_charbuf* name = ccn_charbuf_create();
    ccn_name_from_uri(name, "ccnx:/ndn/ucla.edu/apps/matryoshka/asteroid/octant/");

    struct ccn_closure *action = (struct ccn_closure*)calloc(1, sizeof(struct ccn_closure));
    action->p = RequestCallBack;

    ccn_express_interest(ccn, name, action, NULL);
    
    ccn_run(ccn, -1);
    ccn_destroy(&ccn);

    return 0;
}
*/