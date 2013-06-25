//
//  requestall.c
//  TEST
//
//  Created by Zening Qu on 6/14/13.
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


struct upcalldata {
    int n_excl;
    struct ccn_charbuf **excl; /* Array of n_excl items */
};



enum ccn_upcall_res RequestAllCallBack(
                                    struct ccn_closure *selfp,
                                    enum ccn_upcall_kind kind,
                                    struct ccn_upcall_info *info  /** details about the event */
                                    )
{
    switch (kind) {
        case CCN_UPCALL_CONTENT_UNVERIFIED:
        case CCN_UPCALL_CONTENT:
            printf("CCN_UPCALL_CONTENT\n");
            
            // *** Get Content Name *** //
            struct ccn_charbuf *contentname = ccn_charbuf_create();
            size_t ccnb_size = info->pco->offset[CCN_PCO_E];
            ccn_uri_append(contentname, info->content_ccnb, ccnb_size, 0);
            printf("Content name: %s\n", ccn_charbuf_as_string(contentname));
            // *** Get Content Value *** //
            unsigned char* content_ptr;
            size_t content_length = 0;
            ccn_content_get_value(info->content_ccnb, 0, info->pco, &content_ptr, &content_length);
            //printf("Content Value: %s\n\n", content_ptr);
            
            
            // *** Express New Interest, Exclude Old Data *** //
            struct ccn_charbuf *c = ccn_charbuf_create();;
            struct ccn_charbuf *templ = ccn_charbuf_create();;
            struct ccn_charbuf *comp = ccn_charbuf_create();;
            const unsigned char *ccnb = info->content_ccnb;;
            struct ccn_indexbuf *comps = info->content_comps;;
            
            ccn_name_init(comp);
            ccn_name_init(c);
            
            int matched_comps = info->pi->prefix_comps;
            
            ccn_name_append_str(c, "ndn");
            ccn_name_append_str(c, "ucla.edu");
            ccn_name_append_str(c, "apps");
            ccn_name_append_str(c, "matryoshka");
            ccn_name_append_str(c, "asteroid");
            ccn_name_append_str(c, "octant");
            ccn_name_append_str(c, "0");
            ccn_name_append_str(c, "1");
            ccn_name_append_str(c, "6");
            ccn_name_append_str(c, "6");
            ccn_name_append_str(comp, "02G");
             
            /*
            ccn_name_append_components(c, info->interest_ccnb,
                                             info->interest_comps->buf[0],
                                             info->interest_comps->buf[matched_comps]);
            
            
            printf("%s \n", ccn_charbuf_as_string(c));
            */
            /*
            ccn_name_append_components(comp, ccnb,
                                       comps->buf[matched_comps],
                                       comps->buf[matched_comps + 1]);
             */

            ccn_charbuf_append_tt(templ, CCN_DTAG_Interest, CCN_DTAG);
            ccn_charbuf_append_tt(templ, CCN_DTAG_Name, CCN_DTAG);
            ccn_charbuf_append_closer(templ); // </Name> 

            ccn_charbuf_append_tt(templ, CCN_DTAG_Exclude, CCN_DTAG);
            /*
            struct upcalldata *data = selfp->data;
            data->excl = realloc(data->excl, (data->n_excl + 1) * sizeof(data->excl[0]));
            data->excl[data->n_excl++] = comp;
             */
            //comp = NULL;
            ccn_charbuf_append(templ, comp->buf + 1, comp->length - 2);
            
            ccn_charbuf_append_closer(templ); // </Exclude> 
            ccn_charbuf_append_closer(templ); // </Interest> 
        
            
            ccn_express_interest(info->h, c, selfp, templ);
            ccn_charbuf_destroy(&templ);
            ccn_charbuf_destroy(&c);

            
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

int main()
{
    struct ccn* ccn = NULL;
    ccn = ccn_create();
    if (ccn_connect(ccn, NULL) == -1) {
        printf("could not connect to ccnd.\n");
    }
    
    struct ccn_charbuf* name = ccn_charbuf_create();
    ccn_name_from_uri(name, "ccnx:/ndn/ucla.edu/apps/matryoshka/asteroid/octant/0/1/6/6");
    
    struct ccn_closure *action = (struct ccn_closure*)calloc(1, sizeof(struct ccn_closure));
    action->p = RequestAllCallBack;
    
    struct upcalldata *data = NULL;
    data = calloc(1, sizeof(*data));
    action->data = data;
    
    ccn_express_interest(ccn, name, action, NULL);
    
    
    ccn_run(ccn, -1);
    ccn_destroy(&ccn);
    
    return 0;
}