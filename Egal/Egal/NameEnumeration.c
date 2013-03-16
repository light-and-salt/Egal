//
//  NameEnumeration.c
//  Egal
//
//  Created by Zening Qu on 3/12/13.
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


int EnumerateNames(struct ccn* ccn, struct ccn_charbuf* nm, struct ccn_charbuf* templ);

enum ccn_upcall_res CallBack(
                                struct ccn_closure *selfp,
                                enum ccn_upcall_kind kind,
                                struct ccn_upcall_info *info  /** details about the event */
                                )
{
    static uintmax_t seg = 0;
    
    switch (kind) {
        case CCN_UPCALL_CONTENT_UNVERIFIED:
        case CCN_UPCALL_CONTENT:
            printf("CCN_UPCALL_CONTENT\n");

            // *** Parse Content Object *** //
            unsigned char* content_ptr;
            size_t content_length = 0;
            ccn_content_get_value(info->content_ccnb, 0, info->pco, &content_ptr, &content_length);
            
            
            // *** Get Seg# From Name *** //
            //size_t namestart = info->pco->offset[CCN_PCO_B_Name];
            //size_t namestop = info->pco->offset[CCN_PCO_E_Name];
            //unsigned char* name_ptr;
            //size_t name_length = 0;
            //printf("%d", ccn_ref_tagged_BLOB(CCN_DTAG_Name, info->content_ccnb, namestart, namestop, &name_ptr, name_length));
            //struct ccn_indexbuf* indexbf = ccn_indexbuf_create();
            //ccn_name_comp_get(info->content_ccnb, indexbf, 0, name_ptr, name_length);
            //printf("%s\n", name_ptr);
            
            struct ccn_buf_decoder decoder;
            struct ccn_buf_decoder *d;
            struct ccn_parsed_Link parsed_link = {0};
            struct ccn_parsed_Link *pl = &parsed_link;
            d = ccn_buf_decoder_start(&decoder, content_ptr, content_length);
            int i = ccn_parse_Collection_start(d);
            while(ccn_parse_Collection_next(d, pl, NULL)>0)
            {
                size_t start = pl->offset[CCN_PL_B_Component0];
                size_t stop = pl->offset[CCN_PL_E_ComponentLast];
                unsigned char* component_ptr;
                size_t component_length = 0;
                ccn_ref_tagged_BLOB(CCN_DTAG_Component, content_ptr, start, stop, &component_ptr, component_length);
                printf("%s\n", component_ptr);
            }
            
            
            fwrite(content_ptr, content_length, 1, stdout) - 1;
            printf("\n");
            

            // *** Fetch Later Segments *** //
            if (ccn_is_final_block(info)==1) {
                ccn_set_run_timeout(info->h, 0);
            }
            else if(ccn_is_final_block(info)==0) //this is cute :)
            {
                int res = 0;
                struct ccn_charbuf * c = ccn_charbuf_create();
                size_t length_of_name = info->pco->name_ncomps;
                
                ccn_name_init(c);
                //res = ccn_name_append_components(c, info->content_ccnb, info->pco->offset[CCN_PCO_B_Component0], info->pco->offset[CCN_PCO_E_ComponentLast]);
                res = ccn_name_append_components(c, info->content_ccnb, info->content_comps->buf[0], info->content_comps->buf[length_of_name]);
                
                res = ccn_name_chop(c, NULL, -1);
                //printf("%d\n", res);
                res = ccn_name_append_numeric(c, CCN_MARKER_SEQNUM, seg++);

                EnumerateNames(info->h, c, NULL);
            }
            break;
            
        case CCN_UPCALL_FINAL:
            printf("CCN_UPCALL_FINAL\n");
            free(selfp);
            break;
            
        default:
            break;
    }
    return CCN_UPCALL_RESULT_OK;
}


int EnumerateNames(struct ccn* ccn, struct ccn_charbuf* nm, struct ccn_charbuf* templ)
{
    struct ccn_closure *action = (struct ccn_closure*)calloc(1, sizeof(struct ccn_closure));
    action->p = CallBack;
    ccn_express_interest(ccn, nm, action, templ);
    return 0;
}


int main()
{
    struct ccn* ccn = NULL;
    ccn = ccn_create();
    if (ccn_connect(ccn, NULL) == -1) {
        printf("could not connect to ccnd.\n");
    }
    
    struct ccn_charbuf* name = ccn_charbuf_create();
    ccn_name_from_uri(name, "ccnx:/ndn/ucla.edu/airports/%C1.E.be");
    EnumerateNames(ccn, name, NULL);
    ccn_run(ccn, -1);
    ccn_destroy(&ccn);

}

