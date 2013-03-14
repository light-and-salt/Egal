//
//  NameEnumeration.c
//  Egal
//
//  Created by Zening Qu on 3/12/13.
//  Copyright (c) 2013 Zening Qu. All rights reserved.
//

#include <stdio.h>
#include "main.h"
#include "SyncMacros.h"
#include "ccn.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <ccn/bloom.h>
#include <ccn/ccn.h>
#include <ccn/charbuf.h>
#include <ccn/uri.h>
int EnumerateNames(struct ccn_charbuf* nm);

enum ccn_upcall_res CallBack(
                                struct ccn_closure *selfp,
                                enum ccn_upcall_kind kind,
                                struct ccn_upcall_info *info  /** details about the event */
                                )
{
    //printf("upcall... %d\n", kind);
    switch (kind) {
            
        case CCN_UPCALL_CONTENT_UNVERIFIED:
        case CCN_UPCALL_CONTENT:
            printf("CCN_UPCALL_CONTENT\n");
            // *** Check Final Block *** //
            // printf("Am I the final block? %d\n", ccn_is_final_block(info)); //this is cute :)
            
            // *** Parse Name *** //
            // can I print out the name here?
            unsigned char *comp;
            size_t size;
            int res = 0;
            
            struct ccn_charbuf * c = ccn_charbuf_create();
            res = ccn_name_init(c);

            res = ccn_name_append_components(c, info->content_ccnb, info->pco->offset[CCN_PCO_B_Name], info->pco->offset[CCN_PCO_E_Name]);
            
            /*
            ccn_name_comp_get(info->interest_ccnb, info->interest_comps, 1, &comp, &size);
            printf("Name Component: %s %d\n", comp, size);
            */
            //printf("%s\n", ccn_charbuf_as_string(c));
            //fwrite(c->buf, 256, 1, stdout)-1;
            //printf("\n After the call: \n");
            ccn_name_next_sibling(c);
            //fwrite(c->buf, 256, 1, stdout)-1;
            //printf("%s\n", ccn_charbuf_as_string(c));
            //printf("\n");
            
            
            // *** Parse Content Object *** //
            unsigned char* ptr;
            size_t length = 0;
            ccn_content_get_value(info->content_ccnb, 0, info->pco, &ptr, &length);
            //printf("%d %d %s\n", length, strlen(ptr), ptr);
            fwrite(ptr, length, 1, stdout) - 1;
            
            
            EnumerateNames(c);
            
            break;
            
        case CCN_UPCALL_FINAL:
            printf("CCN_UPCALL_FINAL\n");
            ccn_set_run_timeout(info->h, 0);
            break;
            
        default:
            break;
    }
    
    return CCN_UPCALL_RESULT_OK;
}


int EnumerateNames(struct ccn_charbuf* nm)
{
    struct ccn* ccn = GetHandle();
    
    ccn_name_from_uri(nm, "ccnx:/ndn/ucla.edu/airports/%C1.E.be");
    //ccn_name_append_numeric(nm, CCN_MARKER_SEQNUM, 0);
    
    struct ccn_closure *action = NEW_STRUCT(1, ccn_closure);
    action->p = CallBack;
    
    ccn_express_interest(ccn, nm, action, NULL);

    ccn_run(ccn, -1);
    ccn_destroy(&ccn);
        
    return 0;
}

struct ccn_charbuf* name = NULL;

int main()
{
    // *** Name Enumeration *** //
    name = ccn_charbuf_create();
    EnumerateNames(name);

}

