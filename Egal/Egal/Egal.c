//
//  Egal.c
//  Egal
//
//  Created by Zening Qu on 8/8/12.
//  Copyright (c) 2012 Zening Qu. All rights reserved.
//

#include <stdio.h>
#include "sync.h"


static ccns_callback WatchCallback;

int
Invoke(struct ccns_handle *h,
       struct ccn_charbuf *lhash,
       struct ccn_charbuf *rhash,
       struct ccn_charbuf *name)
{
    return (*WatchCallback)(h, lhash, rhash, name);
}

struct ccns_handle *
w_ccns_open(struct ccn *h,
          struct ccns_slice *slice,
          ccns_callback callback,
          struct ccn_charbuf *rhash,
          struct ccn_charbuf *pname)
{
    WatchCallback = callback;
    ccns_open(h, slice, callback, rhash, pname);
    
}

int nine()
{
    return 9;
}

