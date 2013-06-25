//
//  Aggregate.c
//  Egal
//
//  Created by Zening Qu on 6/20/13.
//  Copyright (c) 2013 Zening Qu. All rights reserved.
//

#include <stdio.h>
#include <ccn/charbuf.h>

int
ccn_charbuf_append2(struct ccn_charbuf *templ, struct ccn_charbuf * comp)
{
    return ccn_charbuf_append(templ, comp->buf + 1, comp->length - 2);
}