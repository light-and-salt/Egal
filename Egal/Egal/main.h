//
//  main.h
//  test
//
//  Created by Zening Qu on 4/23/12.
//  Copyright (c) 2012 REMAP/UCLA. All rights reserved.
//

#ifndef test_main_h
#define test_main_h

int WriteSlice(char* p, char* t);

void WriteToRepo(char* dst, char* value);

void ReadFromRepo(char* dst);

// int ReadFromBuffer(struct bufnode* temp);

struct ccn* GetHandle();

int WatchOverRepo(char* p, char* t);

char* Buffer(char mode, char* name, char* content);

size_t getPCOoffset(struct ccn_parsed_ContentObject *pco, enum ccn_parsed_content_object_offsetid offset);

#endif
