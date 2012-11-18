//
//  main.h
//  test
//
//  Created by Zening Qu on 4/23/12.
//  Copyright (c) 2012 REMAP/UCLA. All rights reserved.
//

#ifndef test_main_h
#define test_main_h

int WriteSlice(struct ccn* h, char* p, char* t);

void WriteToRepo(struct ccn* ccn, char* dst, char* value);

void ReadFromRepo(char* dst);

// int ReadFromBuffer(struct bufnode* temp);

struct ccn* GetHandle();

int WatchOverRepo(struct ccn* h, char* p, char* t);

char* Buffer(char mode, char* name, char* content);


#endif
