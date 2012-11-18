Egal Library
========
Zening Qu 11/18/2012 quzening@remap.ucla.edu

Egal is a C library built with Xcode to support multiplayer on-line game synchronization over NDN. It consists of CCNx source code and some "higher-level" functions that supports game synchronization. The "product" of the Egal library is a file called Egal.bundle, and this is how Egal library is incoporated into our multiplayer game projects developed with Unity.

Using Xcode terminology this repository is a "workspace", and it consists of three "projects":
- CCN: this is where the CCNx source code is stored
- Egal: this where we build the Egal.bundle file
- TEST: this is where the actual code is written and tested

The code in the TEST project is what Egal library adds onto the CCNx project. This part of code is not mixed with the source code and should be regarded as a thin layer of wrapper on top of the source code. 
