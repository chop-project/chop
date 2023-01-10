#ifndef _BV_HELPER_H
#define _BV_HELPER_H
#include "binaryninjaapi.h"
#include "highlevelilinstruction.h"
using namespace BinaryNinja;
using namespace std;

typedef long int addr_t;
typedef unsigned int taint_t;

class BVHelper
{
  private:

    Ref<BinaryView> &bv;

  public:
    BVHelper(Ref<BinaryView> &bv): bv(bv) {}
    ~BVHelper() {}

    addr_t getFunctionByName(string name);
    map<addr_t, vector<string>>* getThrowsBasedOnPatern(vector<string> patterns);
    map<addr_t, vector<string>>* getUnwindsBasedOnPattern(vector<pair<string, string>> patterns);
    bool isSymbolExternal(string name, addr_t function_addr);
    bool searchForSymbol(string name, BNSymbolType regex);
    addr_t getCXA_throw(string function_name);

};

static inline addr_t getAddress(const HighLevelILInstruction& instr){
    if (instr.operation == HLIL_IMPORT || instr.operation == HLIL_CONST_PTR || instr.operation == HLIL_EXTERN_PTR || instr.operation == HLIL_FLOAT_CONST || instr.operation == HLIL_CONST){
       addr_t callee = instr.GetConstant();
       return callee;
    }
    return 0;
}


#endif
