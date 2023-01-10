#ifndef _HLIL_COMPARATOR_H
#define _HLIL_COMPARATOR_H
#include "binaryninjacore.h"
#include "binaryninjaapi.h"
#include "highlevelilinstruction.h"

using namespace BinaryNinja;
using namespace std;

class HLILComparableIL {
   public:
       HighLevelILInstruction il;

       bool operator<(const HLILComparableIL& other) const;
       bool operator==(const HLILComparableIL& other) const;
       bool operator!=(const HLILComparableIL& other) const;
       HLILComparableIL& operator=(const HighLevelILInstruction& obj);
};

#endif
