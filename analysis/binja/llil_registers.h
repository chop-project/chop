#ifndef LLIL_REGISTERS_H
#define LLIL_REGISTERS_H
// Just the registers we need for now.
enum X86_OperandType {
    NONE = 0,
    RBX = 69,
    RSP = 70,
    RBP = 71,
    R12 = 78,
    R13 = 79,
    R14 = 80,
    R15 = 81
};

bool isCalleeSavedRegister(uint32_t reg_idx){
  return reg_idx == RBX ||
         reg_idx == RSP ||
         reg_idx == RBP || 
         reg_idx == R12 ||
         reg_idx == R13 ||
         reg_idx == R14 ||
         reg_idx == R15;
}

bool isCalleeSaved(uint32_t reg_idx){
  return reg_idx == RBX ||
         reg_idx == RBP ||
         reg_idx == R12 ||
         reg_idx == R13 ||
         reg_idx == R14 ||
         reg_idx == R15;
}

bool isCalleeSavedN(uint32_t reg_idx, int num){
  switch (reg_idx) {
       case RBX: return num >= 1;
       case RBP: return num >= 2;
       case R12: return num >= 3;
       case R13: return num >= 4;
       case R14: return num >= 5;
       case R15: return num >= 6; 
       default: return false;
  }
  
  return true;
}

#endif
