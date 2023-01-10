#ifndef _HLIL_PRINTER_H
#define _HLIL_PRINTER_H

void PrintIndent(size_t indent);
void PrintOperation(BNHighLevelILOperation operation);
void PrintVariable(HighLevelILFunction* func, const Variable& var);
void PrintILExpr(const HighLevelILInstruction& instr, size_t indent);
void PrintILExprHR(Ref<Function> &f, const HighLevelILInstruction& instr);
void PrintHLILFunction(Ref<Function> &func);
void PrintHLILFunctionHR(Ref<Function> &func);
#endif
