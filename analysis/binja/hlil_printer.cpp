#include "binaryninjacore.h"
#include "binaryninjaapi.h"
#include "mediumlevelilinstruction.h"
#include "highlevelilinstruction.h"
#include <inttypes.h>

using namespace BinaryNinja;
using namespace std;

#include "hlil_printer.h"
#include "debug.h"

void PrintIndent(size_t indent)
{
	for (size_t i = 0; i < indent; i++)
		debug_print("    ");
}


void PrintOperation(BNHighLevelILOperation operation)
{
#define ENUM_PRINTER(op) \
	case op: \
		debug_print(#op); \
		break;

	switch (operation)
	{
		ENUM_PRINTER(HLIL_NOP)
		ENUM_PRINTER(HLIL_BLOCK)
		ENUM_PRINTER(HLIL_IF)
		ENUM_PRINTER(HLIL_WHILE)
		ENUM_PRINTER(HLIL_DO_WHILE)
		ENUM_PRINTER(HLIL_FOR)
		ENUM_PRINTER(HLIL_SWITCH)
		ENUM_PRINTER(HLIL_CASE)
		ENUM_PRINTER(HLIL_BREAK)
		ENUM_PRINTER(HLIL_CONTINUE)
		ENUM_PRINTER(HLIL_JUMP)
		ENUM_PRINTER(HLIL_RET)
		ENUM_PRINTER(HLIL_NORET)
		ENUM_PRINTER(HLIL_GOTO)
		ENUM_PRINTER(HLIL_LABEL)

		ENUM_PRINTER(HLIL_VAR_DECLARE)
		ENUM_PRINTER(HLIL_VAR_INIT)
		ENUM_PRINTER(HLIL_ASSIGN)
		ENUM_PRINTER(HLIL_ASSIGN_UNPACK)
		ENUM_PRINTER(HLIL_VAR)
		ENUM_PRINTER(HLIL_STRUCT_FIELD)
		ENUM_PRINTER(HLIL_ARRAY_INDEX)
		ENUM_PRINTER(HLIL_SPLIT)
		ENUM_PRINTER(HLIL_DEREF)
		ENUM_PRINTER(HLIL_DEREF_FIELD)
		ENUM_PRINTER(HLIL_ADDRESS_OF)
		ENUM_PRINTER(HLIL_CONST)
		ENUM_PRINTER(HLIL_CONST_PTR)
		ENUM_PRINTER(HLIL_EXTERN_PTR)
		ENUM_PRINTER(HLIL_FLOAT_CONST)
		ENUM_PRINTER(HLIL_IMPORT)
		ENUM_PRINTER(HLIL_ADD)
		ENUM_PRINTER(HLIL_ADC)
		ENUM_PRINTER(HLIL_SUB)
		ENUM_PRINTER(HLIL_SBB)
		ENUM_PRINTER(HLIL_AND)
		ENUM_PRINTER(HLIL_OR)
		ENUM_PRINTER(HLIL_XOR)
		ENUM_PRINTER(HLIL_LSL)
		ENUM_PRINTER(HLIL_LSR)
		ENUM_PRINTER(HLIL_ASR)
		ENUM_PRINTER(HLIL_ROL)
		ENUM_PRINTER(HLIL_RLC)
		ENUM_PRINTER(HLIL_ROR)
		ENUM_PRINTER(HLIL_RRC)
		ENUM_PRINTER(HLIL_MUL)
		ENUM_PRINTER(HLIL_MULU_DP)
		ENUM_PRINTER(HLIL_MULS_DP)
		ENUM_PRINTER(HLIL_DIVU)
		ENUM_PRINTER(HLIL_DIVU_DP)
		ENUM_PRINTER(HLIL_DIVS)
		ENUM_PRINTER(HLIL_DIVS_DP)
		ENUM_PRINTER(HLIL_MODU)
		ENUM_PRINTER(HLIL_MODU_DP)
		ENUM_PRINTER(HLIL_MODS)
		ENUM_PRINTER(HLIL_MODS_DP)
		ENUM_PRINTER(HLIL_NEG)
		ENUM_PRINTER(HLIL_NOT)
		ENUM_PRINTER(HLIL_SX)
		ENUM_PRINTER(HLIL_ZX)
		ENUM_PRINTER(HLIL_LOW_PART)
		ENUM_PRINTER(HLIL_CALL)
		ENUM_PRINTER(HLIL_CMP_E)
		ENUM_PRINTER(HLIL_CMP_NE)
		ENUM_PRINTER(HLIL_CMP_SLT)
		ENUM_PRINTER(HLIL_CMP_ULT)
		ENUM_PRINTER(HLIL_CMP_SLE)
		ENUM_PRINTER(HLIL_CMP_ULE)
		ENUM_PRINTER(HLIL_CMP_SGE)
		ENUM_PRINTER(HLIL_CMP_UGE)
		ENUM_PRINTER(HLIL_CMP_SGT)
		ENUM_PRINTER(HLIL_CMP_UGT)
		ENUM_PRINTER(HLIL_TEST_BIT)
		ENUM_PRINTER(HLIL_BOOL_TO_INT)
		ENUM_PRINTER(HLIL_ADD_OVERFLOW)
		ENUM_PRINTER(HLIL_SYSCALL)
		ENUM_PRINTER(HLIL_TAILCALL)
		ENUM_PRINTER(HLIL_INTRINSIC)
		ENUM_PRINTER(HLIL_BP)
		ENUM_PRINTER(HLIL_TRAP)
		ENUM_PRINTER(HLIL_UNDEF)
		ENUM_PRINTER(HLIL_UNIMPL)
		ENUM_PRINTER(HLIL_UNIMPL_MEM)

		// Floating point
		ENUM_PRINTER(HLIL_FADD)
		ENUM_PRINTER(HLIL_FSUB)
		ENUM_PRINTER(HLIL_FMUL)
		ENUM_PRINTER(HLIL_FDIV)
		ENUM_PRINTER(HLIL_FSQRT)
		ENUM_PRINTER(HLIL_FNEG)
		ENUM_PRINTER(HLIL_FABS)
		ENUM_PRINTER(HLIL_FLOAT_TO_INT)
		ENUM_PRINTER(HLIL_INT_TO_FLOAT)
		ENUM_PRINTER(HLIL_FLOAT_CONV)
		ENUM_PRINTER(HLIL_ROUND_TO_INT)
		ENUM_PRINTER(HLIL_FLOOR)
		ENUM_PRINTER(HLIL_CEIL)
		ENUM_PRINTER(HLIL_FTRUNC)
		ENUM_PRINTER(HLIL_FCMP_E)
		ENUM_PRINTER(HLIL_FCMP_NE)
		ENUM_PRINTER(HLIL_FCMP_LT)
		ENUM_PRINTER(HLIL_FCMP_LE)
		ENUM_PRINTER(HLIL_FCMP_GE)
		ENUM_PRINTER(HLIL_FCMP_GT)
		ENUM_PRINTER(HLIL_FCMP_O)
		ENUM_PRINTER(HLIL_FCMP_UO)

		// The following instructions are only used in SSA form
		ENUM_PRINTER(HLIL_WHILE_SSA)
		ENUM_PRINTER(HLIL_DO_WHILE_SSA)
		ENUM_PRINTER(HLIL_FOR_SSA)
		ENUM_PRINTER(HLIL_VAR_INIT_SSA)
		ENUM_PRINTER(HLIL_ASSIGN_MEM_SSA)
		ENUM_PRINTER(HLIL_ASSIGN_UNPACK_MEM_SSA)
		ENUM_PRINTER(HLIL_VAR_SSA)
		ENUM_PRINTER(HLIL_ARRAY_INDEX_SSA)
		ENUM_PRINTER(HLIL_DEREF_SSA)
		ENUM_PRINTER(HLIL_DEREF_FIELD_SSA)
		ENUM_PRINTER(HLIL_CALL_SSA)
		ENUM_PRINTER(HLIL_SYSCALL_SSA)
		ENUM_PRINTER(HLIL_INTRINSIC_SSA)
		ENUM_PRINTER(HLIL_VAR_PHI)
		ENUM_PRINTER(HLIL_MEM_PHI)

	default:
		debug_print("<invalid operation %" PRId32 ">", operation);
		break;
	}
}


void PrintVariable(HighLevelILFunction* func, const Variable& var)
{
	string name = func->GetFunction()->GetVariableName(var);
	if (name.size() == 0) {
		debug_print("<no name>");
        }
	else {
		debug_print("%s", name.c_str());
        }
}


void PrintILExpr(const HighLevelILInstruction& instr, size_t indent)
{
	PrintIndent(indent);
	PrintOperation(instr.operation);
	debug_print(" (ExprID: %ld)\n", instr.exprIndex);

	indent++;

	for (auto& operand : instr.GetOperands())
	{
		switch (operand.GetType())
		{
		case IntegerHighLevelOperand:
			PrintIndent(indent);
			debug_print("int 0x%" PRIx64 "\n", operand.GetInteger());
			break;

		case IndexHighLevelOperand:
			PrintIndent(indent);
			debug_print("index %" PRIdPTR "\n", operand.GetIndex());
			break;

		case ExprHighLevelOperand:
			PrintILExpr(operand.GetExpr(), indent);
			break;

		case VariableHighLevelOperand:
			PrintIndent(indent);
			debug_print("var ");
			PrintVariable(instr.function, operand.GetVariable());
			debug_print("\n");
			break;

		case SSAVariableHighLevelOperand:
			PrintIndent(indent);
			debug_print("ssa var ");
			PrintVariable(instr.function, operand.GetSSAVariable().var);
			debug_print("#%" PRIdPTR "\n", operand.GetSSAVariable().version);
			break;

		case IndexListHighLevelOperand:
			PrintIndent(indent);
			debug_print("index list ");
			for (auto i : operand.GetIndexList())
				debug_print("%" PRIdPTR " ", i);
			debug_print("\n");
			break;

		case SSAVariableListHighLevelOperand:
			PrintIndent(indent);
			debug_print("ssa var list ");
			for (auto i : operand.GetSSAVariableList())
			{
				PrintVariable(instr.function, i.var);
				debug_print("#%" PRIdPTR " ", i.version);
			}
			debug_print("\n");
			break;

		case ExprListHighLevelOperand:
			PrintIndent(indent);
			debug_print("expr list\n");
			for (auto& i : operand.GetExprList())
				PrintILExpr(i, indent + 1);
			break;

		default:
			PrintIndent(indent);
			debug_print("<invalid operand>\n");
			break;
		}
	}
}

void PrintHLILFunction(Ref<Function> &func){
   // Get the name of the function and display it
   Ref<Symbol> sym = func->GetSymbol();
   if (sym) {
	debug_print("Function at 0x%lx name:%s:\n", func->GetStart(), sym->GetFullName().c_str());
   }
   else {
	debug_print("Function at 0x%" PRIx64 ":\n", func->GetStart());
   }

   // Fetch the medium level IL for the function
   Ref<HighLevelILFunction> il = func->GetHighLevelIL()->GetSSAForm();
   if (!il)
   {
        debug_print("    Does not have HLIL\n\n");
	return;
   }

   // Loop through all blocks in the function
   for (auto& block : il->GetBasicBlocks())
   {
	// Loop though each instruction in the block
	for (size_t instrIndex = block->GetStart(); instrIndex < block->GetEnd(); instrIndex++)
	{
		// Fetch IL instruction
		HighLevelILInstruction instr = (*il)[instrIndex];

		// Display core's intrepretation of the IL instruction
				
		il->GetInstructionText(instrIndex, true, nullptr);
		debug_print("    %" PRIdPTR " @ 0x%" PRIx64 "  ", instrIndex, instr.address);
	       

		// Generically parse the IL tree and display the parts
		PrintILExpr(instr, 2);
	}
    }

    debug_print("\n");
}

void PrintILExprHR(Ref<Function> &f, const HighLevelILInstruction& instr){
   Ref<HighLevelILFunction> hlil_func = f->GetHighLevelIL()->GetSSAForm();
   if (!hlil_func)
       return;
   vector<DisassemblyTextLine> dlines = hlil_func->GetExprText(instr.exprIndex);
   debug_print("    %" PRIdPTR " @ 0x%" PRIx64 "  ", instr.exprIndex, instr.address);
   for (auto& one_line : dlines)
       for (auto& token: one_line.tokens) {
        debug_print("%s ", token.text.c_str());
       }
       debug_print("\n");
}

void PrintHLILFunctionHR(Ref<Function> &func){
   // Get the name of the function and display it
   Ref<Symbol> sym = func->GetSymbol();
   if (sym){
	debug_print("Function at 0x%lx name:%s:\n", func->GetStart(), sym->GetFullName().c_str());
   }
   else {
	debug_print("Function at 0x%" PRIx64 ":\n", func->GetStart());
   }

   // Fetch the medium level IL for the function
   Ref<HighLevelILFunction> il = func->GetHighLevelIL()->GetSSAForm();
   if (!il)
   {
        debug_print("    Does not have HLIL\n\n");
	return;
   }

   // Loop through all blocks in the function
   for (auto& block : il->GetBasicBlocks())
   {
	// Loop though each instruction in the block
	for (size_t instrIndex = block->GetStart(); instrIndex < block->GetEnd(); instrIndex++)
	{
		// Fetch IL instruction
		HighLevelILInstruction instr = (*il)[instrIndex].GetSSAForm();

		// Generically parse the IL tree and display the parts
		PrintILExprHR(func, instr);
	}
    }

    debug_print("\n");
}

