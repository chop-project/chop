#include "hlilcomparator.h"


static bool CompareExprList(const HighLevelILInstructionList& a, const HighLevelILInstructionList& b)
{
	if (a.size() < b.size())
		return true;
	if (a.size() > b.size())
		return false;
	auto i = a.begin();
	auto j = b.begin();
	for (; i != a.end(); ++i, ++j)
	{
		if (*i < *j)
			return true;
		if (*j < *i)
			return false;
	}
	return false;
}


bool HLILComparableIL::operator<(const HLILComparableIL& other) const
{
	if (il.operation < other.il.operation)
		return true;
	if (il.operation > other.il.operation)
		return false;

	switch (il.operation)
	{
	case HLIL_BLOCK:
		return CompareExprList (il.GetBlockExprs<HLIL_BLOCK>(), other.il.GetBlockExprs<HLIL_BLOCK>());
	case HLIL_IF:
		if (il.GetConditionExpr<HLIL_IF>() < other.il.GetConditionExpr<HLIL_IF>())
			return true;
		if (other.il.GetConditionExpr<HLIL_IF>() < il.GetConditionExpr<HLIL_IF>())
			return false;
		if (il.GetTrueExpr<HLIL_IF>() < other.il.GetTrueExpr<HLIL_IF>())
			return true;
		if (other.il.GetTrueExpr<HLIL_IF>() < il.GetTrueExpr<HLIL_IF>())
			return false;
		return il.GetFalseExpr<HLIL_IF>() < other.il.GetFalseExpr<HLIL_IF>();
	case HLIL_WHILE:
		if (il.GetConditionExpr<HLIL_WHILE>() < other.il.GetConditionExpr<HLIL_WHILE>())
			return true;
		if (other.il.GetConditionExpr<HLIL_WHILE>() < il.GetConditionExpr<HLIL_WHILE>())
			return false;
		return il.GetLoopExpr<HLIL_WHILE>() < other.il.GetLoopExpr<HLIL_WHILE>();
	case HLIL_WHILE_SSA:
		if (il.GetConditionPhiExpr<HLIL_WHILE_SSA>() < other.il.GetConditionPhiExpr<HLIL_WHILE_SSA>())
			return true;
		if (other.il.GetConditionPhiExpr<HLIL_WHILE_SSA>() < il.GetConditionPhiExpr<HLIL_WHILE_SSA>())
			return false;
		if (il.GetConditionExpr<HLIL_WHILE>() < other.il.GetConditionExpr<HLIL_WHILE>())
			return true;
		if (other.il.GetConditionExpr<HLIL_WHILE>() < il.GetConditionExpr<HLIL_WHILE>())
			return false;
		return il.GetLoopExpr<HLIL_WHILE>() < other.il.GetLoopExpr<HLIL_WHILE>();
	case HLIL_DO_WHILE:
		if (il.GetLoopExpr<HLIL_DO_WHILE>() < other.il.GetLoopExpr<HLIL_DO_WHILE>())
			return true;
		if (other.il.GetLoopExpr<HLIL_DO_WHILE>() < il.GetLoopExpr<HLIL_DO_WHILE>())
			return false;
		return il.GetConditionExpr<HLIL_DO_WHILE>() < other.il.GetConditionExpr<HLIL_DO_WHILE>();
	case HLIL_DO_WHILE_SSA:
		if  (il.GetLoopExpr<HLIL_DO_WHILE_SSA>() < other.il.GetLoopExpr<HLIL_DO_WHILE_SSA>())
			return true;
		if (other.il.GetLoopExpr<HLIL_DO_WHILE_SSA>() < il.GetLoopExpr<HLIL_DO_WHILE_SSA>())
			return false;
		if  (il.GetConditionPhiExpr<HLIL_DO_WHILE_SSA>() < other.il.GetConditionPhiExpr<HLIL_DO_WHILE_SSA>())
			return true;
		if (other.il.GetConditionPhiExpr<HLIL_DO_WHILE_SSA>() < il.GetConditionPhiExpr<HLIL_DO_WHILE_SSA>())
			return false;
		return il.GetConditionExpr<HLIL_DO_WHILE_SSA>() < other.il.GetConditionExpr<HLIL_DO_WHILE_SSA>();
	case HLIL_FOR:
		if  (il.GetInitExpr<HLIL_FOR>() < other.il.GetInitExpr<HLIL_FOR>())
			return true;
		if (other.il.GetInitExpr<HLIL_FOR>() < il.GetInitExpr<HLIL_FOR>())
			return false;
		if  (il.GetConditionExpr<HLIL_FOR>() < other.il.GetConditionExpr<HLIL_FOR>())
			return true;
		if (other.il.GetConditionExpr<HLIL_FOR>() < il.GetConditionExpr<HLIL_FOR>())
			return false;
		if  (il.GetUpdateExpr<HLIL_FOR>() < other.il.GetUpdateExpr<HLIL_FOR>())
			return true;
		if (other.il.GetUpdateExpr<HLIL_FOR>() < il.GetUpdateExpr<HLIL_FOR>())
			return false;
		return il.GetLoopExpr<HLIL_FOR>() < other.il.GetLoopExpr<HLIL_FOR>();
	case HLIL_FOR_SSA:
		if  (il.GetInitExpr<HLIL_FOR_SSA>() < other.il.GetInitExpr<HLIL_FOR_SSA>())
			return true;
		if (other.il.GetInitExpr<HLIL_FOR_SSA>() < il.GetInitExpr<HLIL_FOR_SSA>())
			return false;
		if  (il.GetConditionPhiExpr<HLIL_FOR_SSA>() < other.il.GetConditionPhiExpr<HLIL_FOR_SSA>())
			return true;
		if (other.il.GetConditionPhiExpr<HLIL_FOR_SSA>() < il.GetConditionPhiExpr<HLIL_FOR_SSA>())
			return false;
		if  (il.GetConditionExpr<HLIL_FOR_SSA>() < other.il.GetConditionExpr<HLIL_FOR_SSA>())
			return true;
		if (other.il.GetConditionExpr<HLIL_FOR_SSA>() < il.GetConditionExpr<HLIL_FOR_SSA>())
			return false;
		if  (il.GetUpdateExpr<HLIL_FOR_SSA>() < other.il.GetUpdateExpr<HLIL_FOR_SSA>())
			return true;
		if (other.il.GetUpdateExpr<HLIL_FOR_SSA>() < il.GetUpdateExpr<HLIL_FOR_SSA>())
			return false;
		return il.GetLoopExpr<HLIL_FOR_SSA>() < other.il.GetLoopExpr<HLIL_FOR_SSA>();
	case HLIL_SWITCH:
		if  (il.GetConditionExpr<HLIL_SWITCH>() < other.il.GetConditionExpr<HLIL_SWITCH>())
			return true;
		if (other.il.GetConditionExpr<HLIL_SWITCH>() < il.GetConditionExpr<HLIL_SWITCH>())
			return false;
		if  (il.GetDefaultExpr<HLIL_SWITCH>() < other.il.GetDefaultExpr<HLIL_SWITCH>())
			return true;
		if (other.il.GetDefaultExpr<HLIL_SWITCH>() < il.GetDefaultExpr<HLIL_SWITCH>())
			return false;
		return CompareExprList (il.GetCases<HLIL_SWITCH>(), other.il.GetCases<HLIL_SWITCH>());
	case HLIL_CASE:
		if  (il.GetTrueExpr<HLIL_CASE>() < other.il.GetTrueExpr<HLIL_CASE>())
			return true;
		if (other.il.GetTrueExpr<HLIL_CASE>() < il.GetTrueExpr<HLIL_CASE>())
			return false;
		return CompareExprList (il.GetValueExprs<HLIL_CASE>(), other.il.GetValueExprs<HLIL_CASE>());
	case HLIL_JUMP:
		return il.GetDestExpr<HLIL_JUMP>() < other.il.GetDestExpr<HLIL_JUMP>();
	case HLIL_RET:
		return CompareExprList (il.GetSourceExprs<HLIL_RET>(), other.il.GetSourceExprs<HLIL_RET>());
	case HLIL_GOTO:
		return il.GetTarget<HLIL_GOTO>() < other.il.GetTarget<HLIL_GOTO>();
	case HLIL_LABEL:
		return il.GetTarget<HLIL_LABEL>() < other.il.GetTarget<HLIL_LABEL>();
	case HLIL_VAR_DECLARE:
		return il.GetVariable<HLIL_VAR_DECLARE>() < other.il.GetVariable<HLIL_VAR_DECLARE>();
	case HLIL_VAR_INIT:
		if (il.size < other.il.size)
			return true;
		if (il.size > other.il.size)
			return false;
		if  (il.GetDestVariable<HLIL_VAR_INIT>() < other.il.GetDestVariable<HLIL_VAR_INIT>())
			return true;
		if (other.il.GetDestVariable<HLIL_VAR_INIT>() < il.GetDestVariable<HLIL_VAR_INIT>())
			return false;
		return il.GetSourceExpr<HLIL_VAR_INIT>() < other.il.GetSourceExpr<HLIL_VAR_INIT>();
	case HLIL_VAR_INIT_SSA:
		if (il.size < other.il.size)
			return true;
		if (il.size > other.il.size)
			return false;
		if  (il.GetDestSSAVariable<HLIL_VAR_INIT_SSA>() < other.il.GetDestSSAVariable<HLIL_VAR_INIT_SSA>())
			return true;
		if (other.il.GetDestSSAVariable<HLIL_VAR_INIT_SSA>() < il.GetDestSSAVariable<HLIL_VAR_INIT_SSA>())
			return false;
		return il.GetSourceExpr<HLIL_VAR_INIT_SSA>() < other.il.GetSourceExpr<HLIL_VAR_INIT_SSA>();
	case HLIL_ASSIGN:
		if (il.size < other.il.size)
			return true;
		if (il.size > other.il.size)
			return false;
		if  (il.GetDestExpr<HLIL_ASSIGN>() < other.il.GetDestExpr<HLIL_ASSIGN>())
			return true;
		if (other.il.GetDestExpr<HLIL_ASSIGN>() < il.GetDestExpr<HLIL_ASSIGN>())
			return false;
		return il.GetSourceExpr<HLIL_ASSIGN>() < other.il.GetSourceExpr<HLIL_ASSIGN>();
	case HLIL_ASSIGN_UNPACK:
		if  (il.GetSourceExpr<HLIL_ASSIGN_UNPACK>() < other.il.GetSourceExpr<HLIL_ASSIGN_UNPACK>())
			return true;
		if (other.il.GetSourceExpr<HLIL_ASSIGN_UNPACK>() < il.GetSourceExpr<HLIL_ASSIGN_UNPACK>())
			return false;
		return CompareExprList (il.GetDestExprs<HLIL_ASSIGN_UNPACK>(), other.il.GetDestExprs<HLIL_ASSIGN_UNPACK>());
	case HLIL_ASSIGN_MEM_SSA:
		if (il.size < other.il.size)
			return true;
		if (il.size > other.il.size)
			return false;
		if  (il.GetDestExpr<HLIL_ASSIGN_MEM_SSA>() < other.il.GetDestExpr<HLIL_ASSIGN_MEM_SSA>())
			return true;
		if (other.il.GetDestExpr<HLIL_ASSIGN_MEM_SSA>() < il.GetDestExpr<HLIL_ASSIGN_MEM_SSA>())
			return false;
		if  (il.GetSourceExpr<HLIL_ASSIGN_MEM_SSA>() < other.il.GetSourceExpr<HLIL_ASSIGN_MEM_SSA>())
			return true;
		if (other.il.GetSourceExpr<HLIL_ASSIGN_MEM_SSA>() < il.GetSourceExpr<HLIL_ASSIGN_MEM_SSA>())
			return false;
		return false;
	case HLIL_ASSIGN_UNPACK_MEM_SSA:
		if  (il.GetSourceExpr<HLIL_ASSIGN_UNPACK_MEM_SSA>() < other.il.GetSourceExpr<HLIL_ASSIGN_UNPACK_MEM_SSA>())
			return true;
		if (other.il.GetSourceExpr<HLIL_ASSIGN_UNPACK_MEM_SSA>() < il.GetSourceExpr<HLIL_ASSIGN_UNPACK_MEM_SSA>())
			return false;
		return CompareExprList(
		    il.GetDestExprs<HLIL_ASSIGN_UNPACK_MEM_SSA>(), other.il.GetDestExprs<HLIL_ASSIGN_UNPACK_MEM_SSA>());
	case HLIL_VAR:
		if (il.size < other.il.size)
			return true;
		if (il.size > other.il.size)
			return false;
		return il.GetVariable<HLIL_VAR>() < other.il.GetVariable<HLIL_VAR>();
	case HLIL_VAR_SSA:
		if (il.size < other.il.size)
			return true;
		if (il.size > other.il.size)
			return false;
		return il.GetSSAVariable<HLIL_VAR_SSA>() < other.il.GetSSAVariable<HLIL_VAR_SSA>();
	case HLIL_STRUCT_FIELD:
		if (il.size < other.il.size)
			return true;
		if (il.size > other.il.size)
			return false;
		if  (il.GetSourceExpr<HLIL_STRUCT_FIELD>() < other.il.GetSourceExpr<HLIL_STRUCT_FIELD>())
			return true;
		if (other.il.GetSourceExpr<HLIL_STRUCT_FIELD>() < il.GetSourceExpr<HLIL_STRUCT_FIELD>())
			return false;
		if  (il.GetOffset<HLIL_STRUCT_FIELD>() < other.il.GetOffset<HLIL_STRUCT_FIELD>())
			return true;
		if (other.il.GetOffset<HLIL_STRUCT_FIELD>() < il.GetOffset<HLIL_STRUCT_FIELD>())
			return false;
		return il.GetMemberIndex<HLIL_STRUCT_FIELD>() < other.il.GetMemberIndex<HLIL_STRUCT_FIELD>();
	case HLIL_ARRAY_INDEX:
		if (il.size < other.il.size)
			return true;
		if (il.size > other.il.size)
			return false;
		if  (il.GetSourceExpr<HLIL_ARRAY_INDEX>() < other.il.GetSourceExpr<HLIL_ARRAY_INDEX>())
			return true;
		if (other.il.GetSourceExpr<HLIL_ARRAY_INDEX>() < il.GetSourceExpr<HLIL_ARRAY_INDEX>())
			return false;
		return il.GetIndexExpr<HLIL_ARRAY_INDEX>() < other.il.GetIndexExpr<HLIL_ARRAY_INDEX>();
	case HLIL_ARRAY_INDEX_SSA:
		if (il.size < other.il.size)
			return true;
		if (il.size > other.il.size)
			return false;
		if  (il.GetSourceExpr<HLIL_ARRAY_INDEX_SSA>() < other.il.GetSourceExpr<HLIL_ARRAY_INDEX_SSA>())
			return true;
		if (other.il.GetSourceExpr<HLIL_ARRAY_INDEX_SSA>() < il.GetSourceExpr<HLIL_ARRAY_INDEX_SSA>())
			return false;
		if  (il.GetIndexExpr<HLIL_ARRAY_INDEX_SSA>() < other.il.GetIndexExpr<HLIL_ARRAY_INDEX_SSA>())
			return true;
		if (other.il.GetIndexExpr<HLIL_ARRAY_INDEX_SSA>() < il.GetIndexExpr<HLIL_ARRAY_INDEX_SSA>())
			return false;
		return false;
	case HLIL_SPLIT:
		if (il.size < other.il.size)
			return true;
		if (il.size > other.il.size)
			return false;
		if  (il.GetHighExpr<HLIL_SPLIT>() < other.il.GetHighExpr<HLIL_SPLIT>())
			return true;
		if (other.il.GetHighExpr<HLIL_SPLIT>() < il.GetHighExpr<HLIL_SPLIT>())
			return false;
		return il.GetLowExpr<HLIL_SPLIT>() < other.il.GetLowExpr<HLIL_SPLIT>();
	case HLIL_DEREF_FIELD:
		if (il.size < other.il.size)
			return true;
		if (il.size > other.il.size)
			return false;
		if  (il.GetSourceExpr<HLIL_DEREF_FIELD>() < other.il.GetSourceExpr<HLIL_DEREF_FIELD>())
			return true;
		if (other.il.GetSourceExpr<HLIL_DEREF_FIELD>() < il.GetSourceExpr<HLIL_DEREF_FIELD>())
			return false;
		if  (il.GetOffset<HLIL_DEREF_FIELD>() < other.il.GetOffset<HLIL_DEREF_FIELD>())
			return true;
		if (other.il.GetOffset<HLIL_DEREF_FIELD>() < il.GetOffset<HLIL_DEREF_FIELD>())
			return false;
		return il.GetMemberIndex<HLIL_DEREF_FIELD>() < other.il.GetMemberIndex<HLIL_DEREF_FIELD>();
	case HLIL_DEREF_SSA:
		if (il.size < other.il.size)
			return true;
		if (il.size > other.il.size)
			return false;
		if  (il.GetSourceExpr<HLIL_DEREF_SSA>() < other.il.GetSourceExpr<HLIL_DEREF_SSA>())
			return true;
		if (other.il.GetSourceExpr<HLIL_DEREF_SSA>() < il.GetSourceExpr<HLIL_DEREF_SSA>())
			return false;
		return false;
	case HLIL_DEREF_FIELD_SSA:
		if (il.size < other.il.size)
			return true;
		if (il.size > other.il.size)
			return false;
		if  (il.GetSourceExpr<HLIL_DEREF_FIELD_SSA>() < other.il.GetSourceExpr<HLIL_DEREF_FIELD_SSA>())
			return true;
		if (other.il.GetSourceExpr<HLIL_DEREF_FIELD_SSA>() < il.GetSourceExpr<HLIL_DEREF_FIELD_SSA>())
			return false;
		if  (il.GetOffset<HLIL_DEREF_FIELD_SSA>() < other.il.GetOffset<HLIL_DEREF_FIELD_SSA>())
			return true;
		if (other.il.GetOffset<HLIL_DEREF_FIELD_SSA>() < il.GetOffset<HLIL_DEREF_FIELD_SSA>())
			return false;
		if  (il.GetMemberIndex<HLIL_DEREF_FIELD_SSA>() < other.il.GetMemberIndex<HLIL_DEREF_FIELD_SSA>())
			return true;
		if (other.il.GetMemberIndex<HLIL_DEREF_FIELD_SSA>() < il.GetMemberIndex<HLIL_DEREF_FIELD_SSA>())
			return false;
		return false;
	case HLIL_ADDRESS_OF:
		return il.GetSourceExpr<HLIL_ADDRESS_OF>() < other.il.GetSourceExpr<HLIL_ADDRESS_OF>();
	case HLIL_EXTERN_PTR:
		if  (il.GetConstant<HLIL_EXTERN_PTR>() < other.il.GetConstant<HLIL_EXTERN_PTR>())
			return true;
		if (other.il.GetConstant<HLIL_EXTERN_PTR>() < il.GetConstant<HLIL_EXTERN_PTR>())
			return false;
		return il.GetOffset<HLIL_EXTERN_PTR>() < other.il.GetOffset<HLIL_EXTERN_PTR>();
	case HLIL_CALL:
		if  (il.GetDestExpr<HLIL_CALL>() < other.il.GetDestExpr<HLIL_CALL>())
			return true;
		if (other.il.GetDestExpr<HLIL_CALL>() < il.GetDestExpr<HLIL_CALL>())
			return false;
		return CompareExprList (il.GetParameterExprs<HLIL_CALL>(), other.il.GetParameterExprs<HLIL_CALL>());
	case HLIL_SYSCALL:
		return CompareExprList (il.GetParameterExprs<HLIL_SYSCALL>(), other.il.GetParameterExprs<HLIL_SYSCALL>());
	case HLIL_TAILCALL:
		if  (il.GetDestExpr<HLIL_TAILCALL>() < other.il.GetDestExpr<HLIL_TAILCALL>())
			return true;
		if (other.il.GetDestExpr<HLIL_TAILCALL>() < il.GetDestExpr<HLIL_TAILCALL>())
			return false;
		return CompareExprList (il.GetParameterExprs<HLIL_TAILCALL>(), other.il.GetParameterExprs<HLIL_TAILCALL>());
	case HLIL_INTRINSIC:
		if  (il.GetIntrinsic<HLIL_INTRINSIC>() < other.il.GetIntrinsic<HLIL_INTRINSIC>())
			return true;
		if (other.il.GetIntrinsic<HLIL_INTRINSIC>() < il.GetIntrinsic<HLIL_INTRINSIC>())
			return false;
		return CompareExprList (il.GetParameterExprs<HLIL_INTRINSIC>(), other.il.GetParameterExprs<HLIL_INTRINSIC>());
	case HLIL_CALL_SSA:
		if  (il.GetDestExpr<HLIL_CALL_SSA>() < other.il.GetDestExpr<HLIL_CALL_SSA>())
			return true;
		if (other.il.GetDestExpr<HLIL_CALL_SSA>() < il.GetDestExpr<HLIL_CALL_SSA>())
			return false;
		return CompareExprList (il.GetParameterExprs<HLIL_CALL_SSA>(), other.il.GetParameterExprs<HLIL_CALL_SSA>());
	case HLIL_SYSCALL_SSA:
		return CompareExprList (il.GetParameterExprs<HLIL_SYSCALL_SSA>(), other.il.GetParameterExprs<HLIL_SYSCALL_SSA>());
	case HLIL_INTRINSIC_SSA:
		if  (il.GetIntrinsic<HLIL_INTRINSIC_SSA>() < other.il.GetIntrinsic<HLIL_INTRINSIC_SSA>())
			return true;
		if (other.il.GetIntrinsic<HLIL_INTRINSIC_SSA>() < il.GetIntrinsic<HLIL_INTRINSIC_SSA>())
			return false;
		return CompareExprList (il.GetParameterExprs<HLIL_INTRINSIC_SSA>(), other.il.GetParameterExprs<HLIL_INTRINSIC_SSA>());
	case HLIL_TRAP:
		return il.GetVector<HLIL_TRAP>() < other.il.GetVector<HLIL_TRAP>();
	case HLIL_ADD:
	case HLIL_SUB:
	case HLIL_AND:
	case HLIL_OR:
	case HLIL_XOR:
	case HLIL_LSL:
	case HLIL_LSR:
	case HLIL_ASR:
	case HLIL_ROL:
	case HLIL_ROR:
	case HLIL_MUL:
	case HLIL_MULU_DP:
	case HLIL_MULS_DP:
	case HLIL_DIVU:
	case HLIL_DIVS:
	case HLIL_MODU:
	case HLIL_MODS:
	case HLIL_DIVU_DP:
	case HLIL_DIVS_DP:
	case HLIL_MODU_DP:
	case HLIL_MODS_DP:
	case HLIL_CMP_E:
	case HLIL_CMP_NE:
	case HLIL_CMP_SLT:
	case HLIL_CMP_ULT:
	case HLIL_CMP_SLE:
	case HLIL_CMP_ULE:
	case HLIL_CMP_SGE:
	case HLIL_CMP_UGE:
	case HLIL_CMP_SGT:
	case HLIL_CMP_UGT:
	case HLIL_TEST_BIT:
	case HLIL_ADD_OVERFLOW:
	case HLIL_FADD:
	case HLIL_FSUB:
	case HLIL_FMUL:
	case HLIL_FDIV:
	case HLIL_FCMP_E:
	case HLIL_FCMP_NE:
	case HLIL_FCMP_LT:
	case HLIL_FCMP_LE:
	case HLIL_FCMP_GE:
	case HLIL_FCMP_GT:
	case HLIL_FCMP_O:
	case HLIL_FCMP_UO:
		if (il.size < other.il.size)
			return true;
		if (il.size > other.il.size)
			return false;
		if (il.AsTwoOperand().GetLeftExpr() < other.il.AsTwoOperand().GetLeftExpr())
			return true;
		if (other.il.AsTwoOperand().GetLeftExpr() < il.AsTwoOperand().GetLeftExpr())
			return false;
		return il.AsTwoOperand().GetRightExpr() < other.il.AsTwoOperand().GetRightExpr();
	case HLIL_ADC:
	case HLIL_SBB:
	case HLIL_RLC:
	case HLIL_RRC:
		if (il.size < other.il.size)
			return true;
		if (il.size > other.il.size)
			return false;
		if (il.AsTwoOperandWithCarry().GetLeftExpr() < other.il.AsTwoOperandWithCarry().GetLeftExpr())
			return true;
		if (other.il.AsTwoOperandWithCarry().GetLeftExpr() < il.AsTwoOperandWithCarry().GetLeftExpr())
			return false;
		if (il.AsTwoOperandWithCarry().GetRightExpr() < other.il.AsTwoOperandWithCarry().GetRightExpr())
			return true;
		if (other.il.AsTwoOperandWithCarry().GetRightExpr() < il.AsTwoOperandWithCarry().GetRightExpr())
			return false;
		return il.AsTwoOperandWithCarry().GetCarryExpr() < other.il.AsTwoOperandWithCarry().GetCarryExpr();
	case HLIL_CONST:
	case HLIL_CONST_PTR:
	case HLIL_FLOAT_CONST:
	case HLIL_IMPORT:
		return il.AsConstant().GetConstant() < other.il.AsConstant().GetConstant();
	case HLIL_DEREF:
	case HLIL_NEG:
	case HLIL_NOT:
	case HLIL_SX:
	case HLIL_ZX:
	case HLIL_LOW_PART:
	case HLIL_BOOL_TO_INT:
	case HLIL_UNIMPL_MEM:
	case HLIL_FSQRT:
	case HLIL_FNEG:
	case HLIL_FABS:
	case HLIL_FLOAT_TO_INT:
	case HLIL_INT_TO_FLOAT:
	case HLIL_FLOAT_CONV:
	case HLIL_ROUND_TO_INT:
	case HLIL_FLOOR:
	case HLIL_CEIL:
	case HLIL_FTRUNC:
		if (il.size < other.il.size)
			return true;
		if (il.size > other.il.size)
			return false;
		return il.AsOneOperand().GetSourceExpr() < other.il.AsOneOperand().GetSourceExpr();
	case HLIL_VAR_PHI:
	{
		if  (il.GetDestSSAVariable<HLIL_VAR_PHI>() < other.il.GetDestSSAVariable<HLIL_VAR_PHI>())
			return true;
		if (other.il.GetDestSSAVariable<HLIL_VAR_PHI>() < il.GetDestSSAVariable<HLIL_VAR_PHI>())
			return false;
		HighLevelILSSAVariableList list = il.GetSourceSSAVariables<HLIL_VAR_PHI>();
		HighLevelILSSAVariableList otherList = other.il.GetSourceSSAVariables<HLIL_VAR_PHI>();
		if (list.size() < otherList.size())
			return true;
		if (list.size() > otherList.size())
			return false;
		auto i = list.begin();
		auto j = otherList.begin();
		for (; i != list.end(); ++i, ++j)
		{
			if (*i < *j)
				return true;
			if (*j < *i)
				return false;
		}
		return false;
	}
	case HLIL_MEM_PHI:
	{
		if  (il.GetDestMemoryVersion<HLIL_MEM_PHI>() < other.il.GetDestMemoryVersion<HLIL_MEM_PHI>())
			return true;
		if (other.il.GetDestMemoryVersion<HLIL_MEM_PHI>() < il.GetDestMemoryVersion<HLIL_MEM_PHI>())
			return false;
		HighLevelILIndexList list = il.GetSourceMemoryVersions<HLIL_MEM_PHI>();
		HighLevelILIndexList otherList = other.il.GetSourceMemoryVersions<HLIL_MEM_PHI>();
		if (list.size() < otherList.size())
			return true;
		if (list.size() > otherList.size())
			return false;
		auto i = list.begin();
		auto j = otherList.begin();
		for (; i != list.end(); ++i, ++j)
		{
			if (*i < *j)
				return true;
			if (*j < *i)
				return false;
		}
		return false;
	}
	default:
		return false;
	}
}


bool HLILComparableIL::operator==(const HLILComparableIL& other) const
{
	return !((*this < other) || (other < *this));
}


bool HLILComparableIL::operator!=(const HLILComparableIL& other) const
{
	return !(*this == other);
}

HLILComparableIL& HLILComparableIL::operator=(const HighLevelILInstruction& obj){
   this->il = obj;

   return *this;
}
