#include "taint_analysis.h"
#include <unistd.h>
#include "debug.h"

#include "llil_registers.h"
#include "llil_printer.h"
#include "hlil_printer.h"

#include "globals.h"

#include "boost/filesystem.hpp"

using namespace boost::filesystem;

#include <fstream>


#define PROPAGATE_ALL_MEM_ASSIGNS
#define TRACK_INDEX_TAINT
#define PROPAGATE_TAINT_ON_WHITELIST

#if 0
#define RBX_TAINT 1 << 1
#define RBP_TAINT 1 << 2
#define R12_TAINT 1 << 3
#define R13_TAINT 1 << 4
#define R14_TAINT 1 << 5
#define R15_TAINT 1 << 6
#define POINTER_TAINT 1 << 8
#define VALUE_TAINT 1 << 9
#define TAINT_DIFFERS 1 << 10
#define INDEX_TAINT 1 << 11
#define BASE_TAINT 1 << 12
#define IB_DIFFERS 1 << 13
#else
#define RBX_TAINT 1 << 0
#define RBP_TAINT 1 << 1
#define R12_TAINT 1 << 2
#define R13_TAINT 1 << 3
#define R14_TAINT 1 << 4
#define R15_TAINT 1 << 5
#define POINTER_TAINT 1 << 6
#define VALUE_TAINT 1 << 7
#define TAINT_DIFFERS 1 << 8
#define INDEX_TAINT 1 << 9
#define BASE_TAINT 1 << 10
#define IB_DIFFERS 1 << 11
#define MIN_STACK_TAINT_SLOT 12
#define MAX_STACK_TAINT_SLOT 31
#endif

#define LOOP_COMPLEXITY 15
#define BRANCH_COMPLEXITY 5
#define BLOCK_COMPLEXITY 2
#define TAINT_INSTR_COMPLEXITY 1

// Add a new sink to the taint list
#define add_sink(_instr, _type, _taint_target, _taint_register, _level) { \
      Sink sink(_instr.address, _type);                      \
      Complexity c;                                    \
      init_complexity(c, this->status);                \
      sink.complexity = c;                             \
      sink.target_mask = _taint_target;                \
      sink.register_mask = _taint_register;            \
      sink.level = _level;                             \
      sink_list.push_back(sink);                       \
     }

// Add sink and record function name as well
#define add_named_sink(_instr, _type, _taint_target, _taint_register, _level) { \
      Sink sink(_instr.address, _type);                \
      Complexity c;                                    \
      init_complexity(c, this->status);                \
      sink.complexity = c;                             \
      sink.target_mask = _taint_target;                \
      sink.register_mask = _taint_register;            \
      sink.level = _level;                             \
      optional<string> func = getFunctionName(_instr); \
      if (func.has_value())                            \
           sink.callee_name = func.value();            \
      sink_list.push_back(sink);                       \
     }

#define mark_pointer_value_taint(_pointer_taint, _value_taint) { \
   if (_value_taint && _pointer_taint && ((_pointer_taint &  tmask) != (_value_taint & tmask))){ \
        _pointer_taint |= TAINT_DIFFERS; \
   } \
   if (_pointer_taint & tmask){ \
        _pointer_taint |= POINTER_TAINT; \
   } \
   if (_value_taint & tmask){ \
         _pointer_taint |= (VALUE_TAINT | _value_taint); \
   } \
}

#define compute_value_taint(_value_taint, _instruction) {\
   HLILComparableIL cmp_src; \
   cmp_src = _instruction; \
   if (!in_assign && TaintedExprs.count(cmp_src)){ \
      _value_taint = TaintedExprs[cmp_src]; \
   } \
}

#define taint_params(_taint, _params, _exprs) { \
      int cntr = 0; \
      for (auto i = _exprs.begin(); i != _exprs.end(); ++i){ \
         auto taint_aux = evalTaint(*i); \
         if (taint_aux) \
             _params.push_back(pair<int,int>(cntr, taint_aux));\
         cntr++; \
         _taint |= taint_aux; \
      }\
} 

#define print_tainted_params() {\
    debug_print("Tainted params: (0x%lx)- ", this->func_addr); \
    for (auto &i : params){ \
      debug_print("(%d [%s]) ", i.first, print_tainted_registers(i.second).c_str()); \
    } \
    debug_print("\n"); \
}

#define debug_print_complexity()     debug_print("[Sink] Complexity: LoopLVL - [%d], BrLVL - [%d], SinkD - [%d], InstT - [%d] Blk - [%d] Func - [%d] Com - [%d] \n", \
                                                                                                                             this->status.loop_level,                \
                                                                                                                             this->status.branch_level,              \
                                                                                                                             this->status.num_sinks,                 \
                                                                                                                             this->status.tainted_exprs,             \
                                                                                                                             this->status.num_blocks,                \
                                                                                                                             this->status.num_funcs, get_current_complexity());

#ifdef USE_TAINTED_BRANCH_HEURISTIC
#warning taint expression heuristic
#define taint_expression(_expr, _taint) { \
     HLILComparableIL i; \
     i = _expr; \
     if (_taint & tmask){ \
       if (TaintedExprs.count(i)){ \
           if (TaintedExprs[i]) { \
            TaintedExprs[i] |= (_taint & tmask); \
           } \
       } \
       else { \
            TaintedExprs[i] = (_taint & tmask); \
       } \
     } else { \
       if (!this->status.in_branch){ \
          TaintedExprs[i] = 0 ;\
       } \
     } \
  } 
#else
#warning taint expression conservative
#define taint_expression(_expr, _taint) { \
     HLILComparableIL i; \
     i = _expr; \
     if (_taint & tmask){ \
       if (TaintedExprs.count(i)){ \
           if (TaintedExprs[i]) { \
            TaintedExprs[i] |= (_taint & tmask); \
           } \
       } \
       else { \
            TaintedExprs[i] = (_taint & tmask); \
       } \
     } else { \
        TaintedExprs[i] = 0;\
     }\
  }
#endif

#define is_deref(_instr) _instr.operation == HLIL_DEREF_SSA || _instr.operation == HLIL_DEREF_FIELD_SSA || _instr.operation == HLIL_ARRAY_INDEX_SSA || _instr.operation == HLIL_ARRAY_INDEX

unsigned int FunctionTaint::get_current_complexity(){
     TaintStatus status = this->status;
     return LOOP_COMPLEXITY * status.loop_level + BRANCH_COMPLEXITY * status.branch_level +
            BLOCK_COMPLEXITY * status.num_blocks + TAINT_INSTR_COMPLEXITY * status.tainted_exprs;
}

taint_t get_register_taint(uint32_t reg_idx){
    switch(reg_idx){
          case RBX:
                     return RBX_TAINT;
          case RBP: 
                     return RBP_TAINT;
          case R12:
                     return R12_TAINT;
          case R13:
                     return R13_TAINT;
          case R14:
                     return R14_TAINT;
          case R15:
                     return R15_TAINT;
          default:
                     return 0;
    }
}

static int taint_slot = MIN_STACK_TAINT_SLOT;
taint_t get_stack_taint(){
   taint_t stack_taint = 1 << taint_slot;

   if (taint_slot == MAX_STACK_TAINT_SLOT) {
       taint_slot = MIN_STACK_TAINT_SLOT;
       debug_print("[Reverse] Reusing stack colors\n");
   } else {
       taint_slot++;
   }

   return stack_taint;
}

uint32_t tmask = ~(POINTER_TAINT | VALUE_TAINT | TAINT_DIFFERS | INDEX_TAINT | BASE_TAINT | IB_DIFFERS);

string print_tainted_registers(uint32_t reg_taint){
   string register_str = "";
   if (reg_taint & RBX_TAINT){
      register_str += "RBX ";
   }

   if (reg_taint & RBP_TAINT){
      register_str += "RBP ";
   }

   if (reg_taint & R12_TAINT){
      register_str += "R12 ";
   }

   if (reg_taint & R13_TAINT){
      register_str += "R13 ";
   }

   if (reg_taint & R14_TAINT){
      register_str += "R14 ";
   }

   if (reg_taint & R15_TAINT){
      register_str += "R15 ";
   }

   for (auto i = MIN_STACK_TAINT_SLOT; i <= MAX_STACK_TAINT_SLOT; i++){
      taint_t tstack = 1 << i;
      if (reg_taint & tstack){
          register_str += "S" + to_string(i - MIN_STACK_TAINT_SLOT) + " "; 
      }
   }

   if (reg_taint & POINTER_TAINT){
      register_str += "P ";
   }

   if (reg_taint & VALUE_TAINT){
      register_str += "V ";
   }

   if (reg_taint & TAINT_DIFFERS){
      register_str += "D ";
   }

   if (reg_taint & BASE_TAINT){
      register_str += "B ";
   }

   if (reg_taint & INDEX_TAINT){
      register_str += "IN ";
   }

   if (reg_taint & IB_DIFFERS){
      register_str += "D ";
   }

   return register_str;
}

#define MAX_TAINT_LEVELS 2
#define MID_LEVEL 1

static inline int dec_level(int level){
     if (level < MAX_TAINT_LEVELS)
         return --level;
     return level;
}

static inline int inc_level(int level){
     if (level)
         return --level;
     return level;
}
unsigned int FunctionTaint::get_ssa_var_taint(SSAVariable var){
   string varName = function->GetVariableName(var.var);
   string SSAName = varName + "#" + std::to_string(var.version);
   /* If SSA variable is tainted then return its taint */
   if (TaintedVars.count(SSAName) != 0)
        return TaintedVars[SSAName];
   /* If not then no taint */
   return 0;
}

unsigned int FunctionTaint::get_var_taint(Variable var){
   string varName = function->GetVariableName(var);
   /* If SSA variable is tainted then return its taint */
   if (TaintedVars.count(varName) != 0)
        return TaintedVars[varName];
   /* If not then no taint */
   return 0;
}

void FunctionTaint::printFunctionName(const HighLevelILInstruction& instr){
    const HighLevelILInstruction il = instr.GetDestExpr();
    if (il.operation == HLIL_IMPORT || il.operation == HLIL_CONST_PTR || il.operation == HLIL_EXTERN_PTR){
       addr_t callee = il.GetConstant();
       Ref<Symbol> sym = bv->GetSymbolByAddress(callee);
       if (!sym)
           return;
       string sym_name = sym->GetFullName();

       debug_print("Tainted function name: %s (0x%lx)\n", sym_name.c_str(), this->func_addr);
    }
    
}

optional<string> FunctionTaint::getFunctionName(const HighLevelILInstruction& instr){
    if (instr.operation != HLIL_CALL_SSA && instr.operation != HLIL_TAILCALL)
        return nullopt;
    const HighLevelILInstruction il = instr.GetDestExpr();
    if (il.operation == HLIL_IMPORT || il.operation == HLIL_CONST_PTR || il.operation == HLIL_EXTERN_PTR){
       addr_t callee = il.GetConstant();
       Ref<Symbol> sym = bv->GetSymbolByAddress(callee);
       if (!sym) {
           std::stringstream stream;
           stream << std::hex << callee;
           std:string result(stream.str());
           return result;
       }
       string sym_name = sym->GetFullName();

       return sym_name;
    }
    return nullopt;
}

addr_t FunctionTaint::getFunctionAddress(const HighLevelILInstruction& instr){
    const HighLevelILInstruction il = instr.GetDestExpr();
    if (il.operation == HLIL_IMPORT || il.operation == HLIL_CONST_PTR || il.operation == HLIL_EXTERN_PTR){
       addr_t callee = il.GetConstant();
       return callee;
    }
    return 0;
}

static void init_complexity(Complexity &C, TaintStatus& status){
     C.loop_level = status.loop_level;
     C.branch_level = status.branch_level;
     C.num_sinks = status.num_sinks;
     C.tainted_exprs = status.tainted_exprs;
     C.num_blocks = status.num_blocks;
     C.num_funcs = status.num_funcs;
}

void FunctionTaint::printCallTaintSummary(const HighLevelILInstruction& instr, unsigned int target_taint, bool call_sink){
   if (target_taint){
      debug_print("[Sink] Tainted target call: (0x%lx) [%s]\n", this->func_addr, print_tainted_registers(target_taint).c_str());
      debug_print("[Sink] Complexity: LoopLVL - [%d], BrLVL - [%d], SinkD - [%d], InstT - [%d] Blk - [%d] Func - [%d] Com - [%d] \n",
                                                                                                     this->status.loop_level,
                                                                                                     this->status.branch_level,
                                                                                                     this->status.num_sinks,
                                                                                                     this->status.tainted_exprs,
                                                                                                     this->status.num_blocks,
                                                                                                     this->status.num_funcs, get_current_complexity());
      this->status.num_sinks++;
      
   } else {
      debug_print("[Function] Complexity: LoopLVL - [%d], BrLVL - [%d], SinkD - [%d], InstT - [%d] Blk - [%d] Func - [%d] Com - [%d] \n",
                                                                                                     this->status.loop_level,
                                                                                                     this->status.branch_level,
                                                                                                     this->status.num_sinks,
                                                                                                     this->status.tainted_exprs,
                                                                                                     this->status.num_blocks,
                                                                                                     this->status.num_funcs, get_current_complexity());
   }

   optional<string> fname = getFunctionName(instr);
   if (fname){
      if (call_sink) {
        debug_print("[Function][Sink] FunctionName: %s\n", fname.value().c_str());
      } else {
         bool prints = doesFunctionPrint(getFunctionAddress(instr));
         if (prints)
           debug_print("[Function][Check-Prints] FunctionName: %s\n", fname.value().c_str());
         else
           debug_print("[Function] FunctionName: %s\n", fname.value().c_str());
      }
   }
   debug_print("Tainted call:\n");
   PrintILExprHR(function, instr);
   PrintILExpr(instr, 0);

}

void FunctionTaint::printCallNoTaintSummary(const HighLevelILInstruction& instr){
   addr_t address = getFunctionAddress(instr);
   if (!this->notaintlist->count(address))
      return;
   optional<string> fname = getFunctionName(instr);
   if (fname){
      debug_print("[No-Taint] FunctionName: %s\n", fname.value().c_str());
   }

   debug_print("[No-Taint] Check call:\n");
   PrintILExprHR(function, instr);
   //PrintILExpr(instr, 0);
}

bool FunctionTaint::isDestInSource(const HighLevelILInstruction& instr){
  bool finished = false;
  const HighLevelILInstruction& src =  instr.GetSourceExpr<HLIL_ASSIGN_MEM_SSA>();
  const HighLevelILInstruction& dst =   instr.GetDestExpr<HLIL_ASSIGN_MEM_SSA>();
  HLILComparableIL dst_cmp;
  dst_cmp = dst;
  src.VisitExprs([&](const HighLevelILInstruction& expr) {
                 if (finished)
                    return false;
                 HLILComparableIL src_cmp;
                 src_cmp = expr;
                 if (src_cmp == dst_cmp){
                    finished = true;
                    return false;
                 }
                 return true;
        });

   return finished;

}

bool FunctionTaint::doesFunctionPrint(addr_t address) {
   // In case of an indirect call no point of printing.
   if (!address)
      return false;
   // If we already discovered this function no point in reanlyzing.
   if (printset->count(address))
      return (*printset)[address];
   Ref<Function> callee = bv->GetAnalysisFunction(bv->GetDefaultPlatform(), address);
   if (!callee)
      return false;
   Ref<HighLevelILFunction> il = callee->GetHighLevelIL()->GetSSAForm().GetPtr();
   bool prints = false;
   if (!il)
   {
      //debug_print("    Does not have HLIL\n\n");
      return false;
   }

   for (auto& block : il->GetBasicBlocks())
   {
	// Loop though each instruction in the block
	for (size_t instrIndex = block->GetStart(); instrIndex < block->GetEnd(); instrIndex++)
	{
	   // Fetch  HLIL instruction
	   HighLevelILInstruction instr = (*il)[instrIndex].GetSSAForm();
           instr.VisitExprs([&](const HighLevelILInstruction& expr) {
                 if (prints)
                    return false;
                 if (expr.operation == HLIL_CALL_SSA || expr.operation == HLIL_TAILCALL){
                     if (expr.GetDestExpr().operation == HLIL_CONST_PTR ||
                         expr.GetDestExpr().operation == HLIL_IMPORT ||
                         expr.GetDestExpr().operation == HLIL_EXTERN_PTR) {
                         addr_t the_call = expr.GetDestExpr().GetConstant();
                         if (leakset->count(the_call)){
                             prints = true;
                             return false;
                         }
                     }
                  
                 }
                 return true;

           });

	}
   }
   (*printset)[address] = prints;
   return prints;
}

void FunctionTaint::printMemoryTaintSummary(const HighLevelILInstruction& instr, unsigned int srcTaint, unsigned int destTaint){
   int level = 5;
   if (srcTaint && destTaint){
      // If we have at least one register taint different in the src and dest
      // this means that, to some degree we may be able to control both src and
      // dest separatelly.
      if ( (srcTaint & tmask) != (destTaint & tmask)) {
         if ((destTaint & INDEX_TAINT) && !(destTaint & BASE_TAINT)){
             //This means we only control the index (which means we can freely exploit
             //this sink without knowing ASLR.
             level = 1;
         } else if (destTaint & INDEX_TAINT){
             // We control the index. Perhaps we could control the index separately from
             // the base.
             level = 2;
         } else {
             level = 3;
         }
      } else {
        // If we control the src and destination via the same register set then the level of this
        // sink is 4 unless the destination is within the src. (this means that our write is actually
        // more constrainted than we thought).
        if (isDestInSource(instr)){
           //debug_print("Destination in source\n");
           level = 5;
        }
        else 
           level = 4;
      }
      // We have a write-what-where. 
      debug_print("[Sink] [Level %d] Tainted write-what-where: (0x%lx) where:[%s] what:[%s]\n", level, this->func_addr, print_tainted_registers(destTaint).c_str(), print_tainted_registers(srcTaint).c_str());
      debug_print("[Sink] Complexity: LoopLVL - [%d], BrLVL - [%d], SinkD - [%d], InstT - [%d] Blk - [%d] Func - [%d] Com - [%d] \n",
                                                                                                     this->status.loop_level,
                                                                                                     this->status.branch_level,
                                                                                                     this->status.num_sinks,
                                                                                                     this->status.tainted_exprs,
                                                                                                     this->status.num_blocks,
                                                                                                     this->status.num_funcs, get_current_complexity());
#if 0
      Sink sink(instr.address, WRITE_WHAT_WHERE_SINK);
      Complexity c;
      init_complexity(c, this->status);
      sink.complexity = c;
      sink.target_mask = destTaint;   
      sink.register_mask = srcTaint;
      sink.level = level;
      sink_list.push_back(sink);
#endif
      add_sink(instr, WRITE_WHAT_WHERE_SINK, destTaint, srcTaint, level);
      this->status.num_sinks++;
      // Write what and write-what-where should propagate another color (TAINTED_WRITE). 
      // We can control data using this sink.
   }
   else if (destTaint){
      // We have a write-where.
      if ((destTaint & INDEX_TAINT) && !(destTaint & BASE_TAINT)){
             //This means we only control the index (which means we can freely exploit
             //this sink without knowing ASLR.
             level = 1;
      } else if (destTaint & INDEX_TAINT){
             // We control the index. Perhaps we could control the index separately from
             // the base.
             level = 2;
      } else {
             level = 3;
      }
      debug_print("[Sink] [Level %d] Tainted write-where: (0x%lx) where:[%s]\n", level, this->func_addr, print_tainted_registers(destTaint).c_str());
      debug_print("[Sink] Complexity: LoopLVL - [%d], BrLVL - [%d], SinkD - [%d], InstT - [%d] Blk - [%d] Func - [%d] Com - [%d] \n", 
                                                                                                     this->status.loop_level,
                                                                                                     this->status.branch_level,
                                                                                                     this->status.num_sinks,
                                                                                                     this->status.tainted_exprs,
                                                                                                     this->status.num_blocks,
                                                                                                     this->status.num_funcs, get_current_complexity());
#if 0
      Sink sink(instr.address, WRITE_WHERE_SINK);
      Complexity c;
      init_complexity(c, this->status);
      sink.complexity = c;
      sink.target_mask = destTaint;   
      sink.register_mask = 0;
      sink.level = level;
      sink_list.push_back(sink);
#endif
      add_sink(instr, WRITE_WHERE_SINK, destTaint, 0, level);
      this->status.num_sinks++;
   }
   else if (srcTaint){
      // We have a write-what.
      debug_print("[Sink] Tainted write-what: (0x%lx) what:[%s]\n", this->func_addr, print_tainted_registers(srcTaint).c_str());
      debug_print("[Sink] Complexity: LoopLVL - [%d], BrLVL - [%d], SinkD - [%d], InstT - [%d] Blk - [%d] Func - [%d] Com - [%d] \n", 
                                                                                                     this->status.loop_level,
                                                                                                     this->status.branch_level,
                                                                                                     this->status.num_sinks,
                                                                                                     this->status.tainted_exprs,
                                                                                                     this->status.num_blocks,
                                                                                                     this->status.num_funcs, get_current_complexity());
#if 0   
      Sink sink(instr.address, WRITE_WHAT_SINK);
      Complexity c;
      init_complexity(c, this->status);
      sink.complexity = c;
      sink.target_mask = 0;   
      sink.register_mask = srcTaint;
      sink_list.push_back(sink);
#endif
      add_sink(instr, WRITE_WHAT_SINK, 0, srcTaint, 0);
      this->status.num_sinks++;
   }

   debug_print("Tainted mem assign:\n");
   PrintILExprHR(function, instr);
   PrintILExpr(instr, 0);
} 

#if 0
static inline bool should_follow_tail_call(TaintStatus &status){
    return status.num_blocks < 5 && status.num_tail_calls == 1 && status.num_funcs < 10 && status.last_tail_call.operation == HLIL_TAILCALL; 
}
#endif

std::optional<FunctionStackInfo> FunctionTaint::runAnalysis(){
   // TODO call runStackVulnerability analysis.
#ifdef DEBUG_MODULE
   Ref<Symbol> debug_sym = function->GetSymbol();
   string dbg_symbol = (debug_sym) ? debug_sym->GetFullName() : "";
   debug_print("Started running analysis on function -> function: (%s) address: (0x%lx) pid (%d)\n", dbg_symbol.c_str(), function->GetStart(), priv_ID);
#endif
   /* Taint parameters */
   taint_slot = MIN_STACK_TAINT_SLOT;
   setInitialTaintStateByModel(MODEL);
   optional<int> result = runTaintingPass();
#if 0
   if (should_follow_tail_call(this->status)){
      Ref<Function> prev = function;
      HighLevelILInstruction the_tail_call = this->status.last_tail_call;
      PrintILExprHR(function, the_tail_call);

      function = bv->GetAnalysisFunction(bv->GetDefaultPlatform(), getFunctionAddress(the_tail_call));
      // Reinitialize Tainted Variables
      // Reinitialize status.
      TaintedVars.clear();
      TaintedExprs.clear();
      memset(&(this->status), 0, sizeof(this->status));
      if (function){
         setInitialTailCallTaintState();
         runTaintingPass();
      } else {
        debug_print("Tail call unavailable!\n");
      }

      function = prev;
   }
#endif

#ifdef DEBUG_MODULE
   debug_print("Finished parsing function -> (%s)...\n", dbg_symbol.c_str());
#endif
   return nullopt;
}

// Iterate over arguments, find out which are callee saved and taint them
void FunctionTaint::setInitialTaintState(){
   // Get Function Parameters
   vector<Variable> params = function->GetParameterVariables().GetValue();

   for (auto param : params){
       debug_print("Storage: %ld (%s)\n", param.storage, function->GetVariableName(param).c_str());
       if ((param.type == RegisterVariableSourceType) && isCalleeSaved(param.storage)){
          string varName = function->GetVariableName(param);
          /* Add SSA 0 param to tainted Vars */
          string SSAName = varName + "#" + std::to_string(0);
          TaintedVars.insert(pair<std::string, unsigned int>(SSAName, get_register_taint(param.storage)));
          debug_print("Added SSA variable %s to list of tainted params\n", SSAName.c_str());
          TaintedVars.insert(pair<std::string, unsigned int>(varName, get_register_taint(param.storage)));
          debug_print("Added Normal variable %s to list of tainted params\n", varName.c_str());
       }
   }
}

void FunctionTaint::setInitialTaintStateByModel(unsigned int model){
   // Get Function Parameters
   vector<Variable> params = function->GetParameterVariables().GetValue();
   bool is_stack_model = (model / STACK_MODEL) == 1;
   unsigned int num_tainted_regs = model % STACK_MODEL;

   for (auto param : params){
       debug_print("Storage: %ld (%s)\n", param.storage, function->GetVariableName(param).c_str());
       if ((param.type == RegisterVariableSourceType) && isCalleeSavedN(param.storage, num_tainted_regs)){
          string varName = function->GetVariableName(param);
          /* Add SSA 0 param to tainted Vars */
          string SSAName = varName + "#" + std::to_string(0);
          TaintedVars.insert(pair<std::string, unsigned int>(SSAName, get_register_taint(param.storage)));
          debug_print("[Callee-Reg] Added SSA variable %s to list of tainted params\n", SSAName.c_str());
          TaintedVars.insert(pair<std::string, unsigned int>(varName, get_register_taint(param.storage)));
          debug_print("[Callee-Reg] Added Non-SSA variable %s to list of tainted params\n", varName.c_str());
       } else if ((param.type == StackVariableSourceType) && is_stack_model){
          string varName = function->GetVariableName(param);
          /* Add SSA 0 param to tainted Vars */
          string SSAName = varName + "#" + std::to_string(0);
          taint_t stack_taint = get_stack_taint();
          TaintedVars.insert(pair<std::string, unsigned int>(SSAName, stack_taint));
          debug_print("[Stack-Taint] Added SSA variable %s to list of tainted params\n", SSAName.c_str());
          TaintedVars.insert(pair<std::string, unsigned int>(varName, stack_taint));
          debug_print("[Stack-Taint] Added Non-SSA variable %s to list of tainted params\n", varName.c_str());
       }
   }
}

#if 0
void FunctionTaint::setInitialTailCallTaintState(Ref<Function> tailcall, Ref<Function> parent){
}
#endif

// Evaluate and return instruction taint 
// markVisited -> mark loop/branch block expressions as they will appear
// again in the basic block list following the branch.
unsigned int FunctionTaint::evalTaint(const HighLevelILInstruction& instr, bool markVisited){
    unsigned int exprTaint = 0;
    unsigned int taint_compute = 0;
    unsigned int target_taint = 0;
    bool call_sink = false;
    bool read_sink = false;
    bool in_assign = this->status.in_assign;
    // We don't want to evaluate taint on the full expression when we're in the
    // left hand side of a mem-assign else we would report an incorrect write-where
    // primitive. So in this case don't check the list of tainted expressions.
    // Check this however if we're evaluating the inner expressions of the left hand
    // side expression.
    this->status.in_assign = false;
    if (markVisited){
       // Skip HLIL_NOP and HLIL_BLOCK expressions as they are never visited again.
       VisitedExprs.insert(instr.exprIndex);
       //printf("Added expression %ld\n", instr.exprIndex);
    }

    switch (instr.operation){
         // TODO Check taint on return maybe?
         case HLIL_RET:
                           {
                            const auto &exprs = instr.GetSourceExprs<HLIL_RET>();
			    for (auto i = exprs.begin(); i != exprs.end(); ++i){
                                evalTaint(*i);
                            }
                           }
         case HLIL_MEM_PHI:
                           break;
         case HLIL_VAR_PHI:
                           {
                            const auto &vars = instr.GetSourceSSAVariables<HLIL_VAR_PHI>();
                            for (auto i = vars.begin(); i != vars.end(); ++i){
                               exprTaint |= get_ssa_var_taint(*i);
                            }
                           }
                           propagateTaint(instr.GetDestSSAVariable<HLIL_VAR_PHI>(), exprTaint);
                           // ADDRESS_OF tokens might use the normal variable form rather than the SSA form (keep the
                           // normal form updated with the latest SSA phi.
                           propagateTaint(instr.GetDestSSAVariable<HLIL_VAR_PHI>().var, exprTaint);
                           break;
         case HLIL_ASSIGN_UNPACK:
                           {
                           exprTaint = evalTaint(instr.GetSourceExpr<HLIL_ASSIGN_UNPACK>());
                           this->status.in_left_assign = true;
                           const auto &exprs = instr.GetDestExprs<HLIL_ASSIGN_UNPACK>();
			   for (auto i = exprs.begin(); i != exprs.end(); ++i){
				//TODO propagate taint on these expressions;
                              // this->status.in_assign = true;
                              // this->status.in_assign = false;
                              propagateTaint(*i, exprTaint);
                            }
                           this->status.in_left_assign = false;
                           }
                           break;
         case HLIL_ASSIGN_MEM_SSA:
                           {

                           exprTaint = evalTaint(instr.GetSourceExpr<HLIL_ASSIGN_MEM_SSA>());
                           // This is a sink so also propagate ADDRESS_OF when computing taint.
                           // On left-hand side we verify the taint of ssa variables in the computation
                           // not the taint of the actual expression.
                           HighLevelILInstruction dst = instr.GetDestExpr<HLIL_ASSIGN_MEM_SSA>();

                           this->status.in_assign = true;
                           this->status.in_left_assign = true;

                           //bool prev_address_of = this->status.eval_address_of;
                           //this->status.eval_address_of = true;

                           taint_compute = evalTaint(dst, false);
                           
                           this->status.in_left_assign = false;

                           //this->status.eval_address_of = prev_address_of;



                           // Add the tainted/untainted expression in a list of tainted/untainted exprs.
#if 0
                           HLILComparableIL i;
                           i = dst;
                           if (TaintedExprs.count(i)){
                              // zero out INDEX, VALUE, BASE, POINTER colors when propagating taint to an expression.
                              // We only need these to make sense of immediate sink expressions.
                              TaintedExprs[i] |= (exprTaint & tmask);
                           } else {
                              if (!exprTaint && this->status.in_branch){
                                 // Don't kill taint on the expression (this is kind of
                                 // an analogy for value) if this happens on a branch.
                                 // In this case
                                 debug_print("MA:Expression %ld must be skipped\n", i.il.exprIndex);
                              } else {
                                 // Add/Remove taint
                                 TaintedExprs[i] = (exprTaint & tmask);
                              }
                           }
#endif
                           taint_expression(dst, exprTaint); 
                           }
                           break;
         case HLIL_ASSIGN_UNPACK_MEM_SSA:
                           debug_print("Unhandled HLIL_ASSIGN_UNPACK_MEM_SSA: %d\n", instr.operation);
                           break;
         /* Some instructions use actual variables which are not in SSA form. Assume SSA version
            0 in this case. */
         case HLIL_VAR:
                           return get_var_taint(instr.GetVariable<HLIL_VAR>());
         case HLIL_VAR_SSA:
                           return get_ssa_var_taint(instr.GetSSAVariable<HLIL_VAR_SSA>());                        
         case HLIL_ASSIGN:
                           exprTaint = evalTaint(instr.GetSourceExpr<HLIL_ASSIGN>());
                           // TODO check if the destination is tainted.
                           // Propagate source expression taint to destination
                           propagateTaint(instr.GetDestExpr<HLIL_ASSIGN>(), exprTaint);
                           break;
         case HLIL_VAR_INIT_SSA:
                           exprTaint = evalTaint(instr.GetSourceExpr<HLIL_VAR_INIT_SSA>());
                           propagateTaint(instr.GetDestSSAVariable<HLIL_VAR_INIT_SSA>(), exprTaint);
                           break;
         case HLIL_VAR_INIT:
                           exprTaint = evalTaint(instr.GetSourceExpr<HLIL_VAR_INIT>());
                           propagateTaint(instr.GetDestVariable<HLIL_VAR_INIT>(), exprTaint);
                           break;
         /* Blocks */
         case HLIL_BLOCK:
                           {
                           const auto &exprs = instr.GetBlockExprs<HLIL_BLOCK>();
			   for (auto i = exprs.begin(); i != exprs.end(); ++i){
                               // If we mix taint here we could also print
                               // block structures such as ifs or switch-case
                               // statements during taint dumping.
                               taint_compute = evalTaint(*i);
                               // Add i to the list of visited expressions so we 
                               // don't retaint the block we rediscover
                               // the block in the outer loop.
                               if (markVisited){
                                   //printf("Added expression %ld\n", (*i).exprIndex);
                                   VisitedExprs.insert((*i).exprIndex);
                               }
                            }
                           }
                           return taint_compute;
         /* Conditionals */
         case HLIL_IF:
                           /* For if expressions combine the taint on the true/false branches */
                           {
                           unsigned int branch_taint = evalTaint(instr.GetConditionExpr<HLIL_IF>());
                           bool prev_in_branch = this->status.in_branch;
                           // If we have taint only on the inner most branch then use heuristic
                           if (branch_taint & tmask){
                               this->status.in_branch = true;
                           } else {
                               this->status.in_branch = false;
                           }
                           this->status.branch_level++;
                           exprTaint = evalTaint(instr.GetTrueExpr<HLIL_IF>(), true);
                           exprTaint |= evalTaint(instr.GetFalseExpr<HLIL_IF>(), true);
                           this->status.in_branch = prev_in_branch;
                           this->status.branch_level--;
                           // TODO check if condition is tainted.
                           }
                           break;
         case HLIL_SWITCH:
                           {
                           // TODO remove taint_compute from block statements. Only used
                           // to dump the CFG around a tainted instruction.
                           unsigned int branch_taint = evalTaint(instr.GetConditionExpr<HLIL_SWITCH>());
                           bool prev_in_branch = this->status.in_branch;
                           if (branch_taint & tmask){
                              this->status.in_branch = true;
                           } else {
                              this->status.in_branch = false;
                           }
                           this->status.branch_level++;
                           taint_compute = evalTaint(instr.GetDefaultExpr<HLIL_SWITCH>());
                           const auto &exprs = instr.GetCases<HLIL_SWITCH>();
			   for (auto i = exprs.begin(); i != exprs.end(); ++i){
                                taint_compute |= evalTaint(*i, true);
                            }
                           this->status.in_branch = prev_in_branch;
                           this->status.branch_level--;
                           }
                           break;

         case HLIL_CASE:
                           exprTaint = evalTaint(instr.GetTrueExpr<HLIL_CASE>(), true);
                           break;
         case HLIL_WHILE_SSA:
                           // First eval the taint on the PHI (this will also propagate taint on any phis used in the loop).
                           taint_compute = evalTaint(instr.GetConditionPhiExpr<HLIL_WHILE_SSA>());
                           // TODO evaluate condition (to gather branch constraints).
                           {
                           this->status.loop_level++;
                           exprTaint = evalTaint(instr.GetLoopExpr<HLIL_WHILE_SSA>(), true);
                           this->status.loop_level--;
                           }
                           // TODO Reevaluate phi condition and see if anything changed in phi taint (if something changed
                           // perhaps it would be good to reevaluate the loop).
                           break;
         case HLIL_DO_WHILE_SSA:
                           {
                           // Eval loop first
                           this->status.loop_level++;
                           exprTaint = evalTaint(instr.GetLoopExpr<HLIL_DO_WHILE_SSA>(), true);
                           this->status.loop_level--;
                           // Propagate taint on phi nodes.
                           taint_compute = evalTaint(instr.GetConditionPhiExpr<HLIL_DO_WHILE_SSA>());
                           // TODO If we have taint on phi condition then perhaps reevaluate loop once more.
                           // TODO evaluate condition (to gather branch constraints).
                           }
                           break;

         case HLIL_FOR_SSA:
                           {
                           this->status.loop_level++;
                           evalTaint(instr.GetInitExpr<HLIL_FOR_SSA>());
                           taint_compute = evalTaint(instr.GetConditionPhiExpr<HLIL_FOR_SSA>());
                           exprTaint = evalTaint(instr.GetLoopExpr<HLIL_FOR_SSA>(), true);
                           this->status.loop_level--;
                           }
                           VisitedExprs.insert(instr.GetUpdateExpr<HLIL_FOR_SSA>().exprIndex);
                           // TODO Evaluate branch ?
                           break;

         case HLIL_JUMP:
                           // Get and check taint on the jump target (TODO make it a sink).
                           {
                           bool prev_address_of = this->status.eval_address_of;
                           this->status.eval_address_of = true;

                           target_taint = evalTaint(instr.AsOneOperand().GetSourceExpr(), false); 

                           this->status.eval_address_of = prev_address_of;


                           if (target_taint){
                               debug_print("[Sink] Tainted jump: (0x%lx) [%s]\n", this->func_addr, print_tainted_registers(target_taint).c_str());
                               debug_print("[Sink] Complexity: LoopLVL - [%d], BrLVL - [%d], SinkD - [%d], InstT - [%d] Blk - [%d] Func - [%d] Com - [%d] \n", 
                                                                                                                             this->status.loop_level,
                                                                                                                             this->status.branch_level,
                                                                                                                             this->status.num_sinks,
                                                                                                                             this->status.tainted_exprs,
                                                                                                                             this->status.num_blocks,
                                                                                                                             this->status.num_funcs, get_current_complexity());
                               this->status.num_sinks++;
#if 0 
                               Sink sink(instr.address, ITARGET_SINK);
                               Complexity c;
                               init_complexity(c, this->status);
                               sink.complexity = c;
                               sink.target_mask = target_taint;   
                               sink.register_mask = 0;
                               sink_list.push_back(sink);
#endif
                               add_sink(instr, ITARGET_SINK, target_taint, 0, 0);
                           }          
                           exprTaint = 0;
                           }
                           break; 
         case HLIL_ADDRESS_OF:
                           // TODO (here if the source is a SSA variable this does not imply 
                           // that the address of the variable is tainted).
                           {
                           exprTaint = 0;
                           compute_value_taint(exprTaint, instr);
                           // TODO we modified this (might overtaint now).
                           const auto &expr = instr.GetSourceExpr<HLIL_ADDRESS_OF>();
                           if (this->status.eval_address_of || is_deref(expr)){
                              exprTaint |= evalTaint(expr, false);
                           }
                           }
                           break;
         case HLIL_DEREF_SSA:
                           // TODO make this a sink.
                           {
                           compute_value_taint(taint_compute, instr);
                           bool prev_in_deref = this->status.in_deref;
                           this->status.in_deref = true;

                           exprTaint = evalTaint(instr.GetSourceExpr<HLIL_DEREF_SSA>(), false);

                           this->status.in_deref = prev_in_deref;
                           if (exprTaint && !this->status.in_left_assign && !prev_in_deref) {
                              add_sink(instr, READ_SINK, 0, exprTaint, 0); 
                              read_sink = true;
                           }   
                           mark_pointer_value_taint(exprTaint, taint_compute);
                           }
                           break; 
         case HLIL_DEREF_FIELD_SSA:
                           // TODO make this a sink.
                           {
                           compute_value_taint(taint_compute, instr);
                           bool prev_in_deref = this->status.in_deref;
                           this->status.in_deref = true;

                           exprTaint = evalTaint(instr.GetSourceExpr<HLIL_DEREF_FIELD_SSA>(), false);

                           this->status.in_deref = prev_in_deref;

                           if (exprTaint && !this->status.in_left_assign && !prev_in_deref) {
                              add_sink(instr, READ_SINK, 0, exprTaint, 0); 
                              read_sink = true;
                           }              
                           mark_pointer_value_taint(exprTaint, taint_compute);
                           }
                           break;
         case HLIL_ARRAY_INDEX_SSA:
                           // TODO make this a sink.
                           // TODO make this a sink.
                           {
                           compute_value_taint(taint_compute, instr);
#ifdef TRACK_INDEX_TAINT
                           bool prev_array_status = this->status.in_array_index;
                           this->status.in_array_index = true;
#endif

                           unsigned int index_taint = evalTaint(instr.GetIndexExpr<HLIL_ARRAY_INDEX_SSA>());

                           bool prev_in_deref = this->status.in_deref;
                           this->status.in_deref = true;

                           unsigned int base_taint = evalTaint(instr.GetSourceExpr<HLIL_ARRAY_INDEX_SSA>(), false);

                           this->status.in_deref = prev_in_deref;

                           exprTaint = index_taint | base_taint;

                           if (exprTaint && !this->status.in_left_assign && !prev_in_deref) {
                              add_sink(instr, READ_SINK, 0, exprTaint, 0); 
                              read_sink = true;
                           }   
#ifdef TRACK_INDEX_TAINT
                           this->status.in_array_index = prev_array_status;
#endif

                           mark_pointer_value_taint(exprTaint, taint_compute);

#ifdef TRACK_INDEX_TAINT
                           // If we are in the first array index.
                           if (!prev_array_status) {
                                 if (index_taint && base_taint && ((index_taint & tmask) != (base_taint & tmask))){
                                    exprTaint |= IB_DIFFERS;
                                 }

                                 if (base_taint){
                                     exprTaint |= BASE_TAINT;
                                 }

                                 if (index_taint){
                                     exprTaint |= INDEX_TAINT;
                                 }

                            }
#endif
                           }

                           break;
         case HLIL_ARRAY_INDEX:
                           {
                           // TODO make this a sink.
#ifdef TRACK_INDEX_TAINT
                           bool prev_array_status = this->status.in_array_index;
                           this->status.in_array_index = true;
#endif
                           taint_compute = evalTaint(instr.GetIndexExpr<HLIL_ARRAY_INDEX>());

                           bool prev_in_deref = this->status.in_deref;
                           this->status.in_deref = true;

                           exprTaint = evalTaint(instr.GetSourceExpr<HLIL_ARRAY_INDEX>(), false);

                           this->status.in_deref = prev_in_deref;
#ifdef TRACK_INDEX_TAINT
                           this->status.in_array_index = prev_array_status;

                           // If we are in the first array index.
                           if (!prev_array_status) {
                                if (taint_compute && exprTaint && ((taint_compute & tmask) != (exprTaint & tmask))){
                                   exprTaint |= IB_DIFFERS;
                                }

                                if (exprTaint){
                                   exprTaint |= BASE_TAINT;
                                }

                                if (taint_compute){
                                   exprTaint |= INDEX_TAINT;
                                }

                            }
#endif
                           
                           exprTaint |= taint_compute;

                           if ((exprTaint & tmask) && !this->status.in_left_assign && !prev_in_deref) {
                              add_sink(instr, READ_SINK, 0, exprTaint, 0); 
                              read_sink = true;
                           }

                           } 

                           break;

         case HLIL_STRUCT_FIELD:
                           // Overtainting here.
                           {
                           compute_value_taint(taint_compute, instr);
                           exprTaint = evalTaint(instr.GetSourceExpr<HLIL_STRUCT_FIELD>(), false);
                           mark_pointer_value_taint(exprTaint, taint_compute);
                           }
                           break;
         case HLIL_SPLIT:
                           exprTaint = evalTaint(instr.GetLowExpr<HLIL_SPLIT>(), false);
                           exprTaint |= evalTaint(instr.GetHighExpr<HLIL_SPLIT>(), false);
                           break;             
         case HLIL_TAILCALL:
                           // TODO check argument taint and target taint.
                           {
                           const auto &exprs = instr.GetParameterExprs<HLIL_TAILCALL>();
                           vector<pair<int, int>> params;

                           bool prev_address_of = this->status.eval_address_of;
                           this->status.eval_address_of = true;

                           taint_params(taint_compute, params, exprs);

                           // TODO perhaps taint the return if any of the params are tainted.
                           target_taint = evalTaint(instr.GetDestExpr<HLIL_TAILCALL>(), false);

                           this->status.eval_address_of = prev_address_of;

                           if (target_taint){
#if 0
                                  Sink sink(instr.address, ICALL_SINK);
                                  Complexity c;
                                  init_complexity(c, this->status);
                                  sink.complexity = c;
                                  sink.target_mask = target_taint;   
                                  sink.register_mask = taint_compute;
                                  sink_list.push_back(sink);
#endif
                                  add_sink(instr, ICALL_SINK, target_taint, taint_compute, 0);
                           }
#ifdef DEBUG_MODULE
                           if (taint_compute){

                              print_tainted_params();
                              
                            }

#endif
                            this->status.num_funcs++;

                           }
                           break;
         case HLIL_CALL_SSA:
                           // TODO check argument taint and target taint.
                           {
                           const auto &exprs = instr.GetParameterExprs<HLIL_CALL_SSA>();
                           vector<pair<int, int>> params;

                           bool prev_address_of = this->status.eval_address_of;
                           this->status.eval_address_of = true;

                           taint_params(taint_compute, params, exprs);

                           // TODO perhaps taint the return if any of the params are tainted.
                           target_taint = evalTaint(instr.GetDestExpr<HLIL_CALL_SSA>(), false);

                           this->status.eval_address_of = prev_address_of;
                           
                           if (target_taint){
#if 0
                                  Sink sink(instr.address, ICALL_SINK);
                                  Complexity c;
                                  init_complexity(c, this->status);
                                  sink.complexity = c;
                                  sink.target_mask = target_taint;   
                                  sink.register_mask = taint_compute;
                                  sink_list.push_back(sink);
#endif
                                  add_sink(instr, ICALL_SINK, target_taint, taint_compute, 0);
                           }
#ifdef DEBUG_MODULE
                           if (taint_compute){

                              print_tainted_params();
                              

#ifdef PROPAGATE_TAINT_ON_WHITELIST
                              addr_t address = getFunctionAddress(instr);
                              if (taint_compute && uafset && address && uafset->count(address)){
#if 0
                                    Sink sink(instr.address, DELETE_SINK);
                                    Complexity c;
                                    init_complexity(c, this->status);
                                    sink.complexity = c; 
                                    optional<string> func = getFunctionName(instr);
                                    if (func.has_value()){
                                       sink.callee_name = func.value();
                                    }
                                    sink.target_mask = 0;   
                                    sink.register_mask = taint_compute;
                                    sink_list.push_back(sink);       
#endif                             
                                    add_named_sink(instr, DELETE_SINK, 0, taint_compute, 0);
                                                              
                              }
                              if (whitelist && address && whitelist->count(address)){
                                   unsigned int propagated_taint = 0;
                                   for (auto &i : params){
                                      if (i.first)
                                        propagated_taint |= i.second;
                                   }
                                  auto i = exprs.begin();
                                  propagateTaint(*i, propagated_taint, TAINT_DEREF);
                              }
                              // If we have taint on anything else but the first param and this is in the leak set investigate further.
                              if (leakset && address && leakset->count(address)){
                                   unsigned int propagated_taint = 0;
                                   for (auto &i : params){
                                      if (i.first)
                                        propagated_taint |= i.second;
                                   }

                                   if (propagated_taint) {
                                       call_sink = true;
#if 0
                                       Sink sink(instr.address, LEAK_SINK);
                                       Complexity c;
                                       init_complexity(c, this->status);
                                       sink.complexity = c; 
                                       optional<string> func = getFunctionName(instr);
                                       if (func.has_value()){
                                           sink.callee_name = func.value();
                                       } 
                                       sink.target_mask = 0;   
                                       sink.register_mask = propagated_taint;
                                       sink_list.push_back(sink);
#endif 
                                       add_named_sink(instr, LEAK_SINK, 0, propagated_taint, 0);
                                   }
                              }

#endif

                            }
#endif
                            this->status.num_funcs++;
                           }
                           break;
         case HLIL_SYSCALL_SSA:
                           {
                           // TODO check argument taint and target taint.
                           const auto &exprs = instr.GetParameterExprs<HLIL_SYSCALL_SSA>();
                           vector<pair<int, int>> params;

                           bool prev_address_of = this->status.eval_address_of;
                           this->status.eval_address_of = true;

                           taint_params(taint_compute, params, exprs);

                           this->status.eval_address_of = prev_address_of;

                           if (taint_compute){

                              debug_print("[Sink] ");
                              print_tainted_params();

                              debug_print("[Sink] Complexity: LoopLVL - [%d], BrLVL - [%d], SinkD - [%d], InstT - [%d] Blk - [%d] Func - [%d] Com - [%d] \n", 
                                                                                                                             this->status.loop_level,
                                                                                                                             this->status.branch_level,
                                                                                                                             this->status.num_sinks,
                                                                                                                             this->status.tainted_exprs,
                                                                                                                             this->status.num_blocks,
                                                                                                                             this->status.num_funcs, get_current_complexity());
                            }
                            this->status.num_funcs++;
                           }
                           break;     
         /* Unhandled expressions (no taint) */
         case HLIL_LABEL:
         case HLIL_GOTO:
         case HLIL_VAR_DECLARE:
         case HLIL_NOP:
         case HLIL_UNDEF:
         case HLIL_UNIMPL:
         case HLIL_BP:
         case HLIL_NORET:
         case HLIL_BREAK:
         case HLIL_CONTINUE:
         case HLIL_INTRINSIC_SSA:
         case HLIL_TRAP:
         case HLIL_UNIMPL_MEM:
                             exprTaint = 0;
                             break;

         /* Const expressions (no taint) */
         case HLIL_CONST:
         case HLIL_CONST_PTR:
         case HLIL_EXTERN_PTR:
         case HLIL_FLOAT_CONST:
         case HLIL_IMPORT:
                             exprTaint = 0;
                             break;
         /* Unary operators */	
	 case HLIL_NEG:
	 case HLIL_NOT:
	 case HLIL_SX:
	 case HLIL_ZX:
	 case HLIL_LOW_PART:
	 case HLIL_BOOL_TO_INT:
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
                             exprTaint = evalTaint(instr.AsOneOperand().GetSourceExpr(), false); 
                             break;
         /* Binary operators */
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
	 case HLIL_ADD_OVERFLOW:
	 case HLIL_FADD:
	 case HLIL_FSUB:
	 case HLIL_FMUL:
	 case HLIL_FDIV:
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
	 case HLIL_FCMP_E:
	 case HLIL_FCMP_NE:
	 case HLIL_FCMP_LT:
	 case HLIL_FCMP_LE:
	 case HLIL_FCMP_GE:
	 case HLIL_FCMP_GT:
	 case HLIL_FCMP_O:
	 case HLIL_FCMP_UO:
                          exprTaint = evalTaint(instr.AsTwoOperand().GetRightExpr(), false);
                          exprTaint |= evalTaint(instr.AsTwoOperand().GetLeftExpr(), false);
                          break;
         /*  Binary operators with carry */
	 case HLIL_ADC:
	 case HLIL_SBB:
	 case HLIL_RLC:
	 case HLIL_RRC:
                          exprTaint = evalTaint(instr.AsTwoOperandWithCarry().GetRightExpr(), false);
                          exprTaint |= evalTaint(instr.AsTwoOperandWithCarry().GetLeftExpr(), false);
                          break; 


         // TODO how to handle HLIL_SPLIT and HLIL_STRUCT_FIELD?
         default:
                    printf("Unhandled instruction: %d\n", instr.operation);
                    PrintILExpr(instr, 0);
                    exprTaint = 0;
                          
    }

#ifdef DEBUG_MODULE
    if (read_sink && (is_deref(instr))){
         debug_print("Tainted read:\n");
         PrintILExprHR(function, instr);
         PrintILExpr(instr, 0);
         this->status.tainted_exprs++;
         return exprTaint; 
        
    }
    if (exprTaint && instr.operation != HLIL_WHILE_SSA 
                  && instr.operation != HLIL_FOR_SSA 
                  && instr.operation != HLIL_DO_WHILE_SSA 
                  && instr.operation != HLIL_IF
                  && instr.operation != HLIL_ASSIGN_MEM_SSA
                  && instr.operation != HLIL_CASE
                  && instr.operation != HLIL_SWITCH) {
         debug_print("Tainted instr:\n");
         PrintILExprHR(function, instr);
         PrintILExpr(instr, 0);
         this->status.tainted_exprs++;
         return exprTaint;
    }

    if ((taint_compute || target_taint) && ( instr.operation == HLIL_CALL_SSA 
                  || instr.operation == HLIL_TAILCALL 
                  || instr.operation == HLIL_SYSCALL_SSA) ) {
         printCallTaintSummary(instr, target_taint, call_sink);
         this->status.tainted_exprs++;
         return taint_compute;
    }

    if  (instr.operation == HLIL_CALL_SSA
                  || instr.operation == HLIL_TAILCALL
                  || instr.operation == HLIL_SYSCALL_SSA) {
        printCallNoTaintSummary(instr);
        return exprTaint;
    }

    if (target_taint &&  instr.operation == HLIL_JUMP) {
         debug_print("Tainted jump:\n");
         PrintILExprHR(function, instr);
         PrintILExpr(instr, 0);
         this->status.tainted_exprs++;
         return exprTaint;
    }

    if ((taint_compute | exprTaint) &&  instr.operation == HLIL_ASSIGN_MEM_SSA) {
         printMemoryTaintSummary(instr, exprTaint, taint_compute);
         this->status.tainted_exprs++;
         return exprTaint;
    }
#endif
    //printf("Visited expression:\n");
    //PrintILExpr(instr, 0);
    return exprTaint;
}
/*
   pointers : HLIL_ADDRESS_OF
   normal: HLIL_STRUCT_FIELD
   derefs: HLIL_DEREF, HLIL_DEREF_FIELD, HLIL_ARRAY_INDEX, HLIL_ARRAY_INDEX_SSA
   
   ASSIGN: HLIL_VAR_SSA, HLIL_VAR, HLIL_SPLIT, HLIL_STRUCT
           

   ASSIGN_MEM: HLIL_ARRAY_INDEX_SSA -> followed only by VAR and SSA_VAR
               HLIL_DEREF_FIELD_SSA -> followed only by SSA_VAR
               HLIL_DEREF -> followed by VAR and SSA_VAR. (

*/
// Propagate new taint. Handles only HLIL_ASSIGN instructions at the moment.
void FunctionTaint::propagateTaint(const HighLevelILInstruction& instr, unsigned int taint, taint_type type){
   switch (instr.operation){
         case HLIL_VAR_SSA:
                          propagateTaint(instr.GetSSAVariable<HLIL_VAR_SSA>(), taint, type);
                          break;
         case HLIL_VAR:
                          propagateTaint(instr.GetVariable<HLIL_VAR>(), taint, type);
                          break;
         case HLIL_SPLIT:
                          /* With split propagate taint on both high/low chunks of the split. These 
                             should be SSA variables */
                          propagateTaint(instr.GetLowExpr<HLIL_SPLIT>(), taint, type);
                          propagateTaint(instr.GetHighExpr<HLIL_SPLIT>(), taint, type);
                          break;
         case HLIL_STRUCT_FIELD:
                           /* Bit more complicated to handle */
                          {

                          const auto &expr = instr.GetSourceExpr<HLIL_STRUCT_FIELD>();

                          if (expr.operation == HLIL_VAR || expr.operation == HLIL_VAR_SSA ){
                              /* Just propagate taint to the entire variable. Normally only part
                                 of the SSA variable will be tainted here, however just propagate
                                 to the entire variable. Consider checking if we have scenarios where
                                 multiple parts of the same SSA variable are tainted independently. In
                                 that case perhaps we want to mix taint rather than replacing old taint.
                                 Intuition is that the SSA counter will change on a next field assign.
                                 For normal variables this may not stand. */
                              propagateTaint(expr, taint);
                              return;
                          }

                          /* If we don't have HLIL_VAR or HLIL_VAR_SSA then we have HLIL_ARRAY_INDEX_SSA,
                             HLIL_DEREF_FIELD_SSA or HLIL_STRUCT_FIELD */
#if 0
                          HLILComparableIL i;
                          i = expr;
                          // Taint this expression (or set to 0 in case no taint)
                          if (TaintedExprs.count(i)){
                              //If we previously had taint on this expression just mix it.
                              TaintedExprs[i] |= (taint & tmask);
                          } else {
                              if (!taint && this->status.in_branch){
                                 // Don't kill taint on deref expertions if this happens on a branch.
                                 // Tells us which branches we might need to skip in order to
                                 // not kill a specific deref taint (in case we need it).
                                 debug_print("TP:Expression %ld must be skipped\n", i.il.exprIndex);
                              } else {
                                 // Add/Remove taint
                                 TaintedExprs[i] = (taint & tmask);
                              }
                          }
#endif
                          taint_expression(expr, taint);
                          // If not just add the expression to the list of tainted expressions.
                          // TODO all other instructions just propagate taint on the expression.
                          //printf("Unhandled HLIL_STRUCT_FIELD propagation: %d\n", instr.operation);
                          //PrintILExpr(instr, 0);
                          }
                          break;
         case HLIL_ADDRESS_OF:
                          {
                              HLILComparableIL i;
                              // Just overwrite taint on HLIL_ADDRESS_OF
                              TaintedExprs[i] = (taint & tmask);

                          }
                          break;
                  
         default:
                   debug_print("Unhandled general propagation: %d\n", instr.operation);
                   PrintILExpr(instr, 0);
   }
}

void FunctionTaint::propagateTaint(const SSAVariable& var, unsigned int taint, taint_type type){

#ifdef PROPAGATE_ALL_MEM_ASSIGNS
   taint &= ~(POINTER_TAINT | VALUE_TAINT | TAINT_DIFFERS);
#endif

#ifdef TRACK_INDEX_TAINT
   taint &= ~(INDEX_TAINT | BASE_TAINT | IB_DIFFERS);
#endif
   if (!taint)
       return;
   string varName = function->GetVariableName(var.var);

   string prefix = "";
#if 0 
   if (type == TAINT_DEREF){
      prefix = "*";
   } else if (type == TAINT_PTR) {
      prefix = "&";
   }
#endif
   string SSAName = prefix + varName + "#" + std::to_string(var.version);
   if (type == TAINT_SSA){
     TaintedVars.insert(pair<std::string, unsigned int>(SSAName, taint));
     debug_print("[Propagate] Propagated taint to variable SSA %s [%s]\n", SSAName.c_str(), print_tainted_registers(TaintedVars[SSAName]).c_str());
   } else if (type == TAINT_DEREF) {
     if (TaintedVars.count(SSAName)){
         TaintedVars[SSAName] |= taint;
     } else {
         TaintedVars[SSAName] = taint;
     }
     debug_print("[Propagate-whitelist] Propagated taint to variable SSA %s [%s]\n", SSAName.c_str(), print_tainted_registers(TaintedVars[SSAName]).c_str());
   }
}

void FunctionTaint::propagateTaint(const Variable& var, unsigned int taint, taint_type type){
#ifdef PROPAGATE_ALL_MEM_ASSIGNS
   taint &= ~(POINTER_TAINT | VALUE_TAINT | TAINT_DIFFERS);
#endif

#ifdef TRACK_INDEX_TAINT
   taint &= ~(INDEX_TAINT | BASE_TAINT | IB_DIFFERS);
#endif

   string varName = function->GetVariableName(var);
   string prefix = "";
#if 0
   if (type == TAINT_DEREF){
      prefix = "*";
   } else if (type == TAINT_PTR) {
      prefix = "&";
   }
#endif
   string fullName = prefix + varName;

   if (!taint) {
      if (TaintedVars.count(fullName)){
         debug_print("[Propagate] Erased taint from variable %s\n", fullName.c_str());
         TaintedVars.erase(fullName);
      }
      return;
   }
   TaintedVars.insert(pair<std::string, unsigned int>(fullName, taint));
   debug_print("[Propagate] Propagated taint to variable %s [%s]\n", fullName.c_str(), print_tainted_registers(TaintedVars[fullName]).c_str());
}


/* Determine frame size based on number of pushes + sub rsp in the prologue.
   Should work for X86_64 but for 32bits some changes will be necessary.
   TODO there are other approaches to compute all possible unwinding states
   for a specific function frame, but the max size of the frame is probably 
   what will be used when unwinding from most catch blocks. */
optional<int> FunctionTaint::runTaintingPass(){
   if (!function->GetHighLevelIL()){
      debug_print("    Check:Does not have HLIL\n\n");
      return nullopt;
   }
   Ref<HighLevelILFunction> il = function->GetHighLevelIL()->GetSSAForm().GetPtr();
   if (!il)
   {
      debug_print("    Does not have HLIL\n\n");
      return nullopt;
   }

   func_addr = function->GetStart();

   for (auto& block : il->GetBasicBlocks())
   {
	// Loop though each instruction in the block
	for (size_t instrIndex = block->GetStart(); instrIndex < block->GetEnd(); instrIndex++)
	{
	   // Fetch  HLIL instruction
	   HighLevelILInstruction instr = (*il)[instrIndex].GetSSAForm();

           if (VisitedExprs.count(instr.exprIndex)){
               VisitedExprs.erase(instr.exprIndex);
               continue;
           }
           //PrintILExpr(instr, 0);
           unsigned int taint = evalTaint(instr, false);
           //this->status.last_tail_call = instr;

	}
        this->status.num_blocks++;
   }
   return 0;

}
set<addr_t> HandlerAnalysis::construct_whitelist(Ref<BinaryView> &bv){
    BVHelper helper(bv);
    set<addr_t> whitelist;
    for (auto &function_name : WHITE_LIST) {
        addr_t func_addr = helper.getFunctionByName(function_name);
        if (func_addr){
            debug_print("[TAINT_PROPAGATION_WHITELIST] Inserted function %s 0x%lx in the whitelist\n", function_name.c_str(), func_addr);
            whitelist.insert(func_addr);
        }
    }
    return whitelist;
}

set<addr_t> HandlerAnalysis::construct_notaintlist(Ref<BinaryView> &bv){
    BVHelper helper(bv);
    set<addr_t> whitelist;
    for (auto &function_name : NO_TAINT_LIST) {
        addr_t func_addr = helper.getFunctionByName(function_name);
        if (func_addr){
            debug_print("[NO_TAINTLIST] Inserted function %s 0x%lxin the notaintlist\n", function_name.c_str(), func_addr);
            whitelist.insert(func_addr);
        }
    }
    return whitelist;
}

set<addr_t> HandlerAnalysis::construct_leakset(Ref<BinaryView> &bv){
    BVHelper helper(bv);
    set<addr_t> whitelist;
    for (auto &function_name : LEAK_LIST) {
        addr_t func_addr = helper.getFunctionByName(function_name);
        if (func_addr){
            debug_print("[LEAK_SET] Inserted function %s 0x%lx in the leakset\n", function_name.c_str(), func_addr);
            whitelist.insert(func_addr);
        }
    }
    return whitelist;
}

void HandlerAnalysis::construct_noreturn_list(Ref<BinaryView> &bv){
    BVHelper helper(bv);
    for (auto &function_name : NO_RETURNS) {
        addr_t func_addr = helper.getFunctionByName(function_name);
        if (func_addr){
            Ref<Function> func = bv->GetAnalysisFunction(bv->GetDefaultPlatform(), func_addr);
            if (func){
                 debug_print("[NO_RETURNS] Inserted function %s 0x%lx in the noreturn list\n", function_name.c_str(), func_addr);
                 func->SetCanReturn(false);
            }
        }
    }
}

set<addr_t> HandlerAnalysis::construct_uaf_list(Ref<BinaryView> &bv){
    BVHelper helper(bv);
    set<addr_t> whitelist;
    for (auto &function_name : UAF) {
        addr_t func_addr = helper.getFunctionByName(function_name);
        if (func_addr){
            debug_print("[UAF_SET] Inserted function %s 0x%lx in the leakset\n", function_name.c_str(), func_addr);
            whitelist.insert(func_addr);
        }
    }
    return whitelist;
}
//extern bool print_destroy;

// We have multiple address ranges handled by the same handler. They
// might all use different action filters.
static vector<CS> get_handlers(FDE &function, addr_t handler_addr){
   vector<CS> handlers;
   for (auto &handler: function.lsda.cses.entries){
      if (handler.lp == handler_addr){
           handlers.push_back(handler);
      }
   }

   return handlers;
}

static int print_action_info(CS &handler, Ref<BinaryView> bv){
    int must_follow = HANDLES_NOTHING;

    // If no action then we have a cleanup handler.
    if (handler.actions.entries.size() == 0){
        debug_print("(cleanup) ");
        return HANDLES_CLEANUP;
    }

    for (auto &action: handler.actions.entries){
        if (action.ar_filter > 0){
            Ref<Symbol> exception_ty = nullptr;
            addr_t addr_ty;
            must_follow |= HANDLES_EXCEPTIONS;
            addr_t info = strtoull(action.ar_info.c_str(), NULL, 16);
            if (info) {
                bv->Read(&addr_ty, info, bv->GetAddressSize());
                exception_ty = bv->GetSymbolByAddress(addr_ty);
                if (exception_ty)
                   debug_print("(%s [filter: %d addr: %s]) ",  exception_ty->GetFullName().c_str(), action.ar_filter, action.ar_info.c_str());
                else
                   debug_print("(no_name [filter: %d addr: %s]) ", action.ar_filter, action.ar_info.c_str());
            } else {
                debug_print("(all [filter: %d addr: %s]) ", action.ar_filter, action.ar_info.c_str());
            }

        }

        if (action.ar_filter == 0){
            must_follow |= HANDLES_CLEANUP;
            debug_print("(cleanup) ");
        }

        if (action.ar_filter < 0){
            debug_print("(throw_further: %s) ", action.ar_info.c_str());
        }
    }
    return must_follow;
}

static int print_handler_info(vector<CS> handlers, addr_t handler_addr, addr_t parent, Ref<BinaryView> bv, vector<Range> &ranges){
     int must_follow = HANDLES_NOTHING;
     Ref<Symbol> parent_sym = bv->GetSymbolByAddress(parent);
     if (parent_sym)
        debug_print("[Handler 0x%lx] START RECORD FOR HANDLER  (parent: %s addr: 0x%lx)\n", handler_addr, parent_sym->GetFullName().c_str(), parent);
     else
        debug_print("[Handler 0x%lx] START RECORD FOR HANDLER  (parent: no_name addr: 0x%lx)\n", handler_addr, parent);
     for (auto &handler : handlers){
         Range range(handler.start, handler.end-1);
         ranges.push_back(range);
         debug_print("\t[Handler 0x%lx] CS Range: 0x%lx - 0x%lx\n", handler.lp, handler.start, handler.end-1);
         debug_print("\t[Handler 0x%lx] Handled exceptions: ", handler.lp);
         must_follow |= print_action_info(handler, bv);
         debug_print("\n");
         debug_print("\t----------------------\n");
     }

     if (parent_sym){
         debug_print("[Handler 0x%lx]  END RECORD FOR HANDLER  (parent: 0x%s addr: 0x%lx)\n", handler_addr, parent_sym->GetFullName().c_str(), parent);
     }
     else {
         debug_print("[Handler 0x%lx]  END RECORD FOR HANDLER  (parent: no_name addr: 0x%lx)\n", handler_addr, parent);
     }


     return must_follow;
}
void HandlerAnalysis::analyze_one_file(string id, string filename){
     //print_destroy = false;
     int num_processed = 0;
     BNAnalysisParameters parameters;
     map<addr_t, addr_t> visited_functions;
     set<addr_t> whitelist;
     set<addr_t> notaintlist;
     set<addr_t> leakset;
     set<addr_t> uafset;
     map<addr_t, bool> printset;
     TaintInfo ti;
     string path_prefix;

     if (id == "0"){
        path_prefix = "";
     } else {
        path_prefix = "extracted/";
     }

     Json::Value *json = db->getAnalysisForFile(1, id);
     if (!json) {
            json = new Json::Value();
            // Write json for binary to a file 
            write_exception_info_json((path_prefix + filename).c_str());
            std::ifstream json_file("/tmp/" + path(filename).filename().string() + ".json", std::ifstream::binary | std::fstream::out );
            json_file >> *json;
     }
     if (json->isNull()){
         debug_print("[!] [check-error] No exceptions handled by: %s\n", id.c_str());
         db->writeTaintInfo(id, ti);
         delete json;
         return;
     }

     FDEs fdes(*json);

     delete json;

     optional<string> real_name = db->getNameForFile(id);
     optional<string> package_name =  db->getPackageForFile(id);

     if (!real_name.has_value() || !package_name.has_value()){
         progress_print("Started analysis on file: noname\n");
     } else {
         progress_print("Started analysis on file: %s package: %s\n", real_name.value().c_str(), package_name.value().c_str());
     }

     progress_print("Started loading binview for file %s hash:%s...(thread %d)\n", id.c_str(), filename.c_str(), priv_ID);

#ifndef BINJA_3_0_3388
     Ref<FileMetadata> metadata = new FileMetadata();
     Ref<BinaryData> bd = new BinaryData(metadata, path_prefix + filename);
     Ref<BinaryView> bv;

     for (auto type : BinaryViewType::GetViewTypes())
     {
         if (type->IsTypeValidForData(bd) && type->GetName() != "Raw")
         {
	      bv = type->Create(bd);
	      break;
	 }
     }
#else
     #warning BINJA_3_0_3388 BUILD
     Json::Value options(Json::objectValue);
     options["files.universal.architecturePreference"] = Json::Value(Json::arrayValue);
     options["files.universal.architecturePreference"].append("x86_64");
     options["analysis.tailCallTranslation"] = false;
     options["analysis.tailCallHeuristics"] = false;
     Ref<BinaryView> bv = OpenView(path_prefix + filename, true, {}, options);
#endif

     progress_print("Finished loading binview...(thread %d)\n", priv_ID);

     if (!bv || bv->GetTypeName() == "Raw")
     {
	debug_print("[!] [check-error] File is not an executable %s\n", id.c_str());
        goto cleanup;
     }

     progress_print("Started update analysis binview...(thread %d)\n", priv_ID);
#ifndef BINJA_3_0_3388
     bv->UpdateAnalysisAndWait();
#endif

     progress_print("Finished update analysis binview...(thread %d)\n", priv_ID);

     whitelist = construct_whitelist(bv);
     notaintlist = construct_notaintlist(bv);
     leakset = construct_leakset(bv);
     construct_noreturn_list(bv);
     uafset = construct_uaf_list(bv);
     for (auto function : fdes.fdes.entries){
        Ref<Function> func = bv->GetAnalysisFunction(bv->GetDefaultPlatform(), function.fstart);
        if (!func){
            continue;
        }

        for (auto handler : function.lsda.cses.entries){
            if (!handler.lp)
                continue;

            if (visited_functions.count(handler.lp)){
               if (visited_functions[handler.lp] != function.fstart){
                   debug_print("[!] Handler 0x%lx comes from multiple functions.(0x%lx, 0x%lx)\n", handler.lp, visited_functions[handler.lp], function.fstart);
               }

               continue;
            }
            vector<CS> handlers = get_handlers(function, handler.lp);
            vector<Range> rq;
            int must_follow = print_handler_info(handlers, handler.lp, function.fstart, bv, rq);

            if (! (must_follow & ~HANDLES_CLEANUP)){
               continue;
            }     

            //bv->CreateUserFunction(bv->GetDefaultPlatform(), handler.lp);
            bv->AddFunctionForAnalysis(bv->GetDefaultPlatform(), handler.lp);
            bv->UpdateAnalysisAndWait();
            visited_functions.insert(std::make_pair(handler.lp, function.fstart));
            
            Ref<Function> handle = bv->GetAnalysisFunction(bv->GetDefaultPlatform(), handler.lp);
            //Ref<Function> handle = bv->GetRecentAnalysisFunctionForAddress(handler.lp);
            if (handle){
               //PrintHLILFunctionHR(handle);
               EH eh(handler.lp, must_follow);
               FunctionTaint f_analysis(handle, bv);
               f_analysis.whitelist = &whitelist;
               f_analysis.notaintlist = &notaintlist;
               f_analysis.printset = &printset;
               f_analysis.leakset = &leakset;
               f_analysis.uafset = &uafset;
               f_analysis.priv_ID = priv_ID;

               f_analysis.runAnalysis();

               for (auto &sink : f_analysis.sink_list){
                   eh.addEntry(sink);
               }
               eh.addRanges(rq);
               ti.addEntry(eh);
               num_processed++;
               //bv->RemoveAnalysisFunction(handle);
            }
            
        }
     }

     bv->GetFile()->Close();
     if (!num_processed){
        debug_print("[!] [check-error] File does not have any handlers %s\n", id.c_str());
     }

cleanup:
#ifndef BINJA_3_0_3388
     bd->GetFile()->Close();
     metadata->Close();
#endif

     // Just a null entry now so we don't reanalyze files.
     if (id != "0"){
        db->writeTaintInfo(id, ti);
     }
     //print_destroy = true;
     return;
}


