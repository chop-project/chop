#include "threat_analysis_ossfuzz.h"
#include <iostream>
#include "hlil_printer.h"
#include <unistd.h>
#include "debug.h"
#include "globals.h"

#include "llil_registers.h"

#include "boost/filesystem.hpp"

using namespace boost::filesystem;

#define RBX_ENCODING 1 << 1
#define RBP_ENCODING 1 << 2
#define R12_ENCODING 1 << 3
#define R13_ENCODING 1 << 4
#define R14_ENCODING 1 << 5
#define R15_ENCODING 1 << 6

unsigned int get_register_encoding(uint32_t reg_idx){
    switch(reg_idx){
          case RBX:
                     return RBX_ENCODING;
          case RBP:
                     return RBP_ENCODING;
          case R12:
                     return R12_ENCODING;
          case R13:
                     return R13_ENCODING;
          case R14:
                     return R14_ENCODING;
          case R15:
                     return R15_ENCODING;
          default:
                     return 0;
    }
}

pair<std::optional<FunctionThreatInfo>, std::optional<FunctionStackInfo>> OSSFunctionLevelAnalysis::runAnalysis(){
   // TODO call runStackVulnerability analysis.
#ifdef DEBUG_MODULE
   Ref<Symbol> debug_sym = function->GetSymbol();
   string dbg_symbol = (debug_sym) ? debug_sym->GetFullName() : "";
   debug_print("Started running analysis on function -> function: (%s) address: (0x%lx) pid (%ld)\n", dbg_symbol.c_str(), function->GetStart(), pthread_self());
#endif
   addr = function->GetStart();
   FunctionThreatInfo ti(addr, function->GetSymbol()->GetFullName());

   optional<vector<ExceptionThreatInfo>> threat_info = nullopt;

   // Run threat analysis only if we have some exported throwers or a cxa_throw function
   if (exportMap || throwMap || cxa_throw) {
     threat_info = runThrowAnalysis();

     if (threat_info.has_value()){
       debug_print("Function %s (0x%lx) throws...\n",  dbg_symbol.c_str(), addr);
       // Create a FunctionThreatInfo object with name = "".
       for (ExceptionThreatInfo &e : threat_info.value()){
         ti.addEntry(e);
       }
     }
   }


#ifdef DEBUG_MODULE
   debug_print("Finished threat analysis analysis on function -> (%s)...\n", dbg_symbol.c_str());
#endif

   // In case we are running the lower bounds analysis just don't rerun stack analysis as this doesn't change.
   if (analysis_ty != THREAT_INFO){
        FunctionStackInfo si(addr);

        return make_pair<std::optional<FunctionThreatInfo>, std::optional<FunctionStackInfo>>(ti, si);
   }

   optional<tuple<unsigned int, unsigned int, int, bool, uint32_t, int>> stack_info = runStackAnalysis();

   if (stack_info.has_value()){

      tuple<unsigned int, unsigned int, int, bool, uint32_t, int> s_analysis = stack_info.value();
      bool uses_canaries = guardedWithCanaries();
      
      FunctionStackInfo si(addr, std::get<0>(s_analysis), std::get<1>(s_analysis),
                                                 std::get<2>(s_analysis), std::get<3>(s_analysis), uses_canaries,
                                                 std::get<4>(s_analysis), std::get<5>(s_analysis));
#ifdef DEBUG_MODULE
      debug_print("Finished stack analysis on function -> (%s)...\n", dbg_symbol.c_str());
#endif

      return make_pair<std::optional<FunctionThreatInfo>, std::optional<FunctionStackInfo>>(ti, si);
   }

#ifdef DEBUG_MODULE
   debug_print("Finished parsing function -> (%s)...\n", dbg_symbol.c_str());
#endif

   // For some reason we don't have any stack info (so create a dummy stack info for this function).
   FunctionStackInfo si(addr);

   return make_pair<std::optional<FunctionThreatInfo>, std::optional<FunctionStackInfo>>(ti, si);
}

/* Determine frame size based on number of pushes + sub rsp in the prologue.
   Should work for X86_64 but for 32bits some changes will be necessary.
   TODO there are other approaches to compute all possible unwinding states
   for a specific function frame, but the max size of the frame is probably 
   what will be used when unwinding from most catch blocks. */
optional<tuple<unsigned int, unsigned int, int, bool, uint32_t, int>> OSSFunctionLevelAnalysis::runStackAnalysis(){
   int preserved = 0;
   unsigned int stack_size = 0;
   int num_callees = 0;
   bool omit_fp = true;


   uint32_t reg_encoding = 0;
   bool finished = false;

   Ref<LowLevelILFunction> il = function->GetLowLevelIL();

   if (!il) {
      log_print("[!] Problem function has no il!\n");
      return nullopt;
   }

   std::vector<Ref<BasicBlock>> bblocks = il->GetBasicBlocks();

   if (bblocks.empty()){
      log_print("[!] Problem function has no bblocks!\n");
      return nullopt;
   }

   Ref<BasicBlock> prologueBB = bblocks.front();

   for (size_t instrIndex = prologueBB->GetStart(); instrIndex < prologueBB->GetEnd(); instrIndex++){
       LowLevelILInstruction instr = (*il)[instrIndex];
       instr.VisitExprs([&](const LowLevelILInstruction& expr) {
           /* Visit push instructions up until the first RSP sub instruction
              after that no other instruction accounts to stack size */
           if (finished)
              return false;

           switch (expr.operation){
                case LLIL_PUSH:
                        if (expr.GetSourceExpr<LLIL_PUSH>().operation == LLIL_REG){
                            uint32_t reg_idx = expr.GetSourceExpr<LLIL_PUSH>().GetSourceRegister<LLIL_REG>();
                            if (isCalleeSaved(reg_idx)) {
                                reg_encoding |= get_register_encoding(reg_idx); 
                                num_callees++;
                                preserved++;
                            }
                            else {
                                Ref<Symbol> sym = function->GetSymbol();
                                string sym_name = "";
                                if (sym) {
                                   sym_name = sym->GetFullName();
                                }
                                //log_print("[!] Problem function %s 0x%lx is saving non-callee register %d\n", sym_name.c_str(), function->GetStart(), reg_idx);
                                preserved++;
                            }

                            return false;
                        }
                        break;
                case LLIL_SET_REG:
                       LowLevelILInstruction src = expr.GetSourceExpr<LLIL_SET_REG>();
                       if (src.operation == LLIL_REG){
                            uint32_t dst_reg = expr.GetDestRegister<LLIL_SET_REG>();
                            uint32_t src_reg = src.GetSourceRegister<LLIL_REG>();
                            /* We save rsp -> rbp so we can control RSP by overwriting
                               the copy on the stack */
                            if (dst_reg == RBP && src_reg == RSP){
                               omit_fp = false;
                            }
                            return false;
                       }
                       if (src.operation == LLIL_SUB){
                            uint32_t dst = expr.GetDestRegister<LLIL_SET_REG>();
                            LowLevelILInstruction reg = src.AsTwoOperand().GetLeftExpr();
                            LowLevelILInstruction cons = src.AsTwoOperand().GetRightExpr();
                            if (reg.operation == LLIL_REG && cons.operation == LLIL_CONST){
                               uint32_t src = reg.GetSourceRegister<LLIL_REG>();
                               /* We are visiting an instruction of the form (sub const, rsp).
                                  No more callees after this. */
                               if (src == RSP && dst == RSP){
                                   stack_size = cons.GetConstant<LLIL_CONST>();
                                   finished = true;
                               }
                               return false;
                            }
                       }
                       break;
           }
           return true;
        });

      if (finished)
         break;
   }
   //printf("Stack size 0x%x preserved %d\n", stack_size, preserved); 

   // +1 to also count return address
   size_t local_size = stack_size;
   stack_size += (preserved + 1) *  bv->GetAddressSize();
   int extra_regs = preserved - num_callees;
   /* Return the number of callee saved registers and if RSP is spilled on the stack */
   return tuple<unsigned int, unsigned int, int, bool, uint32_t, int>(stack_size, local_size, num_callees, omit_fp, reg_encoding, extra_regs);

}

/* Returns true if the function calls stack_chk_fail */
bool OSSFunctionLevelAnalysis::guardedWithCanaries(){
   bool finished = false;
   /* Probably this binary is not compiled with stack protector */
   if (!canary_addr)
      return false;

   Ref<HighLevelILFunction> hlil = function->GetHighLevelIL();

   if (!hlil)
   {
      return false;
   }
   
   Ref<HighLevelILFunction> il = hlil->GetSSAForm();
   
   
   if (!il)
   {
      return false;
   }

  // Find a call to stack chk fail.
   for (auto& block : il->GetBasicBlocks())
   {
      // Loop though each instruction in the block
      for (size_t instrIndex = block->GetStart(); instrIndex < block->GetEnd(); instrIndex++)
      {
          // Fetch IL instruction
          HighLevelILInstruction instr = (*il)[instrIndex];
          // Collect all local callees (i.e., those that are contained in the binary).
          instr.VisitExprs([&](const HighLevelILInstruction& expr) {
                if (finished)
                    return false;
	        switch (expr.operation)
	        {
                  case HLIL_CALL_SSA:
		         if (expr.GetDestExpr<HLIL_CALL_SSA>().operation == HLIL_CONST_PTR) {
                            addr_t callee = expr.GetDestExpr<HLIL_CALL_SSA>().GetConstant<HLIL_CONST_PTR>();
                            if (callee == canary_addr){
                               finished = true;
                               return false;
                            }
                         }
                         break;
                  case HLIL_TAILCALL:
		         if (expr.GetDestExpr<HLIL_TAILCALL>().operation == HLIL_CONST_PTR) {
                            addr_t callee = expr.GetDestExpr<HLIL_TAILCALL>().GetConstant<HLIL_CONST_PTR>();
                            if (callee == canary_addr){
                               finished = true;
                               return false;
                            }
                         }
                         break;
                 }
                 return true;
        });

        if (finished)
            return finished;
       }
   }

   return finished;
}

unsigned int handlesExceptions(FDE& function){
   int handles = 0;
   for (auto &handler: function.lsda.cses.entries){
    if (handler.actions.entries.size() == 0){
        handles |= HANDLES_CLEANUP;
        continue;
    }

    for (auto &action: handler.actions.entries){
        if (action.ar_filter > 0){
             handles |= HANDLES_EXCEPTIONS;
             addr_t info = strtoull(action.ar_info.c_str(), NULL, 16);
             if (!info) {
                 handles |= HANDLES_ALL;
                 break;
             }
        }      
     }
   }

   return handles;
}



static inline void update_exception_info();


bool OSSFunctionLevelAnalysis::checkRanges(addr_t parent, addr_t cs){
   vector<pair<addr_t, addr_t>> &func_ranges = (*catch_ranges)[parent];

   for (auto& range: func_ranges){
      if (range.first <= cs && cs <= range.second)
         return true; 
   }
   return false;
}

optional<vector<ExceptionThreatInfo>> OSSFunctionLevelAnalysis::runThrowAnalysis(){

   // Don't count Unwind_Resume_or_Rethrow and Unwind_Raise_Exception.
   if (throwMap && throwMap->count(start) > 0){
      return nullopt;
   }

   // Don't count cxa_throw.
   if (cxa_throw && cxa_throw == start) {
      return nullopt;
   }


   list<pair<Ref<Function>, CalleeStats>> to_visit;
   // We're at level 0 now.
   CalleeStats stats;
   stats.level = 0;
   stats.parent_cs = 0;
   stats.parent_function = start;
   stats.parent_name = "base";
   to_visit.push_back(make_pair(function, stats));

   // Mark root as visited. We need to do some pruning. Seems that on
   // libstc++ it cycles a bit in some functions.
   visited_functions.insert(start);
   // A  cache holding what exception types we encountered while visiting
   // a function.
   map<addr_t, set<string>> cache; 
   // List of exception description (address, typename, exception_call).
   vector<ExceptionThreatInfo> exceptions;

   // Visit function callees in a BFD search approach up to MAX_LEVEL and report if any callees in the chain throw.
   while (to_visit.size()) {
           pair<Ref<Function> , CalleeStats> elem = to_visit.front();
           to_visit.pop_front();
           int level = elem.second.level;
           addr_t cs = elem.second.parent_cs;
           addr_t parent = elem.second.parent_function;
           string parent_name =  "";
#ifdef DEBUG_MODULE
           Ref<Symbol> debug_sym = elem.first->GetSymbol();
           string dbg_symbol = (debug_sym) ? debug_sym->GetFullName() : "";
           debug_print("[parent_cs 0x%lx] [%s] Visiting internal function %s (0x%lx) at level %d\n", cs, elem.second.parent_name.c_str(), dbg_symbol.c_str(), elem.first->GetStart(), level);
           parent_name = elem.first->GetSymbol()->GetShortName();
#endif

           // We've reached level MAX_LEVEL in the CG without finding any throw/rethrow handler.
           if (level > MAX_LEVEL){
               continue;
           }
           while (elem.first->NeedsUpdate()){
	         bv->UpdateAnalysisAndWait();
           }
           //elem.first->GetView()->UpdateAnalysisAndWait();
           Ref<HighLevelILFunction> hlil = elem.first->GetHighLevelIL();
           if (!hlil) {
               log_print("[!] Problem function has no hil!\n");
               continue;
           }

           Ref<HighLevelILFunction> il = hlil->GetSSAForm();

           if (!il)
           {
               log_print("[!] Problem function has no ssa hlil!\n");
	       continue;
           }
   
           vector<Callee> callees;
           vector<addr_t> imports;
           // Loop through all blocks in the function and collect all direct calls and imports (which may be local to the module).
           for (auto& block : il->GetBasicBlocks())
           {
	      // Loop though each instruction in the block
	      for (size_t instrIndex = block->GetStart(); instrIndex < block->GetEnd(); instrIndex++)
	      {
		// Fetch IL instruction
		HighLevelILInstruction instr = (*il)[instrIndex];
                // Collect all local callees (i.e., those that are contained in the binary).
                instr.VisitExprs([&](const HighLevelILInstruction& expr) {
			switch (expr.operation)
			{
			case HLIL_CALL_SSA:
		                if (expr.GetDestExpr<HLIL_CALL_SSA>().operation == HLIL_CONST_PTR) {
                                   Callee callee;
                                   if (!cs){
                                      // We are in the parent so get the callsite now
                                      callee.cs = expr.address;
                                   } else {
                                      // Use the main function cs
                                      callee.cs = cs;
                                   }
                                   callee.parent_name = parent_name;
                                   callee.expr = expr;
                                   callee.imported = false;
                                   callee.callee = expr.GetDestExpr<HLIL_CALL_SSA>().GetConstant<HLIL_CONST_PTR>();
#ifdef LOWER_BOUND_STATS
                                   if (!checkRanges(parent, callee.expr.address)){
                                      callees.push_back(callee);
                                   }
#else
		                   callees.push_back(callee);
#endif
		                   //PrintILExpr(expr, 2);
		                   // Finished parsing this subexpresion.
		                   return false;
		                } else if (expr.GetDestExpr<HLIL_CALL_SSA>().operation == HLIL_IMPORT) {
                                   Callee callee;
                                   if (!cs){
                                      // We are in the parent so get the callsite now
                                      callee.cs = expr.address;
                                   } else {
                                      // Use the main function cs
                                      callee.cs = cs;
                                   }
                                   callee.parent_name = parent_name;
		                   // If we call imports then follow the link (this should point to either a local or external symbol)
		                   addr_t import = expr.GetDestExpr<HLIL_CALL_SSA>().GetConstant<HLIL_IMPORT>();
		                   addr_t forward_import; 
		                   bv->Read(&forward_import,import, bv->GetAddressSize());
                                   callee.callee = forward_import;
                                   callee.imported = true;
                                   callee.expr = expr;
#ifdef LOWER_BOUND_STATS
                                   if (!checkRanges(parent, callee.expr.address)){
                                      callees.push_back(callee);
                                   }
#else
		                   callees.push_back(callee);
#endif
		                   // Finished parsing subexpression 
		                   return false;   
		                }  
				break;
			case HLIL_TAILCALL:
		                if (expr.GetDestExpr<HLIL_TAILCALL>().operation == HLIL_CONST_PTR) {
                                   Callee callee;
                                   if (!cs){
                                      // We are in the parent so get the callsite now
                                      callee.cs = expr.address;
                                   } else {
                                      // Use the main function cs
                                      callee.cs = cs;
                                   }
                                   callee.parent_name = parent_name;
                                   callee.callee = expr.GetDestExpr<HLIL_TAILCALL>().GetConstant<HLIL_CONST_PTR>();
                                   callee.imported = false;
                                   callee.expr = expr;
#ifdef LOWER_BOUND_STATS
                                   if (!checkRanges(parent, callee.expr.address)){
                                      callees.push_back(callee);
                                   }
#else
		                   callees.push_back(callee);
#endif
		                   return false;
		                }  else if (expr.GetDestExpr<HLIL_TAILCALL>().operation == HLIL_IMPORT) {
                                   Callee callee;
                                   if (!cs){
                                      // We are in the parent so get the callsite now
                                      callee.cs = expr.address;
                                   } else {
                                      // Use the main function cs
                                      callee.cs = cs;
                                   }
                                   callee.parent_name = parent_name;
		                   // If we call imports then follow the link (this should point to either a local or external symbol)
		                   addr_t import = expr.GetDestExpr<HLIL_TAILCALL>().GetConstant<HLIL_IMPORT>();
		                   addr_t forward_import; 
		                   bv->Read(&forward_import,import, bv->GetAddressSize());
                                   callee.callee = forward_import;
                                   callee.imported = true;  
                                   callee.expr = expr;
#ifdef LOWER_BOUND_STATS
                                   if (!checkRanges(parent, callee.expr.address)){
                                      callees.push_back(callee);
                                   }
#else
		                   callees.push_back(callee);
#endif
		                   // Finished parsing subexpression
		                   return false;   
		                }    
				break;
			case HLIL_JUMP:
                                if (expr.GetDestExpr<HLIL_JUMP>().operation == HLIL_IMPORT) {
                                   Callee callee;
                                   if (!cs){
                                      // We are in the parent so get the callsite now
                                      callee.cs = expr.address;
                                   } else {
                                      // Use the main function cs
                                      callee.cs = cs;
                                   }
                                   callee.parent_name = parent_name;
		                   // If we call imports then follow the link (this should point to either a local or external symbol)
		                   addr_t import = expr.GetDestExpr<HLIL_JUMP>().GetConstant<HLIL_IMPORT>();
		                   addr_t forward_import; 
		                   bv->Read(&forward_import,import, bv->GetAddressSize());
                                   callee.callee = forward_import;
                                   callee.imported = true;  
                                   callee.expr = expr;
#ifdef LOWER_BOUND_STATS
                                   if (!checkRanges(parent, callee.expr.address)){
                                      callees.push_back(callee);
                                   }
#else
		                   callees.push_back(callee);
#endif
		                   // Finished parsing subexpression
		                   return false;   
		                }    
				break;
			default:
				break;
			}
			return true;  // Parse any subexpressions
		   });
	         }
            }

            for (auto &callee: callees){
              // Is the callee and export in the throw map or one of the predefined
              // functions that throw?
              if (throwMap && throwMap->count(callee.callee) > 0 ) {
#ifdef DEBUG_MODULE
                     debug_sym = bv->GetSymbolByAddress(callee.callee);
                     dbg_symbol = (debug_sym) ? debug_sym->GetFullName() : "";
                     debug_print("[parent_cs 0x%lx] Callee %s (0x%lx) throws at level %d\n", callee.cs, dbg_symbol.c_str(), callee.callee, level);
#endif
                     vector<string> exceptions_thrown = (*throwMap)[callee.callee]; 
                     for (auto &e : exceptions_thrown){
                         // Add new exception happening at parent.
                         ExceptionThreatInfo ei(callee.cs, callee.expr.address, level, e);
                         // Add new exception to the churn.
                         exceptions.push_back(ei);
                         if (!cache.count(parent)){
                             set<string> pexceptions;
                             pexceptions.insert(e);
                             cache.insert(make_pair(parent, pexceptions));
                         } else {
                             cache[parent].insert(e);
                         }
                     }
                     continue;
               }

               if (cxa_throw && cxa_throw == callee.callee){
                     debug_print("[parent_cs 0x%lx] Callee 0x%lx calls cxa_throw\n", callee.cs, callee.callee);
                    vector<HighLevelILInstruction> exprs = callee.expr.GetParameterExprs();
                     string tname;
                     if (exprs.size() < 2) {
                        tname = "CXA_UNKNOWN";
                     } 
                     else {
                        //PrintILExpr(callee.expr, 0);
                        addr_t tinfo = getAddress(exprs[1]);

                        if (tinfo) {
                          Ref<Symbol> sym = bv->GetSymbolByAddress(tinfo);
                          // Really need to create some macros to make things nicer.
                          if (!sym){
                           std::stringstream sstream;
                           sstream << std::hex << tinfo;
                           tname = string("0x") + sstream.str();
                           tname = tname + "_" + file_id; // Add also file_id when searching these exceptions cross-dso.
                          } else {
                           tname = sym->GetShortName();
                          }
                        } else {
                          tname = "CXA_UNKNOWN";
                        }
                     }
                     debug_print("[parent_cs 0x%lx] [%s] We throw %s\n", callee.cs, callee.parent_name.c_str(), tname.c_str());
                     ExceptionThreatInfo ei(callee.cs, callee.expr.address, level, tname);
                     exceptions.push_back(ei);
                     if (!cache.count(parent)){
                         set<string> pexceptions;
                         pexceptions.insert(tname);
                         cache.insert(make_pair(parent, pexceptions));
                     } else {
                         cache[parent].insert(tname);
                     }
                     continue;
               }

               if (callee.imported){
                   Ref<Symbol> sym = bv->GetSymbolByAddress(callee.callee);
                   if (!sym){
                      //warning_print("Symbol not found 0x%lx\n", callee.callee);
                      continue;
                   }
                   
                   // If symbol is external look it up in the export map.
                   if (sym->GetType() == ExternalSymbol){
                      string sym_name = sym->GetFullName();
                      // If the symbol is there then this imported function throws.
                      if (exportMap && exportMap->count(sym_name) > 0){
#ifdef DEBUG_MODULE
                         debug_print("External callee %s (0x%lx) throws at level %d\n", dbg_symbol.c_str(), callee.callee, level);
#endif                   
                         vector<string> exceptions_thrown = (*exportMap)[sym_name];
                         for (auto &e : exceptions_thrown){
                              // Add new exception happening at parent.
                              ExceptionThreatInfo ei(callee.cs, callee.expr.address, level, e);
                              // Add new exception to the churn.
                              exceptions.push_back(ei);
                              if (!cache.count(parent)){
                                 set<string> pexceptions;
                                 pexceptions.insert(e);
                                 cache.insert(make_pair(parent, pexceptions));
                              } else {
                                 cache[parent].insert(e);
                              }
                         }                         
                        

                      }
                      continue;
                    } 
                    // If it's not external pass it to the next layer.
               }

               // Don't visit the same callee twice
               if (visited_functions.count(callee.callee)){
                  // However if we know the callee throws exceptions
                  // mark its callsite as a throw. We fail to mark a 
                  // throw callsite for function F (which throws) in
                  // the first parent that has two calls to F as these
                  // calls get added at the same time in the visitor queue.
                  // But no biggie.
                  if (cache.count(callee.callee)){
                     vector<string> exceptions_thrown;
                     for (auto &elem : cache[callee.callee]) {
                         exceptions_thrown.push_back(elem);
                     }
                     // Add all exceptions thrown by the callee to this call-site.
                     for (auto &e : exceptions_thrown){
                         ExceptionThreatInfo ei(callee.cs, callee.expr.address, level, e);
                         exceptions.push_back(ei);
                         if (!cache.count(parent)){
                             set<string> pexceptions;
                             pexceptions.insert(e);
                             cache.insert(make_pair(parent, pexceptions));
                         } else {
                             cache[parent].insert(e);
                         }
                     }
                  }
                  continue;
               }
               // Mark as visited so we prune next time we see this call.
               visited_functions.insert(callee.callee);


               Ref<Function> fcallee =  bv->GetAnalysisFunction(function->GetPlatform(), callee.callee);
               if (fcallee){
                   CalleeStats stats_int;
                   stats_int.parent_name = "unknown";
                   Ref<Symbol> sym = fcallee->GetSymbol();
                   if (sym){
                      string sym_n = sym->GetFullName(); 
                      if (sym_n.find("__asan") == 0 || sym_n.find("__sanitizer") == 0 || sym_n.find("__lsan") == 0){
                          // Don't visit any sanitizer or asan functions.
                          continue;
                      }
                   }
                   
                   stats_int.level = level + 1;
                   stats_int.parent_cs = callee.cs;
                   stats_int.parent_function = callee.callee;
                   stats_int.parent_name = callee.parent_name;
                   to_visit.push_back(make_pair(fcallee, stats_int));
               }
            }
    }
    // Only count functions that do not throw but do not save them in the database.
    if (!exceptions.size()) {
       debug_print("Caller 0x%lx does not throw for some reason\n", start);
       return nullopt;
    }
    
    return exceptions;
}

static inline string dump_exception_names(FunctionThreatInfo &f){
     string result = "";
     for (auto &exception_name: f.d_exception_names.entries){
          result = result +  exception_name.name + " ";
     }
     return result;
}

static inline void dump_module_threat_info(ModuleThreatInfo &ml_info){
     // Really nasty output format for a summary.
     log_print("==========MODULE THREAT INFO==========\n");
     for (auto &fi : ml_info.functions.entries){
         if (fi.throws){
          log_print("\taddr. %s\tthrows. True\texported. %s\ttotal. %d\tdistinct. %d\texcnames. [%s]\tname. %s\n", fi.address.c_str(), fi.isExternal ? "True" : "False", fi.total_throws, 
                                                              fi.distinct_throws,
                                                              dump_exception_names(fi).c_str(), fi.short_name.c_str()); 
         } else {
          log_print("\taddr. %s\tthrows. False\ttotal. -\tdistinct. -\texcnames: [-]\tname. %s\n", fi.address.c_str(),fi.short_name.c_str() ); 
         }
     }
     log_print("[THREAT_SUMMARY] TF: %d TTF: %d TET: %d\n", ml_info.total_functions, ml_info.total_throw_functions, ml_info.total_exported_throws);
     log_print("===================================\n");

}

static inline void dump_module_stack_info(ModuleStackInfo &ml_info){
     unsigned int handles = 0, cleanups = 0, handleall = 0;
     log_print("==========MODULE STACK INFO==========\n");
     for (auto &fi : ml_info.functions.entries){
         log_print("Function %s:\tfrm sz. %s\tlcl sz. %s\tomitfp. %s\tstackc. %s\tc-saved %d\tR:[%s]\tEx:[%s]\n", fi.address.c_str(), fi.frame_size.c_str(), fi.local_size.c_str(), 
                                                              fi.omit_fp ? "True" : "False",
                                                              fi.uses_canary ? "True" : "False",
                                                              fi.num_callees, decode_registers(fi.enc_regs, fi.omit_fp).c_str(), decode_exception(fi.enc_exc).c_str()); 
          if (fi.enc_exc & HANDLES_ALL){
               ++handleall;
          }

          if (fi.enc_exc & HANDLES_EXCEPTIONS){
               ++handles;
          }

          if (fi.enc_exc & HANDLES_CLEANUP){
               ++cleanups;
          }
                
     }
     log_print("[EXCEPTION_SUMMARY] TF: %d TP: %d  TH: %d TC: %d TA: %d\n", ml_info.total_functions,  ml_info.total_processed, handles, cleanups, handleall);
     log_print("===================================\n");
}


// Overaproxmation of ranges in a function that may catch.
// This can obviously be optimized but no time right now.
map<addr_t, vector<pair<addr_t, addr_t>>> *  getAllCatchRanges(FDEs& fdes){
  map<addr_t, vector<pair<addr_t, addr_t>>> * ranges = new map<addr_t, vector<pair<addr_t, addr_t>>>();
  for (auto function : fdes.fdes.entries){
        for (auto handler : function.lsda.cses.entries){ 
            if (!handler.lp)
                continue;
            for (auto &action: handler.actions.entries){
                if (action.ar_filter){
                    ((*ranges)[function.fstart]).push_back(make_pair(handler.start, handler.end));
                    log_print("Added [0x%lx] [0x%lx - 0x%lx]\n", function.fstart, handler.start, handler.end);
                    break;
                }
            }
        } 
  }
  if (!ranges->size()){
     delete ranges;
     return nullptr;
  }

  return ranges;
}

void OSSThreatAnalysis::analyze_one_file(string id, string filename){
     // Also write ml_info analysis for backwards compatibility with the old dso
     // analysis.
     ModuleThreatInfo ml_info;
     ModuleStackInfo st_info; 


     addr_t canary_addr = 0;
     string cannary_name("__stack_chk_fail");

     map<addr_t, vector<string>>* throws_ref = nullptr; 
     map<string, vector<string>> *export_ref = nullptr;
     addr_t cxa_throw_func = 0;
     // Mark everything as normal analysis (gets switched if we included lower bounds define).
     analysis_ty threat_analysis_type = analysis_ty::THREAT_INFO;
     ml_info.info_ty = analysis_ty::THREAT_INFO;

     string path_prefix;

     if (id == "0"){
        path_prefix = "";
     } else {
        path_prefix = "extracted/";
     }

     Json::Value *json = nullptr;
     FDEs fdes;
     try {  
        json = new Json::Value();
        // Write json for binary to a file 
        write_exception_info_json((path_prefix + filename).c_str());
        std::ifstream json_file("/tmp/" + path(filename).filename().string() + ".json", std::ifstream::binary | std::fstream::out );
        json_file >> *json;
        FDEs aux(*json);
        delete json;  
        fdes.fdes.entries = aux.fdes.entries;
     } catch(...){
       distro_print("JSON Encoding error on file: %s\n", id.c_str());
       if (json)
          delete json;
       // If we have an exception just continue with null fdes.
     }

     
     progress_print("Started loading binview for file %s hash:%s...(thread %d)\n", id.c_str(), filename.c_str(), priv_ID);
     // References to optional throw table in case we don't have DSO analysis
     // plus a reference with symbols exported from other DSOs alongside
     // a vector of all exceptions thrown by the DSO function.

#ifndef BINJA_3_0_3388

     FileMetadata *metadata = new FileMetadata();
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
     //options["analysis.limits.maxFunctionSize"] = 5 * 65536;
     options["analysis.limits.maxFunctionAnalysisTime"] = 0;

     Ref<BinaryView> bv = OpenView(path_prefix + filename, true, {}, options);
#endif

     progress_print("Finished loading binview...(thread %d)\n", priv_ID);
     // Initialize BVHelper
     BVHelper helper(bv);

     if (!bv)
     {
	fprintf(stderr, "Input file does not appear to be an exectuable\n");
        dump_module_threat_info(ml_info);
        log_print("\n");
        log_print("\n");
        dump_module_stack_info(st_info);
        goto cleanup;
     }

     if (bv->GetTypeName() == "Raw")
     {
	fprintf(stderr, "Input file does not appear to be an exectuable\n");
	bv->GetFile()->Close();
        dump_module_threat_info(ml_info);
        log_print("\n");
        log_print("\n");
        dump_module_stack_info(st_info);
        goto cleanup;
     }

     progress_print("Started update analysis binview...(thread %d)\n", priv_ID);

#ifndef BINJA_3_0_3388
     bv->UpdateAnalysisAndWait();
#endif

     progress_print("Finished update analysis binview...(thread %d)\n", priv_ID);

     canary_addr = helper.getFunctionByName(cannary_name);

     if (canary_addr){
        st_info.uses_canary = true;
        log_print("canary function: 0x%lx\n", canary_addr);
     } else {
        log_print("[!] Binary does not use stack canary.\n");
     }

     cxa_throw_func = helper.getCXA_throw(cxa_throw);
   
     if (!cxa_throw_func){
        log_print("[!] Binary does not have cxa_throw.\n");
     } else {
        log_print("cxa_throw function: 0x%lx\n", cxa_throw_func);
     }


     throws_ref = helper.getThrowsBasedOnPatern(OSS_THROW_VARIANTS);

     if (!throws_ref){
           log_print("[!] Binary does not throw.\n");
     }
     
     // Go through all functions in the binary
     for (auto& func : bv->GetAnalysisFunctionList())
     {
         OSSFunctionLevelAnalysis f_analysis(func, bv, throws_ref, nullptr, cxa_throw_func);
         f_analysis.file_id = id;
         f_analysis.catch_ranges = nullptr;
         f_analysis.canary_addr = canary_addr;
         f_analysis.analysis_ty = threat_analysis_type;
         Ref<Symbol> sym = func->GetSymbol();
         
         if (sym && analysis_functions != ""){
            string shortName = sym->GetShortName();
            if (analysis_functions.find(shortName) == std::string::npos){
                continue;
            }
         }
         log_print("FUNC_ANALYSIS:Analysing function %s.\n", sym->GetShortName().c_str());
         
         pair<optional<FunctionThreatInfo>, optional<FunctionStackInfo>> analysis_result = f_analysis.runAnalysis();
         
         
 
         optional<FunctionThreatInfo> &ti = analysis_result.first;
         bool have_analysis = ti.has_value();
         bool is_exported = false;
         // If this symbol can be exported then add the name to the exported table.
         if (sym && have_analysis){
             bool is_exported = helper.isSymbolExternal(sym->GetFullName(), func->GetStart());
             // Hmm, i'd like to get a reference to this value. Wish I knew how to 
             // define a copy constructor for reference for FunctionThreatInfo.
             // TODO 
             ti.value().isExternal = is_exported;
             ti.value().short_name = sym->GetShortName();
             /*
             if (is_exported){
                log_print("Small test is external %d\n", ti.value().isExternal);
             }*/
             ml_info.addEntry(ti.value(), is_exported);
         }
         else {
             ml_info.total_functions++;
         }

         optional<FunctionStackInfo> &o_si = analysis_result.second;
         have_analysis = o_si.has_value();

     
         /* Add analyzed function to ml_info */
         if (have_analysis){
            unsigned int enc_exc = 0;
            for (auto function : fdes.fdes.entries){
              if (function.fstart == f_analysis.addr) {
                 enc_exc |= handlesExceptions(function);
              }
            }
            FunctionStackInfo si = o_si.value();
            si.enc_exc = enc_exc;
            st_info.addEntry(si);
            //db->writeStackInfoEntryT(id, si);
            //log_print("%s\n", si.parseToSQLQuery(id).c_str());
         }
         else {
            st_info.total_functions++;
         }

     }

     dump_module_threat_info(ml_info);
     log_print("\n");
     log_print("\n");
     dump_module_stack_info(st_info);


     /* Delete all maps we've used */
     if (throws_ref)
        delete throws_ref;


     bv->GetFile()->Close();

cleanup:

#ifndef BINJA_3_0_3388
     bd->GetFile()->Close();
     metadata->Close();
     delete metadata;
#endif
     return;
}


