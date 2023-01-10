#include "threat_analysis.h"
#include <iostream>
#include "hlil_printer.h"
#include <unistd.h>
#include "debug.h"
#include "globals.h"

#include "llil_registers.h"

#include "boost/filesystem.hpp"

using namespace boost::filesystem;

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

pair<std::optional<FunctionThreatInfo>, std::optional<FunctionStackInfo>> FunctionLevelAnalysis::runAnalysis(){
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
optional<tuple<unsigned int, unsigned int, int, bool, uint32_t, int>> FunctionLevelAnalysis::runStackAnalysis(){
   int preserved = 0;
   unsigned int stack_size = 0;
   int num_callees = 0;
   bool omit_fp = true;


   uint32_t reg_encoding = 0;
   bool finished = false;

   Ref<LowLevelILFunction> il = function->GetLowLevelIL();

   if (!il)
      return nullopt;

   std::vector<Ref<BasicBlock>> bblocks = il->GetBasicBlocks();

   if (bblocks.empty())
      return nullopt;

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
bool FunctionLevelAnalysis::guardedWithCanaries(){
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


bool FunctionLevelAnalysis::checkRanges(addr_t parent, addr_t cs){
   vector<pair<addr_t, addr_t>> &func_ranges = (*catch_ranges)[parent];

   for (auto& range: func_ranges){
      if (range.first <= cs && cs <= range.second)
         return true; 
   }
   return false;
}

optional<vector<ExceptionThreatInfo>> FunctionLevelAnalysis::runThrowAnalysis(){

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
#ifdef DEBUG_MODULE
           Ref<Symbol> debug_sym = elem.first->GetSymbol();
           string dbg_symbol = (debug_sym) ? debug_sym->GetFullName() : "";
           debug_print("[parent_cs 0x%lx]  Visiting internal function %s (0x%lx) at level %d\n", cs, dbg_symbol.c_str(), elem.first->GetStart(), level);
#endif

           // We've reached level MAX_LEVEL in the CG without finding any throw/rethrow handler.
           if (level > MAX_LEVEL){
               continue;
           }
           Ref<HighLevelILFunction> hlil = elem.first->GetHighLevelIL();
           if (!hlil) {
               continue;
           }

           Ref<HighLevelILFunction> il = hlil->GetSSAForm();

           if (!il)
           {
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
                     debug_print("We throw %s\n", tname.c_str());
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
                   stats_int.level = level + 1;
                   stats_int.parent_cs = callee.cs;
                   stats_int.parent_function = callee.callee;
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

optional<pair<map<addr_t, int> *, map<addr_t, int> *>> ThreatAnalysis::getThrowAnalysisForFile(string file_id){
     Json::Value* json = db->getAnalysisForFile(analysis_ty::THROW_INFO, file_id);

     if (json == nullptr){
        return nullopt;
     }

     if ((*json).isNull()){
        return nullopt;
     }

     const Json::Value funcs = (*json)["funcs"];

     if (funcs.size() == 0){
        return nullopt;         
     }

     map<addr_t, int> *throws = new map<addr_t, int>();
     map<addr_t, int> *rethrows = new map<addr_t, int>();

     for ( int index = 0; index < funcs.size(); ++index ) {
         const Json::Value func = funcs[index];

         if (func.get("total_throws", 0).asInt() > 0) {
             pair<addr_t, int> map_item = make_pair(strtoull(func["fstart"].asString().c_str(), NULL, 16), 1);
             throws->insert(map_item);
         }

         if (func.get("total_rethrows", 0).asInt() > 0) {
             pair<addr_t, int> map_item = make_pair(strtoull(func["fstart"].asString().c_str(), NULL, 16), 1);
             rethrows->insert(map_item);
         }
     }
     
     // Free JSON we don't need it anymore.
     delete json;

     if (!throws->size()) {
        delete throws;
        throws = nullptr;
     }

     if (!rethrows->size()){
        delete rethrows;
        rethrows = nullptr;
     }

     if (!rethrows && !throws){
        return nullopt;
     }

     return make_pair(throws, rethrows);
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
          //log_print("\taddr. %s\tthrows. False\ttotal. -\tdistinct. -\texcnames: [-]\tname. %s\n", fi.address.c_str(),fi.short_name.c_str() ); 
         }
     }
     log_print("Total module functions: %d\n", ml_info.total_functions);
     log_print("Total throw functions: %d\n", ml_info.total_throw_functions);
     log_print("Total exported throws: %d\n", ml_info.total_exported_throws);
     log_print("===================================\n");

}

static inline void dump_module_stack_info(ModuleStackInfo &ml_info){
     log_print("==========MODULE STACK INFO==========\n");
     for (auto &fi : ml_info.functions.entries){
         log_print("Function %s:\tfrm sz. %s\tlcl sz. %s\tomitfp. %s\tstackc. %s\tc-saved %d\tR:[%s]\tEx:[%s]\n", fi.address.c_str(), fi.frame_size.c_str(), fi.local_size.c_str(), 
                                                              fi.omit_fp ? "True" : "False",
                                                              fi.uses_canary ? "True" : "False",
                                                              fi.num_callees, decode_registers(fi.enc_regs, fi.omit_fp).c_str(), decode_exception(fi.enc_exc).c_str()); 
                
     }
     log_print("Total Functions: (%d) Total Processed (%d)\n", ml_info.total_functions,  ml_info.total_processed);
     log_print("===================================\n");
}

map<string, vector<string>>* ThreatAnalysis::getExportedSymbolsForFileOld(Ref<BinaryView> bv, string file_id, analysis_ty threat_analysis_type){
     // First lets get
     Json::Value* links_json = db->getAnalysisForFile(analysis_ty::DSO_LINKS, file_id);
     map<string, vector<string>> *import_map;

     if (!links_json)
        return nullptr;

     const Json::Value imports = (*links_json)["imports"];
     import_map = new map<string, vector<string>>();

     BVHelper helper(bv);

     for ( int index = 0; index < imports.size(); ++index ) {
         int import_id = imports[index].asInt();

         Json::Value *import_data = db->getAnalysisForFile(threat_analysis_type, std::to_string(import_id));

         /* Lets remove imports that we do not process */
         if (!import_data && processed_files && processed_files->count(std::to_string(import_id)) == 0){
            log_print("[!] Removing import as we are not processing it: %d\n", import_id);
            continue;
         }

         while (processed_files && !import_data){
             /* Probably the import is in transit on another thread. Just wait for it */
             log_print("Thread is sleeping waiting on import %ld %d\n", pthread_self(), import_id);
             std::this_thread::sleep_for(std::chrono::minutes(1));

             import_data = db->getAnalysisForFile(threat_analysis_type, std::to_string(import_id));
         }

         if (!import_data){
            log_print("No data for file id %d\n", import_id);
            continue;
         }

         JSONVector<FunctionThreatInfo> funcs((*import_data)["functions"]);

         delete import_data;

         for (auto &function : funcs.entries){
            if (function.isExternal){
              // Check if the current binary is actually using this symbol.
              bool isNeeded = helper.searchForSymbol(function.name, ImportedFunctionSymbol);
              if (isNeeded){
                 vector<string> container;
                 for (auto &exception_des : function.d_exception_names.entries){ 
                     container.push_back(exception_des.name);
                 }
                 import_map->insert(make_pair(function.name, container));
                 log_print("[Library %d] Added external symbol %s handling [%s] exceptions.\n", import_id, function.name.c_str(), dump_exception_names(function).c_str());
                 
              }
            }
          }
     }

     delete links_json;

     if (!import_map->size()){
        delete import_map;
        return nullptr;
     }

     return import_map;
}

map<string, vector<string>>* ThreatAnalysis::getExportedSymbolsForFile(Ref<BinaryView> bv, string file_id, analysis_ty threat_analysis_type){
     // First lets get
     Json::Value* links_json = db->getAnalysisForFile(analysis_ty::DSO_LINKS, file_id);
     map<string, vector<string>> *import_map;

     if (!links_json)
        return nullptr;

     const Json::Value imports = (*links_json)["imports"];
     import_map = new map<string, vector<string>>();

     BVHelper helper(bv);

     for ( int index = 0; index < imports.size(); ++index ) {
         bool export_active = false;
         
         int import_id = imports[index].asInt();

         export_active = db->hasCombinedAnalysis(threat_analysis_type, std::to_string(import_id));
         
         /*  Check if we at some point have this export. If not continue with next import */
         if (processed_files){
             /* In case this import is not in the queue then stop waiting for it. */
             if (!export_active && processed_files->count(std::to_string(import_id)) == 0){
                 log_print("[!] Removing import as we are not processing it: %d\n", import_id);
                 continue;
             }
             
             while (!export_active){
                 /* Probably the import is in transit on another thread. Just wait for it */
                 log_print("Thread is sleeping waiting on import %ld %d\n", pthread_self(), import_id);
                 fflush(dbgfile[pthread_self()]);
                 std::this_thread::sleep_for(std::chrono::minutes(1));
                 /* Check if the file has finished */
                 export_active = db->hasCombinedAnalysis(threat_analysis_type, std::to_string(import_id));
             }
         }
         
         // Now we know the imported file is finished but we may still not have any exported functions in the file.
         list<Pair> *import_data = db->getExportedSymbols(threat_analysis_type, std::to_string(import_id));
         
         if (!import_data){
            log_print("No data for file id %d\n", import_id);
            continue;
         }

         for (auto &symbol : *(import_data)){
             bool isNeeded = helper.searchForSymbol(symbol.first, ImportedFunctionSymbol); 
             if (isNeeded){
                 vector<string> container;
                 std::stringstream streamData(symbol.second);
                 std::string single_exception;
                 while (std::getline(streamData, single_exception, ' ')) {
                     if (single_exception == "[" || single_exception == "]")
                        continue;
                     container.push_back(single_exception);
                 }
                 import_map->insert(make_pair(symbol.first, container));
                 log_print("[Library %d] Added external symbol %s handling [%s] exceptions.\n", import_id, symbol.first.c_str(), symbol.second.c_str());
             }
         }
         
         delete import_data;
     }

     delete links_json;

     if (!import_map->size()){
        delete import_map;
        return nullptr;
     }

     return import_map;
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

void ThreatAnalysis::analyze_one_file(string id, string filename){
     // Also write ml_info analysis for backwards compatibility with the old dso
     // analysis.
     ModuleThreatInfo ml_info;
     ModuleStackInfo st_info; 
     CombinedModuleSummary c_info;


     addr_t canary_addr = 0;
     string cannary_name("__stack_chk_fail");

     map<addr_t, vector<string>>* throws_ref = nullptr; 
     map<string, vector<string>> *export_ref = nullptr;
     addr_t cxa_throw_func = 0;
     // Mark everything as normal analysis (gets switched if we included lower bounds define).
     analysis_ty threat_analysis_type = analysis_ty::THREAT_INFO;
     ml_info.info_ty = analysis_ty::THREAT_INFO;
     c_info.info_ty = analysis_ty::THREAT_INFO;

     string path_prefix;

     if (id == "0"){
        path_prefix = "";
     } else {
        path_prefix = "extracted/";
     }

     map<addr_t, vector<pair<addr_t, addr_t>>> *ranges = nullptr;

#ifdef LOWER_BOUND_STATS
     #warning lower bounds build
     threat_analysis_type = analysis_ty::THREAT_INFO_LOWER_BOUND;
     ml_info.info_ty = analysis_ty::THREAT_INFO_LOWER_BOUND;
     c_info.info_ty = analysis_ty::THREAT_INFO_LOWER_BOUND;
     // Get threat_info for file, if number of throws is 0 then no point on doing the analysis anymore.
     Json::Value *threat_info = db->getAnalysisForFile(analysis_ty::THREAT_INFO, id);
     if (threat_info){
         // If none of the functions in the previous analysis throw chances 
         // now are even smaller.
         if (!(*threat_info)["total_throw"].asInt()){
             delete threat_info;
             // write dummy entry
             db->writeInfoTable(id, c_info);
             db->writeAnalysisInfo(id, threat_analysis_type, ml_info);
             return;
         }
         delete threat_info;
     }
#endif
     Json::Value *json = nullptr;
     FDEs fdes;
     try {  
       json = db->getAnalysisForFile(1, id);
       if (!json) {
            json = new Json::Value();
            // Write json for binary to a file 
            write_exception_info_json((path_prefix + filename).c_str());
            std::ifstream json_file("/tmp/" + path(filename).filename().string() + ".json", std::ifstream::binary | std::fstream::out );
            json_file >> *json;
      }

      if (json) {
         FDEs aux(*json);
         delete json;
#ifdef LOWER_BOUND_STATS
         ranges = getAllCatchRanges(aux);
#endif   
         fdes.fdes.entries = aux.fdes.entries;
      }
     } catch(...){
       distro_print("JSON Encoding error on file: %s\n", id.c_str());
       if (json)
          delete json;
       // We don't catch exceptions but we may throw
     }

     optional<string> real_name = db->getNameForFile(id);
     optional<string> package_name =  db->getPackageForFile(id);

     if (!real_name.has_value() || !package_name.has_value()){
         progress_print("Started analysis on file: noname\n");
     } else {
         progress_print("Started analysis on file: %s package: %s\n", real_name.value().c_str(), package_name.value().c_str());
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
     Ref<BinaryView> bv = OpenView(path_prefix + filename, true, {}, options);
#endif

     progress_print("Finished loading binview...(thread %d)\n", priv_ID);
     // Initialize BVHelper
     BVHelper helper(bv);

     if (!bv)
     {
	fprintf(stderr, "Input file does not appear to be an exectuable\n");
        // Just write null entries so we don't parse these files again.
        db->writeInfoTable(id, c_info);
        db->writeAnalysisInfo(id, threat_analysis_type, ml_info);
        goto cleanup;
     }

     if (bv->GetTypeName() == "Raw")
     {
	fprintf(stderr, "Input file does not appear to be an exectuable\n");
	bv->GetFile()->Close();
        // Just write null entries so we don't parse these files again.
        db->writeInfoTable(id, c_info);
        db->writeAnalysisInfo(id, threat_analysis_type, ml_info);
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
        log_print("Stack Canary Function: 0x%lx\n", canary_addr);
     } else {
        log_print("[!] Binary does not use stack canary.\n");
     }

     // A minimalistic list of functions that throw in case we don't have DSOs.

     throws_ref = helper.getUnwindsBasedOnPattern(UNWIND_VARIANTS);
   
     if (!throws_ref){
        log_print("[!] Binary does not rethrow.\n");
     }

     cxa_throw_func = helper.getCXA_throw(cxa_throw);
   
     if (!cxa_throw_func){
        log_print("[!] Binary does not have cxa_throw.\n");
     } else {
        log_print("cxa_throw function: 0x%lx\n", cxa_throw_func);
     }

     export_ref = getExportedSymbolsForFile(bv, id, threat_analysis_type);

     if (!export_ref){
         log_print("[!] Binary does not import exceptions from other DSOs.\n");
     }

     // In case we have nothing just try loading some default STD related handlers.
     // Hopefully a link to stdc is missing or it's using some older stdc ?
     if (!throws_ref && !cxa_throw_func && !export_ref){
        throws_ref = helper.getThrowsBasedOnPatern(THROW_VARIANTS);
        // If we have no throw pattern then simply return. We're wasting time
        // analyzing this file.
        if (!throws_ref){
           log_print("[!] Binary does not throw.\n");
           // TODO fix this for lower bounds.
           // No point in closing file as we will now at least run the stack analysis.
           //bv->GetFile()->Close();
           //db->writeAnalysisInfo(id, threat_analysis_type, ml_info);
           //goto cleanup;
           // Continue with stack analysis
        }
     }
     
     // Go through all functions in the binary
     for (auto& func : bv->GetAnalysisFunctionList())
     {
         FunctionLevelAnalysis f_analysis(func, bv, throws_ref, export_ref, cxa_throw_func);
         f_analysis.file_id = id;
         f_analysis.catch_ranges = ranges;
         f_analysis.canary_addr = canary_addr;
         f_analysis.analysis_ty = threat_analysis_type;


         pair<optional<FunctionThreatInfo>, optional<FunctionStackInfo>> analysis_result = f_analysis.runAnalysis();
         
         
 
         optional<FunctionThreatInfo> &ti = analysis_result.first;
         bool have_analysis = ti.has_value();
         bool is_exported = false;
         // If this symbol can be exported then add the name to the exported table.
         Ref<Symbol> sym = func->GetSymbol();
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


     // Write threat info analysis for module
     //db->writeAnalysisInfo(id, threat_analysis_type, ml_info);

     db->writeInfoTable(id, ml_info);
     if (ml_info.info_ty == analysis_ty::THREAT_INFO)
       db->writeInfoTable(id, st_info);

     // Initialize and write threat info + stack info summary.

     c_info.initModuleSummary(ml_info, st_info);
     db->writeInfoTable(id, c_info);


     /* Delete all maps we've used */
     if (throws_ref)
        delete throws_ref;

     if (export_ref)
        delete export_ref;

     bv->GetFile()->Close();

cleanup:
     if (ranges){
        delete ranges;
     }

#ifndef BINJA_3_0_3388
     bd->GetFile()->Close();
     metadata->Close();
     delete metadata;
#endif
     return;
}


