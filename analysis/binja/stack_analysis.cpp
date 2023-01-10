#include "stack_analysis.h"
#include <iostream>
#include <unistd.h>
#include "debug.h"

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

string decode_registers(uint32_t reg_ENCODING, bool omitfp){
   string register_str = "";
   if (reg_ENCODING & RBX_ENCODING){
      register_str += "RBX ";
   }

   if (omitfp && (reg_ENCODING & RBP_ENCODING)){
      register_str += "RBP ";
   }

   if (reg_ENCODING & R12_ENCODING){
      register_str += "R12 ";
   }

   if (reg_ENCODING & R13_ENCODING){
      register_str += "R13 ";
   }

   if (reg_ENCODING & R14_ENCODING){
      register_str += "R14 ";
   }

   if (reg_ENCODING & R15_ENCODING){
      register_str += "R15 ";
   }

   if (!omitfp && (reg_ENCODING & RBP_ENCODING)){
      register_str += "RBP ";
   }

   return register_str;
}

string decode_exception(uint32_t exc_ENCODING){
   string register_str = "";
   if (!exc_ENCODING)
     return "NONE";
   if (exc_ENCODING & HANDLES_ALL){
      register_str += "ALL ";
   }

   if (exc_ENCODING & HANDLES_EXCEPTIONS){
      register_str += "EXC ";
   }

   if (exc_ENCODING & HANDLES_CLEANUP){
      register_str += "CLN. ";
   }


   return register_str;
}


#undef DEBUG_MODULE
std::optional<FunctionStackInfo> FunctionStackAnalysis::runAnalysis(){
   // TODO call runStackVulnerability analysis.
#ifdef DEBUG_MODULE
   Ref<Symbol> debug_sym = function->GetSymbol();
   string dbg_symbol = (debug_sym) ? debug_sym->GetFullName() : "";
   debug_print("Started running analysis on function -> function: (%s) address: (0x%lx) pid (%ld)\n", dbg_symbol.c_str(), function->GetStart(), pthread_self());
#endif
   addr = function->GetStart();
   optional<tuple<unsigned int, unsigned int, int, bool, uint32_t>> result = runStackAnalysis();

   if (result.has_value()){

      tuple<unsigned int, unsigned int, int, bool, uint32_t> s_analysis = result.value();
      bool uses_canaries = guardedWithCanaries();
      
      FunctionStackInfo fi(function->GetStart(), std::get<0>(s_analysis), std::get<1>(s_analysis),
                                                 std::get<2>(s_analysis), std::get<3>(s_analysis), uses_canaries,
                                                 std::get<4>(s_analysis));
#ifdef DEBUG_MODULE
      debug_print("Finished parsing function -> (%s)...\n", dbg_symbol.c_str());
#endif
      return fi;
   }

#ifdef DEBUG_MODULE
   debug_print("Finished parsing function -> (%s)...\n", dbg_symbol.c_str());
#endif
   return nullopt;
}
#define DEBUG_MODULE

/* Determine frame size based on number of pushes + sub rsp in the prologue.
   Should work for X86_64 but for 32bits some changes will be necessary.
   TODO there are other approaches to compute all possible unwinding states
   for a specific function frame, but the max size of the frame is probably 
   what will be used when unwinding from most catch blocks. */
optional<tuple<unsigned int, unsigned int, int, bool, uint32_t>> FunctionStackAnalysis::runStackAnalysis(){
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
                                log_print("[!] Problem function %s 0x%lx is saving non-callee register %d\n", sym_name.c_str(), function->GetStart(), reg_idx);
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
   return tuple<unsigned int, unsigned int, int, bool, uint32_t>(stack_size, local_size, num_callees, omit_fp, reg_encoding);

}

/* Returns true if the function calls stack_chk_fail */
bool FunctionStackAnalysis::guardedWithCanaries(){
   bool finished = false;
   /* Probably this binary is not compiled with stack protector */
   if (!canary_addr)
      return false;

   Ref<HighLevelILFunction> il = function->GetHighLevelIL()->GetSSAForm();

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

void StackAnalysis::analyze_one_file(string id, string filename){
     ModuleStackInfo ml_info;
     addr_t canary_addr = 0;
     string cannary_name("__stack_chk_fail");

     string path_prefix;

     if (id == "0"){
        path_prefix = "";
     } else {
        path_prefix = "extracted/";
     }

#ifdef USE_DB_ANALYSIS
     #warning using DB ANALYSIS INFO
     Json::Value *json = db->getAnalysisForFile(1, id);
#else
     Json::Value *json = new Json::Value();
     // Write json for binary to a file
     write_exception_info_json((path_prefix+ filename).c_str());
     std::ifstream json_file("/tmp/" + path(filename).filename().string() + ".json", std::ifstream::binary | std::fstream::out );
     json_file >> *json;

#endif
     if (!json)
         return;

     FDEs fdes(*json);
     delete json;

     progress_print("Started loading binview for file %s hash:%s...(thread %d)\n", id.c_str(), filename.c_str(), priv_ID);
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

     BVHelper helper(bv);

     progress_print("Finished loading binview...(thread %d)\n", priv_ID);

     if (!bv)
     {
	fprintf(stderr, "Could not open bv\n");
        goto cleanup;
     }
     
     if (bv->GetTypeName() == "Raw")
     {
	fprintf(stderr, "Input file does not appear to be an exectuable\n");
	bv->GetFile()->Close();
        goto cleanup;
     }

     progress_print("Started update analysis binview...(thread %d)\n", priv_ID);
#ifndef BINJA_3_0_3388
     bv->UpdateAnalysisAndWait();
#endif

     progress_print("Finished update analysis binview...(thread %d)\n", priv_ID);



     canary_addr = helper.getFunctionByName(cannary_name);

     if (canary_addr){
        log_print("Stack Canary Function: 0x%lx\n", canary_addr);
        // This module uses stack canaries.
        ml_info.uses_canary = true;
     }


     // Go through all functions in the binary
     for (auto& func : bv->GetAnalysisFunctionList())
     {
         FunctionStackAnalysis f_analysis(func, bv);
         f_analysis.canary_addr = canary_addr;

         optional<FunctionStackInfo> analysis_result = f_analysis.runAnalysis();

         bool have_analysis = analysis_result.has_value();

     
         /* Add analyzed function to ml_info */
         if (have_analysis){
            unsigned int enc_exc = 0;
            for (auto function : fdes.fdes.entries){
              if (function.fstart ==  f_analysis.addr) {
                 enc_exc |= handlesExceptions(function);
              }
            }
            FunctionStackInfo si = analysis_result.value();
            si.enc_exc = enc_exc;
            ml_info.addEntry(si);
         }
         else {
            ml_info.total_functions++;
         }

     }

     // Write threat info analysis for module
     // Just a null entry now so we don't reanalyze files.
     if (id != "0"){
       db->writeStackInfo(id, ml_info);
     }
     for (auto &fi : ml_info.functions.entries){
         log_print("Function %s:\tfrm sz. %s\tlcl sz. %s\tomitfp. %s\tstackc. %s\tc-saved %d\tR:[%s]\tEx:[%s]\n", fi.address.c_str(), fi.frame_size.c_str(), fi.local_size.c_str(), 
                                                              fi.omit_fp ? "True" : "False",
                                                              fi.uses_canary ? "True" : "False",
                                                              fi.num_callees, decode_registers(fi.enc_regs, fi.omit_fp).c_str(), decode_exception(fi.enc_exc).c_str()); 
                
     }

     progress_print("Module analysis complete for %s\n", id.c_str());
     progress_print("Total Functions: (%d) Total Processed (%d)\n", ml_info.total_functions,  ml_info.total_processed);
     bv->GetFile()->Close();

cleanup:

#ifndef BINJA_3_0_3388
     bd->GetFile()->Close();
     metadata->Close();
     delete metadata;
#endif

     return;
}


