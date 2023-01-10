#ifndef _TAINT_ANALYSIS_H
#define _TAINT_ANALYSIS_H
#include "binaryninjacore.h"
#include "binaryninjaapi.h"
#include "mediumlevelilinstruction.h"
#include "highlevelilinstruction.h"
#include "lowlevelilinstruction.h"
#include <iostream>
#include <thread>
#include "analysis.h"
#include "hlilcomparator.h"
using namespace BinaryNinja;
using namespace std;


extern "C" {
void write_exception_info_json(const char *path);
}

#define STACK_MODEL 70
#define MODEL 6

typedef enum {
    TAINT_DEREF = 0,
    TAINT_SSA = 1,
    TAINT_PTR = 2
} taint_type;

struct TaintStatus {
   bool in_assign;
   bool in_branch;
   bool in_array_index;
   bool in_deref;
   bool eval_address_of;
   bool in_left_assign; // true if on a left hand side of an assignment.
   // True if we're propagating taint of compare instructions.
   // This trigger is mostly for conditional expressions in loops, ifs in
   // case we would like to check taint on those. Don't propagate taint if
   // the result of the compare is assigned to a ssa variable as we essentially
   // control a 0/1 state (not really much we can do with that and it might
   // overtaint).
   bool propagate_cmp;

   int loop_level;
   int branch_level;
   unsigned int tainted_exprs;
   unsigned int num_sinks;
   unsigned int num_funcs;
   unsigned int num_blocks;
#if 0
   unsigned int num_tail_calls;

   HighLevelILInstruction last_tail_call;
#endif
};

class FunctionTaint : public FunctionLevelAnalysis_tmpl
{
  private:

    Ref<Function> function;
    Ref<BinaryView> bv;
    addr_t func_addr;

    TaintStatus status;

    // List of SSA variables that are tainted
    map<std::string, unsigned int> TaintedVars;
    // List of tainted exprIds and their taint
    map<HLILComparableIL, unsigned int> TaintedExprs;
    set<unsigned int> VisitedExprs;


    void setInitialTaintState();
    void setInitialTaintStateByModel(unsigned int model);
    // Iterate over subexpressions of an instruction and propagate taint.
    unsigned int evalTaint(const HighLevelILInstruction& instr, bool markVisited = false);
    // Propagate the taint on a specific expression. Overtaints in some cases.
    void propagateTaint(const HighLevelILInstruction& instr, unsigned int taint, taint_type type = TAINT_SSA);
    void propagateTaint(const SSAVariable& var, unsigned int taint, taint_type type = TAINT_SSA);
    void propagateTaint(const Variable& var, unsigned int taint, taint_type type = TAINT_SSA);

    /* Get taint of ssa variable */
    unsigned int get_ssa_var_taint(SSAVariable var);
    unsigned int get_var_taint(Variable var);

    void printFunctionName(const HighLevelILInstruction& instr);
    optional<string> getFunctionName(const HighLevelILInstruction& instr);
    addr_t getFunctionAddress(const HighLevelILInstruction& instr);
    void printCallTaintSummary(const HighLevelILInstruction& instr, unsigned int target_taint, bool call_sink = false);
    void printCallNoTaintSummary(const HighLevelILInstruction& instr);
    void printMemoryTaintSummary(const HighLevelILInstruction& instr, unsigned int srcTaint, unsigned int destTaint);
    bool isDestInSource(const HighLevelILInstruction& instr);
    unsigned int get_current_complexity();
    bool doesFunctionPrint(addr_t address);

  public:
    vector<Sink> sink_list;
    set<addr_t> *whitelist;
    set<addr_t> *notaintlist;
    set<addr_t> *leakset;
    set<addr_t> *uafset;
    map<addr_t, bool> *printset;
    FunctionTaint(Ref<Function> function, Ref<BinaryView> bv)
          : function(function), bv(bv) {
        status.in_assign = false;
        status.propagate_cmp = false;
        status.in_branch = false;
        status.in_array_index = false;
        status.eval_address_of = false;
        status.in_left_assign = false;
        status.in_deref = false;
        status.loop_level = 0;
        status.branch_level = 0;
        status.tainted_exprs = 0;
        status.num_sinks = 0;
        status.num_blocks = 0;
        status.num_funcs = 0;
#if 0
        status.num_tail_calls = 0;
#endif
        /* Some extra monster logic */
        whitelist = nullptr;
        notaintlist = nullptr;
        leakset = nullptr;
        printset = nullptr;
        uafset = nullptr;
    }
    //~FunctionTaint() {}

    optional<int> runTaintingPass();

    std::optional<FunctionStackInfo> runAnalysis();

};

class HandlerAnalysis : public ModuleAnalysis
{
   private:
    void analyze_one_file(string id, string filename) override;

    set<addr_t> construct_whitelist(Ref<BinaryView> &bv);
    set<addr_t> construct_notaintlist(Ref<BinaryView> &bv);
    set<addr_t> construct_leakset(Ref<BinaryView> &bv);
    void construct_noreturn_list(Ref<BinaryView> &bv);
    set<addr_t> construct_uaf_list(Ref<BinaryView> &bv);

   public:
    HandlerAnalysis(wqueue<pair<string,string>>& queue): ModuleAnalysis(queue) {}
    ~HandlerAnalysis() {}

};

#endif
