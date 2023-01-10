#ifndef _STACK_ANALYSIS_H
#define _STACK_ANALYSIS_H
#include "binaryninjacore.h"
#include "binaryninjaapi.h"
#include "mediumlevelilinstruction.h"
#include "highlevelilinstruction.h"
#include "lowlevelilinstruction.h"

#include <thread>
#include "analysis.h"

using namespace BinaryNinja;
using namespace std;

extern "C" {
void write_exception_info_json(const char *path);
}

class FunctionStackAnalysis
{
  private:

    Ref<Function> &function;
    Ref<BinaryView> &bv;

    bool guardedWithCanaries();



  public:
    addr_t canary_addr = 0;
    addr_t addr;

    FunctionStackAnalysis(Ref<Function> &function, Ref<BinaryView> &bv)
          : function(function), bv(bv) {
    }
    ~FunctionStackAnalysis() {}

    optional<tuple<unsigned int, unsigned int, int, bool, uint32_t>> runStackAnalysis();

    std::optional<FunctionStackInfo> runAnalysis();

};

class StackAnalysis : public ModuleAnalysis
{
   private:
    void analyze_one_file(string id, string filename) override;

   public:
    StackAnalysis(wqueue<pair<string,string>>& queue): ModuleAnalysis(queue) {}
    ~StackAnalysis() {}

};

#endif
