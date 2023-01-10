#ifndef _THREAT_ANALYSIS_H
#define _THREAT_ANALYSIS_H
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

class FunctionLevelAnalysis
{
  private:

    Ref<Function> &function;
    Ref<BinaryView> &bv; 
    addr_t start;
    // Functions that explicitly throw from our module
    // TODO at some point move initial THROW_ANALYSIS to this C++ module.
    map<addr_t, vector<string>> *throwMap;
    // List of symbols from external modules
    map<string, vector<string>> *exportMap;

   
    addr_t cxa_throw;

    // Max level in the call-graph after which we stop analysis
    int MAX_LEVEL = 6;

    optional<vector<ExceptionThreatInfo>> runThrowAnalysis();

    pair<int, bool> countCalleeSavedRegisters();
    // Checks if function is in one of the catch ranges.
    bool checkRanges(addr_t parent, addr_t cs);
 
    // Does function use stack protector.
    bool guardedWithCanaries();

    // Stack info. 
    optional<tuple<unsigned int, unsigned int, int, bool, uint32_t, int>> runStackAnalysis();

    // Internal function cache to keep track of what we've visited from this function.
    std::set<addr_t> visited_functions;

  public:
    map<addr_t, vector<pair<addr_t, addr_t>>> *catch_ranges;
    string file_id;
    addr_t canary_addr = 0;
    addr_t addr = 0;
    int analysis_ty = 0;


    FunctionLevelAnalysis(Ref<Function> &function, Ref<BinaryView> &bv,  map<addr_t, vector<string>> *throwMap, map<string, vector<string>> *exportMap, addr_t cxa_throw)
          : function(function), bv(bv), throwMap(throwMap), exportMap(exportMap), cxa_throw(cxa_throw)  {
        start = function->GetStart();
    }
    ~FunctionLevelAnalysis() {}

    pair<std::optional<FunctionThreatInfo>, std::optional<FunctionStackInfo>> runAnalysis();

};

class ThreatAnalysis : public ModuleAnalysis
{
   private:
    std::set<string> *processed_files;

    optional<pair<map<addr_t, int> *, map<addr_t, int> *>> getThrowAnalysisForFile(string file_id);

    map<string, vector<string>>* getExportedSymbolsForFile(Ref<BinaryView> bv, string file_id, analysis_ty type);
    map<string, vector<string>>* getExportedSymbolsForFileOld(Ref<BinaryView> bv, string file_id, analysis_ty type);

    void analyze_one_file(string id, string filename) override;

   public:
    ThreatAnalysis(wqueue<pair<string,string>>& queue, std::set<string>* processed_files): ModuleAnalysis(queue), processed_files(processed_files) {}
    ~ThreatAnalysis() {}

};

#endif
