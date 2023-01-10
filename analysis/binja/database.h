#ifndef _DATABASE_H
#define _DATABASE_H

#include <iostream>
#include <pqxx/pqxx> 
#include <jsoncpp/json/json.h>
using namespace std;
using namespace pqxx;
#include <set>

#include "utils.h"

typedef pair<string, string> Pair;
// Analysis types
// All analyses are moved to 3..
enum analysis_ty {
     EXCEPTION_INFO = 1,
     STACK_CANARY_INFO = 2,
     THROW_INFO = 3,
     DSO_LINKS = 4,
     EXPORT_TABLE = 5,
     THREAT_INFO = 6,
     STACK_INFO = 7,
     TAINT_INFO = 8,
     THREAT_INFO_LOWER_BOUND = 9
};

class DB {
   private:
        // Keep one live connection per-thread.
        connection * conn;
        // Called from constructor to connect to the db.
        connection * connect_db();
 
        map<string, string>* getFilesToAnalyze();

   public:
        // Constructor
        DB();

        // Free connection if opened.
        ~DB();

        std::set<string> *getAllFiles();

        list<Pair> *getAllFilesTopoSorted();
        
        Json::Value* getAnalysisForSHA(int analysis_type, const std::string& file_sha);

        Json::Value* getAnalysisForFile(int analysis_type, const std::string& file_id);

        optional<string> getSHAForFile(const std::string& file_id);
        optional<string> getNameForFile(const std::string& file_id);
        std::optional<string> getPackageForFile(const std::string& file_id);
        list<Pair>* getAllFilesAndIds();

        bool writeExportTable(const std::string& file_id, list<pair<string, bool>> &export_list);

        bool writeThreatInfo(const std::string& file_id, ModuleThreatInfo &ti);

        bool writeStackInfo(const std::string& file_id, ModuleStackInfo &si);

        bool writeTaintInfo(const std::string& file_id, TaintInfo &ti);
        bool writeAnalysisInfo(const std::string& file_id, analysis_ty table, ModuleThreatInfo &ti);

        void writeStackInfoEntryT(const std::string& file_id, FunctionStackInfo &si);

        // General function to write a JSONSerializable object to the database.
        void writeInfoTable(const std::string& file_id, JSONSerializable &si);

        // New function to get exported symbols from module (the json analysis approach is deprecated)
        list<Pair> *getExportedSymbols(int analysis_type, const std::string& file_id);
        bool hasCombinedAnalysis(int analysis_type, const std::string& file_id);

        // Test before using the database.
        bool is_connected();
};

#endif
