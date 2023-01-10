#include "analysis.h"
#include <unistd.h>
#include <fstream>
#include "debug.h"
#include "boost/filesystem.hpp"

using namespace boost::filesystem;

int ModuleAnalysis::ID = 0;

#ifdef DEBUG_FILE
map<pthread_t, FILE *> dbgfile;
#endif

#ifdef ONLY_POPULAR
#define MAX_PACKAGES 200
void printUnMatchedPackages(list<string> &popular_files, set<string> matched){
  printf("No matches for:\n");
  int i = 0;
  for (auto& popular_file: popular_files){
      if (!matched.count(popular_file)){
         printf("%d.  %s\n", i, popular_file.c_str());
         i++;
      }
  }
}
#endif

FunctionLevelAnalysis_tmpl::FunctionLevelAnalysis_tmpl() {
   priv_ID = 0;
}

ModuleAnalysis::ModuleAnalysis(wqueue<pair<string,string>>& queue) : m_queue(queue) {
   priv_ID = ++ID;
   //db = new DB();
#ifdef ONLY_POPULAR
   //std::ifstream file("popular_packages_deb");
   std::ifstream file("popular_packages_deb_200");
   std::string popular;
   int num_packages = 0;
   while (std::getline(file, popular))
   {
      if (num_packages >= MAX_PACKAGES)
         break;
      popular_files.push_back(popular);
      num_packages++;
   }
#endif
}

ModuleAnalysis::~ModuleAnalysis(){
  //delete db;
}

void* ModuleAnalysis::run(){
     // Remove 1 item at a time and process it. Blocks if no items are
     // available to process.
     while (true) {

       distro_print("Fetching another file (thread %d)\n", priv_ID);
       optional<pair<string,string>> item = m_queue.remove();

       if (!item.has_value()) {
#ifdef ONLY_POPULAR
           printUnMatchedPackages(popular_files, matched);
#endif
           return NULL;
       }
       pair<string,string> file = item.value();

       distro_print("Started processing file %s %s\n", file.first.c_str(), file.second.c_str());

#ifdef ONLY_POPULAR

       optional<string> real_name = db->getPackageForFile(file.first);

       if (!real_name.has_value()){
          continue;
       }
      
        string package_name = real_name.value();
        bool found = false;
        for (auto& popular_file: popular_files){
          if (package_name == popular_file){
              printf("Found popular candidate %s in %s\n", file.first.c_str(), popular_file.c_str());
              if (!matched.count(popular_file))
                  matched.insert(popular_file);
              found = true;
              break;
          }
        }

        if (!found)
           continue;
     
#endif

#ifdef DEBUG_FILE
       string prefix;
#if defined(TAINT_ANALYSIS)
       #warning TAINT_BUILD
       prefix = "./taint/";
#elif defined(STACK_ANALYSIS)
       #warning STACK_BUILD
       prefix = "./stackinfo/";
#else
       #warning THREAT_BUILD
       prefix = "./threatinfo/";
#endif
       dbgfile[pthread_self()] =  fopen((prefix + file.first).c_str() ,"w");
#endif

       analyze_one_file(file.first, file.second);

#ifdef DEBUG_FILE
       fclose(dbgfile[pthread_self()]);
#endif
            
     }

     return NULL;
}

void* ModuleAnalysis::run_custom(){
     // Remove 1 item at a time and process it. Blocks if no items are
     // available to process.
     while (true) {

       distro_print("Fetching another file (thread %d)\n", priv_ID);
       optional<pair<string,string>> item = m_queue.remove();
       if (!item.has_value()) {
           return NULL;
       }

       pair<string,string> file = item.value();
       path binpath(file.second);

       distro_print("Started processing file %s %s\n", file.first.c_str(), file.second.c_str());


#ifdef DEBUG_FILE
       string prefix = "./custom/";
       string suffix;
#if defined(TAINT_ANALYSIS)
       suffix = ".taint";
#elif defined(STACK_ANALYSIS)
       suffix = ".stack";
#elif defined(OSS_THREAT_ANALYSIS)
       #warning OSS_FUZZ_ANALYSIS step 2
       suffix = "";
       prefix = "/home/victor/workspace/PHD/exceptions/ossfuzzy/results";
#else
       #warning THREAT_BUILD
       suffix = ".threat";
#endif
       dbgfile[pthread_self()] =  fopen((prefix + path(binpath).filename().string() + suffix).c_str() ,"w");
#endif

       analyze_one_file(file.first, file.second);

#ifdef DEBUG_FILE
       fclose(dbgfile[pthread_self()]);
#endif

     }

     return NULL;
}
