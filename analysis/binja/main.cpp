#include "threat_analysis.h"
#include "threat_analysis_ossfuzz.h"
#include "stack_analysis.h"
#include "taint_analysis.h"
#include "binaryninjacore.h"
#include "binaryninjaapi.h"
#include "mediumlevelilinstruction.h"
#include "highlevelilinstruction.h"
#include "database.h"
#include <iostream>

#define NUM_THREADS 1
using namespace std;
using namespace BinaryNinja;


#ifndef _WIN32
	#include <libgen.h>
	#include <dlfcn.h>
static string GetPluginsDirectory()
{
	Dl_info info;
	if (!dladdr((void*)BNGetBundledPluginDirectory, &info))
		return NULL;

	stringstream ss;
	ss << dirname((char*)info.dli_fname) << "/plugins/";
	return ss.str();
}
#else
static string GetPluginsDirectory()
{
	return "C:\\Program Files\\Vector35\\BinaryNinja\\plugins\\";
}
#endif

void *run(void *arg)
{
    ModuleAnalysis* obj = (ModuleAnalysis*)arg;
    return obj->run();
}

ModuleAnalysis *analysis_factory(wqueue<Pair>  &queue, std::set<string> *processed_files){
#ifdef STACK_ANALYSIS
   return new StackAnalysis(queue);
#elif defined(TAINT_ANALYSIS)
   return new HandlerAnalysis(queue);
#elif defined(OSS_THREAT_ANALYSIS)
   return new OSSThreatAnalysis(queue, processed_files);
#else
   return new ThreatAnalysis(queue, processed_files);
#endif
}

int run_one_module(char *arg){
    pthread_t  thread;
    wqueue<pair<string, string>>  queue;

    string module_id(arg);

    DB *db = new DB();

    optional<string> sha256 = db->getSHAForFile(module_id);
       
    delete db;

    if (!sha256.has_value()){
      fprintf(stdout, "Invalid file id...\n");
      return -1;
    }
    queue.add(pair<string, string>(module_id, sha256.value()));

    ModuleAnalysis *obj = analysis_factory(queue, nullptr);

    obj->run();
    //pthread_create(&thread, NULL, run, obj);

    //(void) pthread_join(thread, NULL);

    delete obj;

    fprintf(stdout, "Finished running analysis...\n");

    return 0;
}

int run_on_custom_function(char *arg){
   string binary_path(arg);
   string id("0");

   wqueue<pair<string, string>>  queue;

   queue.add(pair<string, string>(id, binary_path));

   ModuleAnalysis *obj = analysis_factory(queue, nullptr);

   obj->run_custom();

   fprintf(stdout, "Finished running analysis...\n");

   delete obj;
}

int run_on_specific_functions(char *arg, string functions){
   string binary_path(arg);
   string id("0");

   wqueue<pair<string, string>>  queue;

   queue.add(pair<string, string>(id, binary_path));
#ifdef OSS_THREAT_ANALYSIS
   ModuleAnalysis *obj = new OSSThreatAnalysis(queue, nullptr);
   ((OSSThreatAnalysis *)obj)->analysis_functions = functions; 

   obj->run_custom();

   fprintf(stdout, "Finished running analysis...\n");

   delete obj;
#endif
}

int run_all_modules(void){
   pair<pthread_t, ModuleAnalysis *>  thread[NUM_THREADS];
   wqueue<Pair>  queue;
   std::set<string> *processed_files = nullptr;
   DB *db = new DB();
#ifdef THREAT_ANALYSIS
   #warning THREAT_BUILD
   list<Pair>* work = db->getAllFilesTopoSorted();

   processed_files = db->getAllFiles();
#else
   #warning STACK_BUILD or TAINT_BUILD
   list<Pair>* work = db->getAllFilesAndIds();
#endif

   delete db;

   if (!work){
      fprintf(stdout, "No work...\n");
      return -1;
   }

   for (auto wqitem : *work){
      queue.add(wqitem);
   }
   /* Don't need this anymore */
   delete work;

   /* Create some threads and put them to work. */
   for (int i = 0; i < NUM_THREADS; i++){
      thread[i].second = analysis_factory(queue, processed_files);
      pthread_create(&(thread[i].first), NULL, run, thread[i].second);
   }

   for (int i = 0; i < NUM_THREADS; i++){
      (void) pthread_join(thread[i].first, NULL);
      printf("Freed thread %d\n", i+1);
      delete thread[i].second;
   }

   delete processed_files;

   return 0;

}


int main(int argc, char* argv[])
{

    // In order to initiate the bundled plugins properly, the location
    // of where bundled plugins directory is must be set. Since
    // libbinaryninjacore is in the path get the path to it and use it to
    // determine the plugins directory
    SetBundledPluginDirectory(GetPluginsDirectory());
    InitPlugins();
#ifdef OSS_THREAT_ANALYSIS
    if (argc != 5){
       // Just make sure we don't bust the database by mistake when running oss_fuzz analysis
       printf("[!] Only custom option available for oss_fuzz analysis\n");
       BNShutdown();
       return 0;
    }
#endif
    if (argc == 3){
       string middle(argv[1]);
       if (middle == "-raw") {
          run_on_custom_function(argv[2]);
       }
       else {
          printf("[!] Wrong paramters error\n");
          return -1;
       }
    }
#ifdef OSS_THREAT_ANALYSIS
    else if (argc == 5){
       #warning OSS_FUZZ_ANALYSIS
       string middle(argv[1]);
       string func_trigger(argv[3]);
       if (middle == "-raw" && func_trigger == "-trigger") {
          run_on_specific_functions(argv[2], argv[4]);
       }
       else {
          printf("[!] Wrong paramters error\n");
          return -1;
       }       
    }
#endif
    else if (argc == 2)
    {
       run_one_module(argv[1]);
    } 
    else {
       // TODO run for all modules from the db. 
       // We have the handler for it but need to change that to work
       // with DSO modules. Essentially we need to reorder how we parse
       // modules such that the DSOs will be processed before the modules
       // that use them.
       run_all_modules();
    }
       
 

    // Shutting down is required to allow for clean exit of the core
    BNShutdown();

    return 0;
}
