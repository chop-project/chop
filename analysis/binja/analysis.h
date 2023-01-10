#ifndef _ANALYSIS_H
#define _ANALYSIS_H

#include <stdlib.h>
#include <stdio.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string>
#include <optional>
#include <iostream>

#include "wqueue.h"

#include "bvhelper.h"
#include "database.h"

//#define ONLY_POPULAR
using namespace std;

class ModuleAnalysis { 
   protected:
        static int ID;

        int priv_ID;
        
        /* Link to database */
        DB *db;

        /* Queue of files */
        wqueue<pair<string, string>>& m_queue;

        virtual void analyze_one_file(string id, string filename) = 0;

#ifdef ONLY_POPULAR
        list<string> popular_files;
        set<string> matched;
#endif

   public:
        void* run();
        void* run_custom();

        ModuleAnalysis(wqueue<pair<string,string>>& queue);

        virtual ~ModuleAnalysis();
};

class FunctionLevelAnalysis_tmpl {
   public:
        int priv_ID;

        FunctionLevelAnalysis_tmpl(void);
};

#endif
