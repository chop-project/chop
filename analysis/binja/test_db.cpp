#include "database.h"
// INTENDED FOR TESTING PURPOSES ONLY.
int main(){
    DB c;

    if (!c.is_connected())
       return 0;

   c.getAnalysisForSHA(3, "4d366695fab531a2794c148fd977e543632ae9cc65c721a5b7d7390a61934794");
 
    //c.getAnalysisForFile(5, "491411");

   // Json::Value *json = c.getAnalysisForFile(4, "491411");

   // std::cout << *json << endl;
    
   list<pair<string, bool>> export_list;

   // c.writeExportTable("491411", export_list);

   Json::Value *import_data = c.getAnalysisForFile(analysis_ty::EXPORT_TABLE, "491411");

   if (!import_data){ 
      printf("Errror\n");
   }
   const Json::Value imported_symbols = *import_data;
   for (int i = 0; i < imported_symbols.size(); ++i){
   }
   delete import_data;

#if 0
    map<string, string> *files = c.getFilesToAnalyze();

    map<string, string>::iterator it;

    for (it = files->begin(); it != files->end(); it++)
    {
    std::cout << it->first    // string (key)
              << ':'
              << it->second   // string's value 
              << std::endl;
    }

    delete files;
#endif


    return 1;
}
