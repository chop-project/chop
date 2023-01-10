#include "database.h"
#include <string> 
#include <map>


#include "boost/graph/adjacency_list.hpp"
#include "boost/graph/topological_sort.hpp"
#include "debug.h"
using namespace boost;

typedef property<vertex_name_t, std::string> VertexProperty;
typedef adjacency_list <vecS, vecS, directedS, VertexProperty> vector_graph_t;

DB::DB(){
   // This might fail
   conn = connect_db();
}

DB::~DB(){

   if (conn) {
        //conn->disconnect();
        delete conn;
        cout << "Freeing resources for db" << endl;
   }
}

//  The DB will try connecting on the constructor but might fail
//  just check if we are connected before using this object.
bool DB::is_connected(){
   return conn != nullptr;
}

connection* DB::connect_db(void){
  connection *conn = nullptr;

  try {
        conn = new connection("dbname = exceptionalresearch user = ubuntu password = exceptionalresearch \
                               hostaddr = 127.0.0.1 port = 5432");
        if (conn->is_open()) {
            cout << "Opened database successfully: " << conn->dbname() << endl;
            return conn;
        } else {
            cout << "Can't open database" << endl;
            return nullptr;
        }
  }

  catch (const std::exception &e) {
      cerr << e.what() << std::endl;

      if (conn) {
        //conn->disconnect();
        delete conn;
      }

      return nullptr;
  }
}

map<string, string>* DB::getFilesToAnalyze(){
   map<string, string> *file_map = nullptr;

   if (conn == nullptr){
     return nullptr;
   }

   try { 
     pqxx::nontransaction txn{*conn};
#if 0 
     string query = "SELECT id, sha256 FROM cpp_files_cutoff where rk <= 500 and \
                            id not in (select file_id from threat_stack_summary where info_ty = 6)";
#endif
     string query = "SELECT id, sha256 FROM cpp_files_cutoff where \
                            id not in (select file_id from threat_stack_summary where info_ty = 6) \
                            and id in (select id from files f where f.elf_analyzed = true and f.elf_extracted = true)";
     /* TODO probably we only need those that have throw analysis done */
     pqxx::result res{txn.exec(query)};

     if (res.begin() == res.end()){     
        return nullptr;
     }

     file_map = new map<string, string>();

     for (result::const_iterator it = res.begin(); it != res.end(); ++it){
        file_map->insert(Pair(it[0].as<string>(), it[1].as<string>()));
     }
   
   }
   catch (const std::exception &e) {

      warning_print("Exception while loading processing candidates\n");

      cerr << e.what() << std::endl;

      if (file_map)
          delete file_map;

      return nullptr;
   }

   return file_map;
}

std::set<string>* DB::getAllFiles(){
   std::set<string> *file_set = nullptr;

   if (conn == nullptr){
     return nullptr;
   }

   try {
     pqxx::nontransaction txn{*conn};
     /* TODO probably we only need those that have throw analysis done */
#if 0 
     string query = "SELECT id FROM cpp_files_cutoff where rk <= 500";
#endif
     string query = "SELECT id FROM cpp_files_cutoff where \
                      id in (select id from files f where f.elf_analyzed = true and f.elf_extracted = true)";
     pqxx::result res{txn.exec(query)};

     if (res.begin() == res.end()){
        return nullptr;
     }

     file_set = new set<string>();

     for (result::const_iterator it = res.begin(); it != res.end(); ++it){
        file_set->insert(it[0].as<string>());
     }

   }
   catch (const std::exception &e) {

      cerr << e.what() << std::endl;

      warning_print("Exception loading prune set\n");

      if (file_set)
          delete file_set;

      return nullptr;
   }

   return file_set;
}
// Bit messy but lets make things faster.
list<Pair>*  DB::getAllFilesAndIds(){
   list<Pair> *file_set = nullptr;

   if (conn == nullptr){
     return nullptr;
   }

   try {
     pqxx::nontransaction txn{*conn};
     /* TODO probably we only need those that have throw analysis done */
#ifdef STACK_ANALYSIS
     #warning STACK_ANALYSIS_BUILD
     string query = "SELECT exceptions.id, exceptions.sha256 FROM cpp_files_cutoff exceptions \
                                            where exceptions.id not in (select file_id from analysis where type = 7) and rk <= 107 order by exceptions.size ASC";
#else 
     #warning TAINT_ANALYSIS_BUILD
     string query = "SELECT exceptions.id, exceptions.sha256 FROM cpp_files_cutoff exceptions \
                                            where  \
                                            exceptions.id not in (select file_id from analysis where type = 8) and rk <= 107 order by exceptions.size ASC";
#endif
     pqxx::result res{txn.exec(query)};

     if (res.begin() == res.end()){
        return nullptr;
     }

     file_set = new list<Pair>();

     for (result::const_iterator it = res.begin(); it != res.end(); ++it){
        file_set->push_back(Pair(it[0].as<string>(), it[1].as<string>()));
     }

   }
   catch (const std::exception &e) {

      cerr << e.what() << std::endl;

      warning_print("Exception loading prune set\n");

      if (file_set)
          delete file_set;

      return nullptr;
   }

   return file_set;
}

/* Use a bost DAG to do topological sort on the dependency list */
list<Pair>* DB::getAllFilesTopoSorted(){
   list<Pair> *ordered_list = nullptr;
   /* Our vertices */
   vector<string> nodes;
   /* Map between our string id and our vertex descriptors */
   std::map<std::string, vector_graph_t::vertex_descriptor> refs;

   if (conn == nullptr){
     return nullptr;
   }
   /* Get the map of files to analyze. Those with gcc_exception_table sections */
   map<string, string> *processing_map = getFilesToAnalyze();
   
   /* Safety check */
   if (!processing_map){
       return nullptr;
   }

   for (auto elem : *processing_map){
       nodes.push_back(elem.first);
   }
 
   size_t size = nodes.size();
   vector_graph_t G (size); 

   for( int i = 0; i < size; i++){
       boost::put(vertex_name_t(), G, i, nodes[i]); // set the property of a vertex
       refs[nodes[i]] = boost::vertex(i, G);     // retrives the associated vertex descriptor
   } 

   try { 
     pqxx::nontransaction txn{*conn};
     /* get dso links for all files */
     pqxx::result res{txn.exec("SELECT file_id, data from analysis where type = "+ std::to_string(analysis_ty::DSO_LINKS))};

     if (res.begin() == res.end()){     
        return nullptr;
     }


     /* Only keep DSO dependencies between files we want to analyze */
     for (result::const_iterator it = res.begin(); it != res.end(); ++it){
        string dependent = it[0].as<string>();  
         
        /* If we don't have the element in the processing map just 
           iterate over */
        if (!processing_map->count(dependent)){
           continue;
        }
        /* Get JSON  with all DSOs and prepare graph vertexes */
        Json::Value json;
        std::istringstream stream(it[1].as<string>());
        stream >> json;

        const Json::Value imports = json["imports"];
        for ( int index = 0; index < imports.size(); ++index ) {
               
               string dependee = imports[index].asString();

               if (!processing_map->count(dependee)){
                  continue;
               }
               /* Create a dependency vertix in the graph */
               boost::add_edge(refs[dependee], refs[dependent], G);
        }

      }

      std::deque<int> topo_order;
      boost::topological_sort(G, std::front_inserter(topo_order));

      /* Now that we have all elements in topological order create
         a list of these files and return it to whomever processes
         these elements */
      ordered_list = new list<Pair>();

      for (auto node : topo_order){
          // Push element in the map
          string id = get(vertex_name_t(), G, node);

          ordered_list->push_back(Pair(id, (*processing_map)[id]));
      }
   
      // Don't need this anymore
      delete processing_map;
   
   }
   catch (const std::exception &e) {

      cerr << e.what() << std::endl;

      if (ordered_list)
         delete ordered_list;

      if (processing_map)
         delete processing_map;

      return nullptr;
   }

   return ordered_list;
}

std::optional<string> DB::getSHAForFile(const std::string& file_id){
   result::const_iterator it;

   if (conn == nullptr){
     return nullptr;
   }

   try { 
     pqxx::nontransaction txn{*conn};
     pqxx::result res{txn.exec("SELECT sha256 FROM files where id="+ file_id)};

     it = res.begin();
   
     if (it == res.end()){      
        return std::nullopt;
     }

   }
   catch (const std::exception &e) {

      cerr << e.what() << std::endl;
      
      warning_print("Exception getting SHA for file\n");
      
      return std::nullopt;
   }

   return it[0].as<string>();
}

std::optional<string> DB::getNameForFile(const std::string& file_id){
   result::const_iterator it;

   if (conn == nullptr){
     return nullptr;
   }

   try {
     pqxx::nontransaction txn{*conn};
     pqxx::result res{txn.exec("SELECT filename FROM gcc_exception_files where id="+ file_id)};

     it = res.begin();

     if (it == res.end()){
        return std::nullopt;
     }

   }
   catch (const std::exception &e) {

      cerr << e.what() << std::endl;
      return std::nullopt;
   }

   return it[0].as<string>();
}

std::optional<string> DB::getPackageForFile(const std::string& file_id){
   result::const_iterator it;

   if (conn == nullptr){
     return nullopt;
   }

   try {
     pqxx::nontransaction txn{*conn};
     pqxx::result res{txn.exec("SELECT package FROM gcc_exception_files where id="+ file_id)};

     it = res.begin();

     if (it == res.end()){
        return std::nullopt;
     }

   }
   catch (const std::exception &e) {

      cerr << e.what() << std::endl;
      return std::nullopt;
   }

   return it[0].as<string>();
}

// skeleton code for now 
Json::Value* DB::getAnalysisForSHA(int analysis_type, const std::string& file_sha){

   if (conn == nullptr){
     return nullptr;
   }

   pqxx::nontransaction txn{*conn};
   pqxx::result res{txn.exec("SELECT a.data FROM analysis a, files b where a.type="\
                            + std::to_string(analysis_type) + " and b.sha256='" + file_sha + "' and a.file_id = b.id")};

   auto it = res.begin();
   
   if (it == res.end()){      
      return nullptr;
   }

   Json::Value *json = new Json::Value();

   std::istringstream stream(it[0].as<string>());

   stream >> *json;
   
   return json;
}

// skeleton code for now 
Json::Value* DB::getAnalysisForFile(int analysis_type, const std::string& file_id){
   Json::Value *json = nullptr;

   if (conn == nullptr){
     return nullptr;
   }

   try {
      pqxx::nontransaction txn{*conn};
      pqxx::result res{txn.exec("SELECT a.data FROM analysis a where a.type="\
                            + std::to_string(analysis_type) + " and a.file_id=" + file_id)};

      auto it = res.begin();
   
      if (it == res.end()){
         return nullptr;
      }
      
      if (it[0].is_null())
         return nullptr;

      json = new Json::Value();

      std::istringstream stream(it[0].as<string>());

      stream >> *json;
      
      if (json->isNull()){
          delete json;
          return nullptr;
      }
   } catch (const std::exception &e) {

      warning_print("Exception getting analysis for file: %s\n", file_id.c_str());

      cerr << e.what() << std::endl;

      if (json){
         delete json;
      }

      return nullptr;
   }

   
   //cout << "Some data:" << json->get("total_func", "UTF-8" ).asString() << endl;
   
  return json;
}

// skeleton code for now 
list<Pair> *DB::getExportedSymbols(int analysis_type, const std::string& file_id){
   list<Pair> *export_list; 

   if (conn == nullptr){
     return nullptr;
   }

   try {
      pqxx::nontransaction txn{*conn};
      pqxx::result res{txn.exec("SELECT a.name, a.exceptions_thrown FROM threat_info a where is_external=true and throws=true and a.info_ty="\
                            + std::to_string(analysis_type) + " and a.file_id=" + file_id)};

   
      if (res.begin() == res.end()){
         return nullptr;
      }

      export_list = new list<Pair>();

      for (result::const_iterator it = res.begin(); it != res.end(); ++it){
        export_list->push_back(Pair(it[0].as<string>(), it[1].as<string>()));
      }

      
   } catch (const std::exception &e) {

      warning_print("Exception getting analysis for file: %s", file_id.c_str());

      cerr << e.what() << std::endl;

      if (export_list){
         delete export_list;
      }

      return nullptr;
   }

   
   //cout << "Some data:" << json->get("total_func", "UTF-8" ).asString() << endl;
   
  return export_list;
}

bool DB::hasCombinedAnalysis(int analysis_type, const std::string& file_id){

   if (conn == nullptr){
     return false;
   }

   try {
      pqxx::nontransaction txn{*conn};
      pqxx::result res{txn.exec("SELECT * FROM threat_stack_summary a where a.info_ty="\
                            + std::to_string(analysis_type) + " and a.file_id=" + file_id)};

   
      if (res.begin() == res.end()){
         return false;
      }

      
   } catch (const std::exception &e) {

      warning_print("Exception getting analysis for file: %s", file_id.c_str());

      cerr << e.what() << std::endl;


      return false;
   }

   
   //cout << "Some data:" << json->get("total_func", "UTF-8" ).asString() << endl;
   
  return true;
}

bool replace(std::string& str, const std::string& from, const std::string& to) {
    size_t start_pos = str.find(from);
    if(start_pos == std::string::npos)
        return false;
    str.replace(start_pos, from.length(), to);
    return true;
}

bool DB::writeExportTable(const std::string& file_id, list<pair<string, bool>> &export_list){
   if (conn == nullptr){
     return false;
   }
   Json::Value export_json;
   int i = 0;
   for (auto pair : export_list){
       Json::Value elem_json;
       elem_json["sym"] = pair.first;
       elem_json["is_throw"] = pair.second;
       export_json[i++] = elem_json;
   } 
   Json::StyledWriter writer;

   string json_string = writer.write(export_json);
   while (replace(json_string, "'", ""));
   try {   
    pqxx::work work(*conn);

    debug_print("Before export_table write...\n");
    work.exec("INSERT INTO ANALYSIS (type, file_id, data) VALUES ("
                + std::to_string(analysis_ty::EXPORT_TABLE) + "," + file_id \
                + ",'" + json_string + "'::jsonb) " + \
                "ON CONFLICT ON CONSTRAINT analysis_type_file_id_key " + \
                "DO UPDATE SET data=EXCLUDED.data;");
    work.commit();

    debug_print("After export_table write...\n");
   } catch (const std::exception &e) {

      warning_print("Exception writing export table for file: %s", file_id.c_str());

      cerr << e.what() << std::endl;
      return false;
   }

   return true;
}

bool DB::writeAnalysisInfo(const std::string& file_id, analysis_ty table, ModuleThreatInfo &ti){
   if (conn == nullptr){
      return false;
   }

   Json::StyledWriter writer;
   string json_string = writer.write(ti.parseToJson());
   while (replace(json_string, "'", ""));
   try {
    pqxx::work work(*conn);

    work.exec("INSERT INTO ANALYSIS (type, file_id, data) VALUES ("
                + std::to_string(table) + "," + file_id \
                + ",'" + json_string + "'::jsonb) " + \
                "ON CONFLICT ON CONSTRAINT analysis_type_file_id_key " + \
                "DO UPDATE SET data=EXCLUDED.data;");
    work.commit();

   } catch (const std::exception &e) {

      warning_print("Exception writing threatinfo table for file: %s", file_id.c_str());

      cerr << e.what() << std::endl;
      return false;
   }

   return true;
}

bool DB::writeThreatInfo(const std::string& file_id, ModuleThreatInfo &ti){
   if (conn == nullptr){
      return false;
   }

   Json::StyledWriter writer;
   string json_string = writer.write(ti.parseToJson());
   try {
    pqxx::work work(*conn);

    work.exec("INSERT INTO ANALYSIS (type, file_id, data) VALUES ("
                + std::to_string(analysis_ty::THREAT_INFO) + "," + file_id \
                + ",'" + json_string + "'::jsonb) " + \
                "ON CONFLICT ON CONSTRAINT analysis_type_file_id_key " + \
                "DO UPDATE SET data=EXCLUDED.data;");
    work.commit();

   } catch (const std::exception &e) {

      warning_print("Exception writing threatinfo table for file: %s", file_id.c_str());

      cerr << e.what() << std::endl;
      return false;
   }

   return true;
}

// TODO merge writeThreatInfo, writeStackInfo and writeExportTable in the same function.
bool DB::writeStackInfo(const std::string& file_id, ModuleStackInfo &si){
   if (conn == nullptr){
      return false;
   }

   Json::StyledWriter writer;
   string json_string = writer.write(si.parseToJson());
   try {
    pqxx::work work(*conn);

    work.exec("INSERT INTO ANALYSIS (type, file_id, data) VALUES ("
                + std::to_string(analysis_ty::STACK_INFO) + "," + file_id \
                + ",'" + json_string + "'::jsonb) " + \
                "ON CONFLICT ON CONSTRAINT analysis_type_file_id_key " + \
                "DO UPDATE SET data=EXCLUDED.data;");
    work.commit();

   } catch (const std::exception &e) {

      warning_print("Exception writing stackinfo table for file: %s", file_id.c_str());

      cerr << e.what() << std::endl;
      return false;
   }

   return true;
}

// TODO merge writeThreatInfo, writeStackInfo and writeExportTable in the same function.
bool DB::writeTaintInfo(const std::string& file_id, TaintInfo &ti){
   if (conn == nullptr){
      return false;
   }
   Json::Value null_json;
   Json::StyledWriter writer;
   string json_string = writer.write(ti.parseToJson());
   try {
    pqxx::work work(*conn);

    work.exec("INSERT INTO ANALYSIS (type, file_id, data) VALUES ("
                + std::to_string(analysis_ty::TAINT_INFO) + "," + file_id \
                + ",'" + json_string + "'::jsonb) " + \
                "ON CONFLICT ON CONSTRAINT analysis_type_file_id_key " + \
                "DO UPDATE SET data=EXCLUDED.data;");
    work.commit();

   } catch (const std::exception &e) {

      warning_print("Exception writing taintinfo table for file: %s", file_id.c_str());

      cerr << e.what() << std::endl;
      return false;
   }

   return true;
}

void DB::writeStackInfoEntryT(const std::string& file_id, FunctionStackInfo &si){
   if (conn == nullptr){
      return;
   }

   try {
    pqxx::work work(*conn);
    for (auto &query : si.parseToSQLQuery(file_id)){
       work.exec(query);
    }
    work.commit();

   } catch (const std::exception &e) {

      warning_print("Exception writing stack info entry to table for file: %s", file_id.c_str());

      cerr << e.what() << std::endl;
      return;
   }

   return;
}

void DB::writeInfoTable(const std::string& file_id, JSONSerializable &si){
   // TODO implement write stack-info table.
   if (conn == nullptr){
      return;
   }

   try {
    pqxx::work work(*conn);
    for (auto &query : si.parseToSQLQuery(file_id)){
       work.exec(query);
    }
    work.commit();

   } catch (const std::exception &e) {

      warning_print("Exception writing stack info or threat info entry to table for file: %s", file_id.c_str());

      cerr << e.what() << std::endl;
      return;
   }

   return;
}
