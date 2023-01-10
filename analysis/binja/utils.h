#ifndef UTILS_H
#define UTILS_H
#include "bvhelper.h"

#define HANDLES_EXCEPTIONS 2
#define HANDLES_CLEANUP 1
#define HANDLES_NOTHING 0
#define HANDLES_ALL 4

#define RBX_ENCODING 1 << 1
#define RBP_ENCODING 1 << 2
#define R12_ENCODING 1 << 3
#define R13_ENCODING 1 << 4
#define R14_ENCODING 1 << 5
#define R15_ENCODING 1 << 6

static inline bool is_hex_notation(std::string const& s)
{
  return s.compare(0, 2, "0x") == 0;  //should be enough for our case
     // && s.size() > 2
      //&& s.find_first_not_of("0123456789abcdefABCDEF", 2) == std::string::npos;
}

struct CalleeStats {
   int level;
   addr_t parent_cs;
   addr_t parent_function;
   string parent_name;
};

struct Callee {
   addr_t callee;
   addr_t cs;
   bool imported;
   string parent_name;
   HighLevelILInstruction expr;
};

static string decode_registers(uint32_t reg_ENCODING, bool omitfp){
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

static string decode_exception(uint32_t exc_ENCODING){
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

#if 0
static inline string json_sql(string file_id, Json::Value &){
   string format = "(file_id";
   for (auto const& id : value.getMemberNames()){
      format = format + ", " + id;
   }
}
#endif 

class JSONSerializable {
   public:
         virtual Json::Value parseToJson() = 0;

         virtual vector<string> parseToSQLQuery(string file_id){
             vector<string> no_queries;
             return no_queries;
         }
};



// Class template
template <class T>
class JSONVector : JSONSerializable {
   public:
    // Variable of type T
    vector<T> entries;

    JSONVector() {}

    JSONVector(vector<T> &entries)  {
        for (auto entry : entries){
           this->entries.push_back(entry);
        }
    } 

    JSONVector(Json::Value &json){
       for (int index = 0; index < json.size(); ++index ){
           T elem(json[index]);
           addEntry(elem);
       }
    }

    void addEntry(T elem){
       entries.push_back(elem);
    }
    
    Json::Value parseToJson(){
         Json::Value jsonVector;
         int i = 0;
         for (T &entry : entries){
             jsonVector[i++] = entry.parseToJson();
         }
         return jsonVector;
    }
};

class ExceptionThreatInfo : JSONSerializable {
         // Address in the parent where this exception is thrown.
    public:
         // Parent address
         string paddress;
         // Address of immediate callsite
         string address;
         string name;
         int level;
         ExceptionThreatInfo(addr_t paddress, addr_t address, int level, string name = "") : 
                     level(level), name(name) {
             std::stringstream sstream, pstream;
             sstream << std::hex << address;
             this->address = string("0x") + sstream.str();
             pstream << std::hex << paddress;
             this->paddress = string("0x") + pstream.str();
         };  
         Json::Value parseToJson(){
             Json::Value jsonObj;
             jsonObj["address"] = address;
             jsonObj["paddress"] = paddress;
             jsonObj["name"] = name;
             jsonObj["level"] = level;
             return jsonObj;
         };   

         string parseToSQLQuery(string file_id, int info_ty, string faddress){ 
            return "INSERT INTO exception_instances (file_id, info_ty, address, parent_cs, cs, exception_ty, level ) \
                       VALUES (" + file_id + ",'" + std::to_string(info_ty) + "','" + faddress + "','" + paddress + "','" + address + "','" + name + \
                       "'," + std::to_string(level)+ " )" + \
                            " ON CONFLICT DO NOTHING;";
         }   
};

class ExceptionName : JSONSerializable {
         // Address in the parent where this exception is thrown.
    public:
         string name;
         ExceptionName(string name = "") : 
                     name(name) {
         };  

         ExceptionName(Json::Value &json) : name(json["name"].asString()){}

         Json::Value parseToJson(){
             Json::Value jsonObj;
             jsonObj["name"] = name;
             return jsonObj;
         };       
};

#ifndef INCLUDE_D_EXCEPTIONS
#define INCLUDE_D_EXCEPTIONS
static string decode_exception_names(JSONVector<ExceptionName> &d_exception_names){
    
   string result = "[";
   for (auto &elem: d_exception_names.entries){
       result = result + " " + elem.name;
   } 
   result = result + " ]";
   return result;
}
#endif

class FunctionThreatInfo : JSONSerializable {
    public:
         // Can also be private but perhaps we want to access them directly
         string address;
         string name;
         string short_name;
         bool throws;
         bool isExternal;
         int total_throws;
         int distinct_throws;
         set<string> d_exceptions;
         JSONVector<ExceptionName> d_exception_names;
         JSONVector<ExceptionThreatInfo> exceptions;
         // Constructor
         FunctionThreatInfo(addr_t address, string name = "") : 
                      name(name) {
             short_name = "none";
             throws = false;
             isExternal = false;
             total_throws = 0;
             distinct_throws = 0;
             std::stringstream sstream;
             sstream << std::hex << address;
             this->address = string("0x") + sstream.str();
         };

         FunctionThreatInfo(Json::Value &json) : d_exception_names(JSONVector<ExceptionName>(json["d_exception_names"])),
                                                 throws(json["throws"].asBool()),
                                                 isExternal(json["is_external"].asBool()){
              name = json["name"].asString();
         }

         void addEntry(ExceptionThreatInfo ei){
              total_throws++;
              throws = true;
              /* Add this distinct exception to the churn */
              if (!d_exceptions.count(ei.name)){
                 ExceptionName en(ei.name);
                 d_exception_names.addEntry(en);
                 d_exceptions.insert(ei.name);
                 distinct_throws++;
              }              
              exceptions.addEntry(ei);
         }

         Json::Value parseToJson(){
             Json::Value jsonObj;
             jsonObj["address"] = address;
             jsonObj["throws"] = throws;
             jsonObj["name"] = name;
             jsonObj["total_throws"] = total_throws;
             jsonObj["distinct_throws"] = distinct_throws;
             jsonObj["exceptions"] = exceptions.parseToJson();
             jsonObj["d_exception_names"] = d_exception_names.parseToJson();
             jsonObj["is_external"] = isExternal;

             return jsonObj;
         };

         vector<string> parseToSQLQuery(string file_id, int info_ty) {
            string s_throws = throws ? "true" : "false";
            string s_external = isExternal ? "true" : "false";
            vector<string> queries;
            string main_query = "INSERT INTO threat_info (file_id, info_ty, address, name , short_name, throws, is_external, t_throws, d_throws, exceptions_thrown ) \
                       VALUES (" + file_id + ",'" + std::to_string(info_ty) + "','" + address + "','" + name + "','" + short_name + "'," + s_throws + \
                       "," + s_external + "," +  std::to_string(total_throws) + "," + std::to_string(distinct_throws) + ",'" + decode_exception_names(d_exception_names) +"' )" + \
                            " ON CONFLICT ON CONSTRAINT threat_info_file_id_info_ty_address_key " + \
                            "DO UPDATE SET name=EXCLUDED.name, short_name=EXCLUDED.short_name, throws=EXCLUDED.throws" + \
                            ", is_external=EXCLUDED.is_external, t_throws=EXCLUDED.t_throws, d_throws=EXCLUDED.d_throws, exceptions_thrown=EXCLUDED.exceptions_thrown;";

            queries.push_back(main_query);
            for (auto &einstance: exceptions.entries){
               queries.push_back(einstance.parseToSQLQuery(file_id, info_ty, address));
            }
            return queries;
         }


};

class ModuleThreatInfo : public JSONSerializable {

      public:
           // To check if this is lower bounds or higher bounds.
           int info_ty;
           // How many functions do we have
           int total_functions;
           // Total functions that throw
           int total_throw_functions;
           // How many functions are exported.
           int total_exported_throws;
           // List of vulnerable functions.
           JSONVector<FunctionThreatInfo> functions;

           ModuleThreatInfo() : 
                 total_functions(0), total_throw_functions(0) , total_exported_throws(0) {}

           ModuleThreatInfo(Json::Value &json) : functions(JSONVector<FunctionThreatInfo>(json["functions"])),
                                                 total_functions(0), total_throw_functions(json["total_throw"].asInt()){
           }

           void addEntry(FunctionThreatInfo ti, bool isExternal){
              total_functions++;

              if (ti.throws) {
                 total_throw_functions++;
                 if (isExternal)
                    total_exported_throws++;
              }
                  
              functions.addEntry(ti);
           }

         Json::Value parseToJson(){
             Json::Value jsonObj;
             jsonObj["total_functions"] = total_functions;
             jsonObj["total_throw"] = total_throw_functions;
             jsonObj["total_exported"] = total_exported_throws;
             jsonObj["functions"] = functions.parseToJson();

             return jsonObj;
         }

         //override base parseToSQLQuery method
         vector<string> parseToSQLQuery(string file_id) override {
            vector<string> queries;
            for (auto &elem: functions.entries){
               vector<string> iquery = elem.parseToSQLQuery(file_id, info_ty);
               for (auto &istring: iquery){
                   queries.push_back(istring);
               }
            }
            return queries;
         }
           
};

string decode_registers(uint32_t reg_ENCODING, bool omitfp);
string decode_exception(uint32_t exc_ENCODING);
class FunctionStackInfo : JSONSerializable {
    public:
         // Can also be private but perhaps we want to access them directly
         string address;
         string frame_size;
         string local_size;
         bool omit_fp;
         bool uses_canary;
         int num_callees;
         uint32_t enc_regs;
         unsigned int enc_exc;
         int extra_regs;

         // Just create a dummy stack entry for function.
         FunctionStackInfo(addr_t address) {
             std::stringstream addr_stream;
             addr_stream << std::hex << address;
             this->address = string("0x") + addr_stream.str();
             this->frame_size = "no_size";
             this->local_size = "no_size";
             // Mark it as !omit_fp such that it does not mess up the ModuleStackInfo uses_fp.
             this->omit_fp = true;
             this->uses_canary = false;
             this->num_callees = -1;
             this->enc_regs = 0;
             this->enc_exc = -1;
             this->extra_regs = -1;
         }
         // Constructor
         FunctionStackInfo(addr_t address, unsigned int frame_size, unsigned int local_size, int num_callees, bool omit_fp, bool uses_canary, uint32_t enc_regs) {
             std::stringstream addr_stream, frame_stream, local_stream;
             addr_stream << std::hex << address;
             this->address = string("0x") + addr_stream.str();
             frame_stream << std::hex << frame_size;
             this->frame_size = string("0x") + frame_stream.str();
             local_stream << std::hex << local_size;
             this->local_size = string("0x") + local_stream.str();
             this->uses_canary = uses_canary;
             this->omit_fp = omit_fp;
             this->num_callees = num_callees;
             this->enc_regs = enc_regs;
             this->enc_exc = 0;
             this->extra_regs = 0;
         };

         // Constructor
         FunctionStackInfo(addr_t address, unsigned int frame_size, unsigned int local_size, int num_callees, bool omit_fp, bool uses_canary, uint32_t enc_regs, int extra_regs) {
             std::stringstream addr_stream, frame_stream, local_stream;
             addr_stream << std::hex << address;
             this->address = string("0x") + addr_stream.str();
             frame_stream << std::hex << frame_size;
             this->frame_size = string("0x") + frame_stream.str();
             local_stream << std::hex << local_size;
             this->local_size = string("0x") + local_stream.str();
             this->uses_canary = uses_canary;
             this->omit_fp = omit_fp;
             this->num_callees = num_callees;
             this->enc_regs = enc_regs;
             this->enc_exc = 0;
             this->extra_regs = extra_regs;
         };

         Json::Value parseToJson(){
             Json::Value jsonObj;
             jsonObj["address"] = address;
             jsonObj["frame_size"] = frame_size;
             jsonObj["num_callees"] = num_callees;
             jsonObj["omit_fp"] = omit_fp;
             jsonObj["uses_canary"] = uses_canary;
             jsonObj["local_size"] = local_size;
             jsonObj["enc_regs"] = enc_regs; 
             jsonObj["enc_exc"] = enc_exc;
             return jsonObj;
         };

         vector<string> parseToSQLQuery(string file_id){
            string s_canary = uses_canary ? "true" : "false";
            string s_omit = omit_fp ? "true" : "false";
            vector<string> queries;
            string main_query = "INSERT INTO stack_info (file_id, address, frame_size, local_size, omit_fp, uses_canary, num_callees, extra_regs, reg_str, exc_str, enc_regs, enc_exc) \
                       VALUES (" + file_id + ",'" + address + "','" + frame_size + "','" + local_size + "'," + s_omit + \
                       "," + s_canary + "," +  std::to_string(num_callees) + "," + std::to_string(extra_regs) + ",'[" + decode_registers(enc_regs, omit_fp) +"]','[" +\
                           decode_exception(enc_exc) +"]'," + std::to_string(enc_regs) + "," + std::to_string(enc_exc) + ")" + \
                            " ON CONFLICT ON CONSTRAINT stack_info_file_id_address_key " + \
                            "DO UPDATE SET frame_size=EXCLUDED.frame_size, local_size=EXCLUDED.local_size, omit_fp=EXCLUDED.omit_fp" + \
                            ", uses_canary=EXCLUDED.uses_canary, num_callees=EXCLUDED.num_callees, extra_regs=EXCLUDED.extra_regs, reg_str=EXCLUDED.reg_str, exc_str=EXCLUDED.exc_str" + \
                            ", enc_regs=EXCLUDED.enc_regs, enc_exc=EXCLUDED.enc_exc;";

            queries.push_back(main_query);
            return queries;
         }
};

#if 0
    ModuleInfo id total_processed uses_canary
    FunctionStackInfo module_id address frame_size local_size omit_fp uses_canary num_callees num_regs enc_regs
#endif

class ModuleStackInfo : public JSONSerializable {

      public:
           // How many functions do we have
           int total_functions;
           // How many functions we succesfully processed
           int total_processed;

           bool uses_canary = false;
           
           bool uses_fp = false;

           JSONVector<FunctionStackInfo> functions;

           ModuleStackInfo() :
                 total_functions(0), total_processed(0) {
                uses_canary = false;
                uses_fp = false;
           }

           void addEntry(FunctionStackInfo si){
              total_functions++;

              // Count function as processed unless it's a dummy entry.
              if (si.extra_regs != -1) {
                  total_processed++;
              } else {
                  //printf("[!] Warning no stack info for function %s\n", si.address.c_str());
              }

              if (!uses_fp && !si.omit_fp){
                  uses_fp = true;
              }

              functions.addEntry(si);
           }

         Json::Value parseToJson(){
             Json::Value jsonObj;
             jsonObj["total_functions"] = total_functions;
             jsonObj["total_processed"] = total_processed;
             jsonObj["functions"] = functions.parseToJson();
             jsonObj["uses_canary"] = uses_canary;

             return jsonObj;
         }

         //override base parseToSQLQuery method
         vector<string> parseToSQLQuery(string file_id) override {
            vector<string> queries;
            for (auto &elem: functions.entries){
               vector<string> iquery = elem.parseToSQLQuery(file_id);
               for (auto &istring: iquery){
                   queries.push_back(istring);
               }
            }
            return queries;
         }

};

class CombinedModuleSummary : public JSONSerializable {
      public:
         // To check if this is lower bounds or higher bounds.
         int info_ty;

         // How many functions do we have.
         int total_functions;

         // How many functions throw.
         int total_throws;
        
         int total_exported;
          
         int total_stack;

         // Does module use canary.
         bool uses_canary = false;
         // Does module contain at least one function that preserves frame pointer
         bool uses_fp = false;

         // Dummy combined module for files we never process.
         CombinedModuleSummary(): total_functions(0), total_throws (0), total_exported(0), total_stack(0) {
                uses_canary = false;
                uses_fp = false;
                 
         };

         CombinedModuleSummary(ModuleThreatInfo &ti, ModuleStackInfo &si) {
                total_functions = ti.total_functions;
                total_throws = ti.total_throw_functions;
                total_exported = ti.total_exported_throws;
                total_stack = si.total_processed;
                uses_canary = si.uses_canary;
                uses_fp = si.uses_fp;
                 
         };
         
         void initModuleSummary(ModuleThreatInfo &ti, ModuleStackInfo &si) {
                total_functions = ti.total_functions;
                total_throws = ti.total_throw_functions;
                total_exported = ti.total_exported_throws;
                total_stack = si.total_processed;
                uses_canary = si.uses_canary;
                uses_fp = si.uses_fp;
                 
         }

         Json::Value parseToJson(){
             Json::Value jsonObj;
             return jsonObj;
         }

         vector<string> parseToSQLQuery(string file_id){
            vector<string> queries;
            string s_canary = uses_canary ? "true" : "false";
            string s_uses_fp = uses_fp ? "true" : "false";            
            string main_query = "INSERT INTO threat_stack_summary (file_id, info_ty, total_functions, total_throws, total_exported, total_stack, uses_canary, uses_fp) \
                       VALUES (" + file_id + ",'" + std::to_string(info_ty)  + "'," + std::to_string(total_functions) + "," + std::to_string(total_throws) + "," + \
                        std::to_string(total_exported) + "," + std::to_string(total_stack) + "," + s_canary + "," + s_uses_fp + ")" + \
                            " ON CONFLICT ON CONSTRAINT threat_stack_summary_file_id_info_ty_key " + \
                            "DO UPDATE SET total_functions=EXCLUDED.total_functions, total_throws=EXCLUDED.total_throws, total_exported=EXCLUDED.total_exported" + \
                            ", total_stack=EXCLUDED.total_stack, uses_canary=EXCLUDED.uses_canary, uses_fp=EXCLUDED.uses_fp;";
            queries.push_back(main_query);
            return queries;
         }
};

class Action : JSONSerializable {
    public:
         int ar_filter;
         int ar_disp;
         string ar_info;

         Action(Json::Value &json) {
             ar_filter = json["ar_filter"].asInt();
             ar_disp = json["ar_disp"].asInt();
             ar_info = json["ar_info"].asString();
         }

         Action(int ar_filter, int ar_disp, string ar_info) :
               ar_filter(ar_filter), ar_disp(ar_disp), ar_info(ar_info) {}

         Json::Value parseToJson(){
             Json::Value jsonObj;
             return jsonObj;
         }
};

class CS : JSONSerializable {
    public:
         addr_t start;
         addr_t end;
         addr_t lp;
         JSONVector<Action> actions;

         CS(Json::Value &json) : actions(JSONVector<Action>(json["actions"])) {
             start = strtoull(json["start"].asString().c_str(), NULL, 16);
             end = strtoull(json["end"].asString().c_str(), NULL, 16);
             lp = strtoull(json["lp"].asString().c_str(), NULL, 16);
         }

         Json::Value parseToJson(){
             Json::Value jsonObj;
             return jsonObj;
         }
};

class LSDA : JSONSerializable {
    public:
         addr_t lsda_ptr;
         JSONVector<CS> cses;

         LSDA(Json::Value &json) : cses(JSONVector<CS>(json["cses"])){
             lsda_ptr = strtoull(json["lsda_ptr"].asString().c_str(), NULL, 16);
         }

         Json::Value parseToJson(){
             Json::Value jsonObj;
             return jsonObj;
         }
};

class FDE : JSONSerializable {
    public:
         addr_t fstart;
         addr_t fend;
         LSDA lsda;

         FDE(Json::Value &json) : lsda(LSDA(json["lsda"])){
             fstart = strtoull(json["fstart"].asString().c_str(), NULL, 16);
             fend = strtoull(json["fend"].asString().c_str(), NULL, 16);
         }

         Json::Value parseToJson(){
             Json::Value jsonObj;
             return jsonObj;
         }
};

class FDEs :  JSONSerializable {
    public:
         JSONVector<FDE> fdes;

         FDEs() {}

         FDEs(Json::Value &json) : fdes(JSONVector<FDE>(json)){}

         Json::Value parseToJson(){
             Json::Value jsonObj;
             return jsonObj;
         }
};

#define DELETE_SINK 1 << 1
#define ICALL_SINK 1 << 2
#define WRITE_WHAT_WHERE_SINK 1 << 3
#define WRITE_WHAT_SINK 1 << 4
#define WRITE_WHERE_SINK 1 << 5
#define LEAK_SINK 1 << 6
#define ITARGET_SINK 1 << 7
#define READ_SINK 1 << 8

class Complexity  :  JSONSerializable {
    public:
          int loop_level;
          int branch_level;
          unsigned int tainted_exprs;
          unsigned int num_sinks;
          unsigned int num_funcs;
          unsigned int num_blocks;

         Json::Value parseToJson(){
             Json::Value jsonObj;
             jsonObj["loop_level"] = loop_level;
             jsonObj["branch_level"] = branch_level;
             jsonObj["num_sinks"] = num_sinks;
             jsonObj["num_funcs"] = num_funcs;
             jsonObj["num_blocks"] = num_blocks;
             jsonObj["tainted_exprs"] = tainted_exprs;
             return jsonObj;
         }
};

class Sink :  JSONSerializable {
    public:
         
         addr_t call_site;
         string callee_name;
         unsigned int register_mask;
         unsigned int target_mask;
         unsigned int type;
         int level;
         Complexity complexity;

         Sink(addr_t call_site,unsigned int type){
             this->register_mask = 0;
             this->target_mask = 0;
             this->type = type;
             level = 0;
             this->call_site = call_site;
             callee_name = "";
         }

         Json::Value parseToJson(){
             Json::Value jsonObj;
             std::stringstream addr_stream;
             addr_stream << std::hex << call_site;
             jsonObj["register_mask"] = register_mask;
             jsonObj["target_mask"] = target_mask;
             jsonObj["type"] = type;
             jsonObj["callee_name"] = callee_name;  
             jsonObj["call_site"] =  string("0x") + addr_stream.str(); 
             jsonObj["complexity"] = complexity.parseToJson();
             jsonObj["level"] = level;            
             return jsonObj;              
         }
};

class Range :  JSONSerializable {
    public:
         
         addr_t start;
         addr_t end;

         Range(addr_t start,addr_t end) : start(start), end(end){
         }

         Json::Value parseToJson(){
             Json::Value jsonObj;
             std::stringstream begin_stream, end_stream;
             begin_stream << std::hex << start;
             end_stream <<  std::hex << end;
             jsonObj["start"] =  string("0x") + begin_stream.str(); 
             jsonObj["end"] = string("0x") + end_stream.str();          
             return jsonObj;              
         }
};

class EH :  JSONSerializable {
    public:
         
         JSONVector<Sink> sinks;
         JSONVector<Range> ranges;
         addr_t start;
         unsigned int mask;
         unsigned int num_sinks;
         unsigned int num_leaks;
         unsigned int num_deletes;
         unsigned int num_www;
         unsigned int num_where;
         unsigned int num_what;
         unsigned int num_jumps;
         unsigned int num_icalls;

         EH(addr_t start, unsigned int mask){
             this->start = start;
             this->mask = mask;
             num_sinks =   0;
             num_leaks =   0;
             num_deletes = 0;
             num_www = 0;
             num_where = 0;
             num_what =  0;
             num_jumps = 0;
             num_icalls = 0;
         }

         void addEntry(Sink si){
              num_sinks++;
              switch (si.type){ 
                  case DELETE_SINK:
                           num_deletes++;
                           break;
                  case ICALL_SINK:
                           num_icalls++;
                           break;
                  case WRITE_WHAT_WHERE_SINK:
                           num_www++;
                           break;
                  case WRITE_WHAT_SINK:
                           num_what++;
                           break;
                  case WRITE_WHERE_SINK:
                           num_where++;
                           break;
                  case LEAK_SINK:
                           num_leaks++;
                           break;
                  case ITARGET_SINK:
                           num_jumps++;
                           break;
                            
              }

              sinks.addEntry(si);
         }
         void addRanges(vector<Range> &ranges){
             for (auto &range : ranges){
                 this->ranges.addEntry(range);
             }
         }

         Json::Value parseToJson() {
             Json::Value jsonObj;
             std::stringstream addr_stream;
             addr_stream << std::hex << start;
             jsonObj["start"] = string("0x") + addr_stream.str();
             jsonObj["mask"] = mask;
             jsonObj["num_sinks"] = num_sinks;
             jsonObj["num_leaks"] = num_leaks;
             jsonObj["num_deletes"] = num_deletes;
             jsonObj["num_www"] = num_www;
             jsonObj["num_where"] = num_where;
             jsonObj["num_what"] = num_what;
             jsonObj["num_jumps"] = num_jumps;
             jsonObj["num_icalls"] = num_icalls;
             jsonObj["sinks"] = sinks.parseToJson(); 
             jsonObj["ranges"] = ranges.parseToJson(); 
             return jsonObj;
         }
};

class TaintInfo :  JSONSerializable {
    public:
         
         JSONVector<EH> ehs;
         unsigned int num_sinks;
         unsigned int num_eh;
         unsigned int num_vuln;

         TaintInfo() : num_vuln(0), num_eh(0), num_sinks(0) {
         }
         
         void addEntry(EH entry){
              num_eh++;
              if (entry.sinks.entries.size() != 0){
                 num_vuln++;
              }  
              num_sinks += entry.num_sinks;
              ehs.addEntry(entry);
         }
 

         Json::Value parseToJson(){
             Json::Value jsonObj;
             jsonObj["num_eh"] = num_eh;  
             jsonObj["num_vuln"] = num_vuln;
             jsonObj["num_sinks"] = num_sinks;
             jsonObj["ehs"] = ehs.parseToJson();
             return jsonObj;              
         }
};
#endif

