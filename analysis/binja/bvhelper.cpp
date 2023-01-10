#include "bvhelper.h"
#include "debug.h"
static void eraseSubStr(std::string & mainStr, const std::string & toErase)
{
    // Search for the substring in string
    size_t pos = mainStr.find(toErase);
    if (pos != std::string::npos)
    {
        // If found then erase it from string
        mainStr.erase(pos, toErase.length());
    }
}
addr_t BVHelper::getFunctionByName(string function_name){
    addr_t address = 0;
    vector<Ref<Symbol>> functions;
    functions = bv->GetSymbolsByName(function_name);
    for (auto &sym : functions){ 
       if (sym->GetType() == FunctionSymbol || sym->GetType() == ImportedFunctionSymbol){
		address = sym->GetAddress();
		break;
       }
    }
    return address;
}

bool BVHelper::isSymbolExternal(string name, addr_t function_addr){
   vector<Ref<Symbol>> syms = bv->GetSymbolsByName(name);
   for (auto &sym : syms){ 
       if (sym->GetType() == ImportAddressSymbol){
                addr_t import;
		bv->Read(&import,sym->GetAddress(), bv->GetAddressSize());
		if (import == function_addr)
                   return true;
       }
    }

    return false;
}

map<addr_t, vector<string>>* BVHelper::getThrowsBasedOnPatern(vector<string> patterns){
   map<addr_t, vector<string>>* throws = new map<addr_t, vector<string>>();
   for (auto& func : bv->GetAnalysisFunctionList()){
       for (auto &pattern : patterns){
           Ref<Symbol> sym = func->GetSymbol();
           // sym->GetType() == ImportedFunctionSymbol && 
           if (sym->GetShortName().find(pattern) == 0){
               vector<string> exceptions;
               string aux = sym->GetShortName();
               eraseSubStr(aux, "std::__");
               eraseSubStr(aux, "std::");
               eraseSubStr(aux, "__cxa_throw_");
               eraseSubStr(aux, "__cxa_");
               exceptions.push_back(aux);
               (*throws)[sym->GetAddress()] = exceptions;
               log_print("Added function %s: throw_type %s 0x%lx\n",  sym->GetShortName().c_str(), aux.c_str(), sym->GetAddress());
           }
       }
   }

   if (!throws->size()){
      delete throws;
      return nullptr;
   }  
  
   return throws;
}

map<addr_t, vector<string>>* BVHelper::getUnwindsBasedOnPattern(vector<pair<string, string>> patterns){
   map<addr_t, vector<string>>* throws = new map<addr_t, vector<string>>();
   for (auto& func : bv->GetAnalysisFunctionList()){
       for (auto &pattern : patterns){
           Ref<Symbol> sym = func->GetSymbol();
           // sym->GetType() == ImportedFunctionSymbol && 
           if (sym->GetShortName().find(pattern.first) == 0 && sym->GetType() == ImportedFunctionSymbol){
               vector<string> exceptions;
               exceptions.push_back(pattern.second);
               (*throws)[sym->GetAddress()] = exceptions;
               log_print("Added function %s: resume_type %s 0x%lx\n",  sym->GetShortName().c_str(), pattern.second.c_str(), sym->GetAddress());
           }
       }
   }

   if (!throws->size()){
      delete throws;
      return nullptr;
   }  
  
   return throws;
}

addr_t BVHelper::getCXA_throw(string function_name){
    addr_t address = 0;
    vector<Ref<Symbol>> functions;
    functions = bv->GetSymbolsByName(function_name);
    for (auto &sym : functions){ 
       if (sym->GetType() == FunctionSymbol || sym->GetType() == ImportedFunctionSymbol){
		address = sym->GetAddress();
		break;
       }
    }
    debug_print("Added cxa_throw function at address 0x%lx\n", address);
    return address;
}

bool BVHelper::searchForSymbol(string name, BNSymbolType regex){
    vector<Ref<Symbol>> functions;
    functions = bv->GetSymbolsOfType(regex);
    for (auto &sym : functions){ 
       if (sym->GetFullName() == name){
		return true;
       }
    }
    return false;
}


