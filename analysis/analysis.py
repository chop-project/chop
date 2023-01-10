import psycopg2
from multiprocessing import Pool
from enum import IntEnum, Enum
from pydantic import BaseModel
from typing import List
from db import db_connect
import re
import json as jsonlib
# from binaryninja import SymbolType

# Commented out. We already have the table
'''
db = psycopg2.connect(
    host="localhost",
    database="exceptionalresearch",
    user="ubuntu",
    password="exceptionalresearch",
)

cursor = db.cursor()
cursor.execute(
    """
    CREATE TABLE IF NOT EXISTS Analysis (
        id SERIAL PRIMARY KEY,
        type int,
        file_id integer references files(id),
        data jsonb,
        analysis_done boolean NOT NULL default 'True',
        UNIQUE(type, file_id)
    );

    """
)

db.commit()
'''

class AnalysisType(IntEnum):
    EXCEPTION_INFO = 1
    STACK_CANARY_INFO = 2
    THROW_INFO = 3
    DSO_LINKS = 4
    EXPORT_TABLE = 5
    NEW_THREAT_INFO = 6
    NEW_STACK_INFO = 7
    THREAT_INFO = 26
    TAINT_INFO = 28
    TYPE_NOT_IMPLEMENTED = 0

class HandlerType(Enum):
    CANARY = "__stack_chk_fail"
    RETHROW = "__cxa_rethrow"
    STD_RETHROW = "std::rethrow"
    THROW = "__cxa_throw"
    STD_THROW = "std::__throw"
    TERMINATE = "std::terminate()"

def filter_by_pattern(pattern_list):
    def inner(symbol):
        for pattern in pattern_list:
            if re.match(pattern, symbol.full_name) != None:
               return True
        return False
    return inner

def getSymbolsBasedOnPattern(bv, pattern_list):
    interesting_symbols = bv.get_symbols_of_type(SymbolType.ImportedFunctionSymbol)
    interesting_symbols.extend(bv.get_symbols_of_type(SymbolType.FunctionSymbol))
    iterator = filter(
                filter_by_pattern(pattern_list),
                interesting_symbols,
            )
    return list(map(lambda elem: (elem.full_name, elem.address), list(iterator)))

def getThrowFuncs(bv):
    return getSymbolsBasedOnPattern(bv, [HandlerType.THROW.value, HandlerType.STD_THROW.value])

def getRethrowFuncs(bv):
    return getSymbolsBasedOnPattern(bv, [HandlerType.RETHROW.value, HandlerType.STD_RETHROW.value])

def getTerminateFuncs(bv):
    return getSymbolsBasedOnPattern(bv, [HandlerType.TERMINATE.value])

def getStackCanaryFunc(bv ):
    return getSymbolsBasedOnPattern(bv, [HandlerType.CANARY.value])

def getPopularFiles(rank):
    pass


'''
def filter_throws(symbol):
    for pattern in ThrowPatterns:
       print(symbol[1][0].full_name)
       if re.match(pattern, symbol[1][0].full_name) != None:
          return True
    return False
'''


# Helper classes to parse JSON Analysis

# ***EXCEPTION_INFO parsing classes***
class Action(BaseModel):
    ar_filter: int
    ar_disp: int
    ar_info: str

class CS(BaseModel):
    start: str
    end: str
    lp: str
    actions: List[Action]

class LSDA(BaseModel):
    lsda_ptr: str
    cses: List[CS]

class FDE(BaseModel):
    fstart : str
    fend : str
    lsda: LSDA

class FDEInfo(BaseModel):
    info : List[FDE]

class VulnCS(BaseModel):
    cs : CS
    # True if it contains at least one return path without Stack Protector.
    is_hijack_lp : bool
    # True if it contains a path that calls cxa_throw or cxa_rethrow.
    is_throw_lp : bool
    # True if it contains a path that cals std::terminate.
    is_terminate_lp : bool
    # True if it contains rethrow specification.
    is_spec_rethrow_lp : bool
    # True if it has cleanup action associated.
    is_cleanup_lp : bool
    # True if it can catch any exception.
    is_catch_all_lp : bool
    # True if it can catch specific exceptions.
    is_catch_some_lp : bool

class CanaryFunctionSummary(BaseModel):
    fstart : str
    fend : str
    # How many LPs did we analyze ?
    total_lp : int
    # How many LPs are vulnerable ? no stack protector or at least throw an exception.
    total_vuln_lp : int
    # How many LPs are hijackable ? i.e., end with an uprotected return.
    total_hijack_lp : int
    # How many cleanup LPs
    total_cleanup_lp : int
    # All vulnerable lps
    vuln_lp : List[VulnCS]
    # All hijackable lps
    hijack_lp : List[VulnCS]
    # All cleanup lps
    cleanup_lp : List[VulnCS]

class CanaryModuleSummary(BaseModel):
    funcs : List[CanaryFunctionSummary]
    total_func : int
    total_vuln_func : int
    total_lp : int
    total_vuln_lp : int
    total_hijack_lp : int
    total_cleanup_lp : int
    # Mark as true if the file does not contain a definition for stack_chk_fail.
    is_vulnerable_file : bool

class StackCanaryInfo(BaseModel):
    info : CanaryModuleSummary

class ThrowFunctionSummary(BaseModel):
    # Start address of function
    fstart : str
    # How many times does it throw ?
    total_throws : int
    # How many times does it rethrow ?
    total_rethrows : int

class ThrowModuleSummary(BaseModel):
    # Functions that throw/rethrow exceptions
    funcs : List[ThrowFunctionSummary]
    # How many functions do we have in module ?
    total_func : int
    # How many functions do at least one throw or a rethrow?
    total_throw_rethrow_fuc : int
    # How many functions throw ?
    total_throw_func : int
    # How many functions rethro
    total_rethrow_func : int
    # Raw number of throws in module
    total_throws : int
    # Raw number of rethrows in modules
    total_rethrows : int

class ThrowInfo(BaseModel):
    info : ThrowModuleSummary

class ExportFunctionSummary(BaseModel):
    sym : str
    is_throw : bool

class ExportTableInfo(BaseModel):
    info : List[ExportFunctionSummary]

# List of file_ids (.so files) that this module imports
class DSOModuleSummary(BaseModel):
    imports : List[str]

class DSOInfo(BaseModel):
    info : DSOModuleSummary

class ThreatFunctionSummary(BaseModel):
    address : str
    has_canary : bool
    spills_rsp : bool
    throws : bool
    level : int
    callee_saved : int

class ThreatModuleSummary(BaseModel):
    total_functions : int
    total_throw : int
    total_exported : int
    total_canaries : int
    total_spill_rsp : int
    max_callee_saved : int
    functions : List[ThreatFunctionSummary] = None

class ThreatInfo(BaseModel):
    info : ThreatModuleSummary

class Complexity(BaseModel):
    loop_level : int
    branch_level : int
    num_sinks : int
    num_funcs : int
    num_blocks : int
    tainted_exprs : int

class SinkSummary(BaseModel):
    register_mask : int
    target_mask : int
    type : int
    callee_name : str
    call_site : str
    level : int
    complexity : Complexity

class RangeSummary(BaseModel):
    start : str
    end : str

class EHSummary(BaseModel):
    start : str
    mask : int
    num_sinks : int
    num_leaks : int
    num_deletes : int
    num_www : int
    num_where : int
    num_what : int
    num_jumps : int
    num_icalls : int
    sinks : List[SinkSummary] = None
    ranges : List[RangeSummary] = None

class TaintInfoSummary(BaseModel):
    num_eh : int
    num_vuln : int
    ehs : List[EHSummary] = None

class TaintInfo(BaseModel):
    info : TaintInfoSummary

class NewStackFunction(BaseModel):
    address : str
    frame_size : str
    local_size : str
    num_callees : int
    omit_fp : bool
    uses_canary : bool
    enc_regs : int
    enc_exc : int

class NewStackInfoSummary(BaseModel):
    total_functions : int
    total_processed : int
    uses_canary : bool
    functions : List[NewStackFunction] = None

class NewStackInfo(BaseModel):
    info : NewStackInfoSummary

class ThreatFunctionSummary(BaseModel):
    pass
class NewThreatInfoSummary(BaseModel):
    total_functions : int
    total_throw : int
    total_exported : int
    functions : List[ThreatFunctionSummary] = None    
class NewThreatInfo(BaseModel):
    info : NewThreatInfoSummary

class Model:
    def __init__(self, type, dictionary):
        self.dictionary = dict(info = dictionary)
        self.type = type
    def parse(self):
        obj_types =  {
                AnalysisType.EXCEPTION_INFO: FDEInfo,
                AnalysisType.STACK_CANARY_INFO: StackCanaryInfo,
                AnalysisType.THROW_INFO: ThrowInfo,
                AnalysisType.DSO_LINKS: DSOInfo,
                AnalysisType.EXPORT_TABLE: ExportTableInfo,
                AnalysisType.THREAT_INFO: ThreatInfo,
                AnalysisType.NEW_STACK_INFO: NewStackInfo,
                AnalysisType.NEW_THREAT_INFO: NewThreatInfo,
                AnalysisType.TAINT_INFO : TaintInfo
             }
        obj = obj_types.get(self.type)

        if obj == None:
           raise NotImplementedError

        return obj.parse_obj(self.dictionary)

def getAnalysisForFile(analysis_ty, file_id):
    db = db_connect()
    cursor = db.cursor()
    cursor.execute("""SELECT data from analysis where
                      type =  %(type)s and file_id = %(file_id)s """, dict(type=analysis_ty, file_id = file_id));
    record = cursor.fetchone()

    db.close()

    if not record:
       return None
    else:
       return Model(analysis_ty, record[0]).parse().info

def writeAnalysisForFile(analysis_ty, file_id, data):
    db = db_connect()
    cursor = db.cursor()

    cursor.execute(
            """
            INSERT INTO analysis (type, file_id, data)
            VALUES (%(type)s, %(file_id)s, %(data)s)
            ON CONFLICT DO NOTHING;
            """,
              dict(
                type=analysis_ty,
                file_id=file_id,
                data=jsonlib.dumps(data.dict()),
            ))
    db.commit()
    db.close()
