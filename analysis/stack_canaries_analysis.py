from multiprocessing import Pool, get_context
from analysis import *
from os.path import exists
from db import db_connect
from binaryninja import *

def analyze_one_file(arg):
    file_id, filename, file_sha256, file_size = arg

    print(f'Parsing canary info for file:{filename} file_id:{file_id} sha256:{file_sha256} size:{file_size}')


    # Check if we extracted the file. Based on the query this should never happen.
    if not exists(f'./extracted/{file_sha256}'):
       print(f'Error: file {filename} was not extracted!')
       return

    try:
       bv = BinaryViewType["ELF"].get_view_of_file_with_options(
             f'./extracted/{file_sha256}',
             update_analysis=True,
             options={
                  "analysis.tailCallTranslation": False,  # this is important so we don't miss anything.
                  "analysis.tailCallHeuristics": False,
             },
       )
    except:
       print(f"[!] {filename} id:{file_id} sha:{file_sha256} encountered an exception...")
       return


    if not bv:
        print(f"[!] {filename} id:{file_id} could not be loaded")
        # TODO add a null entry in Analysis so we don't reanalyze this function.
        return

    module_summary = CanaryModuleSummary(funcs = [], total_func = 0, total_vuln_func = 0,
                                         total_lp = 0 , total_vuln_lp = 0, total_hijack_lp = 0,
                                         total_cleanup_lp = 0, is_vulnerable_file = False)

    if HandlerType.CANARY.value not in bv.symbols:
          print(f"[+] {filename} id:{file_id} vulnerable: no canaries")
          # Mark this file for further analysis. Perhaps the stack_chk_fail symbol 
          # is missing but there is another means to apply the stack protector.
          module_summary.is_vulnerable_file = True 

    canary_handlers = getStackCanaryFunc(bv)

    terminate_handlers = getTerminateFuncs(bv)
           
    throw_handlers = getThrowFuncs(bv)

    rethrow_handlers = getRethrowFuncs(bv)

    # Dump some info about throw/rethrow handlers.
    print("====Canary handlers===")
    for elem in canary_handlers:
        print(elem[0] + ":" + hex(elem[1]))

    print("====Throw handlers===")
    for elem in throw_handlers:
        print(elem[0] + ":" + hex(elem[1]))

    print("====ReThrow handlers===")
    for elem in rethrow_handlers:
        print(elem[0] + ":" + hex(elem[1]))

    print("====Terminate handlers===")
    for elem in terminate_handlers:
        print(elem[0] + ":" + hex(elem[1]))


    throw_handlers_compact = list(map(lambda elem: elem[1], throw_handlers))
    rethrow_handlers_compact = list(map(lambda elem: elem[1], rethrow_handlers))
    canary_handlers_compact = list(map(lambda elem: elem[1], canary_handlers))
    terminate_handlers_compact = list(map(lambda elem: elem[1], terminate_handlers))

    # First get exception info for file
    data = getAnalysisForFile(AnalysisType.EXCEPTION_INFO, file_id)

    if data == None:
       print(f"[-] No exception info data for {filename} id:{file_id}")
       # Close bin view.
       bv.file.close() 
       return

    print(f"[+] Starting handler analysis on {filename} id:{file_id}")

    

    for fde in data:
        
        # Skip functions that do not have callsite tables
        if len(fde.lsda.cses) == 0:
           module_summary.total_func = module_summary.total_func + 1;
           continue
    
        function_summary = CanaryFunctionSummary( fstart = fde.fstart, fend = fde.fend, total_lp = 0,
                                           total_vuln_lp = 0, total_hijack_lp = 0, total_cleanup_lp = 0,
                                           vuln_lp = [], hijack_lp = [], cleanup_lp = [])
        for cs in fde.lsda.cses:
            # We will analyze one more lp from this function.
            function_summary.total_lp = function_summary.total_lp + 1
            # Skip cs if it doesn't have any action attached to it.
            # Skip cs if the lp is 0
            if cs.lp == "0x0":
                continue


            vuln_cs = VulnCS(cs = cs, is_hijack_lp = False, is_throw_lp = False, 
                             is_terminate_lp = False, is_spec_rethrow_lp = False,
                             is_cleanup_lp = False, is_catch_all_lp = False,
                             is_catch_some_lp = False)

            # If no actions are attached and lp != 0x0 this is a cleanup LP.
            if len(cs.actions) == 0:
                vuln_cs.is_cleanup_lp = True

            for action in cs.actions:
                # This LP does cleanup
                if action.ar_filter == 0:
                    vuln_cs.is_cleanup_lp = True
                # This LP handles exception specifications.
                if action.ar_filter < 0:
                    vuln_cs.is_spec_rethrow_lp = True
                if action.ar_filter > 0:
                    # This LP can catch all types of exceptions
                    if action.ar_info == "0x0":
                       vuln_cs.is_catch_all_lp = True
                    # This LP can catch some specific exceptions
                    else:
                       vuln_cs.is_catch_some_lp = True
            
            # If this lp doesn't explicitly catch some exception but is cleanup
            # keep track of it in the cleanup list but don't mark it as vulnerable.
            # This goes for rethrow_spec lps as well as they seem to be handled
            # as cleanup code in PHASE 2 of the unwinding process.
            if not vuln_cs.is_catch_all_lp and not vuln_cs.is_catch_some_lp:
                if vuln_cs.is_cleanup_lp or vuln_cs.is_spec_rethrow_lp:
                   function_summary.cleanup_lp.append(vuln_cs)
                   function_summary.total_cleanup_lp = function_summary.total_cleanup_lp + 1
                continue

            lp = int(cs.lp, base = 16)

            bv.add_function(lp)

            landing_pad = bv.get_function_at(lp) 

            if not landing_pad:
                 print(f"[!] {filename} id:{file_id} sha:{file_sha256} encountered a corrupted lp {cs.lp} ...")
                 continue

            found_canary = False

            for call in filter(
                lambda mlil: mlil.operation == MediumLevelILOperation.MLIL_CALL,
                landing_pad.mlil.instructions,
            ):
                if call.operands[1].value.value in throw_handlers_compact:
                     vuln_cs.is_throw_lp = True
                     continue
                if call.operands[1].value.value in rethrow_handlers_compact:                
                     vuln_cs.is_throw_lp = True
                     continue
                if call.operands[1].value.value in terminate_handlers_compact:                
                     vuln_cs.is_terminate_lp = True
                     continue
                if call.operands[1].value.value in canary_handlers_compact:                
                     found_canary = True
                     continue              
                 
            if found_canary and not vuln_cs.is_throw_lp:
               # If we found canary on the path and we do not throw/rethrow then don't add lp
               # to our list of vulnerable lps.
               continue

            # Do we have at least one path that ends with a return ?
            for ret in filter(
                lambda mlil: mlil.operation == MediumLevelILOperation.MLIL_RET,
                landing_pad.mlil.instructions,
            ):
                # If we have at least one return and no stack protector then we could
                # hijack execution using this lp.
                if not found_canary:
                    vuln_cs.is_hijack_lp = True

            # A catch block without a canary and ending with a return is vulnerable
            # A catch block that throws/rethrows is also vulnerable (irregardless of
            # the existence of a canary).
            function_summary.vuln_lp.append(vuln_cs)
            function_summary.total_vuln_lp = function_summary.total_vuln_lp + 1
            
            if vuln_cs.is_hijack_lp:
               function_summary.total_hijack_lp = function_summary.total_hijack_lp + 1
               function_summary.hijack_lp.append(vuln_cs)
        # Finished analyzing another function. 
        module_summary.total_func = module_summary.total_func + 1;  
        module_summary.total_lp = module_summary.total_lp + function_summary.total_lp
        # If we have some vulnerable lps in the function add it to the module summary
        if function_summary.total_vuln_lp != 0:
            module_summary.total_vuln_lp = module_summary.total_vuln_lp + function_summary.total_vuln_lp
            module_summary.total_hijack_lp = module_summary.total_hijack_lp + function_summary.total_hijack_lp
            module_summary.total_vuln_func = module_summary.total_vuln_func + 1 

        # Keep track of how many cleanup lps we have in this module.
        if function_summary.total_cleanup_lp != 0:
            module_summary.total_cleanup_lp = module_summary.total_cleanup_lp + function_summary.total_cleanup_lp

        if function_summary.total_vuln_lp != 0 or function_summary.total_cleanup_lp != 0:
            module_summary.funcs.append(function_summary) 
    
    # Write module summary to db.
    print(module_summary)
    writeAnalysisForFile(AnalysisType.STACK_CANARY_INFO, file_id, module_summary)
    # Close the bin view.
    bv.file.close() 

def main():

    db = db_connect()
    cursor = db.cursor()

    cursor.execute("""
           SELECT f.id, f.filename, f.sha256, f.size FROM gcc_exception_files f
           WHERE f.id NOT IN (SELECT file_id from analysis WHERE file_id = f.id and type = %(type)s) 
           and f.id in  (SELECT file_id from analysis WHERE file_id = f.id and type = %(type_exception)s) 
           ORDER BY f.size ASC
           """, dict(type=AnalysisType.STACK_CANARY_INFO, type_exception = AnalysisType.EXCEPTION_INFO))

    elffiles = cursor.fetchall()

    db.close()
# %%
    with get_context('forkserver').Pool(2) as p:
        p.map(analyze_one_file, elffiles, chunksize = 20)
# %%

if __name__ == '__main__':
    main()

