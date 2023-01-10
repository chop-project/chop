from multiprocessing import Pool, get_context
from analysis import *
from os.path import exists
from db import db_connect
from binaryninja import *

def analyze_one_file(arg):
    file_id, filename, file_sha256 = arg

    print(f'Parsing throw info for file:{filename} file_id:{file_id} sha256:{file_sha256}')


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

    module_summary = ThrowModuleSummary(funcs = [], total_func = 0, total_throw_rethrow_fuc = 0, total_throw_func = 0, 
                                        total_rethrow_func = 0, total_throws = 0, total_rethrows = 0 )

    throw_handlers = getThrowFuncs(bv)

    rethrow_handlers = getRethrowFuncs(bv)

    # Dump some info about throw/rethrow handlers.
    print("====Throw handlers===")
    for elem in throw_handlers:
        print(elem[0] + ":" + hex(elem[1]))

    print("====ReThrow handlers===")
    for elem in rethrow_handlers:
        print(elem[0] + ":" + hex(elem[1]))

    throw_handlers_compact = list(map(lambda elem: elem[1], throw_handlers))
    rethrow_handlers_compact = list(map(lambda elem: elem[1], rethrow_handlers))
    
    print(throw_handlers_compact)
    print(rethrow_handlers_compact)

    for function in bv.functions:
        module_summary.total_func = module_summary.total_func + 1

        # If we don't have any throw/rethrow handlers just do a total count of functions in the module
        if not len(throw_handlers_compact) and not len(rethrow_handlers_compact):
            continue

        function_summary = ThrowFunctionSummary( fstart = str(hex(function.start)), total_throws = 0,
                                           total_rethrows = 0)

        # If function is either ImportedFunction or simply Function in the throw/rethrow list mark it as a throw function
        # Add this entry to the module summary but don't update statistics as this function may never be called.
        if function.start in throw_handlers_compact:
           function_summary.total_throws = function_summary.total_throws + 1
           module_summary.funcs.append(function_summary)
           continue

        if function.start in rethrow_handlers_compact:
           function_summary.total_rethrows = function_summary.total_rethrows + 1
           module_summary.funcs.append(function_summary)
           continue
      
        for call in filter(
                lambda mlil: mlil.operation == MediumLevelILOperation.MLIL_CALL,
                function.mlil.instructions,
            ):
                if call.operands[1].value.value in throw_handlers_compact:
                     function_summary.total_throws = function_summary.total_throws + 1
                     continue
                if call.operands[1].value.value in rethrow_handlers_compact:                
                     function_summary.total_rethrows = function_summary.total_rethrows + 1
                     continue

        if function_summary.total_throws:
           module_summary.total_throw_func = module_summary.total_throw_func + 1
           module_summary.total_throws = module_summary.total_throws + function_summary.total_throws

        if function_summary.total_rethrows:
           module_summary.total_rethrow_func = module_summary.total_rethrow_func + 1
           module_summary.total_rethrows = module_summary.total_rethrows + function_summary.total_rethrows

        if function_summary.total_throws or function_summary.total_rethrows:
           module_summary.total_throw_rethrow_fuc = module_summary.total_throw_rethrow_fuc + 1
           module_summary.funcs.append(function_summary)

    print(module_summary)
    # Write module summary to db.
    writeAnalysisForFile(AnalysisType.THROW_INFO, file_id, module_summary)
    # Close bin view.
    bv.file.close() 


def main():

    db = db_connect()
    cursor = db.cursor()

    cursor.execute("""
                   SELECT F.id, F.filename, F.sha256 FROM gcc_exception_files F
                   WHERE F.id NOT IN (SELECT file_id from analysis WHERE file_id = F.id and type = %(type)s) 
                   ORDER BY f.size ASC
                   """, dict(type=AnalysisType.THROW_INFO))

    elffiles = cursor.fetchall()
    db.close()

    with get_context('forkserver').Pool(2) as p:
        p.map(analyze_one_file, elffiles, chunksize = 20)


if __name__ == '__main__':
    main()

