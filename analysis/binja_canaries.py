from binaryninja import *
from gcc_except_tables import define_call_frames
from gcc_except_tables.lsda import render_typeinfo
import sys
import textwrap

CANARY_NAME = "__stack_chk_fail"

def usage():
    print(
        f"""
    {sys.argv[0]} /path/to/binary
    """
    )


if len(sys.argv) < 2:
    usage()

bv = BinaryViewType["ELF"].get_view_of_file_with_options(
    sys.argv[1],
    update_analysis=True,
    options={
        "analysis.tailCallTranslation": False,  # this is important so we don't miss anything.
        "analysis.tailCallHeuristics": False,
    },
)

if not bv:
    print(f"[!] {sys.argv[1]} could not be loaded")
    exit(1)

if CANARY_NAME not in bv.symbols:
    print(f"[+] {sys.argv[1]} vulnerable: no canaries")
    exit(1)

stack_chk_fail = bv.symbols[CANARY_NAME][0].address

lsdas = define_call_frames(bv)

for lsda in lsdas:
    func = bv.get_function_at(lsda.func_address)
    for callsite in lsda.call_site_table.entries:
        landing_pad = bv.get_function_at(callsite.lp + func.start)
        found_canary = False
        for call in filter(
            lambda mlil: mlil.operation == MediumLevelILOperation.MLIL_CALL,
            landing_pad.mlil.instructions,
        ):
            if call.operands[1].value.value == stack_chk_fail:
                found_canary = True
                break
        if not found_canary:
            print(
                f"[+] callsite {hex(func.start + callsite.start)} - {hex(func.start + callsite.start + callsite.length)} landing_pad {hex(landing_pad.start)} is vulnerable"
            )
            for filter_clause in callsite.get_catch_clause_filters(bv, lsda):
                typ = lsda.get_type_for_filter(filter_clause)
                print(
                    f"    catch clause: {render_typeinfo(bv, typ) if typ is not None else 'catch all'}"
                )
            print(textwrap.indent(str(landing_pad.hlil), "        "))

print(f"[+] {sys.argv[1]} done")
