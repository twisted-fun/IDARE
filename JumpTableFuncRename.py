import idaapi
import ida_kernwin
from idare.utils import jump_table, rename_function


class jump_table_func_rename_t(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = ""
    help = ""
    wanted_name = "IDARE: Jump Table Func Rename"
    wanted_hotkey = ""

    def init(self):
        return idaapi.PLUGIN_OK

    def run(self, arg):
        # Get the jump table user selection
        selection, startaddr, endaddr = ida_kernwin.read_range_selection(None)
        if selection != 1:
            print("Err - Please provide a jump table selection.")
            return False
        print("Selection range: 0x{:x} - 0x{:x}".format(startaddr, endaddr))

        # Ask user for jump table member format to get the position
        # of string, function and overall size of the member
        member_format_input = ida_kernwin.ask_str(
            "string:4,junk:8,function:4", 1000, "Jump Table Member Format"
        )
        member_format = []
        for x in member_format_input.split(","):
            mem_type, num_bytes = x.split(":")
            num_bytes = int(num_bytes)
            member_format.append([mem_type, num_bytes])
        try:
            jt = jump_table(startaddr, endaddr, member_format)
        except:
            print("Err - Jump table selection and Member format mismatch.")
            return False

        for mem_string, mem_function_ea in jt.traverse():
            print("Renaming sub_{:X} -> fn_{}".format(mem_function_ea, mem_string))
            rename_function(mem_function_ea, "fn_" + mem_string)

    def term(self):
        pass


def PLUGIN_ENTRY():
    return jump_table_func_rename_t()
