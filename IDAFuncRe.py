import struct
import idaapi
import ida_kernwin


def rename_function(ea, new_name):
    idaapi.set_name(ea, new_name, idaapi.SN_FORCE)
    idaapi.refresh_idaview_anyway()


class jump_list:
    def __init__(self, startaddr, endaddr, member_format):
        self.startaddr = startaddr
        self.endaddr = endaddr
        self.size = self.endaddr - self.startaddr
        self.member_format = member_format
        self.member_size = self.calculate_member_size()
        self.verify()

    def calculate_member_size(self):
        member_size = 0
        for _, num_bytes in self.member_format:
            member_size += num_bytes
        return member_size

    def verify(self):
        assert self.size % self.member_size == 0
        string_count = 0
        function_count = 0
        for mem_type, _ in self.member_format:
            if mem_type == "string":
                string_count += 1
            elif mem_type == "function":
                function_count += 1
            elif mem_type == "junk":
                continue
            else:
                raise NotImplementedError("Err - Invalid member type specified.")
        assert string_count == 1
        assert function_count == 1

    def get_member_element_ea(self, base_addr, ele_type):
        ele_pointer_addr = base_addr
        ele_pointer_size = 0
        for mem_type, num_bytes in self.member_format:
            if mem_type == ele_type:
                ele_pointer_size = num_bytes
                break
            else:
                ele_pointer_addr += num_bytes
        ele_addr_bytes = idaapi.get_bytes(ele_pointer_addr, ele_pointer_size)
        if ele_pointer_size == 4:
            ele_ea = struct.unpack("<I", ele_addr_bytes)[0]
        elif ele_pointer_size == 8:
            ele_ea = struct.unpack("<Q", ele_addr_bytes)[0]
        else:
            raise NotImplementedError("Err - Invalid pointer size encountered.")

        return ele_ea

    def get_member_string(self, base_addr):
        string_ea = self.get_member_element_ea(base_addr, "string")
        return idaapi.get_strlit_contents(string_ea, -1, 3).decode()

    def get_member_function_ea(self, base_addr):
        function_ea = self.get_member_element_ea(base_addr, "function")
        return function_ea

    def traverse(self):
        jl = []
        for member_addr in range(self.startaddr, self.endaddr, self.member_size):
            member_string = self.get_member_string(member_addr)
            member_function = self.get_member_function_ea(member_addr)
            jl.append([member_string, member_function])
        return jl


class ida_func_re_t(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = ""
    help = ""
    wanted_name = "IDA Func RE"
    wanted_hotkey = "Ctrl+Shift+F"

    def init(self):
        return idaapi.PLUGIN_OK

    def run(self, arg):
        # Get the jump table user selection
        selection, startaddr, endaddr = ida_kernwin.read_range_selection(None)
        if selection != 1:
            print("Err - Please provide a jump list selection.")
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
            jl = jump_list(startaddr, endaddr, member_format)
        except:
            print("Err - Jump table selection and Member format mismatch.")
            return False

        for mem_string, mem_function_ea in jl.traverse():
            print("Renaming sub_{:X} -> fn_{}".format(mem_function_ea, mem_string))
            rename_function(mem_function_ea, "fn_" + mem_string)

    def term(self):
        pass


def PLUGIN_ENTRY():
    return ida_func_re_t()
