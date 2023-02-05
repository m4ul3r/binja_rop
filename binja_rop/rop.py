"""
rop.py: calculate rop gadgets contained in the executable sections of binaries
"""

from operator import itemgetter
from binaryninja import *

_PREV_BYTE_SIZE = 9

_RET_INSTRS = {"retn": [b"\xc3", b"\xf2\xc3"], "retf": [b"\xcb"]}


def _disas_all_instrs(bv: BinaryView, start_addr, ret_addr: int) -> list[str]:
    """
    disassemble all instructions in chunk
    """
    instructions = []
    curr_addr = start_addr
    while curr_addr < ret_addr:
        instr = bv.get_disassembly(curr_addr)
        if instr == "":  # bad addr
            return None
        if instr[0] == "j":  # exclude jumps
            return None
        if instr == "leave":  # exclude leaves
            return None
        if instr in _RET_INSTRS.keys():  # exclude 2 rets
            return None
        instructions.append(instr)
        curr_addr += bv.get_instruction_length(curr_addr)
    # ret opcode was included in last instruction calculation
    if curr_addr != ret_addr:
        return None

    return instructions


def _calculate_gadget_from_ret(
    bv: BinaryView, gadgets: dict[int, str], baseaddr, ret_addr: int
):
    """
    decrement index from ret ins and calculate gadgets
    """
    ret_instr = bv.get_disassembly(ret_addr)
    for i in range(1, _PREV_BYTE_SIZE):
        instructions = _disas_all_instrs(bv, ret_addr - i, ret_addr)
        if instructions is None:
            continue
        gadget_str = ""
        for instr in instructions:
            print(instr)
            print(type(instr))
            gadget_str += f"{instr} ; "
        gadget_rva = ret_addr - i - baseaddr
        gadgets[gadget_rva] = f"{gadget_str}{ret_instr}"
    return gadgets


def _find_gadgets_in_data(bv: BinaryView, baseaddr: int, section: Section) -> dict:
    """
    find ret instructions and spawn a thread to calculate gadgets
    """
    gadgets = dict()
    for _, bytecodes in _RET_INSTRS.items():
        for bytecode in bytecodes:
            next_start = section.start
            next_ret_addr = 0
            while next_start < section.end:
                next_ret_addr = bv.find_next_data(next_start, bytecode)
                if next_ret_addr == None:
                    break

                # TODO thread this
                gadgets = _calculate_gadget_from_ret(
                    bv, gadgets, baseaddr, next_ret_addr
                )
                next_start = next_ret_addr + len(bytecode)

    return gadgets


def _generate_output(bv: BinaryView, gadgets: dict[int, str], title: str):
    """
    display rop gadgets
    """
    markdown = f"rop gadgets found for {bv.file.filename}\n\n"
    body = ""
    found = []
    for addr, gadget in sorted(gadgets.items(), key=itemgetter(1)):
        if gadget not in found:
            gadget_str = " ".join(gadget.split())
            addr = addr + bv.start  # make sure addrs are correct
            # if "pop" in gadget_str:
            # gadget_str = gadget_str.replace("pop", '<span style="color: red;">pop</span>')
            body += f"[0x{addr:016x}](binaryninja://?expr={addr:08x}) \t```{gadget_str}```\n\n"
            found.append(gadget)
    markdown += f"[+] found {len(found)} gadgets\n***\n"
    markdown += body
    bv.show_markdown_report(title, markdown)


# def _generate_html(bv, gadgets, title):
#     """
#     display rop gadgets
#     """
#     markdown = ""
#     # markdown += '<span style="white-space: pre-wrap;">'
#     markdown += "<head><style> tab {display: inline-block; margin-left: 500px;}"
#     markdown += "</style></head>"
#     found = []
#     for addr, gadget in sorted(gadgets.items(), key=itemgetter(1)):
#         if gadget not in found:
#             gadget_str = " ".join(gadget.split())
#             addr = addr + bv.start  # make sure addrs are correct
#             if "pop" in gadget_str:
#                 gadget_str = gadget_str.replace(
#                     "pop", '<span style="color: red;">pop</span>'
#                 )
#             markdown += '<nobr><p style="display: line;"><a href=binaryninja://?expr={:08x}>0x{:016x}</a><tab><code>{}</code></p></nobr>'.format(
#                 addr, addr, gadget_str
#             )
#             found.append(gadget)
#     bv.show_html_report(title, markdown)


class ROPSearch(BackgroundTaskThread):
    """
    class that assists in location rop gadgets in executable code segments
    """

    def __init__(self, view: BinaryView):
        BackgroundTaskThread.__init__(self, "", True)
        self.view = view
        self.gadgets = {}
        self.progress = "[+] binja_rop: searching for rop gadgets"
        self.threads = []
        self.endianness = self.view.perform_get_default_endianness()
        self.arch = self.view.arch
        self.ret_instrs = _RET_INSTRS

    def run(self):
        """
        locate rop gadgets in executable sections of a binary
        """
        if not self.view.executable:
            return

        baseaddr = self.view.segments[0].start
        # get more than just `.text` section
        # bv.is_offset_executable(addr:int)
        # section = self.view.get_section_by_name(".text")

        gadgets = _find_gadgets_in_data(self.view, baseaddr, section)

        if gadgets != {}:
            _generate_output(self.view, gadgets, "rop gadgets")
            # _generate_html(self.view, gadgets, "rop gadgets")
        else:
            show_message_box(
                "binja_rop: gadget search", "could not find any rop gadgets"
            )

        self.progress = ""
