"""
rop.py: calculate rop gadgets contained in the executable sections of binaries
"""

from operator import itemgetter
from binaryninja import *

_PREV_BYTE_SIZE = 32

_RET_INSTRS = {"retn": [b"\xc3", b"\xf2\xc3"], "retf": [b"\xcb"]}


def _disas_all_instrs(bv: BinaryView, start_addr, ret_addr: int) -> list[str]:
    """
    disassemble all instructions in chunk
    """
    instructions: list[str] = []
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


def _calculate_gadget_from_ret(bv: BinaryView, gadgets: dict[int, str], ret_addr: int):
    """
    decrement index from ret ins and calculate gadgets
    """
    ret_instr = bv.get_disassembly(ret_addr)
    for i in range(0, _PREV_BYTE_SIZE + 1):
        instructions = _disas_all_instrs(bv, ret_addr - i, ret_addr)
        if instructions is None:
            continue
        gadget_str = ""
        for instr in instructions:
            gadget_str += f"{instr} ; "
        gadget_rva = ret_addr - i - bv.start
        gadgets[gadget_rva] = f"{gadget_str}{ret_instr}"
    return gadgets


def _find_gadgets_in_data(
    bv: BinaryView, insts: tuple[list[str], int]
) -> dict[int, str]:
    """
    find ret instructions and spawn a thread to calculate gadgets
    """
    gadgets: dict[int, str] = dict()
    for _, bytecodes in _RET_INSTRS.items():
        for bytecode in bytecodes:
            next_start = insts[0][1]
            next_ret_addr = 0
            while next_start < insts[-1][1]:
                next_ret_addr = bv.find_next_data(next_start, bytecode)
                if next_ret_addr is None:
                    break

                # TODO thread this
                gadgets = _calculate_gadget_from_ret(bv, gadgets, next_ret_addr)
                next_start = next_ret_addr + len(bytecode)
                # [y[1] for y in ins].index(4199412)

    return gadgets


def _generate_output(bv: BinaryView, gadgets: dict[int, str], title: str):
    """
    display rop gadgets
    """
    markdown = f"rop gadgets found for {bv.file.filename}\n\n"
    body = ""
    pop_gadgets = ""
    mov_gadgets = ""
    all_gadgets = ""
    found = []
    gadgets = dict(sorted(gadgets.items()))
    print(gadgets)
    for addr, gadget in sorted(gadgets.items(), key=itemgetter(1)):
        if gadget not in found:
            gadget_str = " ".join(gadget.split())
            addr = addr + bv.start  # make sure addrs are correct
            if "pop" in gadget_str:
                gadget_str = gadget_str.replace(
                    "pop", '<span style="color: red;">pop</span>'
                )

            f_gadget_str = (
                f"[0x{addr:016x}](binaryninja://?expr={addr:08x})  \t{gadget_str}\n\n"
            )
            all_gadgets += f_gadget_str

            if "pop" in f_gadget_str:
                pop_gadgets += f_gadget_str
            if "mov" in f_gadget_str:
                mov_gadgets += f_gadget_str

            found.append(gadget)
    markdown += f"[+] found {len(found)} gadgets\n***\n"

    markdown += "[+] pop gadgets\n\n"
    markdown += pop_gadgets
    markdown += "***\n\n"

    markdown += "[+] mov gadgets\n\n"
    markdown += mov_gadgets
    markdown += "***\n\n"

    markdown += "[+] all gadgets\n\n"
    body += all_gadgets

    markdown += body
    bv.show_markdown_report(title, markdown)


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

        # get instructions rather than sections
        instructions = [i for i in self.view.instructions]
        gadgets = _find_gadgets_in_data(self.view, instructions)

        if gadgets != {}:
            _generate_output(self.view, gadgets, "rop gadgets")
            # _generate_html(self.view, gadgets, "rop gadgets")
        else:
            show_message_box(
                "binja_rop: gadget search", "could not find any rop gadgets"
            )

        self.progress = ""
