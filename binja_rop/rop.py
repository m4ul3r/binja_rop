"""
rop.py: calculate rop gadgets contained in the executable sections of binaries
"""

from operator import itemgetter
from binaryninja import *

_PREV_BYTE_SIZE = 32
_RET_INSTRS = {"retn": [b"\xc3", b"\xf2\xc3"], "retf": [b"\xcb"]}

class ROPSearch(BackgroundTaskThread):
    """
    class that assists in location rop gadgets in executable code segments
    """

    def __init__(self, bv: BinaryView):
        BackgroundTaskThread.__init__(self, "", True)
        self.bv = bv
        self.gadgets = {}
        self.progress = "[+] binja_rop: searching for rop gadgets"
        self.endianness = self.bv.perform_get_default_endianness()
        self.arch = self.bv.arch
        self.ret_instrs = _RET_INSTRS

    def run(self):
        """
        locate rop gadgets in executable sections of a binary
        """
        if not self.bv.executable:
            return

        # get instructions rather than sections
        instructions = [i for i in self.bv.instructions]
        gadgets = self._find_gadgets_in_data(instructions)
        if gadgets != {}:
            self._generate_output(gadgets, "rop gadgets")
            # _generate_html(self.view, gadgets, "rop gadgets")
        else:
            show_message_box(
                "binja_rop: gadget search", "could not find any rop gadgets"
            )
        self.progress = ""

    def _disas_all_instrs(self, start_addr, ret_addr: int) -> list[str]:
        """
        disassemble all instructions in chunk
        """
        instructions: list[str] = []
        curr_addr = start_addr
        while curr_addr < ret_addr:
            instr = self.bv.get_disassembly(curr_addr)
            if instr == "":  # bad addr
                return None
            if instr[0] == "j":  # exclude jumps
                return None
            if instr == "leave":  # exclude leaves
                return None
            if instr in _RET_INSTRS.keys():  # exclude 2 rets
                return None
            instructions.append(instr)
            curr_addr += self.bv.get_instruction_length(curr_addr)
        # ret opcode was included in last instruction calculation
        if curr_addr != ret_addr:
            return None

        return instructions

    def _calculate_gadget_from_ret(self, gadgets: dict[int, str], ret_addr: int):
        """
        decrement index from ret ins and calculate gadgets
        """
        ret_instr = self.bv.get_disassembly(ret_addr)
        for i in range(0, _PREV_BYTE_SIZE + 1):
            instructions = self._disas_all_instrs(ret_addr - i, ret_addr)
            if instructions is None:
                continue
            gadget_str = ""
            for instr in instructions:
                gadget_str += f"{instr} ; "
            gadget_rva = ret_addr - i - self.bv.start
            gadgets[gadget_rva] = f"{gadget_str}{ret_instr}"
        return gadgets


    def _find_gadgets_in_data(
        self, insts: tuple[list[str], int]
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
                    next_ret_addr = self.bv.find_next_data(next_start, bytecode)
                    if next_ret_addr is None:
                        break

                    # TODO thread this?
                    gadgets = self._calculate_gadget_from_ret(gadgets, next_ret_addr)
                    next_start = next_ret_addr + len(bytecode)
                    # [y[1] for y in ins].index(4199412)

        return gadgets
    
    def _generate_output(self, gadgets: dict[int, str], title: str):
        """
        display rop gadgets
        """
        markdown = f"rop gadgets found for {self.bv.file.filename}\n\n"
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
                addr = addr + self.bv.start  # make sure addrs are correct
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
        self.bv.show_markdown_report(title, markdown)