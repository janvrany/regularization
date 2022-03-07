
from regularization.vexshape import VEXsig
from bitstring import Bits
from functools import cache
import archinfo
import pyvex

class ISA:
    def __init__(self, name):
        self._name = name

    def _capstone(self):
        raise NotImplementedError("Please implement or return None")

    def _archinfo(self):
        raise NotImplementedError("Must implement")

    def disassemble(self,insn):
        cs = self._capstone()
        if cs:
            for disassembled in cs.disasm(insn.bytes, 0x1000):
                return f"{disassembled.mnemonic} {disassembled.op_str}"
        else:
            return None

    def vex(self, insn):
        return pyvex.block.IRSB(insn.bytes, 0x1000, self._archinfo(), opt_level=-1)

class Insn:
    """
    Class Instruction represents a concrete ("fully-grounded")
    machine intruction.
    """
    def __init__(self, spec, bitfields):
        self._spec = spec
        self._encoding = Bits().join(bitfields)

    def __repr__(self):
        asm = self.disassembled
        if asm:
            asm = f" # {asm}"
        else:
            asm = " # invalid?"
        return f"{self.__class__.__name__}({repr(self._encoding)}){asm}"

    def __int__(self):
        return self._encoding.int

    @property
    def bytes(self):
        return self._encoding.bytes

    @property
    @cache
    def VEX(self):
        return self._spec.isa.vex(self)

    @property
    @cache
    def VEXsig(self):
        return VEXsig(self.VEX)

    @property
    @cache
    def disassembled(self):
        return self._spec.isa.disassemble(self)

class InsnSpec:
    def __init__(self, isa, name, bitfields):
        self._isa = isa
        self._name = name
        self._bitfields = bitfields
        setattr(self._isa, self._name, self)

    def __repr__(self):
        return f"{self.__class__.__name__}({repr(self._name)}, {repr(self._bitfields)})"

    @property
    def isa(self):
        return self._isa

    def num_instances(self):
        """
        Return the number of instruction instances returned in instances() iterator
        """
        num = 1
        for bitfield in self._bitfields:
            if isinstance(bitfield, str):
                pass
            elif isinstance(bitfield, int):
                num = num * 2**bitfield
            else:
                raise ValueError("Invalid bitfield spec")
        return num

    def instances(self, left_to_right = True):
        """
        Return an iterator over all possible instances of this instruction
        """
        class instances_iter:
            def __init__(self, spec, left_to_right):
                self._spec = spec
                self._left_to_right = left_to_right
                self._bitfields = spec._bitfields
                self._bitfield_iters = [ self.bitfield_iter(bitfield) for bitfield in self._bitfields ]
                self._bitfield_bits =  [ next(bitfield_iter) for bitfield_iter in self._bitfield_iters ]
                self._done = False

            def bitfield_iter(self, bitfield):
                if isinstance(bitfield, str):
                    return ( Bits(bin=x) for x in [ bitfield ] )
                elif isinstance(bitfield, int):
                    return ( Bits(uint=x, length=bitfield) for x in range(0, 2**bitfield) )
                else:
                    raise ValueError("Invalid bitfield spec")

            def __iter__(self):
                return self

            def __next__(self):
                if self._done:
                    raise StopIteration

                insn = Insn(self._spec, self._bitfield_bits)

                # Now, prepare bitfields for next instruction
                if self._left_to_right:
                    adv_doneindex = len(self._bitfields) - 1
                    adv_indices = range(0, len(self._bitfields))
                else:
                    adv_doneindex = 0
                    adv_indices = range(len(self._bitfields) - 1, -1, -1)
                for adv_index in adv_indices:
                    try:
                        self._bitfield_bits[adv_index] = next(self._bitfield_iters[adv_index])
                        break
                    except StopIteration:
                        if adv_index == adv_doneindex:
                            self._done = True
                        else:
                            self._bitfield_iters[adv_index] = self.bitfield_iter(self._bitfields[adv_index])
                            self._bitfield_bits[adv_index] = next(self._bitfield_iters[adv_index])
                return insn

        return instances_iter(self, left_to_right)

class powerpcISA(ISA):
    def __init__(self):
        super().__init__('powerpc')
        from regularization.isa._powerpc import _fill_isa as _powerpc_fill_isa
        _powerpc_fill_isa(self)

    @cache
    def _capstone(self):
        from capstone import Cs, CS_ARCH_PPC, CS_MODE_32, CS_MODE_BIG_ENDIAN
        return Cs(CS_ARCH_PPC, CS_MODE_32 | CS_MODE_BIG_ENDIAN)

    @cache
    def _archinfo(self):
        return archinfo.ArchPPC32(archinfo.Endness.BE)

powerpc = powerpcISA()


class armISA(ISA):
    def __init__(self):
        super().__init__('arm')
        from regularization.isa._armv5 import _fill_isa as _arm_fill_isa
        _arm_fill_isa(self)

    @cache
    def _capstone(self):
        from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM
        return Cs(CS_ARCH_ARM, CS_MODE_ARM)

    @cache
    def _archinfo(self):
        return archinfo.ArchARM()

arm = armISA()
