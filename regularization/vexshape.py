import io
from tqdm.auto import trange

CenteredDot = '*'

class _VEXNodeVisitor:
    def visit(self, node):
        visitFuncName = 'visit' + node.__class__.__name__
        if hasattr(self, visitFuncName):
            return getattr(self, visitFuncName)(node)
        else:
            raise NotImplementedError(f"VEX visit function '{visitFuncName}' not yet implemented!")

    def visitAll(self, nodes):
        return [ self.visit(node) for node in nodes ]

    def visitIMark(self, node):
        return None

class _VEXNode2Sigop(_VEXNodeVisitor):
    def visitWrTmp(self, irNode):
        return f"t{irNode.tmp} = {self.visit(irNode.data)}"

    def visitPut(self, irNode):
        return f"PUT({CenteredDot}) = {self.visit(irNode.data)}"

    def visitGet(self, irNode):
        return f"GET:{str(irNode.ty)[4:]} {CenteredDot}"

    def visitBinop(self, irNode):
        return f"{str(irNode.op)[4:]}({','.join(self.visitAll(irNode.args))})"

    def visitUnop(self, irNode):
        return f"{str(irNode.op)[4:]}({','.join(self.visitAll(irNode.args))})"

    def visitRdTmp(self, irNode):
        return f"t{irNode.tmp}"

    def visitConst(self, irNode):
        return f"Const {self.visit(irNode.con)}"

    def visitU32(self, irNode):
        return f"U32 {CenteredDot}"

    def visitExit(self, irNode):
        return f"if ({self.visit(irNode.guard)}) EXIT"

def _stmt2sigop(stmt):
    return _VEXNode2Sigop().visit(stmt)

class VEXsig:
    def __init__(self, irsb):
        self._sigops = [ _stmt2sigop(stmt) for stmt in irsb.statements[1:] ]

    def __str__(self):
        outio = io.StringIO()
        for sigop in self._sigops:
            #outio.write("        ")
            outio.write(str(sigop))
            outio.write('\n')
        out = outio.getvalue()
        outio.close()
        return out

    def __hash__(self):
        return hash( (self.__class__, tuple(self._sigops)) )

    def __eq__(self, other):
        if isinstance(other, self.__class__):
            return self._sigops == other._sigops
        return NotImplemented

class VEXShape:
    def __init__(self, example):
        self._example = example

    def __hash__(self):
        return hash( (self.__class__, self._example.VEXsig) )

    def __eq__(self, other):
        if isinstance(other, self.__class__):
            return self._example.VEXsig == other._example.VEXsig
        return NotImplemented

    def __repr__(self):
        return f"<VEXShape example={self._example}>"

    @property
    def example(self):
        return self._example

    @property
    def signature(self):
        return self._example.VEXsig

class VEXShapeAnalysis:
    def __init__(self, spec):
        self._spec = spec
        self._num_insns_to_analyze = self._spec.num_instances()
        self._insns = self._spec.instances()
        self._shapes = []

    def _next_insn(self):
        insn = next(self._insns)
        self._num_insns_to_analyze = self._num_insns_to_analyze - 1
        return insn

    def run(self, max_to_analyze = None):
        if max_to_analyze == None:
            max_to_analyze = self._num_insns_to_analyze
        self._shapes = set(self._shapes)
        for i in trange(max_to_analyze, desc=f"Analyzing {self._spec._name}"):
            insn = self._next_insn()
            shape = VEXShape(insn)
            if not shape in self._shapes:
                self._shapes.add(shape)
        self._shapes = list(self._shapes)

    @property
    def shapes(self):
        return self._shapes






