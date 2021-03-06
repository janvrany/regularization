"
Simple script to generate ISA specifications suitable for regularization
from ArchC PDLs

Usage:

smalltalk --package-path ~/.../MachineArithmetic:~/.../ArchC/src --execute isagen.st

"
Stdout nextPutLine: 'Loading ArchC...'.
Smalltalk
    loadPackage: 'stx:goodies/petitparser';
    loadPackage: 'MachineArithmetic';
    loadPackage: 'ArchC-Core';
    loadPackage: 'ArchC-RISCV'.

#(powerpc armv5) do:[:isaName |
    | isa |

    isa := AcProcessorDescriptions perform: isaName.

    Stdout nextPutLine: 'Generating ', isaName.
    ('regularization/isa/_', isaName , '.py') asFilename writingFileDo:[:out|
	out nextPutLine: '# Automagically generated by isagen.st from Arch-C spec, do not edit!!'.
	out nextPutLine: 'from regularization.isa import InsnSpec'.
	out nextPutLine: 'def _fill_isa(isa):'.

	AcProcessorDescriptions powerpc instructions do: [:insn |
	    | bitfields |

	    bitfields := String streamContents:[:s|
		insn format bitFields do: [:bitfield |
		    | value |

		    value := insn internalBindings at: bitfield name ifAbsent: nil.
		    value notNil ifTrue: [
			s nextPut:$'.
			value printOn: s base: 2 size: bitfield width fill: $0.
			s nextPut:$'.
		    ] ifFalse: [
			bitfield width printOn: s.
		    ].
		    s nextPutAll: ', '.
		].
	    ].

	    out nextPutLine: ('    InsnSpec(isa, ''%1'', [ %2 ])' bindWith: insn name with: bitfields)
	].
    ].
].
