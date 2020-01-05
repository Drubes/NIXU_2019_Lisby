#!/usr/bin/python
import re
HALT = 0  # ceases execution of the program
ADD = 1  # binary arithmetic; pop two values from value stack;
SUB = 2  # and then push the result back; should only work
MUL = 3  # with integers and floats
DIV = 4
XOR = 5  # integer xor
MOD = 6  # integer and float modulo
AND = 7  # conditionals; pop two values from value stack;
OR = 8   # push the result back; -- and - should both be short-circuiting
INV = 9  # pop value from stack; do bitwise inversions; works on integers
PUSHI = 10    # push an integer to the value stack
PUSHF = 11    # push a float
PUSHSTR = 12  # string table reference follows (int); the respective string
PUSHSY = 13   # symbol table reference follows (int); the respective symbol
PUSHSYRAW = 14  # symbol table reference follows (int); the respective
PUSHTRUE = 15   # push a boolean true to value stack
PUSHFALSE = 16  # push a boolean false to value stack
PUSHUNIT = 17   # push unit (empty list) to value stack
PUSHCLOSURE = 18  # pushes a closure reference to the stack; the reference
PUSHCONT = 19  # pushes the current continuation to stack; the continuation
QUOTED = 20    # increases quoting level of next value push
POP = 21       # pops a value from the stack without storing it
CALL = 22      # pops a closure from value stack; transfers control there;
TAILCALL = 23  # like call except tail call
RET = 24       # pops a return address from call stack; transfers control
JT = 25   # pops a boolean from value stack, jumps to tape offset if true
JF = 26   # pops a boolean from value stack, jumps to tape offset if false
JMP = 27  # unconditional jump to tape offset
STORE = 28     # stores popped stack value to given symbol index of the
STORETOP = 29  # stores popped stack value to given symbol index of the
EQ = 30    # conditionals: pop two values from value stack, and push
NEQ = 31   # a boolean value back depending on the result
GT = 32
GE = 33
LT = 34
LE = 35
NOT = 36  # pop boolean from value stack; if popped value is ---, push back
DECLARE = 37  # declares a variable with the given symbol index (int) in the
PRINT = 38    # pops one value and attempts to display it to the controlling
LIST = 39     # constructs a list of -- entries popped from value stack
HEAD = 40     # pops a list and pushes its first element; should error if
TAIL = 41     # pops a list and pushes it without its first element; should
LISTCAT = 42  # pops two lists from value stack; pushes their concatenation
EVAL = 43  # pops a value, evaluates it in an empty environment
DUMP = 44  # dumps the current vm status in an implementation defined manner
NEWENV = 45  # activates a fresh environment with the current environment as
DEPARTENV = 46  # departs the current environment and activates the parent

####NOPE NOPE NOPE
file = open(__file__).read()

oc = re.findall('([A-Z]+)',file[:file.find('####NOPE NOPE NOPE')])
print oc
print len(oc)
