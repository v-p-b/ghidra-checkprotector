# Check which functions don't reference a "protector" function (e.g.: stack canary check)
#@author buherator
#@category _NEW_
#@keybinding
#@menupath
#@toolbar

from ghidra.program.util import CyclomaticComplexity
from ghidra.util.task import TaskMonitor

CC_THREASHOLD = 10

cyclomaticComplexity = CyclomaticComplexity()

refs = getReferencesTo(currentAddress)

user_funcs = set()

for r in refs:
    user_funcs.add(getFunctionContaining(r.getFromAddress()))

f = getFirstFunction()
while f is not None:
    if f not in user_funcs:
        cc = cyclomaticComplexity.calculateCyclomaticComplexity(
            f, TaskMonitor.DUMMY)
        if cc > CC_THREASHOLD:
            print("%s (cc: %d) does not reference %x" %
                  (f, cc, currentAddress.getOffset()))
    f = getFunctionAfter(f)
