import sys

#cppclean src/*.h | grep "does not need to be #included"
retcode = 0
for l in sys.stdin:
    includer = l.split(':')[0]
    included = l.split("'")[1]

    if included == "rust.h" or included == "suricata-common.h":
        continue
    if includer == "src/suricata-common.h" or includer == "src/rust-context.h" or includer == "src/rust.h" or includer == "src/threads.h":
        continue

    if included == "util-file.h" and includer == "src/detect.h":
        # SigTableElmt structure field FileMatch being a function pointer using a parameter File defined in util-file.h
        continue
    if included == "conf.h" and includer == "src/suricata-plugin.h":
        # SCEveFileType structure field Init being a function pointer using a parameter ConfNode defined in conf.h
        continue
    if included == "util-debug-filters.h" and includer == "src/util-debug.h":
        # Macro SCEnter using SCLogCheckFDFilterEntry defined in util-debug-filters.h
        continue
    if included == "util-spm-bs.h" and includer == "src/util-spm.h":
        # Macro SpmSearch using BasicSearch defined in util-spm-bs.h
        continue

    print("Unnecessary include from %s for %s" % (includer, included))
    retcode = 1

sys.exit(retcode)
