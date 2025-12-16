import sys
import argparse
import csv
import itertools

baseline_hs = list()
baseline_bm = list()
baseline_mm = list()
branch_hs = list()
branch_bm = list()
branch_mm = list()

def load_baseline(path):
    with open(path, newline='') as csvfile:
        f = csv.reader(csvfile, delimiter=',')
        h = next(itertools.islice(f, 0, 1))
        global baseline_header
        baseline_header = h

        for row in f:
            if (row[0] == 'hs'):
                baseline_hs.append(row)
            elif (row[0] == 'bm'):
                baseline_bm.append(row)
            elif (row[0] == 'mm'):
                baseline_mm.append(row)

def load_branch(path):
    with open(path, newline='') as csvfile:
        f = csv.reader(csvfile, delimiter=',')
        _h = next(itertools.islice(f, 0, 1))

        for row in f:
            if (row[0] == 'hs'):
                branch_hs.append(row)
            elif (row[0] == 'bm'):
                branch_bm.append(row)
            elif (row[0] == 'mm'):
                branch_mm.append(row)

def report_baseline_vs_branch(threshold):
    global baseline_header
    h = baseline_header
    cnt = len(baseline_bm)

    print("\n%-64s: %-8s %8s \t\tPercent" % ("HS/VS", "baseline", "branch"))
    for idx in range(0, cnt):
        bl = baseline_hs[idx]
        br = branch_hs[idx]

        for i in range(1, len(bl)):
            if len(bl[i]) == 0:
                continue
            p = int(br[i]) / int(bl[i]) * 100
            if p > (100 + threshold) or p < (100 - threshold):
                cs = "\x1b[1;31m" if (p > (100 + threshold)) else "\x1b[32m"
                ce = "\x1b[0m"
                print("%-64s: %8d %8d:\t\t%s%0.2f%s" % (h[i], int(bl[i]), int(br[i]), cs, p, ce))


    print("\n%-64s: %-8s %8s \t\tPercent" % ("BM", "baseline", "branch"))
    for idx in range(0, cnt):
        bl = baseline_bm[idx]
        br = branch_bm[idx]

        for i in range(1, len(bl)):
            if len(bl[i]) == 0:
                continue
            p = int(br[i]) / int(bl[i]) * 100
            if p > (100 + threshold) or p < (100 - threshold):
                cs = "\x1b[1;31m" if (p > (100 + threshold)) else "\x1b[32m"
                ce = "\x1b[0m"
                print("%-64s: %8d %8d:\t\t%s%0.2f%s" % (h[i], int(bl[i]), int(br[i]), cs, p, ce))

    print("\n%-64s: %-8s %8s \t\tPercent" % ("MM", "baseline", "branch"))
    for idx in range(0, cnt):
        bl = baseline_mm[idx]
        br = branch_mm[idx]

        for i in range(1, len(bl)):
            if len(bl[i]) == 0:
                continue
            p = int(br[i]) / int(bl[i]) * 100
            if p > (100 + threshold) or p < (100 - threshold):
                cs = "\x1b[1;31m" if (p > (100 + threshold)) else "\x1b[32m"
                ce = "\x1b[0m"
                print("%-64s: %8d %8d:\t\t%s%0.2f%s" % (h[i], int(bl[i]), int(br[i]), cs, p, ce))

def report_spms(threshold):
    global baseline_header
    h = baseline_header
    cnt = len(baseline_bm)
    
    print("\n%-64s: %-8s %8s \t\tPercent" % ("HS/VS vs BM", "BM", "HS/VS"))
    for idx in range(0, cnt):
        bl = baseline_bm[idx]
        br = baseline_hs[idx]

        for i in range(1, len(bl)):
            if len(bl[i]) == 0:
                continue
            p = int(br[i]) / int(bl[i]) * 100
            if p > (100 + threshold) or p < (100 - threshold):
                cs = "\x1b[1;31m" if (p > (100 + threshold)) else "\x1b[32m"
                ce = "\x1b[0m"
                print("%-64s: %8d %8d:\t\t%s%0.2f%s" % (h[i], int(bl[i]), int(br[i]), cs, p, ce))

    print("\n%-64s: %-8s %8s \t\tPercent" % ("BM vs MM", "BM", "MM"))
    for idx in range(0, cnt):
        bl = baseline_bm[idx]
        br = baseline_mm[idx]

        for i in range(1, len(bl)):
            if len(bl[i]) == 0:
                continue
            p = int(br[i]) / int(bl[i]) * 100
            if p > (100 + threshold) or p < (100 - threshold):
                cs = "\x1b[1;31m" if (p > (100 + threshold)) else "\x1b[32m"
                ce = "\x1b[0m"
                print("%-64s: %8d %8d:\t\t%s%0.2f%s" % (h[i], int(bl[i]), int(br[i]), cs, p, ce))

    print("\n%-64s: %-8s %8s \t\tPercent" % ("MM vs HS/VS", "MM", "HS/VS"))
    for idx in range(0, cnt):
        bl = baseline_mm[idx]
        br = baseline_hs[idx]

        for i in range(1, len(bl)):
            if len(bl[i]) == 0:
                continue
            p = int(br[i]) / int(bl[i]) * 100
            if p > (100 + threshold) or p < (100 - threshold):
                cs = "\x1b[1;31m" if (p > (100 + threshold)) else "\x1b[32m"
                ce = "\x1b[0m"
                print("%-64s: %8d %8d:\t\t%s%0.2f%s" % (h[i], int(bl[i]), int(br[i]), cs, p, ce))

def main():
    parser = argparse.ArgumentParser(description="Bench tool csv compare script.")
    parser.add_argument("--baseline", action="store",
                        help="Baseline csv file")
    parser.add_argument("--branch", action="store",
                        help="Branch csv file")
    parser.add_argument("--threshold", action="store",
                        help="Threshold percentage point value for reporting a difference")
    args = parser.parse_args()
    load_baseline(args.baseline)
    if args.branch != None and len(args.branch) > 0:
        load_branch(args.branch)
        report_baseline_vs_branch(int(args.threshold))
    else:
        report_spms(int(args.threshold))

if __name__ == "__main__":
    sys.exit(main())
