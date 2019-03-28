import sys
count = 0;
with open("dat") as f:
    content = f.readlines()
    for line in content:
        start = line.index("ecall")
        tmp = line[start:]
        end = tmp.index('(')
        tmp = tmp[:end]
        print("#define {} {}".format(tmp.upper(), count))
        count += 1

