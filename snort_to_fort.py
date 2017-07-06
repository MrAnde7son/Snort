import os.path,re,sys
import argparse


def SnortToFortigate(snort_rules):
    rules = []
    fort_rules = []
    try:
        if os.path.isfile(snort_rules):
            rules += open(snort_rules,'r').readlines()
        elif re.search('^alert\s+(tcp|udp|icmp|ip)\s+[^(]+\(.+\)$', snort_rules, re.IGNORECASE):
            rules += [snort_rules]
        else:
            sys.exit("Invalid rules input.")
    except:
        sys.exit("Error parsing snort rules. Please check the syntax.")
    for r in rules:
        raw = r[r.index('('):]
        raw = re.sub(r'\|[\s\w]+\|', lambda m: re.sub(r'\s*', '', m.group(0)), raw)
        raw = raw.replace('msg:', '--msg ')
        raw = raw.replace('flow:', '--flow ') if "flow" in raw else raw
        raw = raw.replace('pcre:', '--pcre ') if "pcre" in raw else raw
        raw = raw.replace(',established', "") if "established" in raw else raw
        raw = raw.replace('content:', '--pattern ') if "content" in raw else raw
        raw = raw.replace('flags:', '--tcp_flags ') if "flags" in raw else raw
        raw = raw.replace('distance:', '--distance ') if "distance" in raw else raw
        raw = raw.replace('within:', '--within ') if "within" in raw else raw
        raw = re.sub(r'depth:\s*(\d+)', r'--distance \1,packet', raw) if "depth" in raw else raw
        raw = re.sub(r'offset:\s*(\d+)', r'--within \1,packet', raw) if "offset" in raw else raw
        raw = raw.replace('nocase', '--nocase') if "nocase" in raw else raw
        raw = re.sub(r'detection_filter:\s*track\s*([^,]+)\s*,\s*count\s*(\d+)\s*,\s*seconds\s*(\d+)\s*',
                     r'--rate \2,\3; --track \1', raw) if "detection_filter" in raw else raw
        raw = re.sub(r'classtype[^;]+;\s?', '', raw)
        raw = re.sub(r'sid:\d+;\s?', '', raw)
        header = r[:r.index('(')].split(" ")
        raw = re.sub(r'(msg[^;]+;\s?)', r'\1--protocol %s; ' % header[1].upper(), raw)
        if header[2] != 'any':
            raw = re.sub(r'(msg[^;]+;\s?)', r'\1--src_addr %s; ' % header[2], raw)
        if header[3] != 'any':
            raw = re.sub(r'(msg[^;]+;\s?)', r'\1--src_port %s; ' % re.sub(r'[][]',r'',header[3]), raw)
        if header[5] != 'any':
            raw = re.sub(r'(msg[^;]+;\s?)', r'\1--dst_addr %s; ' % header[5], raw)
        if header[6] != 'any':
            raw = re.sub(r'(msg[^;]+;\s?)', r'\1--dst_port %s; ' % re.sub(r'[][]',r'',header[6]), raw)
        fort_rules += [raw]

    return fort_rules



def main():
    parser = argparse.ArgumentParser(description='Snort-to-Fortigate rule converter.')

    parser.add_argument('-r', '--rules', action="store", required=True, help="Specify a rule to convert. You may specify either a rule as a string or snort rules file (all rules will be converted).")
    parser.add_argument('-o', '--output', action="store", help="Specify file to write results to.")

    args = parser.parse_args()

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)
    list = SnortToFortigate(args.rules)
    if args.output is not None:
        try:
            f = open(args.output,'w')
            f.write("".join(list))
            f.close()
        except:
            sys.exit("Error opening %s." % args.output)
    else:
        for r in list:
            print r
    exit(0)

if __name__ == "__main__":
    main()
