import argparse
from sniffing_tools.methods_of_programm import SnifferNetwork

if __name__ == '__main__':
    parse = argparse.ArgumentParser(description="WireShark Tool")
    parse.add_argument("-iface", dest="iface", help="Interface of Network", required=False)
    args = parse.parse_args()
    if args.iface:
        SnifferNetwork.sniffing_iface(args.iface)




