import argparse
import ipaddress
import json
import logging
from collections import defaultdict

import jc

from solvetables import solve_tables

IF_BLACKLIST: list[str] = ["lo"]


def parse_ip(ip_content: str):
    netinfo = {}
    ip_json = json.loads(ip_content)
    for interface in ip_json:
        name = interface["ifname"]
        if name not in IF_BLACKLIST and interface["addr_info"]:
            ips = []
            for addr_info in interface["addr_info"]:
                ip = ipaddress.ip_address(addr_info["local"])
                ipn = ipaddress.ip_network(
                    f"{addr_info['local']}/{addr_info['prefixlen']}", False
                )
                ips.append((ip, ipn))
            if ips:
                netinfo[name] = ips
        else:
            logging.info(f"No address on '{name}'")
    return netinfo


def main(args: list[str] = None) -> dict:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-s",
        "--use-ss",
        default=False,
        action="store_true",
        help="Use ss output instead of netstat.",
    )
    parser.add_argument("ip_a_json", type=argparse.FileType())
    parser.add_argument("netstat", type=argparse.FileType())
    parser.add_argument("iptables", type=argparse.FileType())
    args = parser.parse_args(args=args)

    iptables_content = args.iptables.read()

    netinfo = parse_ip(args.ip_a_json.read())
    interfaces = netinfo.keys()

    netstat_content = args.netstat.read()
    netstat_json = jc.parse("ss" if args.use_ss else "netstat", netstat_content)
    result = defaultdict(dict)
    for row in netstat_json:
        proto = row["netid" if args.use_ss else "proto"]
        if proto not in ["tcp", "udp"]:
            logging.warning(f"Skipping unhandled proto '{proto}'.")
            continue
        if row["state"] in ["ESTAB", "ESTABLISHED"]:
            continue
        range = row["local_address"]
        port = row["local_port_num"]
        # user = row["user"]
        if range in ["127.0.0.1", "::1", "[::1]"]:
            continue
        elif range == "0.0.0.0":
            range += "/0"
        elif range == "::":
            range += "/128"
        elif range == "*":
            range = "0.0.0.0/0"
            # TODO: Add also ::/128
        ip = ipaddress.ip_network(range)
        match proto:
            case "tcp" | "udp":
                # Here a route needs to point back (ip r)
                print(
                    f"Checking if service '{ip}:{proto.upper()}/{port}' is reachable:"
                )
                result[proto][(ip, port)] = defaultdict(list)
                for interface in netinfo:
                    # print(f"\tOn '{interface}':")
                    for addr, addr_net in netinfo[interface]:
                        if ipaddress.ip_address(addr) in ip:
                            # TODO: check for routes back
                            omit_addresses = ",".join(
                                [
                                    "0.0.0.0",
                                    "255.255.255.255",
                                    str(addr),
                                    str(addr_net.broadcast_address),
                                    str(addr_net.network_address),
                                ]
                            )
                            expression = f"protocol == {proto} and in_iface == {interface} and dst_ip == {addr} and src_port != 0 and dst_port == {port} and state !in RELATED,ESTABLISHED and src_ip !in {omit_addresses} and src_ip in {addr_net}"
                            model, translated_model = solve_tables(
                                iptables_rules_file=iptables_content,
                                chain="INPUT",
                                expression=expression,
                                additional_interfaces=interfaces,
                                parser=parser,
                                print=lambda *x: True,
                            )
                            if model:
                                if translated_model is not None:
                                    packet_params = []
                                    for k, v in translated_model.items():
                                        if k not in ["output_interface"]:
                                            packet_params.append(f"{k}={v}")
                                    print(
                                        f"For '{interface}' ({addr}):",
                                        ", ".join(packet_params),
                                    )
                                    result[proto][(ip, port)][interface].append(
                                        translated_model
                                    )
                                else:
                                    print(
                                        f"[*] Potentially reachable on '{interface}' ({addr})"
                                    )
                            # else:
                            #     print("[X] Doesn't seem reachable")
            case "udp":
                # Here it can be sufficient to have a one way connection, depending on the application
                pass
            case "tcp6" | "udp6":
                pass
            case _:
                logging.warning(f"Unhandled proto '{proto}'.")
    return result


if __name__ == "__main__":
    main()
