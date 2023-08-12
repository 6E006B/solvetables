import argparse
import ipaddress
import re
from z3 import *


def create_iptables_argparse() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="iptables")
    parser.add_argument("-A", "--append")
    parser.add_argument("-p", "--protocol", default="all")

    source_group = parser.add_mutually_exclusive_group()
    source_group.add_argument("-s", "--source", default="0.0.0.0/0")
    source_group.add_argument("-ns", "--not-source")

    destination_group = parser.add_mutually_exclusive_group()
    destination_group.add_argument("-d", "--destination", default="0.0.0.0/0")
    destination_group.add_argument("-nd", "--not-destination")

    parser.add_argument("-j", "--jump")

    if_group = parser.add_mutually_exclusive_group()
    if_group.add_argument("-i", "--in-interface")
    if_group.add_argument("-ni", "--not-in-interface")

    of_group = parser.add_mutually_exclusive_group()
    of_group.add_argument("-o", "--out-interface")
    of_group.add_argument("-no", "--not-out-interface")

    sport_group = parser.add_mutually_exclusive_group()
    sport_group.add_argument("--sport", default="0:655335")
    sport_group.add_argument("--sports", dest="sport")

    dport_group = parser.add_mutually_exclusive_group()
    dport_group.add_argument("--dport", default="0:655335")
    dport_group.add_argument("--dports", dest="dport")

    state_group = parser.add_mutually_exclusive_group()
    parser.add_argument("--state")
    parser.add_argument("--ctstate", dest="state")

    parser.add_argument("-m", "--match")
    parser.add_argument("--tcp-flags", nargs=2)
    parser.add_argument("--icmp-type")
    parser.add_argument("--set", action="store_true")
    parser.add_argument("--name")
    parser.add_argument("--mask")
    parser.add_argument("--rsource", action="store_true")
    parser.add_argument("--rcheck", action="store_true")
    parser.add_argument("--seconds")
    parser.add_argument("-f", "--fragment")
    parser.add_argument("-c", "--set-counters")
    return parser


class SolveTables:
    PROTOCOL_ENUM = [
        "all",
        "tcp",
        "udp",
        "udplite",
        "icmp",
        "icmpv6",
        "esp",
        "ah",
        "sctp",
        "mh",
    ]
    CHAIN_ENUM = ["INPUT", "FORWARD", "OUTPUT"]
    STATE_ENUM = ["NEW", "RELATED", "ESTABLISHED"]

    def __init__(self, default_policy: str) -> None:
        self.accept_default = default_policy == "ACCEPT"
        self.interface_list: list[str] = []
        self.constraints: list[(Probe | BoolRef)] = []
        self.rules: list[str] = []
        self.targets: list[str] = []
        self.src_ip_model: BitVecRef = BitVec("src_ip_model", 32)
        self.dst_ip_model: BitVecRef = BitVec("dst_ip_model", 32)
        self.input_interface_model: BitVecRef = BitVec("input_interface_model", 8)
        self.output_interface_model: BitVecRef = BitVec("output_interface_model", 8)
        self.protocol_model: BitVecRef = BitVec("protocol_model", 4)
        self.src_port_model: BitVecRef = BitVec("src_port_model", 16)
        self.dst_port_model: BitVecRef = BitVec("dst_port_model", 16)
        self.state_model: BitVecRef = BitVec("state_model", 4)
        self.iptables_parser: argparse.ArgumentParser = create_iptables_argparse()

    def _create_ip_constraints(
        self, var: BitVecRef, ip: str, invert: bool = False
    ) -> list[BoolRef]:
        cidr = ipaddress.ip_network(ip)
        constraints = [
            ULE(int(cidr[0]), var),
            ULE(var, int(cidr[-1])),
        ]
        if invert:
            constraints = [Not(c) for c in constraints]
        return constraints

    def _create_interface_constraints(
        self, var: BitVecRef, interface: str, invert: bool = False
    ) -> list[BoolRef]:
        if interface is None:
            return []
        else:
            constraint = var == self._get_or_add_interface_index(interface)
            if invert:
                constraint = Not(constraint)
            return [constraint]

    def _create_protocol_constraints(
        self, var: BitVecRef, protocol: str
    ) -> list[BoolRef]:
        protocol_index = self.PROTOCOL_ENUM.index(protocol)
        if protocol_index == 0:
            return []
        else:
            return [var == protocol_index]

    def _create_port_constraints(self, var: BitVecRef, port: str) -> list[BoolRef]:
        if ":" in port:
            port_range = port.split(":")
            port_min = int(port_range[0])
            port_max = int(port_range[-1])
            return [
                ULE(port_min, var),
                ULE(var, port_max),
            ]
        elif "," in port:
            ports = port.split(",")
            return [Or([var == p for p in ports])]
        else:
            return [var == int(port)]

    def _create_state_constraints(self, var: BitVecRef, state: str) -> list[BoolRef]:
        states = []
        for s in state.split(","):
            states.append(self.STATE_ENUM.index(s))
        return [Or([var == s for s in states])]

    def _fix_not_rule(self, rule: str) -> str:
        return rule.replace("! --", "--not-").replace("! -", "-n")

    def _parse_rule(self, rule: str) -> argparse.Namespace:
        rule = self._fix_not_rule(rule)
        args = self.iptables_parser.parse_args(rule.split())
        return args

    def add_rule(self, rule: str):
        args = self._parse_rule(rule)

        sub_constraints = []
        if args.not_source:
            sub_constraints += self._create_ip_constraints(
                self.src_ip_model, args.not_source, invert=True
            )
        else:
            sub_constraints += self._create_ip_constraints(
                self.src_ip_model, args.source
            )
        if args.not_source:
            sub_constraints += self._create_ip_constraints(
                self.dst_ip_model, args.not_destination, invert=True
            )
        else:
            sub_constraints += self._create_ip_constraints(
                self.dst_ip_model, args.destination
            )
        if args.not_in_interface:
            sub_constraints += self._create_interface_constraints(
                self.input_interface_model, args.not_in_interface, invert=True
            )
        else:
            sub_constraints += self._create_interface_constraints(
                self.input_interface_model, args.in_interface
            )
        if args.not_out_interface:
            sub_constraints += self._create_interface_constraints(
                self.output_interface_model, args.not_out_interface, invert=True
            )
        else:
            sub_constraints += self._create_interface_constraints(
                self.output_interface_model, args.out_interface
            )
        sub_constraints += self._create_protocol_constraints(
            self.protocol_model, args.protocol
        )
        sub_constraints += self._create_port_constraints(
            self.src_port_model, args.sport
        )
        sub_constraints += self._create_port_constraints(
            self.dst_port_model, args.dport
        )
        if args.state is not None:
            sub_constraints += self._create_state_constraints(
                self.state_model, args.state
            )

        constraints = And(sub_constraints)

        if args.jump in ["ACCEPT", "REJECT", "DROP"]:
            constraints = simplify(constraints)
            # print("adding constraints:", constraints)
            self.constraints.append(constraints)
            self.rules.append(rule)
            self.targets.append(args.jump)

    def _get_or_add_interface_index(self, interface: str) -> int:
        if interface not in self.interface_list:
            self.interface_list.append(interface)
        return self.interface_list.index(interface)

    def _get_base_rules(self) -> Probe | BoolRef:
        base_rules = And(
            ULT(self.protocol_model, len(self.PROTOCOL_ENUM)),
            ULT(self.input_interface_model, len(self.interface_list)),
            ULT(self.output_interface_model, len(self.interface_list)),
            ULT(self.state_model, len(self.STATE_ENUM)),
        )
        return base_rules

    def build_constraints(self) -> Probe | BoolRef:
        # print("self.constraints:", self.constraints)
        previous_rules = []
        rules = []
        for i, rule in enumerate(self.constraints):
            target = self.targets[i]
            if target == "ACCEPT":
                if previous_rules:
                    rules.append(And(Not(Or(previous_rules)), rule))
                else:
                    rules.append(rule)
            previous_rules.append(rule)
        if self.accept_default:
            rules.append(True)
        base_rules = self._get_base_rules()

        # return And(Or(rules), base_rules)
        return simplify(And(Or(rules), base_rules))

    def check_and_get_model(self, constraints: (Probe | BoolRef)) -> None | ModelRef:
        m = None
        s = Solver()
        rules = self.build_constraints()
        # print("rules:", rules)
        s.add(constraints, rules)
        result = s.check()
        if result == sat:
            m = s.model()
        return m

    def translate_model(self, model: ModelRef):
        protocol_index = (
            model.eval(self.protocol_model, model_completion=True).as_long()
            if model[self.protocol_model] is not None
            else 0
        )
        translated_model = {
            "src_ip": ipaddress.ip_address(
                model.eval(self.src_ip_model, model_completion=True).as_long()
            ),
            "dst_ip": ipaddress.ip_address(
                model.eval(self.dst_ip_model, model_completion=True).as_long()
            ),
            "input_interface": self.interface_list[
                model.eval(self.input_interface_model, model_completion=True).as_long()
            ],
            "output_interface": self.interface_list[
                model.eval(self.output_interface_model, model_completion=True).as_long()
            ],
            "protocol": self.PROTOCOL_ENUM[protocol_index],
            "src_port": model.eval(
                self.src_port_model, model_completion=True
            ).as_long(),
            "dst_port": model.eval(
                self.dst_port_model, model_completion=True
            ).as_long(),
            "state": self.STATE_ENUM[
                model.eval(self.state_model, model_completion=True).as_long()
            ],
        }
        return translated_model

    def identify_rule(self, model: ModelRef) -> None | str:
        for i, rules in enumerate(self.constraints):
            s = Solver()
            s.add(rules)
            s.add(self._get_base_rules())
            for var in [
                self.src_ip_model,
                self.dst_ip_model,
                self.input_interface_model,
                self.output_interface_model,
                self.protocol_model,
                self.src_port_model,
                self.dst_port_model,
                self.state_model,
            ]:
                if model[var] is not None:
                    s.add(var == model[var])
            if s.check() == sat:
                rule = self.rules[i]
                return rule
            s.reset()

    def translate_expression(self, expression: list[str]) -> Probe | BoolRef:
        var_table = {
            "src_ip": self.src_ip_model,
            "dst_ip": self.dst_ip_model,
            "in_iface": self.input_interface_model,
            "out_iface": self.output_interface_model,
            "protocol": self.protocol_model,
            "src_port": self.src_port_model,
            "dst_port": self.dst_port_model,
            "state": self.state_model,
        }
        op_table = {
            "==": BitVecRef.__eq__,
            "!=": BitVecRef.__ne__,
            "<=": ULE,
            ">=": UGE,
            "<": ULT,
            ">": UGT,
        }
        concat_op_table = {
            "and": And,
            "or": Or,
        }

        constraints = None
        concat_op = None

        while len(expression) > 0:
            assert len(expression) >= 3

            operand1 = expression.pop(0)
            operator = expression.pop(0)
            operand2 = expression.pop(0)

            # assert operand1 in var_table.keys()
            top1 = var_table[operand1]

            # assert operator in op_table.keys()
            op = op_table[operator]

            match operand1.split("_"):
                case ["state"]:
                    top2 = self.STATE_ENUM.index(operand2)
                case ["protocol"]:
                    top2 = self.PROTOCOL_ENUM.index(operand2)
                case [_, "iface"]:
                    top2 = self._get_or_add_interface_index(operand2)
                case [_, "port"]:
                    top2 = int(operand2)
                case [_, "ip"]:
                    top2 = int(ipaddress.IPv4Address(operand2))

            sub_constraint = op(top1, top2)
            if constraints is None:
                constraints = sub_constraint
            else:
                constraints = concat_op(constraints, sub_constraint)

            if len(expression) > 0:
                concat_operator = expression.pop(0)
                # assert concat_operator in concat_op_table.keys()
                concat_op = concat_op_table[concat_operator]
        return constraints


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-p", "--default-policy", default=None, choices=["ACCEPT", "DROP", "REJECT"]
    )
    parser.add_argument("chain", choices=["INPUT", "FORWARD", "OUTPUT"])
    parser.add_argument("iptables_save_log", type=argparse.FileType("r"))
    parser.add_argument("expression", nargs="+")
    args = parser.parse_args()

    iptables_rules_file = args.iptables_save_log.read()

    default_policy = args.default_policy
    if default_policy is None:
        match = re.search(
            f"^:{args.chain}\s+(?P<default_policy>(ACCEPT|DROP|REJECT))",
            iptables_rules_file,
            re.M,
        )
        if match is None:
            parser.error(
                f"Unable to detect default policy for {args.chain}, please specify with --default-policy"
            )
        else:
            default_policy = match.group("default_policy")
            print(f"identified default policy for {args.chain} is {default_policy}")
    st = SolveTables(default_policy=default_policy)

    for rule_line in iptables_rules_file.splitlines():
        if rule_line.startswith(f"-A {args.chain}"):
            # print(rule_line)
            st.add_rule(rule_line)

    expression = (
        args.expression[0].split() if len(args.expression) == 1 else args.expression
    )
    additional_constraints = st.translate_expression(expression)
    model = st.check_and_get_model(constraints=additional_constraints)
    if model is not None:
        print("The identified model is:")
        print(model)
        print()
        print("Use the following parameters to create packet for desired effect:")
        translated_model = st.translate_model(model)
        for k, v in translated_model.items():
            print(f"  {k}: {v}")
        print()
        rule = st.identify_rule(model)
        if rule:
            print(f"The iptabeles rule hit is:")
            print(rule)
        else:
            print("Something went wrong! Unable to identify associated rule /o\\")

    else:
        print("The provided constraints are not satisfiable.")


if __name__ == "__main__":
    main()
