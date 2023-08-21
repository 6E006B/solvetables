import argparse
from collections import defaultdict
import ipaddress
import re
import shlex
from z3 import *


def create_iptables_argparse() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="iptables")
    parser.add_argument("-A", "--append")

    protocol_group = parser.add_mutually_exclusive_group()
    protocol_group.add_argument("-p", "--protocol", default="all")
    protocol_group.add_argument("-np", "--not-protocol")

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
    sport_group.add_argument("--sport", default="0:65535")
    sport_group.add_argument("--sports", dest="sport")

    dport_group = parser.add_mutually_exclusive_group()
    dport_group.add_argument("--dport", default="0:65535")
    dport_group.add_argument("--dports", dest="dport")

    state_group = parser.add_mutually_exclusive_group()
    state_group.add_argument("--state")
    state_group.add_argument("--ctstate", dest="state")

    parser.add_argument("-m", "--match")
    parser.add_argument("--tcp-flags", nargs=2)
    parser.add_argument("--icmp-type")
    parser.add_argument("--set", action="store_true")
    parser.add_argument("--name")
    parser.add_argument("--mask")
    parser.add_argument("--rsource", action="store_true")
    parser.add_argument("--rcheck", action="store_true")
    parser.add_argument("--seconds")
    parser.add_argument("-f", "--fragment", action="store_true")
    parser.add_argument("-c", "--set-counters")
    parser.add_argument("--mark")
    parser.add_argument("--set-xmark")
    parser.add_argument("--to-source")
    parser.add_argument("--to-destination")
    parser.add_argument("--src-type")
    parser.add_argument("--dst-type")
    parser.add_argument("--set-mss")
    parser.add_argument("--limit")
    parser.add_argument("--log-prefix")
    parser.add_argument("--log-level")
    parser.add_argument("--hashlimit-upto")
    parser.add_argument("--hashlimit-burst")
    parser.add_argument("--hashlimit-mode")
    parser.add_argument("--hashlimit-name")
    parser.add_argument("--hashlimit-htable-expire")
    parser.add_argument("--remove", action="store_true")
    parser.add_argument("--reject-with")
    return parser


class Rule:
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
    INTERFACE_ENUM = []
    IPTABLES_PARSER = create_iptables_argparse()

    def __init__(self, rule: str):
        self.iptables_rule = rule
        rule = self._fix_not_rule(rule)
        self.args = self.IPTABLES_PARSER.parse_args(shlex.split(rule))
        self.constraints = None

    def get_target(self):
        return self.args.jump

    def get_chain(self):
        return self.args.append

    def _fix_not_rule(self, rule: str) -> str:
        return rule.replace("! --", "--not-").replace("! -", "-n")

    @classmethod
    def _get_or_add_interface_index(cls, interface: str) -> int:
        if interface not in cls.INTERFACE_ENUM:
            cls.INTERFACE_ENUM.append(interface)
        return cls.INTERFACE_ENUM.index(interface)

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
        self, var: BitVecRef, protocol: str, invert: bool = False
    ) -> list[BoolRef]:
        protocol_index = self.PROTOCOL_ENUM.index(protocol)
        # TODO: inverting all interfaces does not really make sense, does it?
        if protocol_index == 0:
            return []
        else:
            constraint = var == protocol_index
            if invert:
                constraint = Not(constraint)
            return [constraint]

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

    def _build_constraints(self, st: "SolveTables"):
        sub_constraints = []
        if self.args.not_source:
            sub_constraints += self._create_ip_constraints(
                st.src_ip_model, self.args.not_source, invert=True
            )
        else:
            sub_constraints += self._create_ip_constraints(
                st.src_ip_model, self.args.source
            )
        if self.args.not_source:
            sub_constraints += self._create_ip_constraints(
                st.dst_ip_model, self.args.not_destination, invert=True
            )
        else:
            sub_constraints += self._create_ip_constraints(
                st.dst_ip_model, self.args.destination
            )
        if self.args.not_in_interface:
            sub_constraints += self._create_interface_constraints(
                st.input_interface_model, self.args.not_in_interface, invert=True
            )
        else:
            sub_constraints += self._create_interface_constraints(
                st.input_interface_model, self.args.in_interface
            )
        if self.args.not_out_interface:
            sub_constraints += self._create_interface_constraints(
                st.output_interface_model,
                self.args.not_out_interface,
                invert=True,
            )
        else:
            sub_constraints += self._create_interface_constraints(
                st.output_interface_model, self.args.out_interface
            )
        if self.args.not_protocol:
            sub_constraints += self._create_protocol_constraints(
                st.protocol_model, self.args.not_protocol, invert=True
            )
        else:
            sub_constraints += self._create_protocol_constraints(
                st.protocol_model, self.args.protocol
            )
        sub_constraints += self._create_port_constraints(
            st.src_port_model, self.args.sport
        )
        sub_constraints += self._create_port_constraints(
            st.dst_port_model, self.args.dport
        )
        if self.args.state is not None:
            sub_constraints += self._create_state_constraints(
                st.state_model, self.args.state
            )

        constraints = And(sub_constraints)
        # constraints = simplify(constraints)
        # print("adding constraints:", constraints)
        self.constraints = constraints

    def get_constraints(self, st: "SolveTables") -> BoolRef:
        if self.constraints is None:
            self._build_constraints(st)
        return self.constraints


class SolveTables:
    BASE_TARGETS = ["ACCEPT", "DROP", "REJECT"]

    def __init__(self, default_policy: str) -> None:
        self.accept_default = default_policy == "ACCEPT"
        self.chain_rules: dict[str, list[Rule]] = defaultdict(list)
        self.chain_constraints: dict[str, BoolRef] = {
            "ACCEPT": True,
            "DROP": False,
            "REJECT": False,
        }
        self.src_ip_model: BitVecRef = BitVec("src_ip_model", 32)
        self.dst_ip_model: BitVecRef = BitVec("dst_ip_model", 32)
        self.input_interface_model: BitVecRef = BitVec("input_interface_model", 8)
        self.output_interface_model: BitVecRef = BitVec("output_interface_model", 8)
        self.protocol_model: BitVecRef = BitVec("protocol_model", 4)
        self.src_port_model: BitVecRef = BitVec("src_port_model", 16)
        self.dst_port_model: BitVecRef = BitVec("dst_port_model", 16)
        self.state_model: BitVecRef = BitVec("state_model", 4)
        self.iptables_parser: argparse.ArgumentParser = create_iptables_argparse()

    def add_rule(self, rule: str):
        new_rule = Rule(rule)
        self.chain_rules[new_rule.get_chain()].append(new_rule)

    def _get_base_constraints(self) -> Probe | BoolRef:
        base_rules = And(
            ULT(self.protocol_model, len(Rule.PROTOCOL_ENUM)),
            ULT(self.input_interface_model, len(Rule.INTERFACE_ENUM)),
            ULT(self.output_interface_model, len(Rule.INTERFACE_ENUM)),
            ULT(self.state_model, len(Rule.STATE_ENUM)),
        )
        return base_rules

    def build_chain_constraints(self, chain: str) -> BoolRef:
        previous_rules = []
        rules = []
        for rule in self.chain_rules[chain]:
            target = rule.get_target()
            constraints = rule.get_constraints(self)
            # print("constraints", constraints)
            if constraints is not None:
                target_constraints = self.get_chain_constraints(chain=target)
                # if target not in self.BASE_TARGETS:
                #     print(f"Additional constraints for '{target}' are:")
                #     print(target_constraints)

                keep_constraints = constraints
                # Include constraints from target chain
                if target_constraints is not None:
                    constraints = And(constraints, target_constraints)
                    # only store combined constraints if target constraints is not False
                    # i.e. DROP or REJECT
                    if target_constraints is not False:
                        keep_constraints = constraints

                # Only add previously rules if they are not empty
                if previous_rules:
                    rules.append(And(Not(Or(previous_rules)), constraints))
                else:
                    rules.append(constraints)

                # Keep a list of previous constraints
                # These will be negated and preprended to the next rule
                previous_rules.append(keep_constraints)
        if self.accept_default:
            # Only add previously rules if they are not empty
            if previous_rules:
                rules.append(And(Not(Or(previous_rules)), True))
            else:
                rules.append(True)
        return Or(rules)

    def get_chain_constraints(self, chain: str) -> BoolRef:
        if chain not in self.chain_constraints:
            self.chain_constraints[chain] = self.build_chain_constraints(chain=chain)
        return self.chain_constraints[chain]

    def build_constraints(self, chain: str) -> Probe | BoolRef:
        # print("self.constraints:", self.constraints)
        chain_constraints = self.get_chain_constraints(chain=chain)
        base_rules = self._get_base_constraints()

        combined_constraints = And(chain_constraints, base_rules)
        # return combined_constraints
        return simplify(combined_constraints)

    def check_and_get_model(
        self, chain: str, constraints: (Probe | BoolRef)
    ) -> None | ModelRef:
        m = None
        s = Solver()
        rules = self.build_constraints(chain)
        # print("final constraints:")
        # print(And(constraints, rules))
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
            "input_interface": Rule.INTERFACE_ENUM[
                model.eval(self.input_interface_model, model_completion=True).as_long()
            ],
            "output_interface": Rule.INTERFACE_ENUM[
                model.eval(self.output_interface_model, model_completion=True).as_long()
            ],
            "protocol": Rule.PROTOCOL_ENUM[protocol_index],
            "src_port": model.eval(
                self.src_port_model, model_completion=True
            ).as_long(),
            "dst_port": model.eval(
                self.dst_port_model, model_completion=True
            ).as_long(),
            "state": Rule.STATE_ENUM[
                model.eval(self.state_model, model_completion=True).as_long()
            ],
        }
        return translated_model

    def identify_rule(self, chain: str, model: ModelRef) -> None | list[str]:
        s = Solver()
        for rule in self.chain_rules[chain]:
            # We can skip these as our packet should be accepted
            if rule.get_target() not in ["DROP", "REJECT"]:
                rule_constraints = rule.get_constraints(self)
                if rule_constraints is not None:
                    s.add(rule_constraints)
                    s.add(self._get_base_constraints())
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
                        match rule.get_target():
                            case "ACCEPT":
                                return [rule.iptables_rule]
                            case "DROP" | "REJECT":
                                print(
                                    "You should never see this, please report your parameters."
                                )
                                continue
                            case _:
                                additional_rules = self.identify_rule(
                                    chain=rule.get_target(), model=model
                                )
                                if additional_rules is None:
                                    continue
                                else:
                                    return [rule.iptables_rule] + additional_rules
                else:
                    print(
                        "This shouldn't happen! Rule constraints are None for:",
                        rule.iptables_rule,
                    )
                s.reset()


class SolveTablesExpression:
    def __init__(self, expression: str, st: SolveTables):
        self.var_table = {
            "src_ip": st.src_ip_model,
            "dst_ip": st.dst_ip_model,
            "in_iface": st.input_interface_model,
            "out_iface": st.output_interface_model,
            "protocol": st.protocol_model,
            "src_port": st.src_port_model,
            "dst_port": st.dst_port_model,
            "state": st.state_model,
        }
        self.op_table = {
            "==": BitVecRef.__eq__,
            "!=": BitVecRef.__ne__,
            "<=": ULE,
            ">=": UGE,
            "<": ULT,
            ">": UGT,
        }
        self.concat_op_table = {
            "and": And,
            "or": Or,
        }

        expression = expression[0].split() if len(expression) == 1 else expression
        self.constraints = self._translate_expression(expression=expression)

    def get_constraints(self) -> BoolRef:
        return self.constraints

    def _translate_in_expression(self, operand1: str, operand2: str) -> BoolRef:
        if "," in operand2:
            values = operand2.split(",")
            sub_constraints = []
            for value in values:
                sub_constraints.append(
                    self._translate_expression_triple("==", operand1, value)
                )
            return Or(sub_constraints)
        elif ":" in operand2:
            min_val, max_val = operand2.split(":")
            sub_constraints = [
                self._translate_expression_triple(">=", operand1, min_val),
                self._translate_expression_triple("<=", operand1, max_val),
            ]
            return And(sub_constraints)
        elif "/" in operand2:
            assert operand1.endswith("_ip")
            ip_net = ipaddress.IPv4Network(operand2)
            sub_constraints = [
                self._translate_expression_triple(">=", operand1, ip_net[0]),
                self._translate_expression_triple("<=", operand1, ip_net[-1]),
            ]
            return And(sub_constraints)

    def _translate_expression_triple(self, operator, operand1, operand2):
        if operator == "in":
            sub_constraint = self._translate_in_expression(operand1, operand2)
        else:
            # assert operand1 in var_table.keys()
            top1 = self.var_table[operand1]

            # assert operator in op_table.keys()
            op = self.op_table[operator]

            match operand1.split("_"):
                case ["state"]:
                    top2 = Rule.STATE_ENUM.index(operand2)
                case ["protocol"]:
                    top2 = Rule.PROTOCOL_ENUM.index(operand2)
                case [_, "iface"]:
                    top2 = Rule._get_or_add_interface_index(operand2)
                case [_, "port"]:
                    top2 = int(operand2)
                case [_, "ip"]:
                    top2 = int(ipaddress.IPv4Address(operand2))
            sub_constraint = op(top1, top2)
        return sub_constraint

    def _translate_expression(self, expression: list[str]) -> Probe | BoolRef:
        constraints = None
        concat_op = None

        while len(expression) > 0:
            assert len(expression) >= 3

            operand1 = expression.pop(0)
            operator = expression.pop(0)
            operand2 = expression.pop(0)

            sub_constraint = self._translate_expression_triple(
                operator, operand1, operand2
            )
            if constraints is None:
                constraints = sub_constraint
            else:
                constraints = concat_op(constraints, sub_constraint)

            if len(expression) > 0:
                concat_operator = expression.pop(0)
                # assert concat_operator in concat_op_table.keys()
                concat_op = self.concat_op_table[concat_operator]
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
        if rule_line.startswith("-A "):
            st.add_rule(rule_line)

    expression = SolveTablesExpression(args.expression, st)
    additional_constraints = expression.get_constraints()
    model = st.check_and_get_model(chain=args.chain, constraints=additional_constraints)
    if model is not None:
        print("The identified model is:")
        print(model)
        print()
        print("Use the following parameters to create packet for desired effect:")
        translated_model = st.translate_model(model)
        for k, v in translated_model.items():
            print(f"  {k}: {v}")
        print()
        rules = st.identify_rule(chain=args.chain, model=model)
        if rules:
            print(
                "The iptabeles rule{} hit {}:".format(
                    "s" if len(rules) > 1 else "", "are" if len(rules) > 1 else "is"
                )
            )
            for rule in rules:
                print(rule)
        else:
            print("Something went wrong! Unable to identify associated rule /o\\")

    else:
        print("The provided constraints are not satisfiable.")


if __name__ == "__main__":
    main()
