import argparse
import ipaddress
import re
import shlex
from collections import defaultdict

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
    sport_group.add_argument("--not-sports", dest="not_sport")
    sport_group.add_argument("--not-sport")

    dport_group = parser.add_mutually_exclusive_group()
    dport_group.add_argument("--dport", default="0:65535")
    dport_group.add_argument("--dports", dest="dport")
    dport_group.add_argument("--not-dports", dest="not_dport")
    dport_group.add_argument("--not-dport")

    state_group = parser.add_mutually_exclusive_group()
    state_group.add_argument("--state")
    state_group.add_argument("--ctstate", dest="state")

    # parser.add_argument("-m", "--match")
    # parser.add_argument("--tcp-flags", nargs=2)
    # parser.add_argument("--icmp-type")
    # parser.add_argument("--set", action="store_true")
    # parser.add_argument("--name")
    # parser.add_argument("--mask")
    # parser.add_argument("--rsource", action="store_true")
    # parser.add_argument("--rcheck", action="store_true")
    # parser.add_argument("--seconds")
    # parser.add_argument("-f", "--fragment", action="store_true")
    # parser.add_argument("-c", "--set-counters")
    # parser.add_argument("--mark")
    # parser.add_argument("--not-mark")
    # parser.add_argument("--set-xmark")
    # parser.add_argument("--to-source")
    # parser.add_argument("--to-destination")
    # parser.add_argument("--src-type")
    # parser.add_argument("--dst-type")
    # parser.add_argument("--set-mss")
    # parser.add_argument("--limit")
    # parser.add_argument("--limit-burst")
    # parser.add_argument("--log-prefix")
    # parser.add_argument("--log-level")
    # parser.add_argument("--hashlimit-upto")
    # parser.add_argument("--hashlimit-burst")
    # parser.add_argument("--hashlimit-mode")
    # parser.add_argument("--hashlimit-name")
    # parser.add_argument("--hashlimit-htable-expire")
    # parser.add_argument("--remove", action="store_true")
    # parser.add_argument("--reject-with")
    # parser.add_argument("--comment")
    # parser.add_argument("--set-dscp")
    # parser.add_argument("--uid-owner")
    # parser.add_argument("--set-class")
    # parser.add_argument("--on-port")
    # parser.add_argument("--on-ip")
    # parser.add_argument("--tproxy-mark")
    # parser.add_argument("-n")
    # parser.add_argument("--u32")
    # parser.add_argument("--pkt-type")
    # parser.add_argument("--connlimit-above")
    # parser.add_argument("--connlimit-mask")
    return parser


def extract_interfaces(iptables_rules_file: str) -> set[str]:
    interfaces = set()
    parser = create_iptables_argparse()

    for rule_line in iptables_rules_file.splitlines():
        if rule_line.startswith("-A "):
            args, _ = parser.parse_known_args(shlex.split(rule_line))
            for arg in [
                "in_interface",
                "not_in_interface",
                "out_interface",
                "not_out_interface",
            ]:
                if args.__dict__[arg]:
                    interfaces.add(args.__dict__[arg])

    return interfaces


class Rule:
    PROTOCOL_ENUM = [
        "all",
        "tcp",
        "udp",
        "udplite",
        "icmp",
        "icmpv6",
        "igmp",
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
        self.constraints = None
        self.iptables_rule = rule
        rule = self._fix_not_rule(rule)
        self.args, unknown_args = self.IPTABLES_PARSER.parse_known_args(
            shlex.split(rule)
        )
        if unknown_args:
            print("Warning: Unhandled iptables arguments:", " ".join(unknown_args))

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
            constraints = [Or([Not(c) for c in constraints])]
        return constraints

    def _create_interface_constraints(
        self, var: BitVecRef, interface: str, invert: bool = False
    ) -> list[BoolRef]:
        constraints = []
        if interface is not None:
            if interface.endswith("*"):
                sub_constraints = []
                for i in self.INTERFACE_ENUM:
                    if i.startswith(interface.rstrip("*")):
                        constraint = var == self._get_or_add_interface_index(i)
                        if invert:
                            constraint = Not(constraint)
                        sub_constraints.append(constraint)
                constraints = [And(sub_constraints) if invert else Or(sub_constraints)]
            else:
                constraint = var == self._get_or_add_interface_index(interface)
                if invert:
                    constraint = Not(constraint)
                constraints = [constraint]
        return constraints

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

    def _create_port_constraints(
        self, var: BitVecRef, port: str, invert: bool = False
    ) -> list[BoolRef]:
        ports = [port]
        constraints = []
        if "," in port:
            ports = port.split(",")
        for port in ports:
            if ":" in port:
                port_range = port.split(":")
                port_min = int(port_range[0])
                port_max = int(port_range[-1])
                if invert:
                    constraints.append(Or(ULT(var, port_min), ULT(port_max, var)))
                else:
                    constraints.append(ULE(port_min, var))
                    constraints.append(ULE(var, port_max))
            else:
                constraint = var == int(port)
                if invert:
                    constraint = Not(constraint)
                constraints.append(constraint)
        return constraints

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
        if self.args.not_destination:
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
        if self.args.not_sport:
            sub_constraints += self._create_port_constraints(
                st.src_port_model, self.args.not_sport, invert=True
            )
        else:
            sub_constraints += self._create_port_constraints(
                st.src_port_model, self.args.sport
            )
        if self.args.not_dport:
            sub_constraints += self._create_port_constraints(
                st.dst_port_model, self.args.not_dport, invert=True
            )
        else:
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


class Chain:
    BASE_CHAINS: dict[str, BoolRef] = {
        "ACCEPT": BoolVal(True),
        "DROP": BoolVal(False),
        "REJECT": BoolVal(False),
        "RETURN": BoolVal(True),
    }

    def __init__(self, name: str, rules: list[Rule]) -> None:
        self.name: str = name
        self.rules: list[Rule] = rules
        self._post_conditions: list[BoolRef] | None = None
        self._inner_constraints: list[BoolRef] | None = None
        if name in self.BASE_CHAINS:
            self._inner_constraints = [self.BASE_CHAINS[name]]
            self._post_conditions = []

    def get_inner_constraints(self, solve_tables: "SolveTables") -> list[BoolRef]:
        if self._inner_constraints is None:
            self._generate_conditions_and_constraints(solve_tables)
        return self._inner_constraints

    def get_post_conditions(self, solve_tables: "SolveTables") -> list[BoolRef]:
        if self._post_conditions is None:
            self._generate_conditions_and_constraints(solve_tables)
        return self._post_conditions

    def _generate_conditions_and_constraints(self, solve_tables: "SolveTables"):
        inner_constraints = []
        # Create default pre-condition as False, so that Or'ing result is not changed
        # (necessary for empty chains)
        pre_conditions = [BoolVal(False)]
        internal_preconditions = []
        for rule in self.rules:
            target: str = rule.get_target()
            rule_constraints = rule.get_constraints(solve_tables)
            new_preconditions = []
            if rule_constraints is not None:
                target_chain: Chain = solve_tables.chains[target]
                if target not in ["DROP", "REJECT", "RETURN"]:
                    target_inner_constraints = target_chain.get_inner_constraints(
                        solve_tables
                    )
                    inner_constraints.append(
                        And(
                            Not(Or(pre_conditions + internal_preconditions)),
                            rule_constraints,
                            Or(target_inner_constraints),
                        )
                    )
                if target == "RETURN":
                    internal_preconditions.append(rule_constraints)
                else:
                    new_preconditions.append(rule_constraints)
                    target_post_conditions = target_chain.get_post_conditions(
                        solve_tables
                    )
                    if len(target_post_conditions) > 0:
                        new_preconditions.append(Or(target_post_conditions))
                    # Make sure previous "RETURN"s are taken into account
                    if len(internal_preconditions) > 0:
                        new_preconditions.append(Not(Or(internal_preconditions)))
                    pre_conditions.append(And(new_preconditions))
        self._inner_constraints = inner_constraints
        self._post_conditions = pre_conditions


class SolveTables:
    def __init__(
        self,
        default_policy: str,
        rules: list[str],
        initial_interfaces: list[str] = [],
    ) -> None:
        self.reset_rules()
        self.accept_default = default_policy == "ACCEPT"
        self.initial_interfaces = initial_interfaces
        for interface in initial_interfaces:
            Rule._get_or_add_interface_index(interface)
        self.chains = self._init_chains(rules)
        self.src_ip_model: BitVecRef = BitVec("src_ip_model", 32)
        self.dst_ip_model: BitVecRef = BitVec("dst_ip_model", 32)
        self.input_interface_model: BitVecRef = BitVec("input_interface_model", 8)
        self.output_interface_model: BitVecRef = BitVec("output_interface_model", 8)
        self.protocol_model: BitVecRef = BitVec("protocol_model", 4)
        self.src_port_model: BitVecRef = BitVec("src_port_model", 16)
        self.dst_port_model: BitVecRef = BitVec("dst_port_model", 16)
        self.state_model: BitVecRef = BitVec("state_model", 4)

    def reset_rules(self):
        Rule.INTERFACE_ENUM = []

    def _init_chains(self, rules: list[str]) -> dict[str, Chain]:
        chains = defaultdict(lambda: Chain("UNDEFINED", []))
        for name in Chain.BASE_CHAINS.keys():
            chains[name] = Chain(name, [])
        chain_rules = defaultdict(list)
        for rule in rules:
            new_rule = Rule(rule)
            chain_rules[new_rule.get_chain()].append(new_rule)
        for chain_name, rules_list in chain_rules.items():
            chains[chain_name] = Chain(chain_name, rules_list)
        return chains

    def _get_base_constraints(self) -> Probe | BoolRef:
        if len(Rule.INTERFACE_ENUM) == 0:
            Rule._get_or_add_interface_index("any")
        base_rules = And(
            ULT(self.protocol_model, len(Rule.PROTOCOL_ENUM)),
            ULT(self.input_interface_model, len(Rule.INTERFACE_ENUM)),
            ULT(self.output_interface_model, len(Rule.INTERFACE_ENUM)),
            ULT(self.state_model, len(Rule.STATE_ENUM)),
            # ULE(0, self.src_ip_model),
            # ULE(self.src_ip_model, 4294967295),
            # ULE(0, self.dst_ip_model),
            # ULE(self.dst_ip_model, 4294967295),
            # ULE(0, self.src_port_model),
            # ULE(self.src_port_model, 65535),
            # ULE(0, self.dst_port_model),
            # ULE(self.dst_port_model, 65535),
        )
        return base_rules

    def build_constraints(self, chain_name: str) -> Probe | BoolRef:
        # print("self.constraints:", self.constraints)
        # chain_constraints = self.get_chain_constraints(chain=chain, add_default=True)
        chain = self.chains[chain_name]
        chain_constraints = chain.get_inner_constraints(self)
        # Add handling of default ACCEPT target
        if self.accept_default:
            chain_constraints.append(Not(Or(chain.get_post_conditions(self))))
        base_rules = self._get_base_constraints()

        combined_constraints = And(Or(chain_constraints), base_rules)
        # return combined_constraints
        return combined_constraints
        # return simplify(combined_constraints)

    def check_and_get_model(
        self, chain: str, constraints: None | BoolRef
    ) -> None | ModelRef:
        m = None
        s = Solver()
        rules = self.build_constraints(chain)
        # print("final constraints:")
        # print(And(constraints, rules))
        s.add(rules)
        if constraints is not None:
            s.add(constraints)
        # print(s.sexpr())
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

    def identify_rule_from_model(
        self, chain: str, model: ModelRef
    ) -> None | list[Rule]:
        model_constraints_list = []
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
                model_constraints_list.append(var == model[var])
        model_constraints = And(model_constraints_list)
        return self.identify_rule(chain=chain, constraints=model_constraints)

    def identify_rule(self, chain: str, constraints: BoolRef) -> None | list[Rule]:
        hit_rules = []
        s = Solver()
        for rule in self.chains[chain].rules:
            rule_constraints = rule.get_constraints(self)
            if rule_constraints is not None:
                all_constraints = simplify(
                    And(rule_constraints, self._get_base_constraints(), constraints)
                )
                s.add(all_constraints)
                if s.check() == sat:
                    hit_rules.append(rule)
                    match rule.get_target():
                        case "ACCEPT" | "RETURN":
                            return hit_rules
                        case "DROP" | "REJECT":
                            print(
                                "You should never see this, please report your parameters."
                            )
                            print(f"Hit {rule.get_target()} rule:")
                            print(f"  {rule.iptables_rule}")
                            return hit_rules
                        case _:
                            additional_rules = self.identify_rule(
                                chain=rule.get_target(), constraints=constraints
                            )
                            if additional_rules is not None:
                                hit_rules += additional_rules
                                if additional_rules[-1].get_target() != "RETURN":
                                    return hit_rules
            else:
                print(
                    "This shouldn't happen! Rule constraints are None for:",
                    rule.iptables_rule,
                )
            s.reset()


class SolveTablesExpression:
    def __init__(self, expression: str | list[str], st: SolveTables):
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

        if isinstance(expression, str):
            expression = [expression]
        expression = expression[0].split() if len(expression) == 1 else expression
        self.constraints = self._translate_expression(expression=expression)

    def get_constraints(self) -> None | BoolRef:
        return self.constraints

    def _translate_in_expression(
        self, operand1: str, operand2: str, negate: bool = False
    ) -> BoolRef:
        if "," in operand2:
            values = operand2.split(",")
            sub_constraints = []
            operator = "!=" if negate else "=="
            conjunction = And if negate else Or
            for value in values:
                sub_constraints.append(
                    self._translate_expression_triple(operator, operand1, value)
                )
            return conjunction(sub_constraints)
        elif ":" in operand2:
            min_val, max_val = operand2.split(":")
            if negate:
                sub_constraints = Or(
                    self._translate_expression_triple("<", operand1, min_val),
                    self._translate_expression_triple(">", operand1, max_val),
                )
            else:
                sub_constraints = And(
                    self._translate_expression_triple(">=", operand1, min_val),
                    self._translate_expression_triple("<=", operand1, max_val),
                )
            return sub_constraints
        elif "/" in operand2:
            assert operand1.endswith("_ip")
            ip_net = ipaddress.IPv4Network(operand2)
            if negate:
                sub_constraints = Or(
                    self._translate_expression_triple("<", operand1, ip_net[0]),
                    self._translate_expression_triple(">", operand1, ip_net[-1]),
                )
            else:
                sub_constraints = And(
                    self._translate_expression_triple(">=", operand1, ip_net[0]),
                    self._translate_expression_triple("<=", operand1, ip_net[-1]),
                )
            return sub_constraints

    def _translate_expression_triple(self, operator, operand1, operand2):
        if operator in ["in", "!in"]:
            sub_constraint = self._translate_in_expression(
                operand1, operand2, negate=operator == "!in"
            )
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

    def _translate_expression(self, expression: list[str]) -> None | BoolRef:
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
    parser.add_argument(
        "-i",
        "--interfaces",
        default=[],
        type=lambda x: [i.strip() for i in x.split(",")],
        help="List of interfaces to explicitly add. NOTE: Interfaces no in the iptables rules need to be defined here or they will not be considered.",
    )
    parser.add_argument("chain", choices=["INPUT", "FORWARD", "OUTPUT"])
    parser.add_argument("iptables_save_log", type=argparse.FileType("r"))
    parser.add_argument("expression", nargs="+")
    args = parser.parse_args()

    iptables_rules_file = args.iptables_save_log.read()

    default_policy = args.default_policy
    if default_policy is None:
        match = re.search(
            f"^:{args.chain}\\s+(?P<default_policy>(ACCEPT|DROP|REJECT))",
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

    interfaces = extract_interfaces(iptables_rules_file)
    if args.interfaces:
        interfaces.update(args.interfaces)
    interfaces = list(interfaces)

    rules: list[str] = []
    for rule_line in iptables_rules_file.splitlines():
        if rule_line.startswith("-A "):
            rules.append(rule_line)

    st = SolveTables(
        default_policy=default_policy, rules=rules, initial_interfaces=interfaces
    )

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
        rules = st.identify_rule_from_model(chain=args.chain, model=model)
        if rules:
            print(
                "The iptabeles rule{} hit {}:".format(
                    "s" if len(rules) > 1 else "", "are" if len(rules) > 1 else "is"
                )
            )
            for rule in rules:
                print(rule.iptables_rule)
        else:
            print("Something went wrong! Unable to identify associated rule /o\\")

    else:
        print("The provided constraints are not satisfiable.")


if __name__ == "__main__":
    main()
