import ipaddress
import pytest
from solvetables import SolveTables, SolveTablesExpression

# TODO: Add explicit model result where known


class BaseTest:
    DEFAULT_POLICY = "DROP"
    IPTABLES_RULES = []

    @pytest.fixture
    def st(self) -> SolveTables:
        rules = []
        for rule in self.IPTABLES_RULES:
            rules.append(rule)
        st = SolveTables(default_policy=self.DEFAULT_POLICY, rules=rules)
        return st


class TestDefaultAccept(BaseTest):
    DEFAULT_POLICY = "ACCEPT"
    IPTABLES_RULES = ["-A INPUT -i eth0 -j DROP"]

    def test_input_drop(self, st: SolveTables):
        additional_constraints = SolveTablesExpression(
            "in_iface == eth0", st
        ).get_constraints()
        model = st.check_and_get_model(
            chain="INPUT", constraints=additional_constraints
        )
        assert model is None

    def test_input_default_out(self, st: SolveTables):
        additional_constraints = SolveTablesExpression(
            "out_iface == eth1", st
        ).get_constraints()
        model = st.check_and_get_model(
            chain="INPUT", constraints=additional_constraints
        )
        assert model is not None

        model_dict = st.translate_model(model)
        assert model_dict["output_interface"] == "eth1"
        assert model_dict["input_interface"] != "eth0"

        rules = st.identify_rule_from_model(chain="INPUT", model=model)
        assert rules is None

    def test_input_default_in(self, st: SolveTables):
        additional_constraints = SolveTablesExpression(
            "in_iface == eth1", st
        ).get_constraints()
        model = st.check_and_get_model(
            chain="INPUT", constraints=additional_constraints
        )
        assert model is not None

        model_dict = st.translate_model(model)
        assert model_dict["input_interface"] == "eth1"


class TestDefaultDrop(BaseTest):
    DEFAULT_POLICY = "DROP"
    IPTABLES_RULES = ["-A INPUT -i eth0 -j ACCEPT"]

    def test_input_accept(self, st: SolveTables):
        additional_constraints = SolveTablesExpression(
            "in_iface == eth0", st
        ).get_constraints()
        model = st.check_and_get_model(
            chain="INPUT", constraints=additional_constraints
        )
        assert model is not None

        model_dict = st.translate_model(model)
        assert model_dict["input_interface"] == "eth0"

        rules = st.identify_rule_from_model(chain="INPUT", model=model)
        assert rules is not None
        assert len(rules) == 1
        assert rules[0].iptables_rule == self.IPTABLES_RULES[0]

    def test_input_default_out(self, st: SolveTables):
        additional_constraints = SolveTablesExpression(
            "out_iface == eth1", st
        ).get_constraints()
        model = st.check_and_get_model(
            chain="INPUT", constraints=additional_constraints
        )
        assert model is not None

        model_dict = st.translate_model(model)
        assert model_dict["input_interface"] == "eth0"
        assert model_dict["output_interface"] == "eth1"

        rules = st.identify_rule_from_model(chain="INPUT", model=model)
        assert rules is not None
        assert len(rules) == 1
        assert rules[0].iptables_rule == self.IPTABLES_RULES[0]

    def test_input_default_in(self, st: SolveTables):
        additional_constraints = SolveTablesExpression(
            "in_iface == eth1", st
        ).get_constraints()
        model = st.check_and_get_model(
            chain="INPUT", constraints=additional_constraints
        )
        assert model is None


class TestIndirection(BaseTest):
    DEFAULT_POLICY = "DROP"
    IPTABLES_RULES = ["-A FORWARD -i eth2 -j INDI", "-A INDI -o eth1 -j ACCEPT"]

    def test_indirection_exact(self, st: SolveTables):
        additional_constraints = SolveTablesExpression(
            "in_iface == eth2 and out_iface == eth1", st
        ).get_constraints()
        model = st.check_and_get_model(
            chain="FORWARD", constraints=additional_constraints
        )
        assert model is not None

        model_dict = st.translate_model(model)
        assert model_dict["input_interface"] == "eth2"
        assert model_dict["output_interface"] == "eth1"

        rules = st.identify_rule_from_model(chain="FORWARD", model=model)
        assert rules is not None
        assert len(rules) == 2
        assert rules[0].iptables_rule == self.IPTABLES_RULES[0]
        assert rules[1].iptables_rule == self.IPTABLES_RULES[1]

    def test_indirection_first(self, st: SolveTables):
        additional_constraints = SolveTablesExpression(
            "in_iface == eth2", st
        ).get_constraints()
        model = st.check_and_get_model(
            chain="FORWARD", constraints=additional_constraints
        )
        assert model is not None

        model_dict = st.translate_model(model)
        assert model_dict["input_interface"] == "eth2"
        assert model_dict["output_interface"] == "eth1"

        rules = st.identify_rule_from_model(chain="FORWARD", model=model)
        assert rules is not None
        assert len(rules) == 2
        assert rules[0].iptables_rule == self.IPTABLES_RULES[0]
        assert rules[1].iptables_rule == self.IPTABLES_RULES[1]

    def test_indirection_last(self, st: SolveTables):
        additional_constraints = SolveTablesExpression(
            "out_iface == eth1", st
        ).get_constraints()
        model = st.check_and_get_model(
            chain="FORWARD", constraints=additional_constraints
        )
        assert model is not None

        model_dict = st.translate_model(model)
        assert model_dict["input_interface"] == "eth2"
        assert model_dict["output_interface"] == "eth1"

        rules = st.identify_rule_from_model(chain="FORWARD", model=model)
        assert rules is not None
        assert len(rules) == 2
        assert rules[0].iptables_rule == self.IPTABLES_RULES[0]
        assert rules[1].iptables_rule == self.IPTABLES_RULES[1]

    def test_indirection_inverse(self, st: SolveTables):
        additional_constraints = SolveTablesExpression(
            "in_iface == eth1 and out_iface == eth2", st
        ).get_constraints()
        model = st.check_and_get_model(
            chain="FORWARD", constraints=additional_constraints
        )
        assert model is None

    def test_indirection_inverse_first(self, st: SolveTables):
        additional_constraints = SolveTablesExpression(
            "in_iface == eth1", st
        ).get_constraints()
        model = st.check_and_get_model(
            chain="FORWARD", constraints=additional_constraints
        )
        assert model is None

    def test_indirection_inverse_last(self, st: SolveTables):
        additional_constraints = SolveTablesExpression(
            "out_iface == eth2", st
        ).get_constraints()
        model = st.check_and_get_model(
            chain="FORWARD", constraints=additional_constraints
        )
        assert model is None


class TestExplicitDrop(BaseTest):
    DEFAULT_POLICY = "DROP"
    IPTABLES_RULES = ["-A FORWARD -i eth0 -j DROP", "-A FORWARD -o eth1 -j ACCEPT"]

    def test_explicit_drop_hit(self, st: SolveTables):
        additional_constraints = SolveTablesExpression(
            "in_iface == eth0", st
        ).get_constraints()
        model = st.check_and_get_model(
            chain="FORWARD", constraints=additional_constraints
        )
        assert model is None

    def test_explicit_drop_not_hit(self, st: SolveTables):
        additional_constraints = SolveTablesExpression(
            "in_iface == eth1", st
        ).get_constraints()
        model = st.check_and_get_model(
            chain="FORWARD", constraints=additional_constraints
        )
        assert model is not None

        model_dict = st.translate_model(model)
        assert model_dict["input_interface"] == "eth1"
        assert model_dict["output_interface"] == "eth1"

        rules = st.identify_rule_from_model(chain="FORWARD", model=model)
        assert rules is not None
        assert len(rules) == 1
        assert rules[0].iptables_rule == self.IPTABLES_RULES[1]

    def test_explicit_drop_hit_accept(self, st: SolveTables):
        additional_constraints = SolveTablesExpression(
            "out_iface == eth1", st
        ).get_constraints()
        model = st.check_and_get_model(
            chain="FORWARD", constraints=additional_constraints
        )
        assert model is not None

        model_dict = st.translate_model(model)
        assert model_dict["input_interface"] != "eth0"
        assert model_dict["output_interface"] == "eth1"

        rules = st.identify_rule_from_model(chain="FORWARD", model=model)
        assert rules is not None
        assert len(rules) == 1
        assert rules[0].iptables_rule == self.IPTABLES_RULES[1]

    def test_explicit_drop_hit_default(self, st: SolveTables):
        additional_constraints = SolveTablesExpression(
            "in_iface == eth1 and out_iface == eth0", st
        ).get_constraints()
        model = st.check_and_get_model(
            chain="FORWARD", constraints=additional_constraints
        )
        assert model is None


class TestInputChain(BaseTest):
    DEFAULT_POLICY = "DROP"
    IPTABLES_RULES = [
        "-A INPUT -s 192.168.4.0/24 -d 192.168.4.1/32 -i eth1 -p tcp -m tcp --dport 443 -j ACCEPT",
        "-A INPUT -s 192.168.4.0/24 -d 192.168.4.1/32 -i eth1 -p tcp -m tcp --sport 22 -j ACCEPT",
        "-A INPUT -s 192.168.14.0/24 -d 192.168.14.1/32 -i eth0 -p tcp -m tcp --sport 1024:65535 --dport 20:21 -j ACCEPT",
    ]

    def test_hit_implicit_sport(self, st: SolveTables):
        additional_constraints = SolveTablesExpression(
            "in_iface == eth1 and dst_port == 80", st
        ).get_constraints()
        model = st.check_and_get_model(
            chain="INPUT", constraints=additional_constraints
        )
        assert model is not None

        model_dict = st.translate_model(model)
        assert model_dict["input_interface"] == "eth1"
        assert model_dict["dst_port"] == 80
        assert model_dict["src_port"] == 22
        src_ip_net = ipaddress.IPv4Network("192.168.4.0/24")
        assert model_dict["src_ip"] in src_ip_net
        dst_ip_net = ipaddress.IPv4Network("192.168.4.1/32")
        assert model_dict["dst_ip"] in dst_ip_net

        rules = st.identify_rule_from_model(chain="INPUT", model=model)
        assert rules is not None
        assert len(rules) == 1
        assert rules[0].iptables_rule == self.IPTABLES_RULES[1]

    def test_hit_not_ip(self, st: SolveTables):
        additional_constraints = SolveTablesExpression(
            "dst_ip != 192.168.4.1", st
        ).get_constraints()
        model = st.check_and_get_model(
            chain="INPUT", constraints=additional_constraints
        )
        assert model is not None

        model_dict = st.translate_model(model)
        assert model_dict["input_interface"] == "eth0"
        assert model_dict["dst_port"] in range(20, 22)
        assert model_dict["src_port"] in range(1024, 65536)
        src_ip_net = ipaddress.IPv4Network("192.168.14.0/24")
        assert model_dict["src_ip"] in src_ip_net
        dst_ip_net = ipaddress.IPv4Network("192.168.14.1/32")
        assert model_dict["dst_ip"] in dst_ip_net

        rules = st.identify_rule_from_model(chain="INPUT", model=model)
        assert rules is not None
        assert len(rules) == 1
        assert rules[0].iptables_rule == self.IPTABLES_RULES[2]

    def test_in_expression_cidr(self, st: SolveTables):
        additional_constraints = SolveTablesExpression(
            "src_ip in 192.168.14.32/30", st
        ).get_constraints()
        model = st.check_and_get_model(
            chain="INPUT", constraints=additional_constraints
        )
        assert model is not None

        model_dict = st.translate_model(model)
        assert model_dict["input_interface"] == "eth0"
        assert model_dict["dst_port"] in range(20, 22)
        assert model_dict["src_port"] in range(1024, 65536)
        src_ip_net = ipaddress.IPv4Network("192.168.14.32/30")
        assert model_dict["src_ip"] in src_ip_net
        dst_ip_net = ipaddress.IPv4Network("192.168.14.1/32")
        assert model_dict["dst_ip"] in dst_ip_net

        rules = st.identify_rule_from_model(chain="INPUT", model=model)
        assert rules is not None
        assert len(rules) == 1
        assert rules[0].iptables_rule == self.IPTABLES_RULES[2]

    def test_notin_expression_cidr(self, st: SolveTables):
        additional_constraints = SolveTablesExpression(
            "in_iface == eth0 and src_ip !in 192.168.14.0/25", st
        ).get_constraints()
        model = st.check_and_get_model(
            chain="INPUT", constraints=additional_constraints
        )
        assert model is not None

        model_dict = st.translate_model(model)
        assert model_dict["input_interface"] == "eth0"
        assert model_dict["dst_port"] in range(20, 22)
        assert model_dict["src_port"] in range(1024, 65536)
        src_ip_net = ipaddress.IPv4Network("192.168.14.128/25")
        assert model_dict["src_ip"] in src_ip_net
        dst_ip_net = ipaddress.IPv4Network("192.168.14.1/32")
        assert model_dict["dst_ip"] in dst_ip_net

        rules = st.identify_rule_from_model(chain="INPUT", model=model)
        assert rules is not None
        assert len(rules) == 1
        assert rules[0].iptables_rule == self.IPTABLES_RULES[2]

    def test_in_expression_range_ip(self, st: SolveTables):
        additional_constraints = SolveTablesExpression(
            "src_ip in 192.168.14.32:192.168.14.40", st
        ).get_constraints()
        model = st.check_and_get_model(
            chain="INPUT", constraints=additional_constraints
        )
        assert model is not None

        model_dict = st.translate_model(model)
        assert model_dict["input_interface"] == "eth0"
        assert model_dict["dst_port"] in range(20, 22)
        assert model_dict["src_port"] in range(1024, 65536)
        assert model_dict["src_ip"] >= ipaddress.IPv4Address("192.168.14.32")
        assert model_dict["src_ip"] <= ipaddress.IPv4Address("192.168.14.40")
        dst_ip_net = ipaddress.IPv4Network("192.168.14.1/32")
        assert model_dict["dst_ip"] in dst_ip_net

        rules = st.identify_rule_from_model(chain="INPUT", model=model)
        assert rules is not None
        assert len(rules) == 1
        assert rules[0].iptables_rule == self.IPTABLES_RULES[2]

    def test_in_expression_list_ip(self, st: SolveTables):
        additional_constraints = SolveTablesExpression(
            "src_ip in 192.168.14.32,192.168.14.40", st
        ).get_constraints()
        model = st.check_and_get_model(
            chain="INPUT", constraints=additional_constraints
        )
        assert model is not None

        model_dict = st.translate_model(model)
        assert model_dict["input_interface"] == "eth0"
        assert model_dict["dst_port"] in range(20, 22)
        assert model_dict["src_port"] in range(1024, 65536)
        assert model_dict["src_ip"] in [
            ipaddress.IPv4Address("192.168.14.32"),
            ipaddress.IPv4Address("192.168.14.40"),
        ]
        dst_ip_net = ipaddress.IPv4Network("192.168.14.1/32")
        assert model_dict["dst_ip"] in dst_ip_net

        rules = st.identify_rule_from_model(chain="INPUT", model=model)
        assert rules is not None
        assert len(rules) == 1
        assert rules[0].iptables_rule == self.IPTABLES_RULES[2]

    def test_in_expression_list_port(self, st: SolveTables):
        additional_constraints = SolveTablesExpression(
            "src_ip in 192.168.14.32/30 and dst_port >= 21 and src_port in 6000,7000,8000",
            st,
        ).get_constraints()
        model = st.check_and_get_model(
            chain="INPUT", constraints=additional_constraints
        )
        assert model is not None

        model_dict = st.translate_model(model)
        assert model_dict["input_interface"] == "eth0"
        assert model_dict["dst_port"] == 21
        assert model_dict["src_port"] in [6000, 7000, 8000]
        src_ip_net = ipaddress.IPv4Network("192.168.14.0/24")
        assert model_dict["src_ip"] in src_ip_net
        dst_ip_net = ipaddress.IPv4Network("192.168.14.1/32")
        assert model_dict["dst_ip"] in dst_ip_net

        rules = st.identify_rule_from_model(chain="INPUT", model=model)
        assert rules is not None
        assert len(rules) == 1
        assert rules[0].iptables_rule == self.IPTABLES_RULES[2]

    def test_in_expression_range_port(self, st: SolveTables):
        additional_constraints = SolveTablesExpression(
            "in_iface == eth0 and dst_port in 1:100 and src_port in 1000:2000", st
        ).get_constraints()
        model = st.check_and_get_model(
            chain="INPUT", constraints=additional_constraints
        )
        assert model is not None

        model_dict = st.translate_model(model)
        assert model_dict["input_interface"] == "eth0"
        assert model_dict["dst_port"] in range(20, 22)
        assert model_dict["src_port"] in range(1024, 2001)
        src_ip_net = ipaddress.IPv4Network("192.168.14.0/24")
        assert model_dict["src_ip"] in src_ip_net
        dst_ip_net = ipaddress.IPv4Network("192.168.14.1/32")
        assert model_dict["dst_ip"] in dst_ip_net

        rules = st.identify_rule_from_model(chain="INPUT", model=model)
        assert rules is not None
        assert len(rules) == 1
        assert rules[0].iptables_rule == self.IPTABLES_RULES[2]

    def test_notin_expression_list_port(self, st: SolveTables):
        additional_constraints = SolveTablesExpression(
            "src_ip in 192.168.14.32/30 and dst_port !in 20,22,24 and src_port !in 6000,7000,8000",
            st,
        ).get_constraints()
        model = st.check_and_get_model(
            chain="INPUT", constraints=additional_constraints
        )
        assert model is not None

        model_dict = st.translate_model(model)
        assert model_dict["input_interface"] == "eth0"
        assert model_dict["dst_port"] == 21
        assert model_dict["src_port"] not in [6000, 7000, 8000]
        assert model_dict["src_port"] in range(1024, 65536)
        src_ip_net = ipaddress.IPv4Network("192.168.14.0/24")
        assert model_dict["src_ip"] in src_ip_net
        dst_ip_net = ipaddress.IPv4Network("192.168.14.1/32")
        assert model_dict["dst_ip"] in dst_ip_net

        rules = st.identify_rule_from_model(chain="INPUT", model=model)
        assert rules is not None
        assert len(rules) == 1
        assert rules[0].iptables_rule == self.IPTABLES_RULES[2]

    def test_notin_expression_range_port(self, st: SolveTables):
        additional_constraints = SolveTablesExpression(
            "in_iface == eth0 and dst_port !in 21:100 and src_port !in 1000:2000", st
        ).get_constraints()
        model = st.check_and_get_model(
            chain="INPUT", constraints=additional_constraints
        )
        assert model is not None

        model_dict = st.translate_model(model)
        assert model_dict["input_interface"] == "eth0"
        assert model_dict["dst_port"] == 20
        assert model_dict["src_port"] in range(2001, 65536)
        src_ip_net = ipaddress.IPv4Network("192.168.14.0/24")
        assert model_dict["src_ip"] in src_ip_net
        dst_ip_net = ipaddress.IPv4Network("192.168.14.1/32")
        assert model_dict["dst_ip"] in dst_ip_net

        rules = st.identify_rule_from_model(chain="INPUT", model=model)
        assert rules is not None
        assert len(rules) == 1
        assert rules[0].iptables_rule == self.IPTABLES_RULES[2]


class TestReturnChain(BaseTest):
    DEFAULT_POLICY = "DROP"
    IPTABLES_RULES = [
        "-A INPUT -s 0.0.0.0/0 -d 0.0.0.0/0 -j DOS_PROTECT",
        "-A INPUT -s 0.0.0.0/0 -d 0.0.0.0/0 -p tcp -m tcp --dport 22 -j DROP",
        "-A INPUT -p tcp -s 192.168.0.0/16 -d 192.168.0.0/16 -j ACCEPT",
        "-A DOS_PROTECT -p tcp -s 0.0.0.0/0 -d 0.0.0.0/0 -m tcp --tcp-flags RST RST -m hashlimit --hashlimit-upto 1/sec --hashlimit-burst 5 -j RETURN",
        "-A DOS_PROTECT -p tcp -s 0.0.0.0/0 -d 0.0.0.0/0 -m tcp --tcp-flags RST RST -j DROP",
        "-A DOS_PROTECT -p tcp -s 0.0.0.0/0 -d 0.0.0.0/0 -j ACCEPT",
    ]

    def test_hit_return_no_constraints(self, st: SolveTables):
        additional_constraints = SolveTablesExpression("", st).get_constraints()
        model = st.check_and_get_model(
            chain="INPUT", constraints=additional_constraints
        )
        assert model is not None

        model_dict = st.translate_model(model)
        assert model_dict["src_port"] != 22
        src_ip_net = ipaddress.IPv4Network("192.168.0.0/16")
        assert model_dict["src_ip"] in src_ip_net
        dst_ip_net = ipaddress.IPv4Network("192.168.0.0/16")
        assert model_dict["dst_ip"] in dst_ip_net
        assert model_dict["protocol"] == "tcp"

        rules = st.identify_rule_from_model(chain="INPUT", model=model)
        assert rules is not None
        assert len(rules) == 3
        assert rules[0].iptables_rule == self.IPTABLES_RULES[0]
        assert rules[1].iptables_rule == self.IPTABLES_RULES[3]
        assert rules[2].iptables_rule == self.IPTABLES_RULES[2]

    def test_hit_return(self, st: SolveTables):
        additional_constraints = SolveTablesExpression(
            "in_iface == eth1 and dst_port == 80", st
        ).get_constraints()
        model = st.check_and_get_model(
            chain="INPUT", constraints=additional_constraints
        )
        assert model is not None

        model_dict = st.translate_model(model)
        assert model_dict["input_interface"] == "eth1"
        assert model_dict["dst_port"] == 80
        assert model_dict["src_port"] != 22
        src_ip_net = ipaddress.IPv4Network("192.168.0.0/16")
        assert model_dict["src_ip"] in src_ip_net
        dst_ip_net = ipaddress.IPv4Network("192.168.0.0/16")
        assert model_dict["dst_ip"] in dst_ip_net

        rules = st.identify_rule_from_model(chain="INPUT", model=model)
        assert rules is not None
        assert len(rules) == 3
        assert rules[0].iptables_rule == self.IPTABLES_RULES[0]
        assert rules[1].iptables_rule == self.IPTABLES_RULES[3]
        assert rules[2].iptables_rule == self.IPTABLES_RULES[2]

    def test_hit_drop_after(self, st: SolveTables):
        additional_constraints = SolveTablesExpression(
            "in_iface == eth1 and dst_port == 22 and protocol == tcp and src_ip == 192.168.1.1",
            st,
        ).get_constraints()
        model = st.check_and_get_model(
            chain="INPUT", constraints=additional_constraints
        )
        assert model is None

    def test_return_hit_default_protocol(self, st: SolveTables):
        additional_constraints = SolveTablesExpression(
            "protocol in icmp,udp", st
        ).get_constraints()
        model = st.check_and_get_model(
            chain="INPUT", constraints=additional_constraints
        )
        assert model is None


class TestEmptyChainDropDefault(BaseTest):
    DEFAULT_POLICY = "DROP"
    IPTABLES_RULES = [
        "-A INPUT -j FIRST",
    ]

    def test_no_constraints(self, st: SolveTables):
        additional_constraints = SolveTablesExpression("", st).get_constraints()
        model = st.check_and_get_model(
            chain="INPUT", constraints=additional_constraints
        )
        assert model is None


class TestEmptyChainAcceptDefault(BaseTest):
    DEFAULT_POLICY = "ACCEPT"
    IPTABLES_RULES = [
        "-A INPUT -j FIRST",
    ]

    def test_no_constraints(self, st: SolveTables):
        additional_constraints = SolveTablesExpression("", st).get_constraints()
        model = st.check_and_get_model(
            chain="INPUT", constraints=additional_constraints
        )
        assert model is not None


class TestEmptyChainAcceptDefaultDropRule(BaseTest):
    DEFAULT_POLICY = "ACCEPT"
    IPTABLES_RULES = [
        "-A INPUT -j FIRST",
        "-A INPUT -j DROP",
    ]

    def test_no_constraints(self, st: SolveTables):
        additional_constraints = SolveTablesExpression("", st).get_constraints()
        model = st.check_and_get_model(
            chain="INPUT", constraints=additional_constraints
        )
        assert model is None


class TestEmptyChainDropDefaultAcceptRule(BaseTest):
    DEFAULT_POLICY = "DROP"
    IPTABLES_RULES = [
        "-A INPUT -j FIRST",
        "-A INPUT -j ACCEPT",
    ]

    def test_no_constraints(self, st: SolveTables):
        additional_constraints = SolveTablesExpression("", st).get_constraints()
        model = st.check_and_get_model(
            chain="INPUT", constraints=additional_constraints
        )
        assert model is not None


class TestDropChainAcceptDefault(BaseTest):
    DEFAULT_POLICY = "ACCEPT"
    IPTABLES_RULES = [
        "-A INPUT -j FIRST",
        "-A FIRST -j DROP",
    ]

    def test_no_constraints(self, st: SolveTables):
        additional_constraints = SolveTablesExpression("", st).get_constraints()
        model = st.check_and_get_model(
            chain="INPUT", constraints=additional_constraints
        )
        # print(st.translate_model(model))
        # print("interfaces:", st.chain_rules["INPUT"][0].INTERFACE_ENUM)
        assert model is None

    def test_constrained(self, st: SolveTables):
        additional_constraints = SolveTablesExpression(
            "src_ip == 0.0.0.0 and dst_ip == 0.0.0.0 and in_iface == eth2 and out_iface == eth2 and protocol == mh and src_port == 0 and dst_port == 0 and state == ESTABLISHED",
            st,
        ).get_constraints()
        model = st.check_and_get_model(
            chain="INPUT", constraints=additional_constraints
        )
        # print(st.translate_model(model))
        assert model is None


class TestDropChainDropDefault(BaseTest):
    DEFAULT_POLICY = "DROP"
    IPTABLES_RULES = [
        "-A INPUT -j FIRST",
        "-A FIRST -j DROP",
    ]

    def test_no_constraints(self, st: SolveTables):
        additional_constraints = SolveTablesExpression("", st).get_constraints()
        model = st.check_and_get_model(
            chain="INPUT", constraints=additional_constraints
        )
        assert model is None


class TestAcceptChainDropDefault(BaseTest):
    DEFAULT_POLICY = "DROP"
    IPTABLES_RULES = [
        "-A INPUT -j FIRST",
        "-A FIRST -j ACCEPT",
    ]

    def test_no_constraints(self, st: SolveTables):
        additional_constraints = SolveTablesExpression("", st).get_constraints()
        model = st.check_and_get_model(
            chain="INPUT", constraints=additional_constraints
        )
        assert model is not None


class TestDropChainDropDefaultAcceptRule(BaseTest):
    DEFAULT_POLICY = "DROP"
    IPTABLES_RULES = [
        "-A INPUT -j FIRST",
        "-A FIRST -j DROP",
        "-A INPUT -j ACCEPT",
    ]

    def test_no_constraints(self, st: SolveTables):
        additional_constraints = SolveTablesExpression("", st).get_constraints()
        model = st.check_and_get_model(
            chain="INPUT", constraints=additional_constraints
        )
        assert model is None


class TestReturnChainDropDefaultAcceptRule(BaseTest):
    DEFAULT_POLICY = "DROP"
    IPTABLES_RULES = [
        "-A INPUT -j FIRST",
        "-A FIRST -j RETURN",
        "-A FIRST -j DROP",
        "-A INPUT -j ACCEPT",
    ]

    def test_no_constraints(self, st: SolveTables):
        additional_constraints = SolveTablesExpression("", st).get_constraints()
        model = st.check_and_get_model(
            chain="INPUT", constraints=additional_constraints
        )
        assert model is not None


class TestReturnChainAcceptDefaultDropRule(BaseTest):
    DEFAULT_POLICY = "ACCEPT"
    IPTABLES_RULES = [
        "-A INPUT -j FIRST",
        "-A FIRST -j RETURN",
        "-A FIRST -j ACCEPT",
        "-A INPUT -j DROP",
    ]

    def test_no_constraints(self, st: SolveTables):
        additional_constraints = SolveTablesExpression("", st).get_constraints()
        model = st.check_and_get_model(
            chain="INPUT", constraints=additional_constraints
        )
        assert model is None


class TestSubnetReturnChainsDefaultAccept(BaseTest):
    DEFAULT_POLICY = "ACCEPT"
    IPTABLES_RULES = [
        "-A INPUT -s 10.0.0.0/8 -j CHAIN",
        "-A CHAIN -s 10.0.1.0/24 -j ACCEPT",
        "-A CHAIN -s 10.0.2.0/24 -j DROP",
        "-A CHAIN -s 10.0.0.0/16 -j RETURN",
        "-A CHAIN -s 10.1.0.0/24 -j DROP",
        "-A CHAIN -s 10.1.1.0/24 -j RETURN",
        "-A CHAIN -s 10.0.0.0/14 -j ACCEPT",
        "-A INPUT -s 10.0.0.0/9 -j DROP",
    ]

    def test_no_constraints(self, st: SolveTables):
        additional_constraints = SolveTablesExpression("", st).get_constraints()
        model = st.check_and_get_model(
            chain="INPUT", constraints=additional_constraints
        )
        assert model is not None

    def test_hit_first_accept_constraints(self, st: SolveTables):
        additional_constraints = SolveTablesExpression(
            "src_ip == 10.0.1.3", st
        ).get_constraints()
        model = st.check_and_get_model(
            chain="INPUT", constraints=additional_constraints
        )
        assert model is not None
        model_dict = st.translate_model(model)
        assert model_dict["src_ip"] == ipaddress.IPv4Address("10.0.1.3")

        rules = st.identify_rule_from_model(chain="INPUT", model=model)
        assert rules is not None
        assert len(rules) == 2
        assert rules[0].iptables_rule == self.IPTABLES_RULES[0]
        assert rules[1].iptables_rule == self.IPTABLES_RULES[1]

    def test_hit_last_accept(self, st: SolveTables):
        additional_constraints = SolveTablesExpression(
            "src_ip == 10.1.2.3", st
        ).get_constraints()
        model = st.check_and_get_model(
            chain="INPUT", constraints=additional_constraints
        )
        assert model is not None
        model_dict = st.translate_model(model)
        assert model_dict["src_ip"] == ipaddress.IPv4Address("10.1.2.3")

        # rules = st.identify_rule_from_model(chain="INPUT", model=model)
        # assert rules is not None
        # assert len(rules) == 2
        # assert rules[0].iptables_rule == self.IPTABLES_RULES[0]
        # assert rules[1].iptables_rule == self.IPTABLES_RULES[6]

    def test_hit_second_return_drop(self, st: SolveTables):
        additional_constraints = SolveTablesExpression(
            "src_ip == 10.0.3.1", st
        ).get_constraints()
        model = st.check_and_get_model(
            chain="INPUT", constraints=additional_constraints
        )
        assert model is None

    def test_hit_default_accept(self, st: SolveTables):
        additional_constraints = SolveTablesExpression(
            "src_ip == 123.0.1.1", st
        ).get_constraints()
        model = st.check_and_get_model(
            chain="INPUT", constraints=additional_constraints
        )
        assert model is not None
        model_dict = st.translate_model(model)
        assert model_dict["src_ip"] == ipaddress.IPv4Address("123.0.1.1")

        # rules = st.identify_rule_from_model(chain="INPUT", model=model)
        # assert rules is not None
        # assert len(rules) == 2
        # assert rules[0].iptables_rule == self.IPTABLES_RULES[0]
        # assert rules[1].iptables_rule == self.IPTABLES_RULES[6]

    def test_hit_outside_drop(self, st: SolveTables):
        additional_constraints = SolveTablesExpression(
            "src_ip in 10.5.0.0/24", st
        ).get_constraints()
        model = st.check_and_get_model(
            chain="INPUT", constraints=additional_constraints
        )
        assert model is None

    def test_hit_default_accept(self, st: SolveTables):
        additional_constraints = SolveTablesExpression(
            "src_ip == 123.0.1.1", st
        ).get_constraints()
        model = st.check_and_get_model(
            chain="INPUT", constraints=additional_constraints
        )
        assert model is not None
        model_dict = st.translate_model(model)
        assert model_dict["src_ip"] == ipaddress.IPv4Address("123.0.1.1")

    # TODO: add more test scenarios for this table


class TestSubnetReturnChainsDefaultAcceptSimplified(BaseTest):
    DEFAULT_POLICY = "ACCEPT"
    IPTABLES_RULES = [
        "-A INPUT -s 10.0.0.0/8 -j CHAIN",
        "-A CHAIN -s 10.0.0.0/16 -j RETURN",
    ]

    def test_no_constraints(self, st: SolveTables):
        additional_constraints = SolveTablesExpression("", st).get_constraints()
        model = st.check_and_get_model(
            chain="INPUT", constraints=additional_constraints
        )
        assert model is not None

    def test_hit_last_accept(self, st: SolveTables):
        additional_constraints = SolveTablesExpression(
            "src_ip == 10.1.2.3", st
        ).get_constraints()
        model = st.check_and_get_model(
            chain="INPUT", constraints=additional_constraints
        )
        assert model is not None
        model_dict = st.translate_model(model)
        assert model_dict["src_ip"] == ipaddress.IPv4Address("10.1.2.3")


class TestSimpleSubnetDefaultAccept(BaseTest):
    DEFAULT_POLICY = "ACCEPT"
    IPTABLES_RULES = [
        "-A INPUT -s 10.0.0.0/8 -j DROP",
    ]

    def test_no_constraints(self, st: SolveTables):
        additional_constraints = SolveTablesExpression("", st).get_constraints()
        model = st.check_and_get_model(
            chain="INPUT", constraints=additional_constraints
        )
        assert model is not None
        model_dict = st.translate_model(model)
        assert model_dict["src_ip"] not in ipaddress.IPv4Network("10.0.0.0/8")

        # rules = st.identify_rule_from_model(chain="INPUT", model=model)
        # assert rules is not None
        # assert len(rules) == 2
        # assert rules[0].iptables_rule == self.IPTABLES_RULES[0]
        # assert rules[1].iptables_rule == self.IPTABLES_RULES[6]

    def test_hit_drop(self, st: SolveTables):
        additional_constraints = SolveTablesExpression(
            "src_ip == 10.0.0.1", st
        ).get_constraints()
        model = st.check_and_get_model(
            chain="INPUT", constraints=additional_constraints
        )
        assert model is None

    def test_hit_default_accept(self, st: SolveTables):
        additional_constraints = SolveTablesExpression(
            "src_ip == 22.3.1.1", st
        ).get_constraints()
        model = st.check_and_get_model(
            chain="INPUT", constraints=additional_constraints
        )
        assert model is not None
        model_dict = st.translate_model(model)
        assert model_dict["src_ip"] not in ipaddress.IPv4Network("10.0.0.0/8")
        assert model_dict["src_ip"] == ipaddress.IPv4Address("22.3.1.1")

        # rules = st.identify_rule_from_model(chain="INPUT", model=model)
        # assert rules is not None
        # assert len(rules) == 1
        # assert rules[0].iptables_rule == self.IPTABLES_RULES[0]


class TestSimpleSubnetDefaultDrop(BaseTest):
    DEFAULT_POLICY = "DROP"
    IPTABLES_RULES = [
        "-A INPUT -s 10.0.0.0/8 -j ACCEPT",
    ]

    def test_no_constraints(self, st: SolveTables):
        additional_constraints = SolveTablesExpression("", st).get_constraints()
        model = st.check_and_get_model(
            chain="INPUT", constraints=additional_constraints
        )
        assert model is not None
        model_dict = st.translate_model(model)
        assert model_dict["src_ip"] in ipaddress.IPv4Network("10.0.0.0/8")

        rules = st.identify_rule_from_model(chain="INPUT", model=model)
        assert rules is not None
        assert len(rules) == 1
        assert rules[0].iptables_rule == self.IPTABLES_RULES[0]

    def test_hit_accept(self, st: SolveTables):
        additional_constraints = SolveTablesExpression(
            "src_ip == 10.0.0.1", st
        ).get_constraints()
        model = st.check_and_get_model(
            chain="INPUT", constraints=additional_constraints
        )
        assert model is not None
        model_dict = st.translate_model(model)
        assert model_dict["src_ip"] in ipaddress.IPv4Network("10.0.0.0/8")

        rules = st.identify_rule_from_model(chain="INPUT", model=model)
        assert rules is not None
        assert len(rules) == 1
        assert rules[0].iptables_rule == self.IPTABLES_RULES[0]

    def test_hit_default_drop(self, st: SolveTables):
        additional_constraints = SolveTablesExpression(
            "src_ip == 22.3.1.1", st
        ).get_constraints()
        model = st.check_and_get_model(
            chain="INPUT", constraints=additional_constraints
        )
        assert model is None


class TestSimpleNotSubnetDefaultDrop(BaseTest):
    DEFAULT_POLICY = "DROP"
    IPTABLES_RULES = [
        "-A INPUT ! -s 10.0.0.0/8 -j ACCEPT",
    ]

    def test_no_constraints(self, st: SolveTables):
        additional_constraints = SolveTablesExpression("", st).get_constraints()
        model = st.check_and_get_model(
            chain="INPUT", constraints=additional_constraints
        )
        assert model is not None
        model_dict = st.translate_model(model)
        assert model_dict["src_ip"] not in ipaddress.IPv4Network("10.0.0.0/8")

        rules = st.identify_rule_from_model(chain="INPUT", model=model)
        assert rules is not None
        assert len(rules) == 1
        assert rules[0].iptables_rule == self.IPTABLES_RULES[0]

    def test_below_accept(self, st: SolveTables):
        additional_constraints = SolveTablesExpression(
            "src_ip == 1.1.1.1", st
        ).get_constraints()
        model = st.check_and_get_model(
            chain="INPUT", constraints=additional_constraints
        )
        assert model is not None
        model_dict = st.translate_model(model)
        assert model_dict["src_ip"] not in ipaddress.IPv4Network("10.0.0.0/8")
        assert model_dict["src_ip"] == ipaddress.IPv4Address("1.1.1.1")

        rules = st.identify_rule_from_model(chain="INPUT", model=model)
        assert rules is not None
        assert len(rules) == 1
        assert rules[0].iptables_rule == self.IPTABLES_RULES[0]

    def test_above_accept(self, st: SolveTables):
        additional_constraints = SolveTablesExpression(
            "src_ip == 255.255.255.255", st
        ).get_constraints()
        model = st.check_and_get_model(
            chain="INPUT", constraints=additional_constraints
        )
        assert model is not None
        model_dict = st.translate_model(model)
        assert model_dict["src_ip"] not in ipaddress.IPv4Network("10.0.0.0/8")
        assert model_dict["src_ip"] == ipaddress.IPv4Address("255.255.255.255")

        rules = st.identify_rule_from_model(chain="INPUT", model=model)
        assert rules is not None
        assert len(rules) == 1
        assert rules[0].iptables_rule == self.IPTABLES_RULES[0]

    def test_hit_drop_address(self, st: SolveTables):
        additional_constraints = SolveTablesExpression(
            "src_ip == 10.0.0.1", st
        ).get_constraints()
        model = st.check_and_get_model(
            chain="INPUT", constraints=additional_constraints
        )
        assert model is None

    def test_hit_drop_subnet(self, st: SolveTables):
        additional_constraints = SolveTablesExpression(
            "src_ip in 10.0.0.0/8", st
        ).get_constraints()
        model = st.check_and_get_model(
            chain="INPUT", constraints=additional_constraints
        )
        assert model is None

    def test_accept_not_subnet(self, st: SolveTables):
        additional_constraints = SolveTablesExpression(
            "src_ip !in 10.0.0.0/8", st
        ).get_constraints()
        model = st.check_and_get_model(
            chain="INPUT", constraints=additional_constraints
        )
        assert model is not None
        model_dict = st.translate_model(model)
        assert model_dict["src_ip"] not in ipaddress.IPv4Network("10.0.0.0/8")

        rules = st.identify_rule_from_model(chain="INPUT", model=model)
        assert rules is not None
        assert len(rules) == 1
        assert rules[0].iptables_rule == self.IPTABLES_RULES[0]


class TestSimpleNotIPDefaultDrop(BaseTest):
    DEFAULT_POLICY = "DROP"
    IPTABLES_RULES = [
        "-A INPUT ! -s 10.0.0.1 -j ACCEPT",
    ]

    def test_no_constraints(self, st: SolveTables):
        additional_constraints = SolveTablesExpression("", st).get_constraints()
        model = st.check_and_get_model(
            chain="INPUT", constraints=additional_constraints
        )
        assert model is not None
        model_dict = st.translate_model(model)
        assert model_dict["src_ip"] != ipaddress.IPv4Address("10.0.0.1")

        rules = st.identify_rule_from_model(chain="INPUT", model=model)
        assert rules is not None
        assert len(rules) == 1
        assert rules[0].iptables_rule == self.IPTABLES_RULES[0]

    def test_below_accept(self, st: SolveTables):
        additional_constraints = SolveTablesExpression(
            "src_ip == 1.1.1.1", st
        ).get_constraints()
        model = st.check_and_get_model(
            chain="INPUT", constraints=additional_constraints
        )
        assert model is not None
        model_dict = st.translate_model(model)
        assert model_dict["src_ip"] != ipaddress.IPv4Address("10.0.0.1")
        assert model_dict["src_ip"] == ipaddress.IPv4Address("1.1.1.1")

        rules = st.identify_rule_from_model(chain="INPUT", model=model)
        assert rules is not None
        assert len(rules) == 1
        assert rules[0].iptables_rule == self.IPTABLES_RULES[0]

    def test_above_accept(self, st: SolveTables):
        additional_constraints = SolveTablesExpression(
            "src_ip == 255.255.255.255", st
        ).get_constraints()
        model = st.check_and_get_model(
            chain="INPUT", constraints=additional_constraints
        )
        assert model is not None
        model_dict = st.translate_model(model)
        assert model_dict["src_ip"] not in ipaddress.IPv4Network("10.0.0.0/8")
        assert model_dict["src_ip"] == ipaddress.IPv4Address("255.255.255.255")

        rules = st.identify_rule_from_model(chain="INPUT", model=model)
        assert rules is not None
        assert len(rules) == 1
        assert rules[0].iptables_rule == self.IPTABLES_RULES[0]

    def test_hit_drop(self, st: SolveTables):
        additional_constraints = SolveTablesExpression(
            "src_ip == 10.0.0.1", st
        ).get_constraints()
        model = st.check_and_get_model(
            chain="INPUT", constraints=additional_constraints
        )
        assert model is None

    def test_accept_not_address(self, st: SolveTables):
        additional_constraints = SolveTablesExpression(
            "src_ip != 10.0.0.1", st
        ).get_constraints()
        model = st.check_and_get_model(
            chain="INPUT", constraints=additional_constraints
        )
        assert model is not None
        model_dict = st.translate_model(model)
        assert model_dict["src_ip"] != ipaddress.IPv4Address("10.0.0.1")

        rules = st.identify_rule_from_model(chain="INPUT", model=model)
        assert rules is not None
        assert len(rules) == 1
        assert rules[0].iptables_rule == self.IPTABLES_RULES[0]


class TestNotInterfacesDefaultDrop(BaseTest):
    DEFAULT_POLICY = "DROP"
    IPTABLES_RULES = [
        "-A INPUT ! -i eth0 -j ACCEPT",
        "-A INPUT -i eth1 -j DROP",
        "-A INPUT -i eth2 -j ACCEPT",
    ]

    def test_no_constraints(self, st: SolveTables):
        additional_constraints = SolveTablesExpression("", st).get_constraints()
        model = st.check_and_get_model(
            chain="INPUT", constraints=additional_constraints
        )
        assert model is not None
        model_dict = st.translate_model(model)
        print(model_dict)
        assert model_dict["input_interface"] in ["eth1", "eth2"]

        rules = st.identify_rule_from_model(chain="INPUT", model=model)
        assert rules is not None
        assert len(rules) == 1
        assert rules[0].iptables_rule == self.IPTABLES_RULES[0]

    def test_drop_eth0(self, st: SolveTables):
        additional_constraints = SolveTablesExpression(
            "in_iface == eth0", st
        ).get_constraints()
        model = st.check_and_get_model(
            chain="INPUT", constraints=additional_constraints
        )
        assert model is None

    def test_hit_eth1(self, st: SolveTables):
        additional_constraints = SolveTablesExpression(
            "in_iface == eth1", st
        ).get_constraints()
        model = st.check_and_get_model(
            chain="INPUT", constraints=additional_constraints
        )
        assert model is not None
        model_dict = st.translate_model(model)
        print(model_dict)
        assert model_dict["input_interface"] == "eth1"

        rules = st.identify_rule_from_model(chain="INPUT", model=model)
        assert rules is not None
        assert len(rules) == 1
        assert rules[0].iptables_rule == self.IPTABLES_RULES[0]

    def test_hit_eth1(self, st: SolveTables):
        additional_constraints = SolveTablesExpression(
            "in_iface == eth2", st
        ).get_constraints()
        model = st.check_and_get_model(
            chain="INPUT", constraints=additional_constraints
        )
        assert model is not None
        model_dict = st.translate_model(model)
        print(model_dict)
        assert model_dict["input_interface"] == "eth2"

        rules = st.identify_rule_from_model(chain="INPUT", model=model)
        assert rules is not None
        assert len(rules) == 1
        assert rules[0].iptables_rule == self.IPTABLES_RULES[0]

    def test_hit_not_eth0(self, st: SolveTables):
        additional_constraints = SolveTablesExpression(
            "in_iface != eth0", st
        ).get_constraints()
        model = st.check_and_get_model(
            chain="INPUT", constraints=additional_constraints
        )
        assert model is not None
        model_dict = st.translate_model(model)
        print(model_dict)
        assert model_dict["input_interface"] in ["eth1", "eth2"]

        rules = st.identify_rule_from_model(chain="INPUT", model=model)
        assert rules is not None
        assert len(rules) == 1
        assert rules[0].iptables_rule == self.IPTABLES_RULES[0]
