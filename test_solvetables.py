import ipaddress
import pytest
from solvetables import SolveTables

# TODO: Add explicit model result where known


class BaseTest:
    DEFAULT_POLICY = "DROP"
    IPTABLES_RULES = []

    @pytest.fixture
    def st(self) -> SolveTables:
        st = SolveTables(default_policy=self.DEFAULT_POLICY)
        for rule in self.IPTABLES_RULES:
            st.add_rule(rule)
        return st


class TestDefaultAccept(BaseTest):
    DEFAULT_POLICY = "ACCEPT"
    IPTABLES_RULES = ["-A INPUT -i eth0 -j DROP"]

    def test_input_drop(self, st: SolveTables):
        additional_constraints = st.translate_expression("in_iface == eth0".split())
        model = st.check_and_get_model(
            chain="INPUT", constraints=additional_constraints
        )
        assert model is None

    def test_input_default_out(self, st: SolveTables):
        additional_constraints = st.translate_expression("out_iface == eth1".split())
        model = st.check_and_get_model(
            chain="INPUT", constraints=additional_constraints
        )
        assert model is not None

        model_dict = st.translate_model(model)
        assert model_dict["output_interface"] == "eth1"
        assert model_dict["input_interface"] != "eth0"

        rules = st.identify_rule(chain="INPUT", model=model)
        assert rules is None

    def test_input_default_in(self, st: SolveTables):
        additional_constraints = st.translate_expression("in_iface == eth1".split())
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
        additional_constraints = st.translate_expression("in_iface == eth0".split())
        model = st.check_and_get_model(
            chain="INPUT", constraints=additional_constraints
        )
        assert model is not None

        model_dict = st.translate_model(model)
        assert model_dict["input_interface"] == "eth0"

        rules = st.identify_rule(chain="INPUT", model=model)
        assert rules is not None
        assert len(rules) == 1
        assert rules[0] == self.IPTABLES_RULES[0]

    def test_input_default_out(self, st: SolveTables):
        additional_constraints = st.translate_expression("out_iface == eth1".split())
        model = st.check_and_get_model(
            chain="INPUT", constraints=additional_constraints
        )
        assert model is not None

        model_dict = st.translate_model(model)
        assert model_dict["input_interface"] == "eth0"
        assert model_dict["output_interface"] == "eth1"

        rules = st.identify_rule(chain="INPUT", model=model)
        assert rules is not None
        assert len(rules) == 1
        assert rules[0] == self.IPTABLES_RULES[0]

    def test_input_default_in(self, st: SolveTables):
        additional_constraints = st.translate_expression("in_iface == eth1".split())
        model = st.check_and_get_model(
            chain="INPUT", constraints=additional_constraints
        )
        assert model is None


class TestIndirection(BaseTest):
    DEFAULT_POLICY = "DROP"
    IPTABLES_RULES = ["-A FORWARD -i eth2 -j INDI", "-A INDI -o eth1 -j ACCEPT"]

    def test_indirection_exact(self, st: SolveTables):
        additional_constraints = st.translate_expression(
            "in_iface == eth2 and out_iface == eth1".split()
        )
        model = st.check_and_get_model(
            chain="FORWARD", constraints=additional_constraints
        )
        assert model is not None

        model_dict = st.translate_model(model)
        assert model_dict["input_interface"] == "eth2"
        assert model_dict["output_interface"] == "eth1"

        rules = st.identify_rule(chain="FORWARD", model=model)
        assert rules is not None
        assert len(rules) == 2
        assert rules[0] == self.IPTABLES_RULES[0]
        assert rules[1] == self.IPTABLES_RULES[1]

    def test_indirection_first(self, st: SolveTables):
        additional_constraints = st.translate_expression("in_iface == eth2".split())
        model = st.check_and_get_model(
            chain="FORWARD", constraints=additional_constraints
        )
        assert model is not None

        model_dict = st.translate_model(model)
        assert model_dict["input_interface"] == "eth2"
        assert model_dict["output_interface"] == "eth1"

        rules = st.identify_rule(chain="FORWARD", model=model)
        assert rules is not None
        assert len(rules) == 2
        assert rules[0] == self.IPTABLES_RULES[0]
        assert rules[1] == self.IPTABLES_RULES[1]

    def test_indirection_last(self, st: SolveTables):
        additional_constraints = st.translate_expression("out_iface == eth1".split())
        model = st.check_and_get_model(
            chain="FORWARD", constraints=additional_constraints
        )
        assert model is not None

        model_dict = st.translate_model(model)
        assert model_dict["input_interface"] == "eth2"
        assert model_dict["output_interface"] == "eth1"

        rules = st.identify_rule(chain="FORWARD", model=model)
        assert rules is not None
        assert len(rules) == 2
        assert rules[0] == self.IPTABLES_RULES[0]
        assert rules[1] == self.IPTABLES_RULES[1]

    def test_indirection_inverse(self, st: SolveTables):
        additional_constraints = st.translate_expression(
            "in_iface == eth1 and out_iface == eth2".split()
        )
        model = st.check_and_get_model(
            chain="FORWARD", constraints=additional_constraints
        )
        assert model is None

    def test_indirection_inverse_first(self, st: SolveTables):
        additional_constraints = st.translate_expression("in_iface == eth1".split())
        model = st.check_and_get_model(
            chain="FORWARD", constraints=additional_constraints
        )
        assert model is None

    def test_indirection_inverse_last(self, st: SolveTables):
        additional_constraints = st.translate_expression("out_iface == eth2".split())
        model = st.check_and_get_model(
            chain="FORWARD", constraints=additional_constraints
        )
        assert model is None


class TestExplicitDrop(BaseTest):
    DEFAULT_POLICY = "DROP"
    IPTABLES_RULES = ["-A FORWARD -i eth0 -j DROP", "-A FORWARD -o eth1 -j ACCEPT"]

    def test_explicit_drop_hit(self, st: SolveTables):
        additional_constraints = st.translate_expression("in_iface == eth0".split())
        model = st.check_and_get_model(
            chain="FORWARD", constraints=additional_constraints
        )
        assert model is None

    def test_explicit_drop_not_hit(self, st: SolveTables):
        additional_constraints = st.translate_expression("in_iface == eth1".split())
        model = st.check_and_get_model(
            chain="FORWARD", constraints=additional_constraints
        )
        assert model is not None

        model_dict = st.translate_model(model)
        assert model_dict["input_interface"] == "eth1"
        assert model_dict["output_interface"] == "eth1"

        rules = st.identify_rule(chain="FORWARD", model=model)
        assert rules is not None
        assert len(rules) == 1
        assert rules[0] == self.IPTABLES_RULES[1]

    def test_explicit_drop_hit_accept(self, st: SolveTables):
        additional_constraints = st.translate_expression("out_iface == eth1".split())
        model = st.check_and_get_model(
            chain="FORWARD", constraints=additional_constraints
        )
        assert model is not None

        model_dict = st.translate_model(model)
        assert model_dict["input_interface"] != "eth0"
        assert model_dict["output_interface"] == "eth1"

        rules = st.identify_rule(chain="FORWARD", model=model)
        assert rules is not None
        assert len(rules) == 1
        assert rules[0] == self.IPTABLES_RULES[1]

    def test_explicit_drop_hit_default(self, st: SolveTables):
        additional_constraints = st.translate_expression(
            "in_iface == eth1 and out_iface == eth0".split()
        )
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
        additional_constraints = st.translate_expression(
            "in_iface == eth1 and dst_port == 80".split()
        )
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

        rules = st.identify_rule(chain="INPUT", model=model)
        assert rules is not None
        assert len(rules) == 1
        assert rules[0] == self.IPTABLES_RULES[1]

    def test_hit_not_ip(self, st: SolveTables):
        additional_constraints = st.translate_expression(
            "dst_ip != 192.168.4.1".split()
        )
        model = st.check_and_get_model(
            chain="INPUT", constraints=additional_constraints
        )
        assert model is not None

        model_dict = st.translate_model(model)
        assert model_dict["input_interface"] == "eth0"
        assert model_dict["dst_port"] in range(20, 21)
        assert model_dict["src_port"] in range(1024, 65535)
        src_ip_net = ipaddress.IPv4Network("192.168.14.0/24")
        assert model_dict["src_ip"] in src_ip_net
        dst_ip_net = ipaddress.IPv4Network("192.168.14.1/32")
        assert model_dict["dst_ip"] in dst_ip_net

        rules = st.identify_rule(chain="INPUT", model=model)
        assert rules is not None
        assert len(rules) == 1
        assert rules[0] == self.IPTABLES_RULES[2]

    def test_in_expression(self, st: SolveTables):
        additional_constraints = st.translate_expression(
            "src_ip in 192.168.14.32/30".split()
        )
        model = st.check_and_get_model(
            chain="INPUT", constraints=additional_constraints
        )
        assert model is not None

        model_dict = st.translate_model(model)
        assert model_dict["input_interface"] == "eth0"
        assert model_dict["dst_port"] in range(20, 21)
        assert model_dict["src_port"] in range(1024, 65535)
        src_ip_net = ipaddress.IPv4Network("192.168.14.0/24")
        assert model_dict["src_ip"] in src_ip_net
        dst_ip_net = ipaddress.IPv4Network("192.168.14.1/32")
        assert model_dict["dst_ip"] in dst_ip_net

        rules = st.identify_rule(chain="INPUT", model=model)
        assert rules is not None
        assert len(rules) == 1
        assert rules[0] == self.IPTABLES_RULES[2]
