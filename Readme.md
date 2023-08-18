# solvetables

Python script to translate `iptables` rules into `Z3` constraints and allow reasoning on them.
The basic idea is to define the undesired scenario and `solvetables` will try to identfy a packet realising this scenario, given the `iptables` configuration.

## iptables Rules

The iptables rules input is expected to be formatted as `iptables-save` export.

## Query Expressions

The query expression language is currently limited to simple comparisons with the base parameters listed below, which can be logically combined by either `and` or `or`.
*(Note: The evaluation of sub-expressions is simply from left to right)*

Available variables:
- `src_ip`
- `dst_ip`
- `in_iface`
- `out_iface`
- `protocol`
- `src_port`
- `dst_port`
- `state`

Available operator:
- `==`
- `!=`
- `<=`
- `>=`
- `<`
- `>`

## Example

The set of iptables rules:
```
-A INPUT -s 192.168.4.0/24 -d 192.168.4.1/32 -i eth1 -p tcp -m tcp --dport 443 -j ACCEPT
-A INPUT -s 192.168.4.0/24 -d 192.168.4.1/32 -i eth1 -p tcp -m tcp --sport 22 -j ACCEPT
-A INPUT -s 192.168.14.0/24 -d 192.168.14.1/32 -i eth0 -p tcp -m tcp --sport 1024:65535 --dport 20:21 -j ACCEPT
```

To obtain a packet that reaches `TCP/80` the expression `dst_port == 80 and protocol == tcp` can be used.
```
python solvetables.py INPUT example-iptables-save.conf "dst_port == 80 and protocol == tcp"
```
Produces the output:
```
The identified model is:
[state_model = 2,
 output_interface_model = 1,
 dst_ip_model = 3232236545,
 src_ip_model = 3232236544,
 protocol_model = 1,
 dst_port_model = 80,
 input_interface_model = 0,
 src_port_model = 22]

Use the following parameters to create packet for desired effect:
  src_ip: 192.168.4.0
  dst_ip: 192.168.4.1
  input_interface: eth1
  output_interface: eth0
  protocol: tcp
  src_port: 22
  dst_port: 80
  state: ESTABLISHED

The iptabeles rule hit is:
-A INPUT -s 192.168.4.0/24 -d 192.168.4.1/32 -i eth1 -p tcp -m tcp --sport 22 -j ACCEPT
```

## Limitations

- Only a subset of iptables parameters are implemented (yet).
- Currently only rules are parsed for the target chain and if the target (`-j`) is either INPUT, FORWARD or OUTPUT.
- The query expression language is quite limited and does not allow more complex structures.
- Likely many, many more
