- Include ip r / ip a information to augment information about the interfaces and networks. This way also indirect paths can be discovered via combinations of INPUT, FORWARD, OUTPUT chains via routing of the host. These probably need to be context sensitive, depending on the considered chain.

- Use tokenizer or something alike to improve expressin parsing for improved expressiveness; to enable something like "(src_port == 123 and dst_port == 8080) or (src_port == 432 and dst_port == 80)".

- Include some heuristics to improve produced example.
  E.g.
  - try to set state to NEW if none is defined (and protocol is tcp or udp)
  - don't use the first and last IPs of a network, like 192.168.0.0

- Exclude output interface from INPUT rules and check for other chain specific setups.

- Warn on flags in rules, which are not handled.