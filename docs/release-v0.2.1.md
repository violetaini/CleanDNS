# CleanDNS v0.2.1

- Verify upstream DNS response IDs, questions, types, classes and opcodes. Ignore unrelated UDP replies, randomize UDP query IDs and preserve client IDs in the returned answers.
- Bound DoH upstream response sizes. Accept internal DoQ forwarding metadata only from IPv4 loopback, and reject unsupported DNS operations at the listener.
- Add `-strict` to domain routing rules to limit matching queries to the specified upstreams. [Rule syntax](https://github.com/violetaini/CleanDNS/blob/main/docs/configuration.md#domain-routing-and-strict-upstreams)
- Compared with AdGuard Home v0.107.79 in an isolated environment using the same mock upstreams. Fourteen representative cases covered normal answers, negative answers, filtering exceptions, rewriting, IPv6 and domain routing. CleanDNS UDP, TCP, DoH GET and POST, and native DoQ returned the expected answers and response codes.
