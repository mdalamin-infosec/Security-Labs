# Synthetic scenarios

[cases.json](cases.json) describes the inputs constructed by
[make_pcap.py](../tests/pcap/make_pcap.py). The `relevant_sid` fields are intended
test expectations, not observed alerts or a claim that attacks succeeded.
The generated PCAP and engine output belong under ignored `outputs/`.

The CLI's separate offline EVE demo is explicitly tagged `synthetic-demo` by
[demo.py](../src/threatwatch/demo.py). It is synthetic input, not captured traffic.

TODO: run the real-engine replay and the Compose ingestion path, retaining actual
sanitized EVE records and per-case results before publishing detection metrics.
