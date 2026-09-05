# Batch-settlement Base58 CPU profile

Pyroscope CPU profiles captured from `service_name="pay-gateway"` during the
100,000-user in-memory batch-settlement benchmark on 2026-09-05 UTC.

## Captures

| File | UTC window | Unix window | Wall time | CPU time | Average cores |
| --- | --- | --- | ---: | ---: | ---: |
| `request-only.json.gz` | 01:30:20–01:32:20 | 1788571820–1788571940 | 120 s | 1,103.52 s | 9.196 |
| `settlement.json.gz` | 01:32:26–01:36:27 | 1788571946–1788572187 | 241 s | 2,043.19 s | 8.478 |

These are the raw Pyroscope Flamebearer JSON responses, gzip-compressed. They
include every stack so a subsequent investigation can inspect callers and not
only the Base58 leaf frames.

SHA-256:

```text
873ed2faa02a7713c95d817e52edd00320bb16319bf9992c5177bbc82406f12a  request-only.json.gz
d7480fe3855e6cecba9fb4c2a87628f85156109576b0f35a9c68793174d9dfb8  settlement.json.gz
```

## Base58 self CPU

| Window | `bs58::encode::encode_into` | `bs58::decode::decode_into` | Combined | Average Base58 cores |
| --- | ---: | ---: | ---: | ---: |
| Request-only | 6.98% | 1.82% | 8.80% | 0.809 |
| Settlement | 6.46% | 1.65% | 8.11% | 0.688 |

Base58 did not increase during settlement. Its normalized share and absolute
cores both decreased slightly because the HTTP request rate fell from roughly
698k/s to 672k/s while the worker waited on RPC submission and confirmation.
The settlement window averaged fewer total CPU cores than the request-only
window (8.478 versus 9.196), so transaction serialization is not the observed
settlement bottleneck.

## Inspecting the raw profile

```sh
gzip -dc request-only.json.gz | jq '.flamebearer | {numTicks, names, levels}'
gzip -dc settlement.json.gz | jq '.flamebearer | {numTicks, names, levels}'
```

The profile type was:

```text
process_cpu:cpu:nanoseconds:cpu:nanoseconds{service_name="pay-gateway"}
```

