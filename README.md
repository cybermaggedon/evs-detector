# `evs-detector`

Eventstream analytic for Cyberprobe event streams.  Subscribes to Pulsar
for Cyberprobe events and annotates events with any indicator hits against
a set of IOCs (Indicators of Compromise) defined in a file.

## Getting Started

The target deployment product is a container engine.  The analytic expects
a Pulsar service to be running.

```
  docker run -d \
      -e PULSAR_BROKER=pulsar://<PULSAR-HOST>:6650 \
      -e INDICATORS=/ind/indicators.json \
      -v ./:/ind \
      -p 8088:8088 \
      docker.io/cybermaggedon/evs-detector:<VERSION>
```

The above command mounts the current directory under `/ind` in the container,
and configures to use the file `/ind/indicators.json` as the indicator set.

### Prerequisites

You need to have a container deployment system e.g. Podman, Docker, Moby.

You also need a Pulsar exchange, being fed by events from Cyberprobe.

### Installing

The easiest way is to use the containers we publish to Docker hub.
See https://hub.docker.com/r/cybermaggedon/evs-detector

```
  docker pull docker.io/cybermaggedon/evs-detector:<VERSION>
```

If you want to build this yourself, you can just clone the Github repo,
and type `make`.

## Deployment configuration

The following environment variables are used to configure:

| Variable | Purpose | Default |
|----------|---------|---------|
| `INPUT` | Specifies the Pulsar topic to subscribe to.  This is just the topic part of the URL e.g. `cyberprobe`. By default the input is `withloc` which is the output  of the `evs-geoip` analytic. | `withloc` |
| `OUTPUT` | Specifies a comma-separated list of Pulsar topics to publish annotated events to.  This is just the topic part of the URL e.g. `withioc`. By default, the output is `withioc`. | `withioc` |
| `INDICATORS` | Specifies a filename of indicator which is loaded.  The file is monitored for change, and reloaded automatically. | `indicators.json` |
| `METRICS_PORT` | Specifies the port number to serve Prometheus metrics on.  If not set, metrics will not be served. The container has a default setting of 8088. | `8088` |

## Indicator Schema

See examples in [indicators.json](indicators.json) in the GitHub repo.

### Indicator set

An **indicator set** is a JSON file consisting of one object with fields:
- `description` is a human-readable description.
- `version` is an identifier which can be used to track file updates.
- `indicators` is an array of **indicator** objects.

e.g.

```
{
    "description": "Some test data",
    "version": "d7f022d3-cda2-45ef-8d89-66334967f4e2",
    "indicators": [
        {
           ...
        }
    ]
}
```

### Indicator

An **indicator** is a JSON object describing  a single indicator.  It has
the following fields:

- `id` is an ID for the indicator.  Should probably be unique if you want to
  use it for something useful.
- `descriptor' is a record of metadata associated with events when the
  indicator matches.
- An expression describes the state under which the indicator matches an
  event.  It can consist of:
  - A **type** and **value** recorded in the `type` and `value` fields.
  - A logical expression combining other expressions using the _and_, _or_
    and _not_ operators.

e.g.

```
{
    "id": "0acf0328-6276-4726-9686-510633881413",
    "descriptor": {
        ...
    },
    "type": "ipv4",
    "value": "192.179.1.72"
}
```

### Descriptor

The **descriptor** is an object containing a number of fields.  These fields
are all copied onto an event when an IOC matches:

- `category` describes a risk category associated with an indicator
- `source` describes the source of an indicator e.g. threat exchange name
- `author` is the author of an indicator, an email address
- `description` is a human-readable description of the threat
- `probability` is a probability score of the threat
- `type` and `value` are used to describe data describe query terms which
  would be used to find events which match this indicator.

### Type/value field

| Type      |    Description                                |
|-----------|-----------------------------------------------|
|`ipv4`     | IPv4 address in dotted decimal notation, matches when an event has this address in the source or destination fields |
|`ipv4.src` | IPv4 address, but only matches source addresses. |
|`ipv4.dest` | IPv4 address, but only matches destination addresses. |
|`ipv6`     | IPv6 address in standard IPv6 notation, matches when an event has this address in the source or destination fields |
|`ipv6.src` | IPv6 address, but only matches source addresses. |
|`ipv6.dest` | IPv6 address, but only matches destination addresses. |
|`tcp`     | TCP port number in decimal form, matches when an event has this port number in the source or destination fields |
|`tcp.src` | TCP port number, but only matches source port. |
|`tcp.dest` | TCP port number, but only matches destination port. |
|`udp`     | UDP port number in decimal form, matches when an event has this port number in the source or destination fields |
|`udp.src` | UDP port number, but only matches source port. |
|`udp.dest` | UDP port number, but only matches destination port. |
|`hostname` | Hostname present in a number of fields, e.g. DNS query/answer and HTTP Host. |
|`url` | Normalised URL, determined from e.g. HTTP request/response matching. |
|`email` | Email from SMTP fields. |

### Logical AND/OR, NOT expressions

A logical _and_ expression can be described using the `and` field containing
an array of expressions.  A logical _or_ expression can be described using the
`or` field containing an array of expressions.  A logical _not_ expression
can be described using the `not` field containing a single expression.

e.g. 

```
"and": [
    {
        "type": "ipv4", "value": "2.3.4.5"
    },
    "not": {
        "or": [
            {
                "type": "ipv4", "value": "1.2.3.4"
            },
            {
                "type": "ipv4", "value": "5.6.7.8"
            }
        ]
    }
]
```

