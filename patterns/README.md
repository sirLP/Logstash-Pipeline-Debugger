# Grok Patterns Directory

This directory contains custom Grok patterns that can be used in your Logstash configurations.

## Usage

In your Logstash grok filter, reference this directory:

```ruby
grok {
  patterns_dir => ["/path/to/patterns"]
  match => { "message" => "%{PFELK_FILTERLOG_DATA}" }
}
```

The parser automatically loads patterns from this directory, so you can use them in your grok filters.

## Pattern Files

- **pfelk** - Common pfSense/OPNsense firewall patterns
- **suricata** - Suricata IDS/IPS patterns  
- **haproxy** - HAProxy load balancer patterns

## Adding Custom Patterns

Create a new file in this directory with your pattern definitions:

```
# Pattern format: PATTERN_NAME regex_pattern

MY_CUSTOM_PATTERN [a-zA-Z0-9]+
ANOTHER_PATTERN %{INT:field_name}
```

Then use them in your grok filters:

```ruby
grok {
  match => { "message" => "%{MY_CUSTOM_PATTERN:my_field}" }
}
```

## Pattern Syntax

Patterns use Grok syntax:
- `%{PATTERN_NAME}` - Use a pattern
- `%{PATTERN_NAME:field_name}` - Capture to a field
- `%{PATTERN_NAME:[nested][field]}` - Capture to nested field

## Built-in Patterns

The parser includes all standard Grok patterns like:
- `IPV4`, `IPV6` - IP addresses
- `INT`, `NUMBER` - Numbers
- `WORD`, `NOTSPACE` - Text
- `TIMESTAMP_ISO8601` - Timestamps
- And many more...

Custom patterns in this directory extend the built-in ones.
