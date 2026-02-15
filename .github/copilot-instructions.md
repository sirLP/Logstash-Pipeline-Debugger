# Logstash pfSense Parser Visualizer - AI Coding Agent Instructions

## Project Overview
A Flask web application that parses and visualizes Logstash configurations for pfSense/OPNsense firewall logs. It simulates Logstash filter pipelines to help debug and understand log processing, showing step-by-step field transformations.

## Architecture

### Three-Tier Flow
1. **Frontend** (`templates/index.html`, `static/app.js`) - Manages UI, config chain, and API calls
2. **Backend API** (`app.py`) - Flask routes, conditional evaluation, and pipeline orchestration
3. **Parser Engine** (`logstash_parser.py`) - Recursive config parsing with full conditional logic support

### Data Pipeline
```
Raw Log → Input Stream → Config Chain (00→02→10...→50) → Nested Conditionals → Filter Execution → Field Tracking → Visualization
```

## Critical pfELK Pattern
Configuration files in `conf.d/` follow numbered naming convention:
- `00-input.pfelk` - Input stream definitions (ports, types, tags)
- `02-firewall.pfelk` - Firewall log parsing (CSV extraction)
- `10-unbound.pfelk` - DNS/DNSSEC parsing with nested conditionals
- `30-geoip.pfelk` - Geographic enrichment
- `50-outputs.pfelk` - Namespace routing and Elasticsearch data streams

**Files are processed in alphanumeric order** - numbering controls pipeline sequence.

## Logstash Parsing Quirks

### Nested Field Syntax
```python
# Logstash uses bracket notation for nested fields
"[dns][question][name]"  # Not dot notation
"[@metadata][namespace]" # Special metadata prefix
```

### Conditional Logic
The parser handles deeply nested if/else-if/else chains (`_parse_filter_block`, line 76):
- Recursive descent through condition trees
- Filters inherit parent conditions for skip logic
- `evaluate_condition()` in `app.py` (line 328) handles: `==`, `!=`, `=~`, `!~`, `in`, `not in`, `and`, `or`

### Grok Pattern Resolution
Custom patterns in `patterns/pfelk.grok` extend base patterns (line 18-60 in `logstash_parser.py`):
```python
'UNBOUND' → custom pattern
'IPV4' → built-in pattern
# Pattern inheritance requires recursive substitution
```

**Critical**: Grok patterns use two field capture syntaxes:
1. `%{TYPE:[field][name]}` - Standard Grok nested syntax
2. `(?<[field][name]>regex)` - Oniguruma named capture groups

Both are converted to Python-safe names: `[kea][dhcp][operation]` → `kea_dhcp_operation`
- Parser handles this in pattern loading (line 535-551)
- Field mapping ensures proper nesting in final output
- **Hyphens in group names cause regex errors** - use underscores or nested brackets

## Key Implementation Details

### Field Tracking
`process_tree()` in `app.py` (line 204) creates before/after snapshots:
- Green highlights: newly added fields
- Orange highlights: modified fields  
- Red boxes: skipped filters (condition not met)

### Mutate Operations
`_apply_mutate()` (logstash_parser.py, line 620) handles:
- `add_field`, `replace`, `rename` with nested bracket paths
- `add_tag`, `remove_tag` with array manipulation
- `convert` for type coercion (integer, float, string)
- `strip`, `split` for string operations

### CSV Parsing
Firewall logs use CSV extraction (`02-firewall.pfelk`):
```ruby
mutate {
  copy => { "filter_message" => "pfelk_csv" }
  split => { "pfelk_csv" => "," }
}
# Then reference: "[pfelk_csv][0]", "[pfelk_csv][1]", etc.
```

## Development Workflow

### Running Locally
```bash
./start.sh  # Handles venv, dependencies, and Flask startup
# Or manually:
source venv/bin/activate
python app.py  # Starts on localhost:5000
```

### Testing Configs
Use sample logs in `static/app.js` (lines 14-19) or load actual `.pfelk` files from `conf.d/`.

### Adding Filters
1. Implement `_apply_{filter_type}()` in `logstash_parser.py`
2. Add extraction logic in `_parse_filter_config()` (line 262)
3. Update `apply_filter()` dispatcher (line 357)
4. For lookups: add CSV to `databases/`, implement in `_apply_translate()` or similar
5. For GeoIP: ensure `.mmdb` files are in `GeoIP/`, implement in `_apply_geoip()`

## Common Gotchas

### String Escaping
Logstash configs have nested quote levels - use raw strings in Python:
```python
r'match => { "field" => "pattern" }'  # Avoids escape hell
```

### Brace Matching
`_find_matching_brace()` (line 173) tracks strings/regex to avoid false matches:
```ruby
if [field] =~ /\}/  # Brace in regex shouldn't close block
```

### Metadata Fields
`[@metadata][*]` fields are special - they don't appear in final output but control routing:
```ruby
mutate { add_field => { "[@metadata][pfelk_namespace]" => "firewall" } }
# Later used in: data_stream_namespace => "%{[@metadata][pfelk_namespace]}"
```

### Grok Pattern Debugging
If you see `bad character in group name` errors:
1. Check for hyphens in capture group names - use `_` or nested `[brackets]`
2. Verify Oniguruma syntax `(?<[field][name]>...)` is being converted properly
3. Add debug prints in `_apply_grok()` to see pattern simplification
4. Common culprits: `[kea-dhcp]` should be `[kea][dhcp]`

## File Patterns

- `*.pfelk` - Logstash configuration fragments
- `patterns/*.grok` - Grok pattern definitions
- `databases/*.csv` - Lookup tables for enrichment (used by translate/lookup filters in pipeline)
- `GeoIP/*.mmdb` - MaxMind GeoIP databases (fully integrated for IP geolocation)
- `*.pcap` - PCAP files for testing (`/api/parse_pcap` endpoint processes these)

## Enrichment & Lookup Integration

### GeoIP Enrichment
The `30-geoip.pfelk` config uses GeoIP databases for source/destination IP enrichment:
```ruby
geoip {
  source => "[source][ip]"
  target => "[source][geo]"
  database => "/path/to/GeoIP/GeoLite2-City.mmdb"
}
```

### CSV Lookups
Database files in `databases/` provide enrichment:
- `rule-names.csv` - Maps rule IDs to descriptions (`35-rules-desc.pfelk`)
- `service-names-port-numbers.csv` - Port number to service mappings (`36-ports-desc.pfelk`)

### PCAP Processing
The Flask app supports PCAP parsing via `parse_pcap()` endpoint (line 471 in `app.py`):
- Extracts syslog messages from network captures
- Processes through the same pipeline as live logs
- Useful for debugging production traffic

## When Adding Features

1. **New filter type**: Add to `logstash_parser.py` with parse/apply methods
2. **UI changes**: Modify `templates/index.html` + `static/app.js` in tandem
3. **Config examples**: Add to sample configs in `app.js` or `conf.d/`
4. **Pattern updates**: Edit `patterns/pfelk.grok`, ensure pattern inheritance resolves
5. **Enrichment data**: Add CSV files to `databases/`, reference in pipeline configs

## ECS Compliance
This project targets Elastic Common Schema (ECS). Prefer standard field names:
- `[source][ip]` not `src_ip`
- `[event][action]` not `action`
- `[dns][question][name]` not `query_name`

Non-ECS fields use `[pf][*]` prefix for pfSense-specific data.
