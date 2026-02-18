"""
Flask application for Logstash pfSense Parser Visualizer
"""
from flask import Flask, render_template, request, jsonify
import re
import json
import os
from datetime import datetime
try:
    from logstash_pipeline import LogstashParser, parse_config_to_tree
except Exception:
    from logstash_parser import LogstashParser, parse_config_to_tree

app = Flask(__name__)

# Store configurations and streams in memory
config_chain = []
input_streams = []

# Patterns directory
PATTERNS_DIR = os.path.join(os.path.dirname(__file__), 'patterns')


def deep_merge_dict(base, updates):
    """Recursively merge two dictionaries, mutating and returning base."""
    for key, value in updates.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            deep_merge_dict(base[key], value)
        else:
            base[key] = value
    return base

def extract_output_config(config_text):
    """Extract output configuration from Logstash config"""
    import re
    
    # Look for output block
    output_match = re.search(r'output\s*\{(.*?)\n\}', config_text, re.DOTALL)
    if not output_match:
        return None
    
    output_block = output_match.group(1)
    
    # Look for elasticsearch block
    es_match = re.search(r'elasticsearch\s*\{(.*?)\n\s*\}', output_block, re.DOTALL)
    if not es_match:
        return None
    
    es_config = es_match.group(1)
    
    # Extract configuration values
    config_data = {
        'type': 'elasticsearch',
        'data_stream': {},
        'connection': {}
    }
    
    # Extract data stream settings
    data_stream_match = re.search(r'data_stream\s*=>\s*"([^"]+)"', es_config)
    if data_stream_match:
        config_data['data_stream']['enabled'] = data_stream_match.group(1) == "true"
    
    type_match = re.search(r'data_stream_type\s*=>\s*"([^"]+)"', es_config)
    if type_match:
        config_data['data_stream']['type'] = type_match.group(1)
    
    dataset_match = re.search(r'data_stream_dataset\s*=>\s*"([^"]+)"', es_config)
    if dataset_match:
        config_data['data_stream']['dataset'] = dataset_match.group(1)
    
    namespace_match = re.search(r'data_stream_namespace\s*=>\s*"([^"]+)"', es_config)
    if namespace_match:
        config_data['data_stream']['namespace'] = namespace_match.group(1)
    
    # Extract connection settings
    hosts_match = re.search(r'hosts\s*=>\s*\[(.*?)\]', es_config)
    if hosts_match:
        hosts = re.findall(r'"([^"]+)"', hosts_match.group(1))
        config_data['connection']['hosts'] = hosts
    
    user_match = re.search(r'user\s*=>\s*"([^"]+)"', es_config)
    if user_match:
        config_data['connection']['user'] = user_match.group(1)
    
    ssl_match = re.search(r'ssl_enabled\s*=>\s*(\w+)', es_config)
    if ssl_match:
        config_data['connection']['ssl_enabled'] = ssl_match.group(1) == "true"
    
    ssl_verify_match = re.search(r'ssl_verification_mode\s*=>\s*"([^"]+)"', es_config)
    if ssl_verify_match:
        config_data['connection']['ssl_verification_mode'] = ssl_verify_match.group(1)
    
    ssl_ca_match = re.search(r'ssl_certificate_authorities\s*=>\s*\[(.*?)\]', es_config)
    if ssl_ca_match:
        ca_certs = re.findall(r'"([^"]+)"', ssl_ca_match.group(1))
        if ca_certs:
            config_data['connection']['ssl_certificate_authorities'] = ca_certs
    
    return config_data

@app.route('/')
def index():
    """Render main page"""
    return render_template('index.html')

@app.route('/api/patterns', methods=['GET'])
def get_patterns():
    """Get all available grok patterns from the patterns directory"""
    try:
        patterns = {}
        
        if os.path.exists(PATTERNS_DIR):
            for filename in os.listdir(PATTERNS_DIR):
                filepath = os.path.join(PATTERNS_DIR, filename)
                if os.path.isfile(filepath):
                    with open(filepath, 'r') as f:
                        patterns[filename] = f.read()
        
        return jsonify({
            'success': True,
            'patterns': patterns,
            'patterns_dir': PATTERNS_DIR
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/parse', methods=['POST'])
def parse_log():
    """Parse a log entry through the Logstash configuration chain"""
    try:
        data = request.json
        log_entry = data.get('logEntry', '')
        configs = data.get('configs', [])
        input_stream = data.get('inputStream')
        event_seed = data.get('eventSeed')
        
        if not log_entry:
            return jsonify({'error': 'No log entry provided'}), 400
        
        if not configs:
            return jsonify({'error': 'No configurations provided'}), 400
        
        # Initialize parser
        parser = LogstashParser()
        
        # Initialize event
        event = {'message': log_entry}
        if isinstance(event_seed, dict):
            deep_merge_dict(event, event_seed)
            event['message'] = log_entry
        if input_stream:
            if input_stream.get('type'):
                event['type'] = input_stream['type']
            if input_stream.get('tags'):
                event['tags'] = input_stream['tags']
        
        # Process through each config using tree-based parsing
        all_steps = []
        
        for config in configs:
            # Print clear separator for config processing
            print("\n" + "*" * 80)
            print(f"*  Processing of '{config['name']}' started")
            print("*" * 80 + "\n")
            
            # Parse config to tree
            tree = parse_config_to_tree(config['content'])
            
            # Process event through tree
            config_result = {
                'config_name': config['name'],
                'tree_steps': process_tree(tree, event, parser)
            }
            all_steps.append(config_result)
            
            # Print completion
            print("\n" + "*" * 80)
            print(f"*  Processing of '{config['name']}' completed")
            print("*" * 80 + "\n")
        
        # Check for output configuration in the last config file
        output_config = None
        for config in configs:
            if 'output' in config['content'].lower():
                # Extract output configuration
                output_config = extract_output_config(config['content'])
                if output_config:
                    break
        
        # Prepare response
        response = {
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'input': {
                'logEntry': log_entry,
                'inputStream': input_stream,
                'configFiles': [{'name': c['name']} for c in configs]
            },
            'processing': {
                'configs': all_steps,
                'finalEvent': event
            },
            'output': output_config
        }
        
        return jsonify(response)
    
    except Exception as e:
        import traceback
        print(f"Error processing log: {str(e)}")
        print(traceback.format_exc())
        return jsonify({
            'error': str(e),
            'traceback': traceback.format_exc()
        }), 500


def process_tree(nodes, event, parser, depth=0):
    """Process event through tree structure recursively"""
    import copy
    results = []
    conditional_matched = False  # Track if any conditional in THIS LEVEL's chain has matched
    
    for node in nodes:
        if node['type'] == 'conditional':
            # Check if this is part of the same if/else chain by looking at condition_type
            # Reset conditional_matched for new 'if' blocks (not else_if or else)
            if node.get('condition_type') == 'if':
                conditional_matched = False
            
            # If a previous conditional in this chain matched, skip remaining ones
            if conditional_matched and node.get('condition_type') in ['else_if', 'else']:
                # Still show structure but don't execute
                print(f"[PROCESS_TREE] Skipping conditional (previous matched): {node.get('condition')}")
                step = {
                    'type': 'conditional',
                    'condition': node['condition'],
                    'condition_type': node.get('condition_type', 'if'),
                    'line': node.get('line'),
                    'depth': depth,
                    'matched': False,
                    'executed': False,
                    'event_before': copy.deepcopy(event),
                    'skipped_reason': 'Previous condition matched',
                    'children': get_tree_structure(node.get('children', []), depth + 1)
                }
                results.append(step)
                continue
            
            # Evaluate condition
            print(f"[PROCESS_TREE] Evaluating conditional at line {node.get('line')}: {node['condition']}")
            condition_result = evaluate_condition(node['condition'], event)
            print(f"[PROCESS_TREE] Condition result: {condition_result}")
            
            step = {
                'type': 'conditional',
                'condition': node['condition'],
                'condition_type': node.get('condition_type', 'if'),
                'line': node.get('line'),
                'depth': depth,
                'matched': condition_result,
                'event_before': copy.deepcopy(event),
                'children': []
            }
            
            # If condition is true, process children
            if condition_result:
                print(f"[PROCESS_TREE] Processing {len(node.get('children', []))} children of matched conditional")
                step['children'] = process_tree(node.get('children', []), event, parser, depth + 1)
                step['executed'] = True
                conditional_matched = True  # Mark that we found a match
            else:
                step['executed'] = False
                # Still show the structure but mark as skipped
                step['children'] = get_tree_structure(node.get('children', []), depth + 1)
            
            results.append(step)
            
        elif node['type'] == 'filter':
            # Apply filter - use deep copy to capture true before state
            print(f"[PROCESS_TREE] Executing filter '{node['filter_type']}' at line {node.get('line')}")
            before_event = copy.deepcopy(event)
            filter_result = parser.apply_filter(node['filter_type'], node['config'], event)
            print(f"[PROCESS_TREE] Filter '{node['filter_type']}' completed with result: {filter_result.get('changes', 'Unknown')}")
            
            step = {
                'type': 'filter',
                'filter_type': node['filter_type'],
                'line': node.get('line'),
                'config': node.get('config', ''),
                'depth': depth,
                'executed': True,
                'changes': filter_result.get('changes', 'No Changes'),
                'fields_added': filter_result.get('fields_added', []),
                'fields_modified': filter_result.get('fields_modified', []),
                'fields_removed': filter_result.get('fields_removed', []),
                'tags_added': filter_result.get('tags_added', []),
                'tags_removed': filter_result.get('tags_removed', []),
                'event_before': before_event,
                'event_after': copy.deepcopy(event)
            }
            
            results.append(step)
    
    return results


def get_tree_structure(nodes, depth):
    """Get tree structure without executing (for skipped branches)"""
    structure = []
    
    for node in nodes:
        if node['type'] == 'conditional':
            step = {
                'type': 'conditional',
                'condition': node['condition'],
                'condition_type': node.get('condition_type', 'if'),
                'line': node.get('line'),
                'depth': depth,
                'executed': False,
                'matched': False,
                'skipped': True,
                'event_before': {},
                'children': get_tree_structure(node.get('children', []), depth + 1)
            }
            structure.append(step)
        elif node['type'] == 'filter':
            step = {
                'type': 'filter',
                'filter_type': node['filter_type'],
                'line': node.get('line'),
                'config': node.get('config', ''),
                'depth': depth,
                'executed': False,
                'skipped': True
            }
            structure.append(step)
    
    return structure


def evaluate_condition(condition, event):
    """Evaluate a Logstash conditional expression"""
    if condition == 'true':  # else block
        return True
    
    print(f"[CONDITION EVAL] Evaluating: '{condition}'")
    
    # Handle "value" in [field] syntax (e.g., "firewall" in [tags])
    in_match = re.match(r'"([^"]+)"\s+in\s+\[([^\]]+)\]', condition.strip())
    if in_match:
        value, field = in_match.groups()
        field_value = get_nested_field(event, field)
        print(f"[CONDITION DEBUG] 'in' operator: looking for '{value}' in field '{field}'")
        print(f"[CONDITION DEBUG] Field value: {field_value}, type: {type(field_value)}")
        if isinstance(field_value, list):
            result = value in field_value
            print(f"[CONDITION DEBUG] '{value}' in {field_value} = {result}")
            return result
        print(f"[CONDITION DEBUG] Field not a list, returning False")
        return False
    
    # Handle compound conditions with 'and' and 'or'
    if ' and ' in condition:
        parts = condition.split(' and ')
        results = [evaluate_condition(part.strip(), event) for part in parts]
        result = all(results)
        print(f"[CONDITION EVAL] AND condition: {parts} -> {results} -> {result}")
        return result
    
    if ' or ' in condition:
        parts = condition.split(' or ')
        results = [evaluate_condition(part.strip(), event) for part in parts]
        result = any(results)
        print(f"[CONDITION EVAL] OR condition: {parts} -> {results} -> {result}")
        return result
    
    # Handle negated field existence: ![field_name]
    if condition.strip().startswith('!'):
        negated_condition = condition.strip()[1:]
        result = not evaluate_condition(negated_condition, event)
        print(f"[CONDITION EVAL] NOT condition: !({negated_condition}) -> {result}")
        return result
    
    # Handle field existence: [field_name] or [nested][field]
    if re.match(r'^\[[^\]]+(?:\]\[[^\]]+)*\]$', condition.strip()):
        field_ref = condition.strip()
        field_name = field_ref[1:-1]  # Remove outer brackets
        field_value = get_nested_field(event, field_name)
        result = field_value is not None
        print(f"[CONDITION EVAL] Field existence: {field_ref} -> {result}")
        return result
    
    # Handle equality: [field] == "value" or [nested][field] == "value"
    eq_match = re.match(r'(\[[^\]]+(?:\]\[[^\]]+)*\])\s*==\s*"([^"]*)"', condition)
    if eq_match:
        field_ref, value = eq_match.groups()
        field_name = field_ref[1:-1]  # Remove outer brackets
        field_value = get_nested_field(event, field_name)
        return str(field_value) == value if field_value is not None else False
    
    # Handle regex match: [field] =~ /pattern/ or [nested][field] =~ /pattern/
    # Also handle negative regex match: [field] !~ /pattern/
    regex_match = re.match(r'(\[[^\]]+(?:\]\[[^\]]+)*\])\s*(=~|!~)\s*/([^/]+)/', condition)
    if regex_match:
        field_ref, operator, pattern = regex_match.groups()
        # Extract field name from [field] or [nested][field] format
        field_name = field_ref[1:-1]  # Remove outer brackets
        field_value = get_nested_field(event, field_name)
        print(f"[CONDITION DEBUG] Regex match: field_ref={field_ref}, operator={operator}, field_name={field_name}, pattern={pattern}, value={field_value}")
        if field_value is not None:
            try:
                match_result = bool(re.search(pattern, str(field_value)))
                # Invert result for negative match (!~)
                result = match_result if operator == '=~' else not match_result
                print(f"[CONDITION DEBUG] Regex result: {result} (match={match_result}, operator={operator})")
                return result
            except Exception as e:
                print(f"[CONDITION DEBUG] Regex error: {e}")
                return False
        print(f"[CONDITION DEBUG] Field value is None, returning {'True' if operator == '!~' else 'False'}")
        return operator == '!~'  # If field doesn't exist, !~ returns True, =~ returns False
    
    # Handle inequality: [field] != "value" or [nested][field] != "value"
    neq_match = re.match(r'(\[[^\]]+(?:\]\[[^\]]+)*\])\s*!=\s*"([^"]*)"', condition)
    if neq_match:
        field_ref, value = neq_match.groups()
        field_name = field_ref[1:-1]  # Remove outer brackets
        field_value = get_nested_field(event, field_name)
        return str(field_value) != value if field_value is not None else True
    
    # Default: condition not recognized
    return False


def get_nested_field(event, field_path):
    """Get a nested field value from event using bracket notation"""
    # Handle nested fields like [log][syslog][priority]
    # field_path could be "log][syslog][appname" or "log" or "message"
    
    # If field_path already has brackets, extract parts directly
    if '][' in field_path:
        # field_path is like "log][syslog][appname"
        parts = re.findall(r'\[([^\]]+)\]', '[' + field_path + ']')
    elif field_path.startswith('['):
        # field_path is like "[log][syslog][appname]"
        parts = re.findall(r'\[([^\]]+)\]', field_path)
    else:
        # Simple field like "message" or "log"
        parts = [field_path]
    
    print(f"[GET_NESTED_FIELD] field_path: '{field_path}' -> parts: {parts}")
    
    current = event
    for part in parts:
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            print(f"[GET_NESTED_FIELD] Failed at part '{part}', current type: {type(current)}, keys: {current.keys() if isinstance(current, dict) else 'N/A'}")
            return None
    
    print(f"[GET_NESTED_FIELD] Success! Returned: {current}")
    return current


@app.route('/api/validate-config', methods=['POST'])
def validate_config():
    """Validate a Logstash configuration"""
    try:
        data = request.json
        config_text = data.get('config', '')
        
        parser = LogstashParser()
        filters = parser.parse_config(config_text)
        
        return jsonify({
            'valid': True,
            'filterCount': len(filters),
            'filters': [{'type': f['type'], 'hasCondition': f.get('condition') is not None} for f in filters]
        })
    
    except Exception as e:
        return jsonify({'valid': False, 'error': str(e)}), 400

@app.route('/api/parse_pcap', methods=['POST'])
def parse_pcap():
    """Parse PCAP file and extract syslog messages"""
    try:
        if 'pcap' not in request.files:
            return jsonify({'error': 'No PCAP file provided'}), 400
        
        pcap_file = request.files['pcap']
        if pcap_file.filename == '':
            return jsonify({'error': 'Empty filename'}), 400
        
        # Save temporarily
        import tempfile
        with tempfile.NamedTemporaryFile(delete=False, suffix='.pcap') as tmp:
            pcap_file.save(tmp.name)
            tmp_path = tmp.name
        
        logs = []
        
        try:
            # Try using scapy
            from scapy.all import rdpcap, Raw, IP, IPv6
            packets = rdpcap(tmp_path)

            def ip_endpoints(pkt):
                src_ip = None
                dst_ip = None
                if pkt.haslayer(IP):
                    src_ip = pkt[IP].src
                    dst_ip = pkt[IP].dst
                elif pkt.haslayer(IPv6):
                    src_ip = pkt[IPv6].src
                    dst_ip = pkt[IPv6].dst
                return src_ip, dst_ip

            for pkt in packets:
                if not pkt.haslayer(Raw):
                    continue

                payload = bytes(pkt[Raw].load)
                src_ip, dst_ip = ip_endpoints(pkt)
                timestamp = pkt.time if hasattr(pkt, 'time') else None

                # Syslog/text extraction path
                try:
                    payload_str = payload.decode('utf-8', errors='ignore').strip()

                    if not payload_str or len(payload_str) < 10:
                        continue

                    if '<' in payload_str[:10] or any(keyword in payload_str[:120] for keyword in ['filterlog', 'dhcpd', 'unbound', 'suricata', 'php-fpm', 'openvpn', 'sshd']):
                        logs.append({
                            'payload': payload_str,
                            'timestamp': timestamp,
                            'src_ip': src_ip,
                            'dst_ip': dst_ip,
                        })
                except Exception:
                    continue
        except ImportError:
            # Fallback: simple hex dump extraction (basic implementation)
            with open(tmp_path, 'rb') as f:
                content = f.read()
                # Look for syslog-like patterns in the binary data
                text = content.decode('utf-8', errors='ignore')
                # Extract lines that look like syslog
                for line in text.split('\n'):
                    line = line.strip()
                    if line and '<' in line[:10]:
                        logs.append({
                            'payload': line,
                            'timestamp': None,
                            'src_ip': None,
                            'dst_ip': None
                        })
        finally:
            # Clean up temp file
            os.unlink(tmp_path)
        
        return jsonify({
            'success': True,
            'logs': logs,
            'count': len(logs)
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=8080)
