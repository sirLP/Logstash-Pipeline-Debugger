"""
Python-based Logstash Configuration Parser
Handles conditional logic, filters, and log processing
"""
import re
import json
from typing import List, Dict, Any, Optional
from pygrok import Grok
from copy import deepcopy


class LogstashParser:
    """Parse and process Logstash configurations"""
    
    def __init__(self):
        self.grok_patterns = self._init_grok_patterns()
    
    def _init_grok_patterns(self) -> Dict[str, str]:
        """Initialize common Grok patterns"""
        return {
            # Base patterns
            'USERNAME': r'[a-zA-Z0-9._-]+',
            'USER': r'%{USERNAME}',
            'INT': r'(?:[+-]?(?:[0-9]+))',
            'BASE10NUM': r'(?<![0-9.+-])(?>[+-]?(?:(?:[0-9]+(?:\.[0-9]+)?)|(?:\.[0-9]+)))',
            'NUMBER': r'(?:%{BASE10NUM})',
            'WORD': r'\b\w+\b',
            'NOTSPACE': r'\S+',
            'SPACE': r'\s*',
            'DATA': r'.*?',
            'GREEDYDATA': r'.*',
            
            # Network patterns
            'IPV4': r'(?<![0-9])(?:(?:[0-1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5])[.](?:[0-1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5])[.](?:[0-1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5])[.](?:[0-1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5]))(?![0-9])',
            'IP': r'(?:%{IPV4})',
            'HOSTNAME': r'\b(?:[0-9A-Za-z][0-9A-Za-z-]{0,62})(?:\.(?:[0-9A-Za-z][0-9A-Za-z-]{0,62}))*(?:\.|)?',
            'IPORHOST': r'(?:%{IP}|%{HOSTNAME})',
            'POSINT': r'\b(?:[1-9][0-9]*)\b',
            'NONNEGINT': r'\b(?:[0-9]+)\b',
            'PORT': r'%{POSINT}',
            
            # Syslog patterns
            'SYSLOGTIMESTAMP': r'(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) +[0-9]{1,2} [0-9]{2}:[0-9]{2}:[0-9]{2}',
            'SYSLOGPROG': r'[\w._/-]+',
            'SYSLOGHOST': r'%{IPORHOST}',
            
            # Timestamp patterns
            'TIMESTAMP_ISO8601': r'%{YEAR}-%{MONTHNUM}-%{MONTHDAY}[T ]%{HOUR}:?%{MINUTE}(?::?%{SECOND})?%{ISO8601_TIMEZONE}?',
            'YEAR': r'(?:\d{4})',
            'MONTHNUM': r'(?:0?[1-9]|1[0-2])',
            'MONTHDAY': r'(?:(?:0[1-9])|(?:[12][0-9])|(?:3[01])|[1-9])',
            'HOUR': r'(?:2[0123]|[01]?[0-9])',
            'MINUTE': r'(?:[0-5][0-9])',
            'SECOND': r'(?:(?:[0-5]?[0-9]|60)(?:[:.,][0-9]+)?)',
            'ISO8601_TIMEZONE': r'(?:Z|[+-]%{HOUR}(?::?%{MINUTE}))',
            
            # MAC address
            'MAC': r'(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}',
        }
    
    def parse_config(self, config_text: str) -> List[Dict[str, Any]]:
        """Parse Logstash configuration and extract filters"""
        # Extract filter block
        filter_match = re.search(r'filter\s*\{(.*)\}', config_text, re.DOTALL)
        if not filter_match:
            return []
        
        filter_block = filter_match.group(1)
        filters = []
        
        # Parse the filter block recursively
        self._parse_filter_block(filter_block, filters, None)
        
        return filters
    
    def _parse_filter_block(self, text: str, filters: List[Dict], condition: Optional[Dict]):
        """Recursively parse filter blocks with conditional logic"""
        # Extract top-level conditional blocks
        blocks = self._extract_conditional_blocks(text)
        
        if blocks:
            # Process each conditional block
            for block in blocks:
                if block['type'] in ['if', 'else_if']:
                    parsed_condition = self._parse_condition(block['condition'])
                    self._parse_filter_block(block['content'], filters, parsed_condition)
                elif block['type'] == 'else':
                    self._parse_filter_block(block['content'], filters, {'type': 'else', 'original': 'else'})
            
            # Remove conditional blocks to get remaining top-level filters
            cleaned_text = text
            for block in sorted(blocks, key=lambda x: x['start'], reverse=True):
                cleaned_text = cleaned_text[:block['start']] + cleaned_text[block['end']:]
            
            # Extract remaining filters
            if cleaned_text.strip():
                self._extract_filters(cleaned_text, filters, condition)
        else:
            # No conditionals, extract all filters
            self._extract_filters(text, filters, condition)
    
    def _extract_conditional_blocks(self, text: str) -> List[Dict[str, Any]]:
        """Extract if/else/else-if blocks from text"""
        blocks = []
        pos = 0
        
        while pos < len(text):
            # Skip whitespace
            while pos < len(text) and text[pos].isspace():
                pos += 1
            
            if pos >= len(text):
                break
            
            remaining = text[pos:]
            
            # Try to match conditional keywords
            # Use more careful regex to capture condition including regex patterns
            else_if_match = re.match(r'else\s+if\s+(.+?)\s*\{', remaining)
            if_match = re.match(r'if\s+(.+?)\s*\{', remaining)
            else_match = re.match(r'else\s*\{', remaining)
            
            match = None
            block_type = None
            condition = None
            
            if else_if_match:
                match = else_if_match
                block_type = 'else_if'
                condition = else_if_match.group(1).strip()
                print(f"[CONDITION PARSE] else_if condition: '{condition}'")
            elif if_match:
                match = if_match
                block_type = 'if'
                condition = if_match.group(1).strip()
                print(f"[CONDITION PARSE] if condition: '{condition}' from remaining: '{remaining[:100]}'")
            elif else_match:
                match = else_match
                block_type = 'else'
            else:
                # Check if this is a filter plugin
                filter_match = re.match(r'(\w+)\s*\{', remaining)
                if filter_match:
                    # Skip past this filter
                    open_brace = pos + filter_match.end() - 1
                    close_brace = self._find_matching_brace(text, open_brace)
                    if close_brace != -1:
                        pos = close_brace + 1
                        continue
                pos += 1
                continue
            
            if match:
                start_pos = pos
                open_brace = pos + match.end() - 1
                close_brace = self._find_matching_brace(text, open_brace)
                
                if close_brace != -1:
                    content = text[open_brace + 1:close_brace]
                    blocks.append({
                        'type': block_type,
                        'condition': condition,
                        'content': content,
                        'start': start_pos,
                        'end': close_brace + 1
                    })
                    pos = close_brace + 1
                else:
                    pos += 1
        
        return blocks
    
    def _find_matching_brace(self, text: str, open_pos: int) -> int:
        """Find the matching closing brace for an opening brace, ignoring braces in strings/regex"""
        depth = 1
        pos = open_pos + 1
        in_string = False
        in_regex = False
        string_char = None
        escape_next = False
        
        while pos < len(text) and depth > 0:
            char = text[pos]
            
            # Handle escape sequences
            if escape_next:
                escape_next = False
                pos += 1
                continue
            
            if char == '\\':
                escape_next = True
                pos += 1
                continue
            
            # Handle strings
            if char in ['"', "'"]:
                if not in_regex:
                    if not in_string:
                        in_string = True
                        string_char = char
                    elif char == string_char:
                        in_string = False
                        string_char = None
            
            # Handle regex patterns /.../ 
            elif char == '/':
                # Check if this looks like a regex pattern (preceded by =~ or !~)
                before = text[max(0, pos-10):pos].strip()
                if before.endswith('=~') or before.endswith('!~'):
                    in_regex = not in_regex
            
            # Only count braces if not in string or regex
            elif not in_string and not in_regex:
                if char == '{':
                    depth += 1
                elif char == '}':
                    depth -= 1
            
            if depth == 0:
                return pos
            pos += 1
        
        return -1
    
    def _extract_filters(self, text: str, filters: List[Dict], condition: Optional[Dict], parent_condition: Optional[Dict] = None):
        """Extract filter plugins from text"""
        pos = 0
        
        while pos < len(text):
            # Look for filter plugin
            match = re.match(r'\s*(\w+)\s*\{', text[pos:])
            if not match:
                pos += 1
                continue
            
            filter_type = match.group(1)
            
            # Skip conditional keywords
            if filter_type in ['if', 'else']:
                pos += 1
                continue
            
            open_brace = pos + match.end() - 1
            close_brace = self._find_matching_brace(text, open_brace)
            
            if close_brace != -1:
                config = text[open_brace + 1:close_brace].strip()
                
                filters.append({
                    'type': filter_type,
                    'config': config,
                    'condition': condition,
                    'parent_condition': parent_condition,  # Track parent for skip logic
                    'parsed_config': self._parse_filter_config(filter_type, config)
                })
                
                pos = close_brace + 1
            else:
                pos += 1
    
    def _parse_filter_config(self, filter_type: str, config: str) -> Dict[str, Any]:
        """Parse individual filter configuration"""
        parsed = {}
        
        if filter_type == 'grok':
            parsed['patterns'] = self._extract_grok_patterns(config)
        elif filter_type == 'mutate':
            parsed['operations'] = self._extract_mutate_operations(config)
        elif filter_type == 'csv':
            parsed['csv_config'] = self._extract_csv_config(config)
        elif filter_type == 'date':
            parsed['date_config'] = self._extract_date_config(config)
        elif filter_type == 'json':
            parsed['json_config'] = self._extract_json_config(config)
        else:
            parsed['raw'] = config
        
        return parsed
    
    def _extract_grok_patterns(self, config: str) -> List[Dict[str, str]]:
        """Extract grok patterns from configuration"""
        patterns = []
        matches = re.finditer(r'match\s*=>\s*\{\s*"([^"]+)"\s*=>\s*"([^"]+)"\s*\}', config)
        for match in matches:
            patterns.append({
                'field': match.group(1),
                'pattern': match.group(2)
            })
        return patterns
    
    def _extract_mutate_operations(self, config: str) -> Dict[str, str]:
        """Extract mutate operations from configuration"""
        operations = {}
        op_types = ['add_field', 'add_tag', 'remove_tag', 'remove_field', 'rename', 'replace', 'convert']
        
        for op_type in op_types:
            pattern = rf'{op_type}\s*=>\s*(.+?)(?=\n\s*\w+\s*=>|\}})'
            match = re.search(pattern, config, re.DOTALL)
            if match:
                operations[op_type] = match.group(1).strip()
        
        return operations
    
    def _extract_csv_config(self, config: str) -> Dict[str, Any]:
        """Extract CSV configuration"""
        result = {}
        
        # Extract source field
        source_match = re.search(r'source\s*=>\s*"([^"]+)"', config)
        if source_match:
            result['source'] = source_match.group(1)
        
        # Extract columns
        columns_match = re.search(r'columns\s*=>\s*\[(.*?)\]', config, re.DOTALL)
        if columns_match:
            columns_text = columns_match.group(1)
            result['columns'] = [c.strip().strip('"') for c in columns_text.split(',')]
        
        return result
    
    def _extract_date_config(self, config: str) -> Dict[str, Any]:
        """Extract date configuration"""
        result = {}
        
        match_field = re.search(r'match\s*=>\s*\[\s*"([^"]+)"\s*,\s*"([^"]+)"\s*\]', config)
        if match_field:
            result['field'] = match_field.group(1)
            result['format'] = match_field.group(2)
        
        target = re.search(r'target\s*=>\s*"([^"]+)"', config)
        if target:
            result['target'] = target.group(1)
        else:
            result['target'] = '@timestamp'
        
        return result
    
    def _extract_json_config(self, config: str) -> Dict[str, Any]:
        """Extract JSON configuration"""
        result = {}
        
        source_match = re.search(r'source\s*=>\s*"([^"]+)"', config)
        if source_match:
            result['source'] = source_match.group(1)
        
        target_match = re.search(r'target\s*=>\s*"([^"]+)"', config)
        if target_match:
            result['target'] = target_match.group(1)
        
        add_tag_match = re.search(r'add_tag\s*=>\s*"([^"]+)"', config)
        if add_tag_match:
            result['add_tag'] = add_tag_match.group(1)
        
        return result
    
    def apply_filter(self, filter_type: str, config: str, event: Dict[str, Any]) -> Dict[str, Any]:
        """Apply a filter to an event"""
        result = {
            'filter_type': filter_type,
            'changes': 'No Changes',
            'fields_added': [],
            'fields_modified': []
        }
        
        try:
            if filter_type == 'grok':
                result.update(self._apply_grok(config, event))
            elif filter_type == 'mutate':
                result.update(self._apply_mutate(config, event))
            elif filter_type == 'json':
                result.update(self._apply_json(config, event))
            elif filter_type == 'date':
                result.update(self._apply_date(config, event))
            elif filter_type == 'geoip':
                result.update(self._apply_geoip(config, event))
            elif filter_type == 'translate':
                result.update(self._apply_translate(config, event))
            elif filter_type == 'cidr':
                result.update(self._apply_cidr(config, event))
            elif filter_type == 'dns':
                result.update(self._apply_dns(config, event))
            # Add more filter types as needed
        except Exception as e:
            import traceback
            print(f"[FILTER ERROR] Exception in {filter_type} filter: {str(e)}")
            print(f"[FILTER ERROR] Traceback:\n{traceback.format_exc()}")
            result['error'] = str(e)
            result['changes'] = 'Error'
        
        return result
    
    def _apply_grok(self, config: str, event: Dict[str, Any]) -> Dict[str, Any]:
        """Apply grok filter using pygrok library with support for nested field names"""
        import re
        import os
        
        fields_added = []
        fields_modified = []
        tags_added = []
        
        # Extract match configuration
        # Format can be:
        # match => { "field" => "pattern" }  OR
        # match => [ "field", "pattern1", "pattern2", ... ]  (try patterns in order)
        
        field_name = None
        grok_patterns = []
        
        print(f"[GROK DEBUG] Config text for pattern extraction: {config[:500]}")
        
        # Try hash format first
        match_pattern = re.search(r'match\s*=>\s*\{\s*"([^"]+)"\s*=>\s*"(.+?)"\s*\}', config, re.DOTALL)
        if match_pattern:
            field_name, pattern = match_pattern.groups()
            grok_patterns = [pattern]
            print(f"[GROK DEBUG] Found hash format match")
        else:
            # Try array format with multiple patterns
            # Format: match => [ "field", "pattern1", "pattern2", ... ]
            # Need to match the entire array, so find the matching closing bracket
            # Use a more careful approach to handle brackets inside quoted strings
            array_start = re.search(r'match\s*=>\s*\[', config)
            if array_start:
                # Find the matching closing bracket by counting bracket depth
                # but only outside of quoted strings
                start_pos = array_start.end()
                bracket_depth = 1
                in_quotes = False
                escape_next = False
                end_pos = start_pos
                
                for i, char in enumerate(config[start_pos:], start=start_pos):
                    if escape_next:
                        escape_next = False
                        continue
                    if char == '\\':
                        escape_next = True
                        continue
                    if char == '"' and not escape_next:
                        in_quotes = not in_quotes
                    elif not in_quotes:
                        if char == '[':
                            bracket_depth += 1
                        elif char == ']':
                            bracket_depth -= 1
                            if bracket_depth == 0:
                                end_pos = i
                                break
                
                if bracket_depth == 0:
                    # Extract the content between the brackets
                    array_content = config[start_pos:end_pos]
                    # Extract all quoted strings
                    all_quoted = re.findall(r'"([^"\\]*(?:\\.[^"\\]*)*)"', array_content)
                    if all_quoted:
                        field_name = all_quoted[0]
                        grok_patterns = all_quoted[1:]
                        print(f"[GROK DEBUG] Array format matched - field: {field_name}, patterns: {len(grok_patterns)}")
        
        if not field_name or not grok_patterns:
            print(f"[GROK DEBUG] No match pattern found in config: {config[:200]}")
            return {'changes': 'No Changes', 'fields_added': [], 'fields_modified': []}
        
        print(f"[GROK DEBUG] Field: {field_name}")
        print(f"[GROK DEBUG] Patterns to try: {grok_patterns}")
        
        # Get the field value to parse
        field_value = self._get_nested_field(event, field_name)
        
        if field_value is None:
            print(f"[GROK DEBUG] Field '{field_name}' not found in event")
            return {'changes': 'No Changes', 'fields_added': [], 'fields_modified': []}
        
        print(f"[GROK DEBUG] Parsing value: {str(field_value)[:200]}")
        
        # Try each pattern in order until one matches
        for pattern_index, grok_pattern in enumerate(grok_patterns):
            print(f"[GROK DEBUG] Trying pattern {pattern_index + 1}/{len(grok_patterns)}: {grok_pattern[:100]}")
            
            try:
                # Convert nested field names in pattern to simple names and create mapping
                # e.g., [log][syslog][priority] -> log_syslog_priority
                field_mapping = {}  # Maps simple_name -> nested_name
                simplified_pattern = grok_pattern
                
                # Find all field names in the pattern like %{TYPE:field_name}
                field_refs = re.findall(r'%\{[^:]+:([^\}]+)\}', grok_pattern)
            
                for field_ref in field_refs:
                    if '[' in field_ref and ']' in field_ref:
                        # This is a nested field like [log][syslog][priority]
                        # Convert to simple name: log_syslog_priority
                        simple_name = field_ref.replace('[', '').replace(']', '_').strip('_')
                        field_mapping[simple_name] = field_ref
                        
                        # Replace in pattern
                        simplified_pattern = simplified_pattern.replace(f':{field_ref}', f':{simple_name}')
                
                # Also handle Oniguruma named capture groups with brackets: (?<[field][name]>...)
                # Convert to Python-compatible: (?<field_name>...)
                named_captures = re.findall(r'\(\?<(\[[^\]]+\](?:\[[^\]]+\])*?)>', grok_pattern)
                for nested_field in named_captures:
                    simple_name = nested_field.replace('[', '').replace(']', '_').strip('_')
                    field_mapping[simple_name] = nested_field
                    # Replace in pattern
                    simplified_pattern = simplified_pattern.replace(f'(?<{nested_field}>', f'(?<{simple_name}>')
                
                print(f"[GROK DEBUG] Simplified pattern: {simplified_pattern[:200]}")
                print(f"[GROK DEBUG] Field mapping: {field_mapping}")
                
                # Load custom patterns from patterns directory
                patterns_dir = os.path.join(os.path.dirname(__file__), 'patterns')
                custom_patterns = {}
                
                # Load all pattern files and merge them into a dictionary
                if os.path.exists(patterns_dir):
                    for filename in os.listdir(patterns_dir):
                        if filename.startswith('.') or filename == 'README.md':
                            continue
                        filepath = os.path.join(patterns_dir, filename)
                        if os.path.isfile(filepath):
                            print(f"[GROK DEBUG] Loading patterns from: {filename}")
                            try:
                                with open(filepath, 'r') as f:
                                    for line in f:
                                        line = line.strip()
                                        # Skip comments and empty lines
                                        if not line or line.startswith('#'):
                                            continue
                                        # Pattern format: NAME regex_pattern
                                        parts = line.split(None, 1)
                                        if len(parts) == 2:
                                            pattern_name, pattern_value = parts
                                            # Convert nested field names to simple names for pygrok
                                            # e.g., [process][pgid] -> process_pgid
                                            # Also track these in field_mapping for proper conversion back
                                            simplified_pattern_def = pattern_value
                                            
                                            # Handle standard Grok syntax: %{TYPE:[field][name]}
                                            nested_fields = re.findall(r'%\{[^:]+:(\[[^\]]+\](?:\[[^\]]+\])*)\}', pattern_value)
                                            for nested_field in nested_fields:
                                                simple_name = nested_field.replace('[', '').replace(']', '_').rstrip('_')
                                                simplified_pattern_def = simplified_pattern_def.replace(f':{nested_field}', f':{simple_name}')
                                                # Add to field_mapping so we know to convert back
                                                field_mapping[simple_name] = nested_field
                                            
                                            # Handle Oniguruma named capture groups: (?<[field][name]>...)
                                            onig_fields = re.findall(r'\(\?<(\[[^\]]+\](?:\[[^\]]+\])*?)>', pattern_value)
                                            for nested_field in onig_fields:
                                                simple_name = nested_field.replace('[', '').replace(']', '_').strip('_')
                                                simplified_pattern_def = simplified_pattern_def.replace(f'(?<{nested_field}>', f'(?<{simple_name}>')
                                                # Add to field_mapping so we know to convert back
                                                field_mapping[simple_name] = nested_field
                                            
                                            custom_patterns[pattern_name] = simplified_pattern_def
                                            print(f"[GROK DEBUG]   Loaded pattern: {pattern_name}")
                            except Exception as e:
                                print(f"[GROK DEBUG] Error loading {filename}: {e}")
                
                print(f"[GROK DEBUG] Total custom patterns loaded: {len(custom_patterns)}")
                if 'UNBOUND' in custom_patterns:
                    print(f"[GROK DEBUG] UNBOUND pattern: {custom_patterns['UNBOUND']}")
                if 'UNBOUND_RESOLVING' in custom_patterns:
                    print(f"[GROK DEBUG] UNBOUND_RESOLVING pattern: {custom_patterns['UNBOUND_RESOLVING']}")
                if 'KEADHCP4' in custom_patterns:
                    print(f"[GROK DEBUG] KEADHCP4 pattern: {custom_patterns['KEADHCP4']}")
                if 'KEADHCP_EXECUTE' in custom_patterns:
                    print(f"[GROK DEBUG] KEADHCP_EXECUTE pattern: {custom_patterns['KEADHCP_EXECUTE']}")
                if 'LOGLEVEL' in custom_patterns:
                    print(f"[GROK DEBUG] LOGLEVEL pattern found: {custom_patterns['LOGLEVEL']}")
                else:
                    print(f"[GROK DEBUG] LOGLEVEL pattern NOT found - this might be the issue!")
                
                # Use pygrok to parse the pattern with simplified field names
                from pygrok import Grok
                print(f"[GROK DEBUG] Creating Grok with pattern: {simplified_pattern[:100]}")
                print(f"[GROK DEBUG] Using custom_patterns: {bool(custom_patterns)}")
                grok = Grok(simplified_pattern, custom_patterns=custom_patterns if custom_patterns else None)
                match_result = grok.match(str(field_value))
                print(f"[GROK DEBUG] Match result: {match_result}")
                
                if match_result:
                    # Add matched fields to event, applying nesting where needed
                    for key, value in match_result.items():
                        if value is not None:
                            # Check if this was a nested field that we simplified
                            if key in field_mapping:
                                # Use the original nested field name from the main pattern
                                nested_field = field_mapping[key]
                                self._set_nested_field(event, nested_field, value)
                                fields_added.append(nested_field)
                            else:
                                # Regular field - keep as-is
                                # Note: Fields from custom patterns with brackets would have been
                                # added to field_mapping during pattern loading, so they're handled above
                                if key in event:
                                    fields_modified.append(key)
                                else:
                                    fields_added.append(key)
                                event[key] = value
                    
                    print(f"[GROK DEBUG] Fields added: {fields_added}, modified: {fields_modified}")
                    
                    # Check for add_tag directive
                    add_tag_match = re.search(r'add_tag\s*=>\s*"([^"]+)"', config)
                    if add_tag_match:
                        tag_name = add_tag_match.group(1)
                        if 'tags' not in event:
                            event['tags'] = []
                        if tag_name not in event['tags']:
                            event['tags'].append(tag_name)
                            tags_added.append(tag_name)
                            print(f"[GROK DEBUG] Added tag: {tag_name}")
                    
                    if fields_added or fields_modified or tags_added:
                        return {
                            'changes': 'Fields Added' if fields_added else 'Fields Modified',
                            'fields_added': fields_added,
                            'fields_modified': fields_modified,
                            'tags_added': tags_added
                        }
            except Exception as e:
                # If this pattern fails, try the next one
                print(f"[GROK DEBUG] Pattern {pattern_index + 1} failed: {str(e)}")
                import traceback
                traceback.print_exc()
                continue
        
        # No patterns matched
        print(f"[GROK DEBUG] No match found (tried {len(grok_patterns)} patterns)")
        return {'changes': 'No Changes', 'fields_added': [], 'fields_modified': [], 'tags_added': []}
    
    def _apply_mutate(self, config: str, event: Dict[str, Any]) -> Dict[str, Any]:
        """Apply mutate filter with all supported operations"""
        fields_added = []
        fields_modified = []
        fields_removed = []
        tags_added = []
        tags_removed = []
        
        print(f"[MUTATE DEBUG] Config string (first 500 chars): {config[:500]}")
        
        # add_field - Add new fields (with field reference expansion)
        # Use a more complex regex that handles nested {} in field references like %{[field][0]}
        add_field_match = re.search(r'add_field\s*=>\s*\{((?:[^{}]|\{[^}]*\})*)\}', config, re.DOTALL)
        if add_field_match:
            fields_str = add_field_match.group(1)
            print(f"[MUTATE DEBUG] Found add_field block: {fields_str[:200]}")
            field_pairs = re.findall(r'"([^"]+)"\s*=>\s*"([^"]+)"', fields_str, re.DOTALL)
            print(f"[MUTATE DEBUG] add_field found {len(field_pairs)} pairs")
            for field, value in field_pairs:
                # Expand field references like %{field} or %{[array][0]}
                expanded_value = self._expand_field_references(value, event)
                print(f"[MUTATE DEBUG] {field} = '{value}' -> '{expanded_value}'")
                self._set_nested_field(event, field, expanded_value)
                fields_added.append(field)
        else:
            print(f"[MUTATE DEBUG] No add_field match found")
        
        # replace - Replace field values (creates if doesn't exist)
        replace_match = re.search(r'replace\s*=>\s*\{([^}]+)\}', config, re.DOTALL)
        if replace_match:
            fields_str = replace_match.group(1)
            field_pairs = re.findall(r'"([^"]+)"\s*=>\s*"([^"]+)"', fields_str)
            for field, value in field_pairs:
                expanded_value = self._expand_field_references(value, event)
                if self._get_nested_field(event, field) is not None:
                    fields_modified.append(field)
                else:
                    fields_added.append(field)
                self._set_nested_field(event, field, expanded_value)
        
        # update - Update existing fields only (don't create)
        update_match = re.search(r'update\s*=>\s*\{([^}]+)\}', config)
        if update_match:
            fields_str = update_match.group(1)
            field_pairs = re.findall(r'"([^"]+)"\s*=>\s*"([^"]+)"', fields_str)
            for field, value in field_pairs:
                if self._get_nested_field(event, field) is not None:
                    self._set_nested_field(event, field, value)
                    fields_modified.append(field)
        
        # rename - Rename fields
        rename_match = re.search(r'rename\s*=>\s*\{([^}]+)\}', config)
        if rename_match:
            fields_str = rename_match.group(1)
            field_pairs = re.findall(r'"([^"]+)"\s*=>\s*"([^"]+)"', fields_str)
            for old_field, new_field in field_pairs:
                old_value = self._get_nested_field(event, old_field)
                if old_value is not None:
                    self._set_nested_field(event, new_field, old_value)
                    self._remove_nested_field(event, old_field)
                    fields_added.append(new_field)
                    fields_removed.append(old_field)
        
        # remove_field - Remove fields
        remove_field_match = re.search(r'remove_field\s*=>\s*\[([^\]]+)\]', config)
        if remove_field_match:
            fields_str = remove_field_match.group(1)
            fields_to_remove = re.findall(r'"([^"]+)"', fields_str)
            for field in fields_to_remove:
                if self._remove_nested_field(event, field):
                    fields_removed.append(field)
        
        # add_tag - Add tags (supports both string and array syntax)
        add_tag_match = re.search(r'add_tag\s*=>\s*(.+?)(?:\n|$)', config)
        if add_tag_match:
            tag_value = add_tag_match.group(1).strip()
            tags = []
            
            # Check if it's an array: ["tag1", "tag2"]
            if tag_value.startswith('['):
                tags_str = re.search(r'\[([^\]]+)\]', tag_value)
                if tags_str:
                    tags = re.findall(r'"([^"]+)"', tags_str.group(1))
            # Single string: "tag"
            else:
                single_tag = re.search(r'"([^"]+)"', tag_value)
                if single_tag:
                    tags = [single_tag.group(1)]
            
            if tags:
                if 'tags' not in event:
                    event['tags'] = []
                    fields_added.append('tags')
                elif not isinstance(event['tags'], list):
                    event['tags'] = [event['tags']]
                for tag in tags:
                    if tag not in event['tags']:
                        event['tags'].append(tag)
                        tags_added.append(tag)
        
        # remove_tag - Remove tags (supports both array and string formats)
        # Array format: remove_tag => ["tag1", "tag2"]
        remove_tag_match = re.search(r'remove_tag\s*=>\s*\[([^\]]+)\]', config)
        if remove_tag_match:
            tags_str = remove_tag_match.group(1)
            tags_to_remove = re.findall(r'"([^"]+)"', tags_str)
            if 'tags' in event and isinstance(event['tags'], list):
                for tag in tags_to_remove:
                    if tag in event['tags']:
                        tags_removed.append(tag)
                        print(f"[MUTATE DEBUG] Removing tag (array): {tag}")
                event['tags'] = [t for t in event['tags'] if t not in tags_to_remove]
        else:
            # String format: remove_tag => "tag1"
            remove_tag_match = re.search(r'remove_tag\s*=>\s*"([^"]+)"', config)
            if remove_tag_match:
                tag_to_remove = remove_tag_match.group(1)
                print(f"[MUTATE DEBUG] Found remove_tag directive: {tag_to_remove}")
                print(f"[MUTATE DEBUG] Current tags: {event.get('tags', [])}")
                if 'tags' in event and isinstance(event['tags'], list):
                    if tag_to_remove in event['tags']:
                        tags_removed.append(tag_to_remove)
                        print(f"[MUTATE DEBUG] Removing tag (string): {tag_to_remove}")
                    else:
                        print(f"[MUTATE DEBUG] Tag not found in event tags")
                    event['tags'] = [t for t in event['tags'] if t != tag_to_remove]
                    print(f"[MUTATE DEBUG] Tags after removal: {event.get('tags', [])}")
                print(f"[MUTATE DEBUG] tags_removed list: {tags_removed}")
        
        # copy - Copy field value to another field (keeps original)
        copy_match = re.search(r'copy\s*=>\s*\{([^}]+)\}', config)
        if copy_match:
            fields_str = copy_match.group(1)
            field_pairs = re.findall(r'"([^"]+)"\s*=>\s*"([^"]+)"', fields_str)
            for source_field, dest_field in field_pairs:
                source_value = self._get_nested_field(event, source_field)
                if source_value is not None:
                    self._set_nested_field(event, dest_field, source_value)
                    fields_added.append(dest_field)
        
        # convert - Convert field types
        convert_match = re.search(r'convert\s*=>\s*\{([^}]+)\}', config)
        if convert_match:
            fields_str = convert_match.group(1)
            field_pairs = re.findall(r'"([^"]+)"\s*=>\s*"([^"]+)"', fields_str)
            for field, type_name in field_pairs:
                value = self._get_nested_field(event, field)
                if value is not None:
                    converted = self._convert_type(value, type_name)
                    if converted is not None:
                        self._set_nested_field(event, field, converted)
                        fields_modified.append(field)
        
        # lowercase - Convert to lowercase
        lowercase_match = re.search(r'lowercase\s*=>\s*\[([^\]]+)\]', config)
        if lowercase_match:
            fields_str = lowercase_match.group(1)
            fields_to_lower = re.findall(r'"([^"]+)"', fields_str)
            for field in fields_to_lower:
                value = self._get_nested_field(event, field)
                if value is not None and isinstance(value, str):
                    self._set_nested_field(event, field, value.lower())
                    fields_modified.append(field)
        
        # uppercase - Convert to uppercase
        uppercase_match = re.search(r'uppercase\s*=>\s*\[([^\]]+)\]', config)
        if uppercase_match:
            fields_str = uppercase_match.group(1)
            fields_to_upper = re.findall(r'"([^"]+)"', fields_str)
            for field in fields_to_upper:
                value = self._get_nested_field(event, field)
                if value is not None and isinstance(value, str):
                    self._set_nested_field(event, field, value.upper())
                    fields_modified.append(field)
        
        # strip - Remove whitespace
        strip_match = re.search(r'strip\s*=>\s*\[([^\]]+)\]', config)
        if strip_match:
            fields_str = strip_match.group(1)
            fields_to_strip = re.findall(r'"([^"]+)"', fields_str)
            for field in fields_to_strip:
                value = self._get_nested_field(event, field)
                if value is not None and isinstance(value, str):
                    self._set_nested_field(event, field, value.strip())
                    fields_modified.append(field)
        
        # split - Split string into array
        split_match = re.search(r'split\s*=>\s*\{([^}]+)\}', config)
        if split_match:
            fields_str = split_match.group(1)
            field_pairs = re.findall(r'"([^"]+)"\s*=>\s*"([^"]+)"', fields_str)
            for field, separator in field_pairs:
                value = self._get_nested_field(event, field)
                if value is not None and isinstance(value, str):
                    self._set_nested_field(event, field, value.split(separator))
                    fields_modified.append(field)
        
        # join - Join array into string
        join_match = re.search(r'join\s*=>\s*\{([^}]+)\}', config)
        if join_match:
            fields_str = join_match.group(1)
            field_pairs = re.findall(r'"([^"]+)"\s*=>\s*"([^"]+)"', fields_str)
            for field, separator in field_pairs:
                value = self._get_nested_field(event, field)
                if value is not None and isinstance(value, list):
                    self._set_nested_field(event, field, separator.join(str(v) for v in value))
                    fields_modified.append(field)
        
        # gsub - Global string substitution (regex)
        gsub_match = re.search(r'gsub\s*=>\s*\[([^\]]+)\]', config)
        if gsub_match:
            fields_str = gsub_match.group(1)
            # Format: ["field", "pattern", "replacement"]
            parts = re.findall(r'"([^"]+)"', fields_str)
            if len(parts) >= 3:
                for i in range(0, len(parts) - 2, 3):
                    field, pattern, replacement = parts[i], parts[i+1], parts[i+2]
                    value = self._get_nested_field(event, field)
                    if value is not None and isinstance(value, str):
                        new_value = re.sub(pattern, replacement, value)
                        self._set_nested_field(event, field, new_value)
                        fields_modified.append(field)
        
        # merge - Merge arrays or hashes
        merge_match = re.search(r'merge\s*=>\s*\{([^}]+)\}', config)
        if merge_match:
            fields_str = merge_match.group(1)
            field_pairs = re.findall(r'"([^"]+)"\s*=>\s*"([^"]+)"', fields_str)
            for dest_field, source_field in field_pairs:
                dest_value = self._get_nested_field(event, dest_field)
                source_value = self._get_nested_field(event, source_field)
                if source_value is not None:
                    if isinstance(dest_value, list) and isinstance(source_value, list):
                        dest_value.extend(source_value)
                        fields_modified.append(dest_field)
                    elif isinstance(dest_value, dict) and isinstance(source_value, dict):
                        dest_value.update(source_value)
                        fields_modified.append(dest_field)
        
        if fields_added or fields_modified or fields_removed or tags_added or tags_removed:
            changes = []
            if fields_added:
                changes.append('Fields Added')
            if fields_modified:
                changes.append('Fields Modified')
            if fields_removed:
                changes.append('Fields Removed')
            if tags_added:
                changes.append('Tags Added')
            if tags_removed:
                changes.append('Tags Removed')
            
            return {
                'changes': ', '.join(changes) if changes else 'No Changes',
                'fields_added': fields_added,
                'fields_modified': fields_modified,
                'fields_removed': fields_removed,
                'tags_added': tags_added,
                'tags_removed': tags_removed
            }
        
        return {'changes': 'No Changes', 'fields_added': [], 'fields_modified': [], 'fields_removed': [], 'tags_added': [], 'tags_removed': []}
    
    def _convert_type(self, value: Any, type_name: str) -> Any:
        """Convert value to specified type"""
        try:
            if type_name == 'integer' or type_name == 'int':
                return int(value)
            elif type_name == 'float':
                return float(value)
            elif type_name == 'string':
                return str(value)
            elif type_name == 'boolean' or type_name == 'bool':
                if isinstance(value, str):
                    return value.lower() in ('true', 'yes', '1', 'on')
                return bool(value)
        except (ValueError, TypeError):
            return None
        return None
    
    def _remove_nested_field(self, event: Dict[str, Any], field_path: str) -> bool:
        """Remove a nested field, returns True if removed"""
        parts = re.findall(r'\[([^\]]+)\]', field_path)
        
        if not parts:
            # Not a nested field
            if field_path in event:
                del event[field_path]
                return True
            return False
        
        # Navigate to parent
        current = event
        for part in parts[:-1]:
            if part not in current or not isinstance(current[part], dict):
                return False
            current = current[part]
        
        # Remove the final field
        if parts[-1] in current:
            del current[parts[-1]]
            return True
        return False
    
    def _expand_field_references(self, value: str, event: Dict[str, Any]) -> str:
        """Expand field references like %{field} or %{[array][0]} in a string"""
        def replace_reference(match):
            field_ref = match.group(1)
            
            # Handle array/nested syntax: [field][subfield][0]
            if field_ref.startswith('['):
                field_value = self._get_nested_field(event, field_ref)
            else:
                # Simple field name
                field_value = event.get(field_ref)
            
            # Convert to string, return empty if None
            return str(field_value) if field_value is not None else ''
        
        # Replace all %{...} references
        expanded = re.sub(r'%\{([^}]+)\}', replace_reference, value)
        return expanded
    
    def _apply_json(self, config: str, event: Dict[str, Any]) -> Dict[str, Any]:
        """Apply JSON filter"""
        fields_added = []
        
        # Extract source field
        source_match = re.search(r'source\s*=>\s*"([^"]+)"', config)
        if not source_match:
            return {'changes': 'No Changes', 'fields_added': [], 'fields_modified': []}
        
        source_field = source_match.group(1)
        source_value = self._get_nested_field(event, source_field)
        
        if source_value is None:
            return {'changes': 'No Changes', 'fields_added': [], 'fields_modified': []}
        
        # Extract target field (optional)
        target_match = re.search(r'target\s*=>\s*"([^"]+)"', config)
        target_field = target_match.group(1) if target_match else None
        
        try:
            parsed_json = json.loads(str(source_value))
            
            if target_field:
                # Store parsed JSON in target field
                self._set_nested_field(event, target_field, parsed_json)
                fields_added.append(target_field)
            else:
                # Merge parsed JSON into event
                if isinstance(parsed_json, dict):
                    for key, value in parsed_json.items():
                        event[key] = value
                        fields_added.append(key)
            
            return {
                'changes': 'Fields Added',
                'fields_added': fields_added,
                'fields_modified': []
            }
        except json.JSONDecodeError:
            return {
                'changes': 'Error',
                'error': 'Invalid JSON',
                'fields_added': [],
                'fields_modified': []
            }
    
    def _apply_date(self, config: str, event: Dict[str, Any]) -> Dict[str, Any]:
        """Apply date filter - parse timestamp and set @timestamp field"""
        from datetime import datetime
        import dateutil.parser
        
        fields_added = []
        fields_modified = []
        
        # Extract match configuration: match => [ "field", "format" ]
        match_pattern = re.search(r'match\s*=>\s*\[\s*"([^"]+)"\s*,\s*"([^"]+)"\s*\]', config)
        if not match_pattern:
            return {'changes': 'No Changes', 'fields_added': [], 'fields_modified': []}
        
        source_field = match_pattern.group(1)
        date_format = match_pattern.group(2)
        
        # Get source value
        source_value = self._get_nested_field(event, source_field)
        if source_value is None:
            return {'changes': 'No Changes', 'fields_added': [], 'fields_modified': []}
        
        # Extract target field (default is @timestamp)
        target_match = re.search(r'target\s*=>\s*"([^"]+)"', config)
        target_field = target_match.group(1) if target_match else '@timestamp'
        
        try:
            # Parse the timestamp based on format
            if date_format == 'ISO8601':
                # Use dateutil for flexible ISO8601 parsing
                parsed_date = dateutil.parser.isoparse(str(source_value))
            elif date_format == 'UNIX':
                # Unix timestamp (seconds since epoch)
                parsed_date = datetime.fromtimestamp(float(source_value))
            elif date_format == 'UNIX_MS':
                # Unix timestamp in milliseconds
                parsed_date = datetime.fromtimestamp(float(source_value) / 1000.0)
            else:
                # Use strftime format
                parsed_date = datetime.strptime(str(source_value), date_format)
            
            # Convert to ISO8601 string (Elasticsearch/Logstash standard)
            iso_timestamp = parsed_date.isoformat()
            
            # Set the target field
            if target_field in event:
                fields_modified.append(target_field)
            else:
                fields_added.append(target_field)
            
            self._set_nested_field(event, target_field, iso_timestamp)
            
            return {
                'changes': 'Fields Added' if fields_added else 'Fields Modified',
                'fields_added': fields_added,
                'fields_modified': fields_modified
            }
        except (ValueError, TypeError) as e:
            # Date parsing failed
            return {
                'changes': 'Error',
                'error': f'Failed to parse date: {str(e)}',
                'fields_added': [],
                'fields_modified': []
            }
    
    def _apply_geoip(self, config: str, event: Dict[str, Any]) -> Dict[str, Any]:
        """Apply geoip filter - enrich IP address with geographic data"""
        fields_added = []
        fields_modified = []
        
        # Extract source field configuration: source => "[source][ip]"
        source_match = re.search(r'source\s*=>\s*"([^"]+)"', config)
        if not source_match:
            return {'changes': 'No Changes', 'fields_added': [], 'fields_modified': []}
        
        source_field = source_match.group(1)
        
        # Get IP address from source field
        ip_address = self._get_nested_field(event, source_field)
        if ip_address is None:
            print(f"[GEOIP DEBUG] Source field '{source_field}' not found in event")
            return {'changes': 'No Changes', 'fields_added': [], 'fields_modified': []}
        
        print(f"[GEOIP DEBUG] Processing IP: {ip_address}")
        
        # Extract target field (default is geoip)
        target_match = re.search(r'target\s*=>\s*"([^"]+)"', config)
        target_field = target_match.group(1) if target_match else 'geoip'
        
        try:
            # Try to use geoip2 library if available
            try:
                import geoip2.database
                import geoip2.errors
                import os
                
                # Get the directory where this script is located
                script_dir = os.path.dirname(os.path.abspath(__file__))
                
                # Try to find GeoLite2 database
                database_paths = [
                    os.path.join(script_dir, 'GeoIP', 'GeoLite2-City.mmdb'),  # Project GeoIP folder
                    '/usr/share/GeoIP/GeoLite2-City.mmdb',
                    '/usr/local/share/GeoIP/GeoLite2-City.mmdb',
                    'GeoLite2-City.mmdb',
                    os.path.expanduser('~/GeoLite2-City.mmdb')
                ]
                
                database_path = None
                for path in database_paths:
                    if os.path.exists(path):
                        database_path = path
                        break
                
                if database_path:
                    print(f"[GEOIP DEBUG] Using database: {database_path}")
                    with geoip2.database.Reader(database_path) as reader:
                        response = reader.city(ip_address)
                        
                        # Build geoip data structure
                        geoip_data = {}
                        
                        if response.country.name:
                            geoip_data['country_name'] = response.country.name
                        if response.country.iso_code:
                            geoip_data['country_code2'] = response.country.iso_code
                            geoip_data['country_code3'] = response.country.iso_code
                        if response.continent.name:
                            geoip_data['continent_code'] = response.continent.code
                        if response.city.name:
                            geoip_data['city_name'] = response.city.name
                        if response.postal.code:
                            geoip_data['postal_code'] = response.postal.code
                        if response.location.latitude and response.location.longitude:
                            geoip_data['location'] = {
                                'lat': response.location.latitude,
                                'lon': response.location.longitude
                            }
                        if response.location.time_zone:
                            geoip_data['timezone'] = response.location.time_zone
                        
                        # Set the target field
                        self._set_nested_field(event, target_field, geoip_data)
                        fields_added.append(target_field)
                        
                        print(f"[GEOIP DEBUG] Added geoip data: {geoip_data}")
                        
                        return {
                            'changes': 'Fields Added',
                            'fields_added': fields_added,
                            'fields_modified': fields_modified
                        }
                else:
                    print("[GEOIP DEBUG] GeoLite2 database not found, using mock data")
                    raise ImportError("Database not found")
                    
            except ImportError as e:
                # Fallback to mock data for demonstration
                print(f"[GEOIP DEBUG] Using mock geoip data: {str(e)}")
                
                # Create mock geoip data based on IP
                geoip_data = {
                    'country_name': 'United States',
                    'country_code2': 'US',
                    'country_code3': 'US',
                    'continent_code': 'NA',
                    'city_name': 'Mountain View',
                    'postal_code': '94043',
                    'location': {
                        'lat': 37.4192,
                        'lon': -122.0574
                    },
                    'timezone': 'America/Los_Angeles'
                }
                
                # Set the target field
                self._set_nested_field(event, target_field, geoip_data)
                fields_added.append(target_field)
                
                return {
                    'changes': 'Fields Added (Mock Data)',
                    'fields_added': fields_added,
                    'fields_modified': fields_modified
                }
                
        except Exception as e:
            print(f"[GEOIP DEBUG] Error: {str(e)}")
            return {
                'changes': 'Error',
                'error': f'GeoIP lookup failed: {str(e)}',
                'fields_added': [],
                'fields_modified': []
            }
    
    def _get_nested_field(self, event: Dict, field_path: str) -> Any:
        """Get value from nested field path, supporting both dicts and arrays"""
        # Handle simple field names
        if '[' not in field_path:
            return event.get(field_path)
        
        # Parse nested path: [field][subfield][0]
        parts = re.findall(r'\[([^\]]+)\]', field_path)
        
        current = event
        for part in parts:
            if current is None:
                return None
            
            # Check if this part is a numeric index (array access)
            if part.isdigit():
                index = int(part)
                if isinstance(current, list) and 0 <= index < len(current):
                    current = current[index]
                else:
                    return None
            # Dictionary access
            elif isinstance(current, dict) and part in current:
                current = current[part]
            else:
                return None
        
        return current
    
    def _set_nested_field(self, event: Dict, field_path: str, value: Any):
        """Set nested field value - supports [field1][field2][field3] syntax"""
        # Handle nested fields like [log][syslog][priority]
        # Extract all parts between brackets
        parts = re.findall(r'\[([^\]]+)\]', field_path)
        
        if not parts:
            # Not a nested field, set directly
            # If both current and new value are dicts, merge them
            if isinstance(value, dict) and field_path in event and isinstance(event[field_path], dict):
                event[field_path].update(value)
            else:
                event[field_path] = value
            return
        
        # Navigate through the nested structure, creating dicts as needed
        current = event
        for part in parts[:-1]:
            if part not in current:
                current[part] = {}
            elif not isinstance(current[part], dict):
                # Can't nest further - overwrite with dict
                current[part] = {}
            current = current[part]
        
        # Set the final value
        final_key = parts[-1]
        # If both current and new value are dicts, merge them
        if isinstance(value, dict) and final_key in current and isinstance(current[final_key], dict):
            current[final_key].update(value)
        else:
            current[final_key] = value

    def _parse_condition(self, condition_str: str) -> Dict[str, Any]:
        """Parse condition string into structured format"""
        condition_str = condition_str.strip()
        
        # Parse "value" in [field] syntax (e.g., "firewall" in [tags])
        in_match = re.match(r'"([^"]+)"\s+in\s+\[([^\]]+)\]', condition_str)
        if in_match:
            value = in_match.group(1)
            field = in_match.group(2)
            return {
                'type': 'comparison',
                'field': field,
                'operator': 'in',
                'value': value,
                'is_regex': False,
                'original': condition_str
            }
        
        # Parse comparison operators
        comp_match = re.match(r'\[([^\]]+)\]\s*(==|!=|=~|!~|>|<|>=|<=)\s*(.+)', condition_str)
        if comp_match:
            field = comp_match.group(1)
            operator = comp_match.group(2)
            value = comp_match.group(3).strip()
            
            # Remove quotes
            if (value.startswith('"') and value.endswith('"')) or (value.startswith("'") and value.endswith("'")):
                value = value[1:-1]
            
            # Handle regex patterns
            is_regex = False
            if value.startswith('/') and value.endswith('/'):
                value = value[1:-1]
                is_regex = True
                # Remove leading ^ for "starts with" patterns
                if value.startswith('^'):
                    value = value[1:]
            
            return {
                'type': 'comparison',
                'field': field,
                'operator': operator,
                'value': value,
                'is_regex': is_regex,
                'original': condition_str
            }
        
        # Field existence check
        exists_match = re.match(r'\[([^\]]+)\]', condition_str)
        if exists_match:
            return {
                'type': 'exists',
                'field': exists_match.group(1),
                'original': condition_str
            }
        
        return {
            'type': 'unknown',
            'original': condition_str
        }
    
    def _evaluate_condition(self, condition: Optional[Dict], data: Dict[str, Any]) -> bool:
        """Evaluate a condition against data"""
        if not condition:
            return True
        
        if condition['type'] == 'else':
            return True
        
        if condition['type'] == 'comparison':
            field_value = data.get(condition['field'], '')
            condition_value = condition['value']
            operator = condition['operator']
            
            # Handle 'in' operator for array membership (e.g., "value" in [tags])
            if operator == 'in':
                # Get the field value (should be an array)
                field = condition.get('field')
                print(f"[CONDITION DEBUG] 'in' operator: looking for '{condition_value}' in field '{field}'")
                if field:
                    field_value = self._get_nested_field(data, field)
                    print(f"[CONDITION DEBUG] Field value: {field_value}, type: {type(field_value)}")
                    if isinstance(field_value, list):
                        result = condition_value in field_value
                        print(f"[CONDITION DEBUG] '{condition_value}' in {field_value} = {result}")
                        return result
                print(f"[CONDITION DEBUG] Field not found or not a list, returning False")
                return False
            
            if operator == '==':
                return str(field_value) == str(condition_value)
            elif operator == '!=':
                return str(field_value) != str(condition_value)
            elif operator == '=~':
                if condition['is_regex']:
                    return bool(re.search(condition_value, str(field_value)))
                else:
                    return condition_value in str(field_value)
            elif operator == '!~':
                if condition['is_regex']:
                    return not bool(re.search(condition_value, str(field_value)))
                else:
                    return condition_value not in str(field_value)
            elif operator == '>':
                try:
                    return float(field_value) > float(condition_value)
                except:
                    return False
            elif operator == '<':
                try:
                    return float(field_value) < float(condition_value)
                except:
                    return False
        
        if condition['type'] == 'exists':
            return condition['field'] in data and data[condition['field']] is not None
        
        return False
    
    def process_log(self, log_entry: str, filters: List[Dict], input_stream: Optional[Dict] = None) -> Dict[str, Any]:
        """Process a log entry through the filter chain"""
        steps = []
        current_data = {'message': log_entry}
        
        # Add input stream metadata
        if input_stream:
            current_data['type'] = input_stream.get('type', '')
            current_data['[input][type]'] = input_stream.get('type', '')
            current_data['[input][port]'] = input_stream.get('port', 0)
            current_data['[input][protocol]'] = input_stream.get('protocol', '')
            if 'tags' in input_stream and input_stream['tags']:
                current_data['tags'] = input_stream['tags'][:]
        
        # Initial step
        steps.append({
            'step': 0,
            'filterType': 'input',
            'description': 'Raw log entry',
            'fields': dict(current_data),
            'newFields': [],
            'modifiedFields': [],
            'removedFields': [],
            'inputStream': input_stream
        })
        
        # Process filters with parent condition tracking
        step_number = 1
        skipped_parents = set()  # Track which parent conditions have failed
        
        for i, filter_def in enumerate(filters):
            previous_data = dict(current_data)
            parent_condition = filter_def.get('parent_condition')
            own_condition = filter_def.get('condition')
            
            # Check if this filter's parent condition was already evaluated and failed
            parent_failed = False
            if parent_condition:
                parent_id = id(parent_condition)
                if parent_id in skipped_parents:
                    parent_failed = True
                elif parent_condition['type'] != 'else':
                    # Evaluate parent condition for the first time
                    parent_met = self._evaluate_condition(parent_condition, current_data)
                    if not parent_met:
                        skipped_parents.add(parent_id)
                        parent_failed = True
            
            # Skip if parent failed
            if parent_failed:
                parent_desc = parent_condition.get("original", "") if parent_condition else ""
                steps.append(self._create_skipped_step(
                    step_number, filter_def, current_data,
                    f'Parent condition not met: {parent_desc}'
                ))
                step_number += 1
                continue
            
            # Evaluate this filter's own condition
            if own_condition:
                condition_met = self._evaluate_condition(own_condition, current_data)
                if not condition_met:
                    steps.append(self._create_skipped_step(
                        step_number, filter_def, current_data,
                        'Condition not met'
                    ))
                    step_number += 1
                    continue
            
            # Execute filter
            try:
                current_data = self._apply_filter(filter_def, current_data)
                changes = self._track_changes(previous_data, current_data)
                
                steps.append({
                    'step': step_number,
                    'filterType': filter_def['type'],
                    'filterConfig': filter_def['config'],
                    'parsedConfig': filter_def['parsed_config'],
                    'description': self._get_filter_description(filter_def['type']),
                    'condition': filter_def.get('condition'),
                    'conditionMet': True,
                    'fields': dict(current_data),
                    **changes,
                    'success': True
                })
            except Exception as e:
                steps.append({
                    'step': step_number,
                    'filterType': filter_def['type'],
                    'filterConfig': filter_def['config'],
                    'description': self._get_filter_description(filter_def['type']),
                    'condition': filter_def.get('condition'),
                    'error': str(e),
                    'fields': dict(previous_data),
                    'success': False
                })
            
            step_number += 1
        
        return {
            'steps': steps,
            'finalData': current_data
        }
    
    def _process_filters_recursive(self, filters: List[Dict], current_data: Dict, steps: List[Dict], 
                                   step_number: int, parent_skipped: bool = False) -> int:
        """Recursively process filters with parent condition awareness"""
        # Group filters into if/else chains
        filter_groups = self._group_filters_into_chains(filters)
        
        # Process each filter group
        for group in filter_groups:
            if group['type'] == 'chain':
                # Process if/else chain
                chain_executed = False
                
                for filter_def in group['filters']:
                    previous_data = dict(current_data)
                    
                    # If parent was skipped, skip all children
                    if parent_skipped:
                        steps.append(self._create_skipped_step(
                            step_number, filter_def, current_data, 
                            'Parent condition not met - entire block skipped'
                        ))
                        step_number += 1
                        continue
                    
                    if chain_executed:
                        # Skip rest of chain
                        steps.append(self._create_skipped_step(
                            step_number, filter_def, current_data, 
                            'Previous condition in chain already executed'
                        ))
                        step_number += 1
                        continue
                    
                    condition_met = self._evaluate_condition(filter_def.get('condition'), current_data)
                    
                    if not condition_met:
                        steps.append(self._create_skipped_step(
                            step_number, filter_def, current_data, 
                            'Condition not met'
                        ))
                        step_number += 1
                        continue
                    
                    # Execute filter
                    chain_executed = True
                    try:
                        current_data = self._apply_filter(filter_def, current_data)
                        changes = self._track_changes(previous_data, current_data)
                        
                        steps.append({
                            'step': step_number,
                            'filterType': filter_def['type'],
                            'filterConfig': filter_def['config'],
                            'parsedConfig': filter_def['parsed_config'],
                            'description': self._get_filter_description(filter_def['type']),
                            'condition': filter_def.get('condition'),
                            'conditionMet': True,
                            'fields': dict(current_data),
                            **changes,
                            'success': True
                        })
                    except Exception as e:
                        steps.append({
                            'step': step_number,
                            'filterType': filter_def['type'],
                            'filterConfig': filter_def['config'],
                            'description': self._get_filter_description(filter_def['type']),
                            'condition': filter_def.get('condition'),
                            'error': str(e),
                            'fields': dict(previous_data),
                            'success': False
                        })
                    
                    step_number += 1
            else:
                # Single filter
                filter_def = group['filter']
                previous_data = dict(current_data)
                
                # Check if parent was skipped
                if parent_skipped:
                    steps.append(self._create_skipped_step(
                        step_number, filter_def, current_data,
                        'Parent condition not met - entire block skipped'
                    ))
                    step_number += 1
                    continue
                
                # Check filter's own condition
                condition = filter_def.get('condition')
                if condition:
                    condition_met = self._evaluate_condition(condition, current_data)
                    if not condition_met:
                        steps.append(self._create_skipped_step(
                            step_number, filter_def, current_data,
                            'Condition not met'
                        ))
                        step_number += 1
                        continue
                
                # Execute filter
                try:
                    current_data = self._apply_filter(filter_def, current_data)
                    changes = self._track_changes(previous_data, current_data)
                    
                    steps.append({
                        'step': step_number,
                        'filterType': filter_def['type'],
                        'filterConfig': filter_def['config'],
                        'parsedConfig': filter_def['parsed_config'],
                        'description': self._get_filter_description(filter_def['type']),
                        'condition': filter_def.get('condition'),
                        'conditionMet': True,
                        'fields': dict(current_data),
                        **changes,
                        'success': True
                    })
                except Exception as e:
                    steps.append({
                        'step': step_number,
                        'filterType': filter_def['type'],
                        'filterConfig': filter_def['config'],
                        'description': self._get_filter_description(filter_def['type']),
                        'error': str(e),
                        'fields': dict(previous_data),
                        'success': False
                    })
                
                step_number += 1
        
        return step_number
    
    def _group_filters_into_chains(self, filters: List[Dict]) -> List[Dict]:
        """Group filters into if/else chains with parent-child relationships"""
        groups = []
        i = 0
        
        while i < len(filters):
            filter_def = filters[i]
            condition = filter_def.get('condition')
            
            if not condition:
                groups.append({'type': 'single', 'filter': filter_def})
                i += 1
                continue
            
            if condition['type'] in ['comparison', 'exists']:
                # Start of potential chain - look for siblings at same level
                chain = [filter_def]
                j = i + 1
                
                # Look ahead for else-if or else that are siblings (not nested children)
                while j < len(filters):
                    next_filter = filters[j]
                    next_condition = next_filter.get('condition')
                    
                    if next_condition and next_condition['type'] == 'else':
                        chain.append(next_filter)
                        j += 1
                        break  # Else ends the chain
                    else:
                        # Not part of this chain
                        break
                
                if len(chain) > 1:
                    groups.append({'type': 'chain', 'filters': chain})
                    i = j
                else:
                    groups.append({'type': 'single', 'filter': filter_def})
                    i += 1
            elif condition['type'] == 'else':
                # Standalone else
                groups.append({'type': 'single', 'filter': filter_def})
                i += 1
            else:
                groups.append({'type': 'single', 'filter': filter_def})
                i += 1
        
        return groups
    
    def _create_skipped_step(self, step_number: int, filter_def: Dict, current_data: Dict, reason: str) -> Dict:
        """Create a skipped step entry"""
        return {
            'step': step_number,
            'filterType': filter_def['type'],
            'filterConfig': filter_def['config'],
            'parsedConfig': filter_def['parsed_config'],
            'description': self._get_filter_description(filter_def['type']),
            'condition': filter_def.get('condition'),
            'conditionMet': False,
            'skipped': True,
            'skipReason': reason,
            'fields': dict(current_data),
            'newFields': [],
            'modifiedFields': [],
            'removedFields': [],
            'success': True
        }
    
    def _apply_filter(self, filter_def: Dict, data: Dict[str, Any]) -> Dict[str, Any]:
        """Apply a filter to data"""
        result = dict(data)
        filter_type = filter_def['type']
        parsed_config = filter_def['parsed_config']
        
        if filter_type == 'grok':
            result = self._apply_grok(parsed_config, result)
        elif filter_type == 'mutate':
            result = self._apply_mutate(parsed_config, result)
        elif filter_type == 'csv':
            result = self._apply_csv(parsed_config, result)
        elif filter_type == 'date':
            result = self._apply_date(parsed_config, result)
        elif filter_type == 'json':
            result = self._apply_json(parsed_config, result)
        
        return result
    
        return matches
    
    def _track_changes(self, previous: Dict, current: Dict) -> Dict[str, List[str]]:
        """Track field changes between steps"""
        new_fields = []
        modified_fields = []
        removed_fields = []
        
        for key in current:
            if key not in previous:
                new_fields.append(key)
            elif previous[key] != current[key]:
                modified_fields.append(key)
        
        for key in previous:
            if key not in current:
                removed_fields.append(key)
        
        return {
            'newFields': new_fields,
            'modifiedFields': modified_fields,
            'removedFields': removed_fields
        }
    
    def _get_filter_description(self, filter_type: str) -> str:
        """Get human-readable description for filter"""
        descriptions = {
            'grok': 'Parse structured data from unstructured text using patterns',
            'mutate': 'Transform and modify field values',
            'date': 'Parse dates and set @timestamp field',
            'geoip': 'Add geographical information based on IP addresses',
            'dissect': 'Extract structured fields using delimiters',
            'csv': 'Parse comma-separated values',
            'kv': 'Parse key-value pairs',
            'json': 'Parse JSON data',
            'translate': 'Translate field values using a dictionary lookup',
            'cidr': 'Check if IP addresses match CIDR network ranges',
            'dns': 'Perform DNS lookups (forward or reverse)'
        }
        return descriptions.get(filter_type, f'Apply {filter_type} filter')
    
    def _apply_translate(self, config: str, event: Dict[str, Any]) -> Dict[str, Any]:
        """Apply translate filter to lookup values from a dictionary/CSV file"""
        import re
        import csv
        import os
        
        fields_added = []
        fields_modified = []
        
        print(f"[TRANSLATE DEBUG] Config: {config[:200]}")
        
        # Extract parameters
        source_match = re.search(r'source\s*=>\s*"([^"]+)"', config)
        target_match = re.search(r'target\s*=>\s*"([^"]+)"', config)
        dict_path_match = re.search(r'dictionary_path\s*=>\s*"([^"]+)"', config)
        fallback_match = re.search(r'fallback\s*=>\s*"([^"]+)"', config)
        
        if not source_match or not target_match:
            print("[TRANSLATE DEBUG] Missing source or target field")
            return {'changes': 'No Changes', 'fields_added': [], 'fields_modified': []}
        
        source_field = source_match.group(1)
        target_field = target_match.group(1)
        dict_path = dict_path_match.group(1) if dict_path_match else None
        fallback = fallback_match.group(1) if fallback_match else None
        
        print(f"[TRANSLATE DEBUG] Source: {source_field}")
        print(f"[TRANSLATE DEBUG] Target: {target_field}")
        print(f"[TRANSLATE DEBUG] Dictionary: {dict_path}")
        print(f"[TRANSLATE DEBUG] Fallback: {fallback}")
        
        # Get source value
        source_value = self._get_nested_field(event, source_field)
        
        if source_value is None:
            print(f"[TRANSLATE DEBUG] Source field '{source_field}' not found")
            return {'changes': 'No Changes', 'fields_added': [], 'fields_modified': []}
        
        print(f"[TRANSLATE DEBUG] Source value: {source_value}")
        
        # Load dictionary from CSV file
        translation_dict = {}
        if dict_path:
            # Convert Logstash paths like /etc/pfelk/databases/... to local paths
            if dict_path.startswith('/etc/pfelk/'):
                # Strip /etc/pfelk/ and make relative to script directory
                csv_path = os.path.join(os.path.dirname(__file__), dict_path.replace('/etc/pfelk/', ''))
            elif not os.path.isabs(dict_path):
                # Relative path - make it relative to script directory
                csv_path = os.path.join(os.path.dirname(__file__), dict_path)
            else:
                # Use absolute path as-is
                csv_path = dict_path
            
            print(f"[TRANSLATE DEBUG] Looking for CSV at: {csv_path}")
            
            if os.path.exists(csv_path):
                try:
                    with open(csv_path, 'r', encoding='utf-8') as f:
                        csv_reader = csv.reader(f)
                        for row in csv_reader:
                            if len(row) >= 2:
                                # Key is first column, value is second column
                                translation_dict[row[0].strip()] = row[1].strip()
                    print(f"[TRANSLATE DEBUG] Loaded {len(translation_dict)} translations from CSV")
                except Exception as e:
                    print(f"[TRANSLATE DEBUG] Error reading CSV: {e}")
            else:
                print(f"[TRANSLATE DEBUG] CSV file not found at {csv_path}")
        
        # Perform translation
        translated_value = translation_dict.get(str(source_value))
        
        if translated_value is None:
            # Use fallback if provided
            if fallback:
                # Replace %{[field]} placeholders in fallback
                translated_value = fallback
                # Replace field references like %{[rule][uuid]}
                for match in re.finditer(r'%\{([^\}]+)\}', fallback):
                    field_ref = match.group(1)
                    field_val = self._get_nested_field(event, field_ref)
                    if field_val is not None:
                        translated_value = translated_value.replace(match.group(0), str(field_val))
                print(f"[TRANSLATE DEBUG] Using fallback: {translated_value}")
            else:
                print(f"[TRANSLATE DEBUG] No translation found and no fallback")
                return {'changes': 'No Changes', 'fields_added': [], 'fields_modified': []}
        else:
            print(f"[TRANSLATE DEBUG] Translation found: {translated_value}")
        
        # Check if target field exists
        existing_value = self._get_nested_field(event, target_field)
        
        # Set the translated value
        self._set_nested_field(event, target_field, translated_value)
        
        if existing_value is None:
            fields_added.append(target_field)
            changes = 'Fields Added'
        else:
            fields_modified.append(target_field)
            changes = 'Fields Modified'
        
        print(f"[TRANSLATE DEBUG] Set {target_field} = {translated_value}")
        
        return {
            'changes': changes,
            'fields_added': fields_added,
            'fields_modified': fields_modified
        }
    
    def _apply_cidr(self, config: str, event: Dict[str, Any]) -> Dict[str, Any]:
        """Apply cidr filter to check if IP addresses match CIDR ranges"""
        import re
        import ipaddress
        
        tags_added = []
        
        print(f"[CIDR DEBUG] Config: {config[:200]}")
        
        # Extract parameters
        address_match = re.search(r'address\s*=>\s*\[\s*"([^"]+)"\s*\]', config)
        network_search = re.search(r'network\s*=>\s*\[(.*?)\]', config, re.DOTALL)
        network_match = re.findall(r'"([^"]+)"', network_search.group(1)) if network_search else []
        add_tag_match = re.search(r'add_tag\s*=>\s*"([^"]+)"', config)
        
        if not address_match or not network_match:
            print("[CIDR DEBUG] Missing address or network parameter")
            return {'changes': 'No Changes', 'tags_added': []}
        
        address_field = address_match.group(1)
        networks = network_match
        tag_to_add = add_tag_match.group(1) if add_tag_match else None
        
        print(f"[CIDR DEBUG] Address field: {address_field}")
        print(f"[CIDR DEBUG] Networks: {networks}")
        print(f"[CIDR DEBUG] Tag to add: {tag_to_add}")
        
        # Get the IP address from the event (handle field references like %{[source][ip]})
        ip_field = address_field
        # Remove %{...} wrapping if present (e.g., %{[source][ip]} -> [source][ip])
        if ip_field.startswith('%{') and ip_field.endswith('}'):
            ip_field = ip_field[2:-1]
        # Now ip_field should be in format like [source][ip] which is what _get_nested_field expects
        
        print(f"[CIDR DEBUG] Parsed field: {ip_field}")
        
        ip_value = self._get_nested_field(event, ip_field)
        
        if not ip_value:
            print(f"[CIDR DEBUG] IP field '{ip_field}' not found or empty")
            return {'changes': 'No Changes', 'tags_added': []}
        
        print(f"[CIDR DEBUG] IP value: {ip_value}")
        
        # Check if IP matches any of the networks
        try:
            ip_addr = ipaddress.ip_address(ip_value)
            matched = False
            
            for network_str in networks:
                try:
                    network = ipaddress.ip_network(network_str, strict=False)
                    if ip_addr in network:
                        matched = True
                        print(f"[CIDR DEBUG] IP {ip_value} matches network {network_str}")
                        break
                except ValueError as e:
                    print(f"[CIDR DEBUG] Invalid network: {network_str} - {e}")
                    continue
            
            if matched and tag_to_add:
                # Add tag
                if 'tags' not in event:
                    event['tags'] = []
                if tag_to_add not in event['tags']:
                    event['tags'].append(tag_to_add)
                    tags_added.append(tag_to_add)
                    print(f"[CIDR DEBUG] Added tag: {tag_to_add}")
                    return {
                        'changes': 'Tags Added',
                        'tags_added': tags_added
                    }
            
            print(f"[CIDR DEBUG] IP {ip_value} did not match any networks")
            return {'changes': 'No Changes', 'tags_added': []}
            
        except ValueError as e:
            print(f"[CIDR DEBUG] Invalid IP address: {ip_value} - {e}")
            return {'changes': 'No Changes', 'tags_added': []}
    
    def _apply_dns(self, config: str, event: Dict[str, Any]) -> Dict[str, Any]:
        """Apply dns filter to perform DNS lookups (forward or reverse)"""
        import re
        import socket
        
        fields_added = []
        fields_modified = []
        
        print(f"[DNS DEBUG] Config: {config[:200]}")
        
        # Extract parameters - use a greedy match and find the last ]
        # For reverse => [ ... ], capture everything between the brackets
        reverse_match = []
        if 'reverse =>' in config:
            # Find the reverse => [ part and then find all quoted strings until we hit the closing ]
            reverse_section = re.search(r'reverse\s*=>\s*\[(.*?)\]\s*(?:action|resolve|\})', config, re.DOTALL)
            if reverse_section:
                reverse_match = re.findall(r'"([^"]+)"', reverse_section.group(1))
                print(f"[DNS DEBUG] Reverse section: {reverse_section.group(1)}")
        
        resolve_match = []
        if 'resolve =>' in config:
            resolve_section = re.search(r'resolve\s*=>\s*\[(.*?)\]\s*(?:action|reverse|\})', config, re.DOTALL)
            if resolve_section:
                resolve_match = re.findall(r'"([^"]+)"', resolve_section.group(1))
        
        action_match = re.search(r'action\s*=>\s*"([^"]+)"', config)
        action = action_match.group(1) if action_match else "append"
        
        print(f"[DNS DEBUG] Reverse fields: {reverse_match}")
        print(f"[DNS DEBUG] Resolve fields: {resolve_match}")
        print(f"[DNS DEBUG] Action: {action}")
        
        # Process reverse DNS lookups (IP -> hostname)
        for field_ref in reverse_match:
            # Remove brackets if present
            if field_ref.startswith('[') and field_ref.endswith(']'):
                field_path = field_ref
            else:
                field_path = f"[{field_ref}]"
            
            # Get the IP address
            ip_value = self._get_nested_field(event, field_path)
            
            if not ip_value:
                print(f"[DNS DEBUG] Field '{field_path}' not found or empty")
                continue
            
            print(f"[DNS DEBUG] Reverse lookup for IP: {ip_value}")
            
            try:
                # Perform reverse DNS lookup
                hostname = socket.gethostbyaddr(str(ip_value))[0]
                print(f"[DNS DEBUG] Resolved {ip_value} -> {hostname}")
                
                # Check if field exists
                existing_value = self._get_nested_field(event, field_path)
                
                # Set the hostname based on action
                if action == "replace":
                    self._set_nested_field(event, field_path, hostname)
                    if existing_value and existing_value != hostname:
                        fields_modified.append(field_path)
                    else:
                        fields_added.append(field_path)
                elif action == "append":
                    # For append, we'd typically add to an array, but for simplicity, replace
                    self._set_nested_field(event, field_path, hostname)
                    if existing_value:
                        fields_modified.append(field_path)
                    else:
                        fields_added.append(field_path)
                
            except (socket.herror, socket.gaierror) as e:
                print(f"[DNS DEBUG] Reverse lookup failed for {ip_value}: {e}")
                continue
        
        # Process forward DNS lookups (hostname -> IP)
        for field_ref in resolve_match:
            # Remove brackets if present
            if field_ref.startswith('[') and field_ref.endswith(']'):
                field_path = field_ref
            else:
                field_path = f"[{field_ref}]"
            
            # Get the hostname
            hostname_value = self._get_nested_field(event, field_path)
            
            if not hostname_value:
                print(f"[DNS DEBUG] Field '{field_path}' not found or empty")
                continue
            
            print(f"[DNS DEBUG] Forward lookup for hostname: {hostname_value}")
            
            try:
                # Perform forward DNS lookup
                ip_address = socket.gethostbyname(str(hostname_value))
                print(f"[DNS DEBUG] Resolved {hostname_value} -> {ip_address}")
                
                # Check if field exists
                existing_value = self._get_nested_field(event, field_path)
                
                # Set the IP based on action
                if action == "replace":
                    self._set_nested_field(event, field_path, ip_address)
                    if existing_value and existing_value != ip_address:
                        fields_modified.append(field_path)
                    else:
                        fields_added.append(field_path)
                elif action == "append":
                    self._set_nested_field(event, field_path, ip_address)
                    if existing_value:
                        fields_modified.append(field_path)
                    else:
                        fields_added.append(field_path)
                
            except (socket.herror, socket.gaierror) as e:
                print(f"[DNS DEBUG] Forward lookup failed for {hostname_value}: {e}")
                continue
        
        if fields_added or fields_modified:
            changes = []
            if fields_added:
                changes.append('Fields Added')
            if fields_modified:
                changes.append('Fields Modified')
            return {
                'changes': ', '.join(changes),
                'fields_added': fields_added,
                'fields_modified': fields_modified
            }
        
        return {'changes': 'No Changes', 'fields_added': [], 'fields_modified': []}


def parse_config_to_tree(config_text):
    """
    Parse Logstash configuration text into a hierarchical tree structure using the same
    logic as the frontend visualizer (app.js extractFiltersFromConfig).
    """
    lines = config_text.split('\n')
    depth = 0
    in_filter_block = False
    filters = []
    
    for i, line in enumerate(lines):
        trimmed = line.strip()
        
        if not trimmed or trimmed.startswith('#'):
            continue
        
        # Check if entering filter block
        if re.match(r'^filter\s*\{', trimmed):
            in_filter_block = True
            depth = 0
            continue
        
        if not in_filter_block:
            continue
        
        # Count braces (excluding escaped ones)
        open_braces = len(re.findall(r'(?<!\\)\{', line))
        close_braces = len(re.findall(r'(?<!\\)\}', line))
        
        # Check for conditionals BEFORE adjusting depth
        # Match 'if' followed by either [ or " (for array membership checks)
        # Handle optional closing brace before if (e.g., "} if ...")
        if re.match(r'^(\}\s*)?if\s+[\[\"]', trimmed):
            # Find the last { which should be the block opening
            # Work backwards from the end to find it
            last_brace = trimmed.rfind('{')
            # Find where 'if' starts
            if_pos = trimmed.find('if ')
            if last_brace > if_pos + 3:  # "if " is 3 chars
                captured_condition = trimmed[3:last_brace].strip()
            else:
                captured_condition = 'unknown'
            print(f"[TREE PARSE] if condition - trimmed: '{trimmed}' captured: '{captured_condition}'")
            node = {
                'type': 'conditional',
                'condition': captured_condition,
                'condition_type': 'if',
                'depth': depth,
                'children': [],
                'line': i + 1
            }
            print(f"[TREE PARSE] Adding conditional 'if' at depth {depth}, line {i + 1}")
            filters.append(node)
            
        elif re.match(r'^(\}\s*)?else\s+if\s+[\[\"]', trimmed):
            # else-if needs to be at the same depth as the preceding if
            # The depth has already been decremented by the closing brace, so use current depth
            elseif_depth = depth
            # Find the last { which should be the block opening
            last_brace = trimmed.rfind('{')
            # Find where 'else if' starts
            elseif_pos = trimmed.find('else if ')
            if last_brace > elseif_pos + 8:  # "else if " is 8 chars
                captured_condition = trimmed[elseif_pos + 8:last_brace].strip()
            else:
                captured_condition = 'unknown'
            print(f"[TREE PARSE] else if condition - trimmed: '{trimmed}' captured: '{captured_condition}'")
            node = {
                'type': 'conditional',
                'condition': captured_condition,
                'condition_type': 'else_if',
                'depth': elseif_depth,
                'children': [],
                'line': i + 1
            }
            filters.append(node)
            print(f"[TREE PARSE] Adding conditional 'else_if' at depth {elseif_depth}, line {i + 1}")
            
        elif re.match(r'^(\}\s*)?else\s*\{', trimmed):
            # else needs to be at the same depth as the preceding if
            # The depth has already been decremented by the closing brace, so use current depth
            else_depth = depth
            node = {
                'type': 'conditional',
                'condition': 'true',
                'condition_type': 'else',
                'depth': else_depth,
                'children': [],
                'line': i + 1
            }
            filters.append(node)
            print(f"[TREE PARSE] Adding conditional 'else' at depth {else_depth}, line {i + 1}")
            
        # Parse filter plugins
        elif re.match(r'^(grok|mutate|date|csv|json|kv|dissect|geoip|translate|cidr|dns|drop)\s*\{', trimmed):
            filter_match = re.match(r'^(\w+)\s*\{', trimmed)
            if filter_match:
                filter_type = filter_match.group(1)
                
                # Extract filter configuration
                filter_config = trimmed
                brace_count = open_braces - close_braces
                j = i + 1
                
                while brace_count > 0 and j < len(lines):
                    next_line = lines[j]
                    filter_config += '\n' + next_line
                    brace_count += len(re.findall(r'(?<!\\)\{', next_line))
                    brace_count -= len(re.findall(r'(?<!\\)\}', next_line))
                    j += 1
                
                node = {
                    'type': 'filter',
                    'filter_type': filter_type,
                    'config': filter_config,
                    'depth': depth,
                    'line': i + 1
                }
                print(f"[TREE PARSE] Adding filter '{filter_type}' at depth {depth}, line {i + 1}")
                filters.append(node)
        
        # Now adjust depth based on braces
        old_depth = depth
        depth += open_braces
        depth -= close_braces
        depth = max(0, depth)
        
        # Check if we've exited the filter block
        if depth < 0:
            break
    
    # Now build the tree from the flat list with depths
    return build_tree_from_depths(filters)


def build_tree_from_depths(filters):
    """Convert flat list of filters with depths into nested tree structure"""
    if not filters:
        return []
    
    root = []
    stack = [(root, -1)]  # (container, depth)
    
    for filter_item in filters:
        current_depth = filter_item['depth']
        condition_type = filter_item.get('condition_type')
        
        # For else_if and else, we need to be siblings with the preceding if/else_if
        # So pop the stack to get back to the parent level
        if condition_type in ['else_if', 'else']:
            # Pop until we're at the parent level (one level above current_depth)
            while len(stack) > 1 and stack[-1][1] >= current_depth:
                stack.pop()
        else:
            # For regular nodes and 'if', pop stack until we find the right parent
            while len(stack) > 1 and stack[-1][1] >= current_depth:
                stack.pop()
        
        # Create node without depth field
        node = {k: v for k, v in filter_item.items() if k != 'depth'}
        
        # Add to current container
        stack[-1][0].append(node)
        
        # If this is a conditional, push its children container onto stack
        if filter_item['type'] == 'conditional':
            stack.append((node['children'], current_depth))
    
    return root

