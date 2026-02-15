/**
 * Logstash Parser Engine
 * Simulates Logstash filter processing for pfSense logs
 */

class LogstashParser {
    constructor() {
        this.grokPatterns = this.initializeGrokPatterns();
    }

    /**
     * Initialize common Grok patterns
     */
    initializeGrokPatterns() {
        return {
            // Base patterns
            'USERNAME': '[a-zA-Z0-9._-]+',
            'USER': '%{USERNAME}',
            'INT': '(?:[+-]?(?:[0-9]+))',
            'BASE10NUM': '(?<![0-9.+-])(?>[+-]?(?:(?:[0-9]+(?:\\.[0-9]+)?)|(?:\\.[0-9]+)))',
            'NUMBER': '(?:%{BASE10NUM})',
            'WORD': '\\b\\w+\\b',
            'NOTSPACE': '\\S+',
            'SPACE': '\\s*',
            'DATA': '.*?',
            'GREEDYDATA': '.*',
            'QUOTEDSTRING': '(?>(?<!\\\\)(?>"(?>\\\\.|[^\\\\"]+)+"|""|(?>"(?>\\\\.|[^\\\\"]+)+")|""))',
            
            // Network patterns
            'IP': '(?:%{IPV6}|%{IPV4})',
            'IPV4': '(?<![0-9])(?:(?:[0-1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5])[.](?:[0-1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5])[.](?:[0-1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5])[.](?:[0-1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5]))(?![0-9])',
            'IPV6': '((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)(\\.(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)(\\.(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)(\\.(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)(\\.(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)(\\.(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)(\\.(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)(\\.(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)){3}))|:)))',
            'HOSTNAME': '\\b(?:[0-9A-Za-z][0-9A-Za-z-]{0,62})(?:\\.(?:[0-9A-Za-z][0-9A-Za-z-]{0,62}))*(\\.?|\\b)',
            'IPORHOST': '(?:%{IP}|%{HOSTNAME})',
            'HOSTPORT': '%{IPORHOST}:%{POSINT}',
            'POSINT': '\\b(?:[1-9][0-9]*)\\b',
            'PORT': '%{POSINT}',
            
            // Syslog patterns
            'SYSLOGFACILITY': '<%{NONNEGINT:syslog_facility}>',
            'SYSLOGPRI': '<%{NONNEGINT:syslog_pri}>',
            'NONNEGINT': '\\b(?:[0-9]+)\\b',
            'SYSLOGTIMESTAMP': '(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) +[0-9]{1,2} [0-9]{2}:[0-9]{2}:[0-9]{2}',
            'SYSLOGPROG': '[\\w._/-]+',
            'SYSLOGHOST': '%{IPORHOST}',
            'SYSLOGBASE': '%{SYSLOGTIMESTAMP:timestamp} (?:%{SYSLOGFACILITY} )?%{SYSLOGHOST:logsource} %{SYSLOGPROG:program}(?:\\[%{POSINT:pid}\\])?:',
            'SYSLOGLINE': '%{SYSLOGBASE} %{GREEDYDATA:message}',
            
            // Timestamp patterns
            'TIMESTAMP_ISO8601': '%{YEAR}-%{MONTHNUM}-%{MONTHDAY}[T ]%{HOUR}:?%{MINUTE}(?::?%{SECOND})?%{ISO8601_TIMEZONE}?',
            'YEAR': '(?:%{NONNEGINT})',
            'MONTHNUM': '(?:0?[1-9]|1[0-2])',
            'MONTHDAY': '(?:(?:0[1-9])|(?:[12][0-9])|(?:3[01])|[1-9])',
            'HOUR': '(?:2[0123]|[01]?[0-9])',
            'MINUTE': '(?:[0-5][0-9])',
            'SECOND': '(?:(?:[0-5]?[0-9]|60)(?:[:.,][0-9]+)?)',
            'ISO8601_TIMEZONE': '(?:Z|[+-]%{HOUR}(?::?%{MINUTE}))',
            
            // pfSense specific patterns
            'PFSENSE_LOG_ENTRY': '%{INT:rule_number},%{DATA:sub_rule},%{DATA:anchor},%{INT:tracker},%{DATA:interface},%{DATA:reason},%{DATA:action},%{DATA:direction},%{INT:ip_version}',
            'PFSENSE_IP_DATA': '%{IP:src_ip},%{IP:dst_ip},%{INT:src_port},%{INT:dst_port},%{DATA:data_length}',
        };
    }

    /**
     * Parse Logstash configuration
     */
    parseConfig(configText) {
        const filters = [];
        
        // Extract filter block
        const filterMatch = configText.match(/filter\s*\{([\s\S]*)\}/);
        if (!filterMatch) {
            return filters;
        }

        const filterBlock = filterMatch[1];
        const filterPlugins = this.extractFilterPlugins(filterBlock);
        
        return filterPlugins;
    }

    /**
     * Extract filter plugins from configuration
     */
    extractFilterPlugins(text) {
        const filters = [];
        
        // Parse top-level and nested filters with conditionals
        this.parseFilterBlock(text, filters, null);
        
        return filters;
    }

    /**
     * Parse filter block recursively to handle conditionals
     */
    parseFilterBlock(text, filters, condition) {
        // First, identify and extract all TOP-LEVEL conditional blocks only
        const blocks = this.extractTopLevelConditionalBlocks(text);
        
        if (blocks.length === 0) {
            // No conditionals, parse all filters at this level
            this.extractSimpleFilters(text, filters, condition);
            return;
        }
        
        // Process conditional blocks
        blocks.forEach(block => {
            if (block.type === 'if' || block.type === 'else_if') {
                const parsedCondition = this.parseCondition(block.condition);
                // Recursively parse the block content with the new condition
                this.parseFilterBlock(block.content, filters, parsedCondition);
            } else if (block.type === 'else') {
                // For else blocks, create a special condition
                this.parseFilterBlock(block.content, filters, { type: 'else', original: 'else' });
            }
        });
        
        // Extract any filters that are not inside conditional blocks (top-level filters)
        let cleanedText = text;
        blocks.sort((a, b) => b.start - a.start); // Sort in reverse to remove from end
        blocks.forEach(block => {
            cleanedText = cleanedText.substring(0, block.start) + cleanedText.substring(block.end);
        });
        
        // Only extract top-level filters if there's actual content left
        const trimmedCleanedText = cleanedText.trim();
        if (trimmedCleanedText.length > 0 && !this.isOnlyWhitespaceAndComments(trimmedCleanedText)) {
            this.extractSimpleFilters(cleanedText, filters, condition);
        }
    }

    /**
     * Check if text contains only whitespace and comments
     */
    isOnlyWhitespaceAndComments(text) {
        // Remove comments
        const withoutComments = text.replace(/#[^\n]*/g, '');
        return withoutComments.trim().length === 0;
    }

    /**
     * Extract only TOP-LEVEL conditional blocks (don't recurse into nested ones)
     */
    extractTopLevelConditionalBlocks(text) {
        const blocks = [];
        let pos = 0;
        
        while (pos < text.length) {
            // Skip whitespace
            while (pos < text.length && /\s/.test(text[pos])) {
                pos++;
            }
            
            if (pos >= text.length) break;
            
            // Look for conditional keywords at current position
            const remainingText = text.substring(pos);
            
            // Check for 'else if'
            const elseIfMatch = remainingText.match(/^else\s+if\s+([^{]+)\{/);
            // Check for standalone 'if'
            const ifMatch = remainingText.match(/^if\s+([^{]+)\{/);
            // Check for 'else'
            const elseMatch = remainingText.match(/^else\s*\{/);
            
            let match = null;
            let type = null;
            let condition = null;
            let matchLength = 0;
            
            if (elseIfMatch) {
                match = elseIfMatch;
                type = 'else_if';
                condition = elseIfMatch[1].trim();
                matchLength = elseIfMatch[0].length;
            } else if (ifMatch) {
                match = ifMatch;
                type = 'if';
                condition = ifMatch[1].trim();
                matchLength = ifMatch[0].length;
            } else if (elseMatch) {
                match = elseMatch;
                type = 'else';
                matchLength = elseMatch[0].length;
            } else {
                // No conditional found, check if this is a filter plugin
                const filterMatch = remainingText.match(/^(\w+)\s*\{/);
                if (filterMatch) {
                    // This is a filter, not a conditional - skip past it
                    const openBracePos = pos + filterMatch[0].length - 1;
                    const closeBracePos = this.findMatchingBrace(text, openBracePos);
                    if (closeBracePos !== -1) {
                        pos = closeBracePos + 1;
                        continue;
                    }
                }
                pos++;
                continue;
            }
            
            if (match) {
                const startPos = pos;
                const openBracePos = pos + matchLength - 1;
                
                // Find matching closing brace
                const endPos = this.findMatchingBrace(text, openBracePos);
                
                if (endPos !== -1) {
                    const content = text.substring(openBracePos + 1, endPos);
                    
                    blocks.push({
                        type: type,
                        condition: condition,
                        content: content,
                        start: startPos,
                        end: endPos + 1
                    });
                    
                    // Jump past this entire block
                    pos = endPos + 1;
                } else {
                    pos++;
                }
            }
        }
        
        return blocks;
    }

    /**
     * Extract conditional blocks (if/else if/else)
     */
    extractConditionalBlocksOld(text) {
        const blocks = [];
        let pos = 0;
        
        while (pos < text.length) {
            // Skip whitespace
            while (pos < text.length && /\s/.test(text[pos])) {
                pos++;
            }
            
            if (pos >= text.length) break;
            
            // Look for conditional keywords at current position
            const remainingText = text.substring(pos);
            
            // Check for 'else if'
            const elseIfMatch = remainingText.match(/^else\s+if\s+([^{]+)\{/);
            // Check for standalone 'if' (not preceded by 'else')
            const ifMatch = remainingText.match(/^if\s+([^{]+)\{/);
            // Check for 'else'
            const elseMatch = remainingText.match(/^else\s*\{/);
            
            let match = null;
            let type = null;
            let condition = null;
            let matchLength = 0;
            
            if (elseIfMatch) {
                match = elseIfMatch;
                type = 'else_if';
                condition = elseIfMatch[1].trim();
                matchLength = elseIfMatch[0].length;
            } else if (ifMatch && (!elseMatch || remainingText.indexOf('if') < remainingText.indexOf('else'))) {
                match = ifMatch;
                type = 'if';
                condition = ifMatch[1].trim();
                matchLength = ifMatch[0].length;
            } else if (elseMatch) {
                match = elseMatch;
                type = 'else';
                matchLength = elseMatch[0].length;
            } else {
                // No conditional found at this position, skip character
                pos++;
                continue;
            }
            
            if (match) {
                const startPos = pos;
                const openBracePos = pos + matchLength - 1;
                
                // Find matching closing brace
                const endPos = this.findMatchingBrace(text, openBracePos);
                
                if (endPos !== -1) {
                    const content = text.substring(openBracePos + 1, endPos);
                    
                    blocks.push({
                        type: type,
                        condition: condition,
                        content: content,
                        start: startPos,
                        end: endPos + 1
                    });
                    
                    pos = endPos + 1;
                } else {
                    pos++;
                }
            }
        }
        
        return blocks;
    }

    /**
     * Find matching closing brace
     */
    findMatchingBrace(text, openPos) {
        let depth = 1;
        let pos = openPos + 1;
        
        while (pos < text.length && depth > 0) {
            if (text[pos] === '{') {
                depth++;
            } else if (text[pos] === '}') {
                depth--;
            }
            
            if (depth === 0) {
                return pos;
            }
            
            pos++;
        }
        
        return -1;
    }

    /**
     * Extract simple filter plugins (non-conditional)
     */
    extractSimpleFilters(text, filters, condition) {
        const pluginRegex = /(\w+)\s*\{/g;
        let match;
        
        while ((match = pluginRegex.exec(text)) !== null) {
            const filterType = match[1];
            
            // Skip conditional keywords
            if (['if', 'else'].includes(filterType)) {
                continue;
            }
            
            // Find the opening brace position
            const openBracePos = match.index + match[0].length - 1;
            const closeBracePos = this.findMatchingBrace(text, openBracePos);
            
            if (closeBracePos !== -1) {
                const config = text.substring(openBracePos + 1, closeBracePos).trim();
                
                filters.push({
                    type: filterType,
                    config: config,
                    parsedConfig: this.parseFilterConfig(filterType, config),
                    condition: condition
                });
            }
        }
    }

    /**
     * Parse condition string
     */
    parseCondition(conditionStr) {
        // Remove extra whitespace
        conditionStr = conditionStr.trim();
        
        // Parse comparison operators
        const comparisonRegex = /\[([^\]]+)\]\s*(==|!=|=~|!~|>|<|>=|<=)\s*(.+)/;
        const match = conditionStr.match(comparisonRegex);
        
        if (match) {
            const field = match[1];
            const operator = match[2];
            let value = match[3].trim();
            
            // Remove quotes from value
            if (value.startsWith('"') && value.endsWith('"')) {
                value = value.slice(1, -1);
            } else if (value.startsWith("'") && value.endsWith("'")) {
                value = value.slice(1, -1);
            }
            
            // Handle regex patterns (format: /pattern/)
            let isRegex = false;
            if (value.startsWith('/') && value.endsWith('/')) {
                value = value.slice(1, -1);
                isRegex = true;
            }
            
            // Special handling for regex that starts with ^
            if (isRegex && value.startsWith('^\\{')) {
                // Pattern like /^\{/ means "starts with {"
                value = value.substring(1); // Remove the ^
            }
            
            return {
                type: 'comparison',
                field: field,
                operator: operator,
                value: value,
                isRegex: isRegex,
                original: conditionStr
            };
        }
        
        // Handle field existence check
        const existsMatch = conditionStr.match(/\[([^\]]+)\]/);
        if (existsMatch) {
            return {
                type: 'exists',
                field: existsMatch[1],
                original: conditionStr
            };
        }
        
        return {
            type: 'unknown',
            original: conditionStr
        };
    }

    /**
     * Evaluate condition against data
     */
    evaluateCondition(condition, data, previousConditions = []) {
        if (!condition) {
            return true; // No condition means always execute
        }
        
        if (condition.type === 'else') {
            // Else executes only if all previous if/else-if conditions in the chain failed
            // For now, we'll track this in the processing logic
            return true;
        }
        
        if (condition.type === 'comparison') {
            const fieldValue = data[condition.field];
            const conditionValue = condition.value;
            
            switch (condition.operator) {
                case '==':
                    return fieldValue == conditionValue;
                case '!=':
                    return fieldValue != conditionValue;
                case '=~':
                    if (condition.isRegex) {
                        try {
                            const regex = new RegExp(conditionValue);
                            return regex.test(String(fieldValue || ''));
                        } catch (e) {
                            return false;
                        }
                    }
                    return String(fieldValue || '').includes(conditionValue);
                case '!~':
                    if (condition.isRegex) {
                        try {
                            const regex = new RegExp(conditionValue);
                            return !regex.test(String(fieldValue || ''));
                        } catch (e) {
                            return true;
                        }
                    }
                    return !String(fieldValue || '').includes(conditionValue);
                case '>':
                    return Number(fieldValue) > Number(conditionValue);
                case '<':
                    return Number(fieldValue) < Number(conditionValue);
                case '>=':
                    return Number(fieldValue) >= Number(conditionValue);
                case '<=':
                    return Number(fieldValue) <= Number(conditionValue);
                default:
                    return false;
            }
        }
        
        if (condition.type === 'exists') {
            return condition.field in data && data[condition.field] !== undefined && data[condition.field] !== null;
        }
        
        return false;
    }

    /**
     * Process log entry through filters with if/else chain handling
     */
    processLog(logEntry, filters, inputStreamInfo = null) {
        const steps = [];
        let currentData = { message: logEntry };
        
        // Add input stream metadata if provided
        if (inputStreamInfo) {
            currentData['type'] = inputStreamInfo.type;
            currentData['[input][type]'] = inputStreamInfo.type;
            currentData['[input][port]'] = inputStreamInfo.port;
            currentData['[input][protocol]'] = inputStreamInfo.protocol;
            
            // Add tags from input configuration if present
            if (inputStreamInfo.tags) {
                currentData['tags'] = Array.isArray(inputStreamInfo.tags) ? [...inputStreamInfo.tags] : [inputStreamInfo.tags];
            }
        }
        
        // Initial step
        steps.push({
            step: 0,
            filterType: 'input',
            description: 'Raw log entry',
            fields: { ...currentData },
            newFields: [],
            modifiedFields: [],
            removedFields: [],
            inputStream: inputStreamInfo
        });

        // Group filters by if/else chains
        const filterGroups = this.groupFiltersIntoChains(filters);
        
        // Process each filter or filter chain
        let stepNumber = 1;
        filterGroups.forEach(group => {
            if (group.type === 'chain') {
                // Process if/else-if/else chain
                let chainExecuted = false;
                
                group.filters.forEach(filter => {
                    const previousData = { ...currentData };
                    
                    if (chainExecuted) {
                        // Already executed one branch in this chain, skip the rest
                        steps.push({
                            step: stepNumber++,
                            filterType: filter.type,
                            filterConfig: filter.config,
                            parsedConfig: filter.parsedConfig,
                            description: this.getFilterDescription(filter),
                            condition: filter.condition,
                            conditionMet: false,
                            skipped: true,
                            skipReason: 'Previous condition in chain already executed',
                            fields: { ...currentData },
                            newFields: [],
                            modifiedFields: [],
                            removedFields: [],
                            success: true
                        });
                        return;
                    }
                    
                    const conditionMet = this.evaluateCondition(filter.condition, currentData);
                    
                    if (!conditionMet) {
                        steps.push({
                            step: stepNumber++,
                            filterType: filter.type,
                            filterConfig: filter.config,
                            parsedConfig: filter.parsedConfig,
                            description: this.getFilterDescription(filter),
                            condition: filter.condition,
                            conditionMet: false,
                            skipped: true,
                            fields: { ...currentData },
                            newFields: [],
                            modifiedFields: [],
                            removedFields: [],
                            success: true
                        });
                        return;
                    }
                    
                    // Condition met, execute this branch
                    chainExecuted = true;
                    
                    try {
                        currentData = this.applyFilter(filter, currentData);
                        const changes = this.trackChanges(previousData, currentData);
                        
                        steps.push({
                            step: stepNumber++,
                            filterType: filter.type,
                            filterConfig: filter.config,
                            parsedConfig: filter.parsedConfig,
                            description: this.getFilterDescription(filter),
                            condition: filter.condition,
                            conditionMet: true,
                            fields: { ...currentData },
                            ...changes,
                            success: true
                        });
                    } catch (error) {
                        steps.push({
                            step: stepNumber++,
                            filterType: filter.type,
                            filterConfig: filter.config,
                            description: this.getFilterDescription(filter),
                            condition: filter.condition,
                            conditionMet: true,
                            error: error.message,
                            fields: { ...previousData },
                            success: false
                        });
                    }
                });
            } else {
                // Single filter (not part of a chain)
                const filter = group.filter;
                const previousData = { ...currentData };
                
                try {
                    currentData = this.applyFilter(filter, currentData);
                    const changes = this.trackChanges(previousData, currentData);
                    
                    steps.push({
                        step: stepNumber++,
                        filterType: filter.type,
                        filterConfig: filter.config,
                        parsedConfig: filter.parsedConfig,
                        description: this.getFilterDescription(filter),
                        condition: filter.condition,
                        conditionMet: true,
                        fields: { ...currentData },
                        ...changes,
                        success: true
                    });
                } catch (error) {
                    steps.push({
                        step: stepNumber++,
                        filterType: filter.type,
                        filterConfig: filter.config,
                        description: this.getFilterDescription(filter),
                        condition: filter.condition,
                        conditionMet: true,
                        error: error.message,
                        fields: { ...previousData },
                        success: false
                    });
                }
            }
        });

        return { steps, finalData: currentData };
    }

    /**
     * Group filters into if/else chains
     */
    groupFiltersIntoChains(filters) {
        const groups = [];
        let i = 0;
        
        while (i < filters.length) {
            const filter = filters[i];
            
            if (!filter.condition) {
                // No condition, single filter
                groups.push({ type: 'single', filter: filter });
                i++;
                continue;
            }
            
            if (filter.condition.type === 'comparison' || filter.condition.type === 'exists') {
                // Start of a potential if/else chain
                const chain = [filter];
                let j = i + 1;
                
                // Look ahead for else-if or else
                while (j < filters.length) {
                    const nextFilter = filters[j];
                    
                    if (nextFilter.condition && nextFilter.condition.type === 'else') {
                        chain.push(nextFilter);
                        j++;
                        break; // Else ends the chain
                    } else if (nextFilter.condition && (nextFilter.condition.type === 'comparison' || nextFilter.condition.type === 'exists')) {
                        // Could be an else-if, add to chain
                        chain.push(nextFilter);
                        j++;
                    } else {
                        // Not part of this chain
                        break;
                    }
                }
                
                if (chain.length > 1) {
                    groups.push({ type: 'chain', filters: chain });
                    i = j;
                } else {
                    groups.push({ type: 'single', filter: filter });
                    i++;
                }
            } else if (filter.condition.type === 'else') {
                // Standalone else (shouldn't happen, but handle it)
                groups.push({ type: 'single', filter: filter });
                i++;
            } else {
                groups.push({ type: 'single', filter: filter });
                i++;
            }
        }
        
        return groups;
    }

    /**
     * Parse individual filter configuration
     */
    parseFilterConfig(filterType, config) {
        const parsed = {};
        
        switch (filterType) {
            case 'grok':
                parsed.patterns = this.extractGrokPatterns(config);
                break;
            case 'mutate':
                parsed.operations = this.extractMutateOperations(config);
                break;
            case 'date':
                parsed.dateConfig = this.extractDateConfig(config);
                break;
            case 'geoip':
                parsed.geoipConfig = this.extractGeoipConfig(config);
                break;
            case 'dissect':
                parsed.dissectPattern = this.extractDissectPattern(config);
                break;
            default:
                parsed.raw = config;
        }
        
        return parsed;
    }

    /**
     * Extract Grok patterns from configuration
     */
    extractGrokPatterns(config) {
        const patterns = [];
        const matchRegex = /match\s*=>\s*\{\s*"([^"]+)"\s*=>\s*"([^"]+)"\s*\}/g;
        
        let match;
        while ((match = matchRegex.exec(config)) !== null) {
            patterns.push({
                field: match[1],
                pattern: match[2]
            });
        }
        
        return patterns;
    }

    /**
     * Extract mutate operations
     */
    extractMutateOperations(config) {
        const operations = {};
        
        // Extract various mutate operations
        const operationTypes = ['add_field', 'add_tag', 'remove_tag', 'remove_field', 'rename', 'replace', 'convert', 'gsub', 'split', 'join', 'merge', 'strip', 'lowercase', 'uppercase'];
        
        operationTypes.forEach(opType => {
            const regex = new RegExp(`${opType}\\s*=>\\s*([\\s\\S]*?)(?=\\n\\s*\\w+\\s*=>|\\}\\s*$)`, 'g');
            const match = regex.exec(config);
            if (match) {
                operations[opType] = match[1].trim();
            }
        });
        
        return operations;
    }

    /**
     * Extract date configuration
     */
    extractDateConfig(config) {
        const matchField = config.match(/match\s*=>\s*\[\s*"([^"]+)"\s*,\s*"([^"]+)"\s*\]/);
        const target = config.match(/target\s*=>\s*"([^"]+)"/);
        
        return {
            field: matchField ? matchField[1] : null,
            format: matchField ? matchField[2] : null,
            target: target ? target[1] : '@timestamp'
        };
    }

    /**
     * Extract GeoIP configuration
     */
    extractGeoipConfig(config) {
        const source = config.match(/source\s*=>\s*"([^"]+)"/);
        
        return {
            source: source ? source[1] : null
        };
    }

    /**
     * Extract Dissect pattern
     */
    extractDissectPattern(config) {
        const mapping = config.match(/mapping\s*=>\s*\{\s*"([^"]+)"\s*=>\s*"([^"]+)"\s*\}/);
        
        return {
            field: mapping ? mapping[1] : null,
            pattern: mapping ? mapping[2] : null
        };
    }



    /**
     * Apply individual filter to data
     */
    applyFilter(filter, data) {
        const result = { ...data };
        
        switch (filter.type) {
            case 'grok':
                return this.applyGrok(filter.parsedConfig, result);
            case 'mutate':
                return this.applyMutate(filter.parsedConfig, result);
            case 'date':
                return this.applyDate(filter.parsedConfig, result);
            case 'dissect':
                return this.applyDissect(filter.parsedConfig, result);
            case 'csv':
                return this.applyCsv(filter.parsedConfig, result);
            default:
                return result;
        }
    }

    /**
     * Apply Grok filter
     */
    applyGrok(config, data) {
        const result = { ...data };
        
        if (!config.patterns || config.patterns.length === 0) {
            return result;
        }

        config.patterns.forEach(({ field, pattern }) => {
            if (result[field]) {
                const regex = this.convertGrokToRegex(pattern);
                const match = result[field].match(regex);
                
                if (match && match.groups) {
                    Object.assign(result, match.groups);
                }
            }
        });

        return result;
    }

    /**
     * Convert Grok pattern to JavaScript regex
     */
    convertGrokToRegex(pattern) {
        let regex = pattern;
        
        // Replace Grok patterns with their regex equivalents
        let iterations = 0;
        const maxIterations = 50;
        
        while (/%\{(\w+)(?::(\w+))?\}/.test(regex) && iterations < maxIterations) {
            regex = regex.replace(/%\{(\w+)(?::(\w+))?\}/g, (match, patternName, fieldName) => {
                const patternRegex = this.grokPatterns[patternName] || this.grokPatterns['DATA'];
                
                if (fieldName) {
                    return `(?<${fieldName}>${patternRegex})`;
                }
                return `(?:${patternRegex})`;
            });
            iterations++;
        }
        
        return new RegExp(regex);
    }

    /**
     * Apply Mutate filter
     */
    applyMutate(config, data) {
        const result = { ...data };
        
        if (config.operations.add_field) {
            const fields = this.parseHashConfig(config.operations.add_field);
            Object.assign(result, fields);
        }
        
        if (config.operations.add_tag) {
            const tags = this.parseArrayConfig(config.operations.add_tag);
            if (!result.tags) {
                result.tags = [];
            } else if (!Array.isArray(result.tags)) {
                result.tags = [result.tags];
            }
            result.tags = [...result.tags, ...tags];
        }
        
        if (config.operations.remove_tag) {
            const tagsToRemove = this.parseArrayConfig(config.operations.remove_tag);
            if (Array.isArray(result.tags)) {
                result.tags = result.tags.filter(tag => !tagsToRemove.includes(tag));
            }
        }
        
        if (config.operations.remove_field) {
            const fields = this.parseArrayConfig(config.operations.remove_field);
            fields.forEach(field => delete result[field]);
        }
        
        if (config.operations.rename) {
            const renames = this.parseHashConfig(config.operations.rename);
            Object.entries(renames).forEach(([oldName, newName]) => {
                if (result[oldName]) {
                    result[newName] = result[oldName];
                    delete result[oldName];
                }
            });
        }
        
        if (config.operations.replace) {
            const replacements = this.parseHashConfig(config.operations.replace);
            Object.entries(replacements).forEach(([field, newValue]) => {
                result[field] = newValue;
            });
        }
        
        if (config.operations.convert) {
            const conversions = this.parseHashConfig(config.operations.convert);
            Object.entries(conversions).forEach(([field, type]) => {
                if (result[field]) {
                    switch(type) {
                        case 'integer':
                            result[field] = parseInt(result[field]);
                            break;
                        case 'float':
                            result[field] = parseFloat(result[field]);
                            break;
                        case 'string':
                            result[field] = String(result[field]);
                            break;
                        case 'boolean':
                            result[field] = Boolean(result[field]);
                            break;
                    }
                }
            });
        }
        
        if (config.operations.lowercase) {
            const fields = this.parseArrayConfig(config.operations.lowercase);
            fields.forEach(field => {
                if (result[field]) {
                    result[field] = String(result[field]).toLowerCase();
                }
            });
        }
        
        if (config.operations.uppercase) {
            const fields = this.parseArrayConfig(config.operations.uppercase);
            fields.forEach(field => {
                if (result[field]) {
                    result[field] = String(result[field]).toUpperCase();
                }
            });
        }
        
        if (config.operations.strip) {
            const fields = this.parseArrayConfig(config.operations.strip);
            fields.forEach(field => {
                if (result[field]) {
                    result[field] = String(result[field]).trim();
                }
            });
        }
        
        return result;
    }

    /**
     * Apply Date filter
     */
    applyDate(config, data) {
        const result = { ...data };
        
        if (config.field && result[config.field]) {
            result[config.target || '@timestamp'] = new Date(result[config.field]).toISOString();
        }
        
        return result;
    }

    /**
     * Apply Dissect filter
     */
    applyDissect(config, data) {
        const result = { ...data };
        
        if (config.field && config.pattern && result[config.field]) {
            const parts = config.pattern.split('%{');
            // Simple dissect implementation
            // This is a simplified version
        }
        
        return result;
    }

    /**
     * Apply CSV filter
     */
    applyCsv(config, data) {
        const result = { ...data };
        // CSV parsing implementation
        return result;
    }

    /**
     * Parse hash-style configuration
     */
    parseHashConfig(configStr) {
        const result = {};
        const regex = /"([^"]+)"\s*=>\s*"([^"]+)"/g;
        let match;
        
        while ((match = regex.exec(configStr)) !== null) {
            result[match[1]] = match[2];
        }
        
        return result;
    }

    /**
     * Parse array-style configuration
     */
    parseArrayConfig(configStr) {
        const matches = configStr.match(/"([^"]+)"/g);
        return matches ? matches.map(m => m.replace(/"/g, '')) : [];
    }

    /**
     * Track field changes between steps
     */
    trackChanges(previous, current) {
        const newFields = [];
        const modifiedFields = [];
        const removedFields = [];
        
        // Find new and modified fields
        Object.keys(current).forEach(key => {
            if (!(key in previous)) {
                newFields.push(key);
            } else {
                // Deep comparison for arrays and objects
                const prevValue = previous[key];
                const currValue = current[key];
                
                if (Array.isArray(prevValue) && Array.isArray(currValue)) {
                    // Compare arrays
                    if (JSON.stringify(prevValue) !== JSON.stringify(currValue)) {
                        modifiedFields.push(key);
                    }
                } else if (typeof prevValue === 'object' && typeof currValue === 'object' && prevValue !== null && currValue !== null) {
                    // Compare objects
                    if (JSON.stringify(prevValue) !== JSON.stringify(currValue)) {
                        modifiedFields.push(key);
                    }
                } else if (prevValue !== currValue) {
                    modifiedFields.push(key);
                }
            }
        });
        
        // Find removed fields
        Object.keys(previous).forEach(key => {
            if (!(key in current)) {
                removedFields.push(key);
            }
        });
        
        return { newFields, modifiedFields, removedFields };
    }

    /**
     * Get human-readable description for filter
     */
    getFilterDescription(filter) {
        const descriptions = {
            'grok': 'Parse structured data from unstructured text using patterns',
            'mutate': 'Transform and modify field values',
            'date': 'Parse dates and set @timestamp field',
            'geoip': 'Add geographical information based on IP addresses',
            'dissect': 'Extract structured fields using delimiters',
            'csv': 'Parse comma-separated values',
            'kv': 'Parse key-value pairs',
            'json': 'Parse JSON data'
        };
        
        return descriptions[filter.type] || `Apply ${filter.type} filter`;
    }
}
