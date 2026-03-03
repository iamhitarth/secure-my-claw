#!/usr/bin/env node
/**
 * Validate config blocks in the security guide against current OpenClaw schema.
 * This is the core validator - checks that config examples use correct keys.
 */

const fs = require('fs');
const path = require('path');

// Current OpenClaw config schema (key paths that exist)
const VALID_TOP_LEVEL_KEYS = new Set([
  'gateway', 'channels', 'agents', 'bindings', 'session', 'messages', 'talk',
  'tools', 'skills', 'plugins', 'browser', 'ui', 'hooks', 'canvasHost',
  'discovery', 'env', 'secrets', 'auth', 'logging', 'wizard', 'models', 'cron'
]);

// Keys that used to exist but are now wrong
const DEPRECATED_KEYS = {
  'security': 'Split into gateway.auth, tools.exec, etc.',
  'mcp': 'Now plugin-based, use plugins.entries',
  'telegram': 'Move to channels.telegram',
  'discord': 'Move to channels.discord', 
  'whatsapp': 'Move to channels.whatsapp',
  'signal': 'Move to channels.signal',
  'slack': 'Move to channels.slack',
};

// Config path mappings (old → new)
const PATH_MIGRATIONS = {
  'gateway.host': 'gateway.bind',
  'gateway.token': 'gateway.auth.token',
  'gateway.password': 'gateway.auth.password',
  'security.rateLimit': 'gateway.auth.rateLimit',
  'security.exec': 'tools.exec',
  'security.elevated': 'tools.elevated',
};

class ConfigValidator {
  constructor() {
    this.errors = [];
    this.warnings = [];
  }

  validateYamlBlock(code, line, context) {
    // YAML blocks are automatically wrong - OpenClaw uses JSON5
    this.errors.push({
      line,
      context,
      type: 'wrong-format',
      message: 'OpenClaw uses JSON5 (openclaw.json), not YAML',
      code: code.substring(0, 100) + '...'
    });
  }

  validateJsonBlock(code, line, context) {
    // Parse and check structure
    let parsed;
    try {
      // Try JSON5-style parsing via eval (safe for config objects)
      parsed = eval('(' + code + ')');
    } catch (e) {
      this.errors.push({
        line,
        context,
        type: 'parse-error',
        message: `JSON parse failed: ${e.message}`,
        code: code.substring(0, 100) + '...'
      });
      return;
    }

    // Check top-level keys
    for (const key of Object.keys(parsed)) {
      if (DEPRECATED_KEYS[key]) {
        this.errors.push({
          line,
          context,
          type: 'deprecated-key',
          message: `'${key}' is deprecated: ${DEPRECATED_KEYS[key]}`,
          key
        });
      } else if (!VALID_TOP_LEVEL_KEYS.has(key)) {
        this.warnings.push({
          line,
          context,
          type: 'unknown-key',
          message: `Unknown top-level key '${key}' - may be outdated`,
          key
        });
      }
    }

    // Check for old path patterns in the structure
    this.checkPathMigrations(parsed, '', line, context);
  }

  checkPathMigrations(obj, prefix, line, context) {
    if (typeof obj !== 'object' || obj === null) return;

    for (const [key, value] of Object.entries(obj)) {
      const path = prefix ? `${prefix}.${key}` : key;
      
      if (PATH_MIGRATIONS[path]) {
        this.errors.push({
          line,
          context,
          type: 'wrong-path',
          message: `'${path}' should be '${PATH_MIGRATIONS[path]}'`,
          oldPath: path,
          newPath: PATH_MIGRATIONS[path]
        });
      }

      if (typeof value === 'object' && value !== null) {
        this.checkPathMigrations(value, path, line, context);
      }
    }
  }

  validateGuide(guidePath) {
    const content = fs.readFileSync(guidePath, 'utf8');
    const lines = content.split('\n');

    let inBlock = false;
    let blockType = '';
    let blockCode = [];
    let blockStartLine = 0;
    let lastHeading = '';

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];

      if (line.startsWith('#')) {
        lastHeading = line.replace(/^#+\s*/, '');
      }

      if (line.startsWith('```') && !inBlock) {
        inBlock = true;
        blockType = line.slice(3).trim().toLowerCase();
        blockCode = [];
        blockStartLine = i + 2; // 1-indexed, after the ```
        continue;
      }

      if (line.startsWith('```') && inBlock) {
        inBlock = false;
        const code = blockCode.join('\n');

        // Only validate config-like blocks
        if (blockType === 'yaml' || blockType === 'yml') {
          // Check if it looks like OpenClaw config
          if (code.includes('gateway:') || code.includes('security:') || 
              code.includes('telegram:') || code.includes('channels:')) {
            this.validateYamlBlock(code, blockStartLine, lastHeading);
          }
        } else if (blockType === 'json' || blockType === 'json5' || blockType === 'jsonc') {
          if (code.includes('gateway') || code.includes('channels') || 
              code.includes('security') || code.includes('agents')) {
            this.validateJsonBlock(code, blockStartLine, lastHeading);
          }
        }

        continue;
      }

      if (inBlock) {
        blockCode.push(line);
      }
    }

    // Also check for inline references to wrong paths
    const wrongPathPatterns = [
      { pattern: /config\.yaml/g, message: 'Should be openclaw.json' },
      { pattern: /~\/\.openclaw\/config\.yaml/g, message: 'Should be ~/.openclaw/openclaw.json' },
    ];

    for (let i = 0; i < lines.length; i++) {
      for (const { pattern, message } of wrongPathPatterns) {
        if (pattern.test(lines[i])) {
          this.errors.push({
            line: i + 1,
            context: 'inline text',
            type: 'wrong-reference',
            message,
            text: lines[i].trim().substring(0, 80)
          });
        }
        pattern.lastIndex = 0; // Reset regex
      }
    }

    return {
      errors: this.errors,
      warnings: this.warnings,
      summary: {
        totalErrors: this.errors.length,
        totalWarnings: this.warnings.length,
        byType: this.errors.reduce((acc, e) => {
          acc[e.type] = (acc[e.type] || 0) + 1;
          return acc;
        }, {})
      }
    };
  }
}

// Run if called directly
if (require.main === module) {
  const guidePath = process.argv[2] || path.join(__dirname, '..', 'guide.md');
  const validator = new ConfigValidator();
  const result = validator.validateGuide(guidePath);

  if (process.argv.includes('--json')) {
    console.log(JSON.stringify(result, null, 2));
  } else {
    console.log('🔍 Config Validation Results');
    console.log('============================\n');

    if (result.errors.length === 0 && result.warnings.length === 0) {
      console.log('✅ All config blocks are valid!\n');
    } else {
      if (result.errors.length > 0) {
        console.log(`❌ ${result.errors.length} Errors:\n`);
        for (const err of result.errors) {
          console.log(`  Line ${err.line} [${err.context}]`);
          console.log(`    ${err.type}: ${err.message}`);
          if (err.code) console.log(`    Code: ${err.code}`);
          console.log('');
        }
      }

      if (result.warnings.length > 0) {
        console.log(`⚠️  ${result.warnings.length} Warnings:\n`);
        for (const warn of result.warnings) {
          console.log(`  Line ${warn.line} [${warn.context}]`);
          console.log(`    ${warn.type}: ${warn.message}`);
          console.log('');
        }
      }
    }

    console.log('Summary:', JSON.stringify(result.summary, null, 2));
  }

  // Exit with error if there are errors
  process.exit(result.errors.length > 0 ? 1 : 0);
}

module.exports = { ConfigValidator };
