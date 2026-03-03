#!/usr/bin/env node
/**
 * Extract testable code blocks from the security guide.
 * Outputs JSON array of { type, code, line, context }
 */

const fs = require('fs');
const path = require('path');

const guidePath = process.argv[2] || path.join(__dirname, '..', 'guide.md');
const content = fs.readFileSync(guidePath, 'utf8');
const lines = content.split('\n');

const blocks = [];
let inBlock = false;
let blockType = '';
let blockCode = [];
let blockStartLine = 0;
let lastHeading = '';

for (let i = 0; i < lines.length; i++) {
  const line = lines[i];
  
  // Track headings for context
  if (line.startsWith('#')) {
    lastHeading = line.replace(/^#+\s*/, '');
  }
  
  // Start of code block
  if (line.startsWith('```') && !inBlock) {
    inBlock = true;
    blockType = line.slice(3).trim().toLowerCase() || 'text';
    blockCode = [];
    blockStartLine = i + 1;
    continue;
  }
  
  // End of code block
  if (line.startsWith('```') && inBlock) {
    inBlock = false;
    
    const code = blockCode.join('\n');
    
    // Classify the block
    let testType = 'skip';
    
    if (blockType === 'bash' || blockType === 'sh' || blockType === 'shell') {
      // Check if it's a command vs output example
      if (code.includes('# →') || code.includes('# Expected') || code.match(/^[A-Z_]+=.*$/m)) {
        testType = 'bash-check'; // Commands that should work
      } else if (code.trim().startsWith('#')) {
        testType = 'skip'; // Pure comments
      } else {
        testType = 'bash-run';
      }
    } else if (blockType === 'json' || blockType === 'json5' || blockType === 'jsonc') {
      testType = 'json-parse';
    } else if (blockType === 'yaml' || blockType === 'yml') {
      testType = 'yaml-parse';
    }
    
    // Skip blocks that are clearly examples/output
    if (code.includes('your-') || code.includes('example') || code.includes('...')) {
      testType = 'skip-placeholder';
    }
    
    blocks.push({
      type: blockType,
      testType,
      code,
      line: blockStartLine,
      context: lastHeading,
      length: blockCode.length
    });
    
    continue;
  }
  
  if (inBlock) {
    blockCode.push(line);
  }
}

// Output summary
const summary = {
  total: blocks.length,
  byTestType: {},
  byBlockType: {}
};

blocks.forEach(b => {
  summary.byTestType[b.testType] = (summary.byTestType[b.testType] || 0) + 1;
  summary.byBlockType[b.type] = (summary.byBlockType[b.type] || 0) + 1;
});

if (process.argv.includes('--summary')) {
  console.log(JSON.stringify(summary, null, 2));
} else if (process.argv.includes('--testable')) {
  const testable = blocks.filter(b => !b.testType.startsWith('skip'));
  console.log(JSON.stringify(testable, null, 2));
} else {
  console.log(JSON.stringify(blocks, null, 2));
}
