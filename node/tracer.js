// Run with:
// node --require trace.js malware.js

const Module = require('module');
const origLoad = Module._load;

function showStack() {
  const e = new Error();
  return e.stack.split('\n').slice(3).join('\n');
}

function logCall(ns, name, args) {
  // ignore destructors
  if (name == "free") return
  
  try {
    process.stderr.write(`[${ns}.${name}] args=${JSON.stringify(args)}\nStack:\n${showStack()}\n---\n`);
  } catch {
    process.stderr.write(`[${ns}.${name}] args=<error displaying args>\n`)
  }
}

function wrapAll(obj, ns, seen = new WeakSet()) {
  if (!obj || (typeof obj !== 'object' && typeof obj !== 'function') || seen.has(obj)) return obj;
  seen.add(obj);

  if (typeof obj === 'function') {
    const orig = obj;
    const wrapped = function(...args) {
      logCall(ns, orig.name || '<anon>', args);
      return orig.apply(this, args);
    };
    try { Object.defineProperties(wrapped, Object.getOwnPropertyDescriptors(orig)); } catch {}
    return wrapped;
  }

  for (const k of Object.keys(obj)) {
    //if (ns.startsWith('node:console') || ns.startsWith('console')) continue; // skip console
    try {
      const val = obj[k];
      if (typeof val === 'function') {
        const orig = val;
        obj[k] = function(...args) {
          logCall(ns, k, args);
          return orig.apply(this, args);
        };
      } else if (val && typeof val === 'object') {
        wrapAll(val, `${ns}.${k}`, seen);
      }
    } catch {}
  }
  return obj;
}

Module._load = function(request, parent, isMain) {
  const loaded = origLoad.apply(this, arguments);
  try {
    const resolved = Module._resolveFilename(request, parent);
    process.stderr.write(`module load: ${resolved}\n`) 
    if (!resolved.includes('console')) {
      return wrapAll(loaded, resolved);
    }
  } catch {}
  return loaded;
};
