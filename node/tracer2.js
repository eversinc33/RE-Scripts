DISPLAY_STACK = false

const { execSync } = require('child_process');
const Module = require('module');
const fs = require('fs');
const path = require('path');
const origLoad = Module._load;

// keep originals to avoid recursion
const _writeFileSync = fs.writeFileSync;
const _writeFile = fs.writeFile;
const _appendFileSync = fs.appendFileSync;
const _appendFile = fs.appendFile;
const _openSync = fs.openSync;

// Anti-Anti-VM
// --------------------------------

// RAM
const os = require('os')
const _totalmem = os.totalmem;
os.totalmem = () => 16 * 1024 ** 3 // 16 GB

// CPU
const _cpus = os.cpus
os.cpus = () => [
  {
    model: 'Intel(R) Core(TM) i7-9700K CPU @ 3.60GHz',
    speed: 3600,
    times: { user: 0, nice: 0, sys: 0, idle: 0, irq: 0 }
  },
  {
    model: 'Intel(R) Core(TM) i7-9700K CPU @ 3.60GHz',
    speed: 3600,
    times: { user: 0, nice: 0, sys: 0, idle: 0, irq: 0 }
  },
  {
    model: 'Intel(R) Core(TM) i7-9700K CPU @ 3.60GHz',
    speed: 3600,
    times: { user: 0, nice: 0, sys: 0, idle: 0, irq: 0 }
  },
  {
    model: 'Intel(R) Core(TM) i7-9700K CPU @ 3.60GHz',
    speed: 3600,
    times: { user: 0, nice: 0, sys: 0, idle: 0, irq: 0 }
  }
]

// --------------------------------

function showStack() {
  const e = new Error();
  return e.stack.split('\n').slice(3).join('\n');
}

function logCall(ns, name, args) {
  if (name == "free") return
  try {
    DISPLAY_STACK
      ? process.stderr.write(`[${ns}.${name}] args=${JSON.stringify(args)}\nStack:\n${showStack()}\n---\n`)
      : process.stderr.write(`[${ns}.${name}] args=${JSON.stringify(args)}\n`);
  } catch {
    process.stderr.write(`[${ns}.${name}] args=<error displaying args>\n`)
  }
}

// safe helpers to avoid recursion
function safeCopy(filePath, data) {
  try {
    const baseName = path.basename(filePath);
    const copyPath = path.join(process.cwd(), baseName);
    _writeFileSync(copyPath, data);
  } catch {}
}

function safeLogHttp(args) {
  try {
    _appendFileSync('./requests.txt', JSON.stringify(args[0]) + "\n");
  } catch {}
}

function wrapAll(obj, ns, seen = new WeakSet()) {
  if (!obj || (typeof obj !== 'object' && typeof obj !== 'function') || seen.has(obj)) return obj;
  seen.add(obj);

  if (typeof obj === 'function') {
    const orig = obj;
    const wrapped = function (...args) {
      logCall(ns, orig.name || '<anon>', args);
      return orig.apply(this, args);
    };
    try { Object.defineProperties(wrapped, Object.getOwnPropertyDescriptors(orig)); } catch {}
    return wrapped;
  }

  for (const k of Object.keys(obj)) {
    try {
      const val = obj[k];
      if (typeof val === 'function') {
        const orig = val;

        obj[k] = function (...args) {
          logCall(ns, k, args);

          // --------------------------------
          // Spoof exec
          if (k == "execSync" || k == "exec") {
            if (args[0] == "tasklist") return "";
            if (args[0].startsWith("powershell")) return "4";
          }

          // Pretend *.lock files don't exist
          if (k === "openSync" && typeof args[0] === "string" && args[0].endsWith(".lock")) {
            let err = new Error("ENOENT: no such file or directory, open '" + args[0] + "'");
            err.code = "ENOENT";
            err.errno = -4058; // Windows
            err.syscall = "open";
            err.path = args[0];
            throw err;
          }

          // File writes: duplicate + perform real op
          if (ns.includes('fs')) {
            if (k === 'writeFileSync') {
              let [filePath, data] = args;
              if (typeof filePath === 'string') safeCopy(filePath, data);
              return _writeFileSync.apply(fs, args);
            }
            if (k === 'writeFile') {
              let [filePath, data] = args;
              if (typeof filePath === 'string') safeCopy(filePath, data);
              return _writeFile.apply(fs, args);
            }
            if (k === 'appendFileSync') {
              let [filePath, data] = args;
              if (typeof filePath === 'string') safeCopy(filePath, data);
              return _appendFileSync.apply(fs, args);
            }
            if (k === 'appendFile') {
              let [filePath, data] = args;
              if (typeof filePath === 'string') safeCopy(filePath, data);
              return _appendFile.apply(fs, args);
            }
          }

          // Log HTTP requests
          if ((ns.includes('http') || ns.includes('https')) && (k === 'request' || k === 'get')) {
            safeLogHttp(args);
          }
          // --------------------------------

          return orig.apply(this, args);
        };

      } else if (val && typeof val === 'object') {
        wrapAll(val, `${ns}.${k}`, seen);
      }
    } catch {}
  }
  return obj;
}

Module._load = function (request, parent, isMain) {
  const loaded = origLoad.apply(this, arguments);
  try {
    const resolved = Module._resolveFilename(request, parent);
    process.stderr.write(`module load: ${resolved}\n`);
    if (!resolved.includes('console')) {
      return wrapAll(loaded, resolved);
    }
  } catch {}
  return loaded;
};

