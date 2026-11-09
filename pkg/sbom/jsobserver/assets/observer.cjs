// werf JavaScript bundle observer. Loaded by bootstrap.cjs only on Node.js
// releases with module.registerHooks; it wraps the JavaScript API of the Rollup
// and esbuild packages the build actually loads and records, for every output
// file, the installed packages that contributed bytes to it.
"use strict";

const { createHash } = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { fileURLToPath } = require("node:url");

const instrumentKey = Symbol.for("werf.jsObserver.instrument");
const rollupFacadeQuery = "werf-js-observer-rollup";
const rollupFacadeSuffix = `?${rollupFacadeQuery}`;

module.exports = function start({ registerHooks, appendLine, settings }) {
  const packageCache = new Map();

  function appendEvent(event) {
    appendLine(`${JSON.stringify({ version: settings.protocolVersion, ...event })}\n`);
  }

  function warn(message) {
    appendEvent({ warning: message });
  }

  // Lines are assembled from outputs serialized once; the result is the same
  // JSON as serializing the whole event.
  function emitOutputs(outputs) {
    const head = `{"version":${JSON.stringify(settings.protocolVersion)},"outputs":[`;
    const tail = "]}\n";
    const emptyLineBytes = Buffer.byteLength(head) + Buffer.byteLength(tail);
    let batch = [];
    let batchBytes = emptyLineBytes;
    const flush = () => {
      if (batch.length > 0) appendLine(head + batch.join(",") + tail);
      batch = [];
      batchBytes = emptyLineBytes;
    };
    for (const output of outputs) {
      const serialized = JSON.stringify(output);
      const bytes = Buffer.byteLength(serialized);
      if (emptyLineBytes + bytes > settings.maxEventBytes) {
        warn(`observation of ${output.path} exceeds ${settings.maxEventBytes} bytes and is not recorded`);
        continue;
      }
      const separatorBytes = batch.length > 0 ? 1 : 0;
      if (batchBytes + separatorBytes + bytes > settings.maxEventBytes) flush();
      batchBytes += (batch.length > 0 ? 1 : 0) + bytes;
      batch.push(serialized);
    }
    flush();
  }

  function observe(tool, collect) {
    try {
      emitOutputs(collect());
    } catch (err) {
      warn(`${tool} output observation failed: ${err && err.message}`);
    }
  }

  function readManifest(dir) {
    try {
      return JSON.parse(fs.readFileSync(path.join(dir, "package.json"), "utf8"));
    } catch {
      return null;
    }
  }

  function isPackageDirectory(dir) {
    const parent = path.dirname(dir);
    if (path.basename(parent) === "node_modules") return true;
    return path.basename(parent).startsWith("@") && path.basename(path.dirname(parent)) === "node_modules";
  }

  // Nested package.json files without a name and a version (for example
  // {"type":"module"} in a dist directory) do not start a package.
  function owningPackage(realFile) {
    const visited = [];
    let dir = path.dirname(realFile);
    let found = null;
    for (;;) {
      if (packageCache.has(dir)) {
        found = packageCache.get(dir);
        break;
      }
      visited.push(dir);
      const manifest = readManifest(dir);
      if (manifest && typeof manifest.name === "string" && manifest.name !== "" && typeof manifest.version === "string" && manifest.version !== "") {
        found = { name: manifest.name, version: manifest.version, root: dir };
        break;
      }
      const parent = path.dirname(dir);
      if (isPackageDirectory(dir) || parent === dir) break;
      dir = parent;
    }
    for (const dir of visited) packageCache.set(dir, found);
    return found;
  }

  function projectRoot(startDir) {
    let dir;
    try {
      dir = fs.realpathSync(startDir);
    } catch {
      return null;
    }
    for (;;) {
      if (fs.existsSync(path.join(dir, "package.json"))) return dir;
      const parent = path.dirname(dir);
      if (parent === dir) return null;
      dir = parent;
    }
  }

  function isInside(child, parent) {
    const relative = path.relative(parent, child);
    return relative === "" || (!relative.startsWith("..") && !path.isAbsolute(relative));
  }

  // The project being built is first-party, and so are workspace packages
  // inside it; installed dependencies and linked packages outside it are not.
  function thirdPartyPackage(file, root) {
    let realFile;
    try {
      if (!fs.statSync(file).isFile()) return null;
      realFile = fs.realpathSync(file);
    } catch {
      return null;
    }
    const owner = owningPackage(realFile);
    if (!owner) return null;
    // Without a known project root only installed dependencies are certainly not first-party.
    if (root === null) return owner.root.split(path.sep).includes("node_modules") ? owner : null;
    if (isInside(root, owner.root)) return null;
    if (isInside(owner.root, root) && !path.relative(root, owner.root).split(path.sep).includes("node_modules")) return null;
    return owner;
  }

  function sortedPackages(packages) {
    return [...packages.values()]
      .map(({ name, version }) => ({ name, version }))
      .sort((a, b) => (a.name === b.name ? (a.version < b.version ? -1 : 1) : a.name < b.name ? -1 : 1));
  }

  function sha256(data) {
    return `sha256:${createHash("sha256").update(data).digest("hex")}`;
  }

  function fileDigest(file) {
    try {
      if (!fs.statSync(file).isFile()) return null;
      return sha256(fs.readFileSync(file));
    } catch {
      return null;
    }
  }

  function fileHolds(file, data) {
    try {
      return fs.readFileSync(file).equals(data);
    } catch {
      return false;
    }
  }

  function addPackage(packages, owner) {
    if (owner) packages.set(`${owner.name}@${owner.version}`, owner);
  }

  // Plugin modules prefixed with "\0" are not absolute paths and stay unattributed.
  function rollupModuleFile(id) {
    if (typeof id !== "string") return null;
    const query = id.indexOf("?");
    const file = query === -1 ? id : id.slice(0, query);
    return path.isAbsolute(file) ? file : null;
  }

  function rollupOutputs(method, outputOptions, result) {
    const dir = outputOptions && outputOptions.dir
      ? path.resolve(outputOptions.dir)
      : outputOptions && outputOptions.file ? path.dirname(path.resolve(outputOptions.file)) : null;
    if (!dir || !result || !Array.isArray(result.output)) return [];
    const root = projectRoot(process.cwd());
    const outputs = [];
    for (const item of result.output) {
      if (item.type !== "chunk" || !item.modules) continue;
      const packages = new Map();
      for (const [id, info] of Object.entries(item.modules)) {
        if (!(info && info.renderedLength > 0)) continue;
        const file = rollupModuleFile(id);
        if (file) addPackage(packages, thirdPartyPackage(file, root));
      }
      if (packages.size === 0) continue;
      const outputPath = path.resolve(dir, item.fileName);
      const code = Buffer.from(item.code, "utf8");
      // An outputOptions plugin hook can make Rollup write somewhere else.
      if (method === "write" && !fileHolds(outputPath, code)) {
        warn(`Rollup output ${outputPath} does not hold the written chunk and is not recorded`);
        continue;
      }
      outputs.push({ path: outputPath, digest: sha256(code), packages: sortedPackages(packages) });
    }
    return outputs;
  }

  function observeRollupBundle(bundle) {
    if (!bundle || typeof bundle !== "object") return;
    for (const method of ["generate", "write"]) {
      const original = bundle[method];
      if (typeof original !== "function") continue;
      bundle[method] = {
        async [method](outputOptions, ...rest) {
          const result = await original.call(this, outputOptions, ...rest);
          observe("Rollup", () => rollupOutputs(method, outputOptions, result));
          return result;
        },
      }[method];
    }
  }

  function wrapRollup(original) {
    if (typeof original !== "function") {
      warn("Rollup exports are not recognized, its bundles are not observed");
      return original;
    }
    return {
      async rollup(inputOptions, ...rest) {
        const bundle = await original.call(this, inputOptions, ...rest);
        observeRollupBundle(bundle);
        return bundle;
      },
    }.rollup;
  }

  // Plugins still see the forced metafile in initialOptions and onEnd results;
  // only the result returned to the caller is restored. esbuild also reads
  // options the caller's object inherits, so the copy keeps its prototype.
  function forceMetafile(options) {
    if (!options || typeof options !== "object") return null;
    if (options.metafile === true) return { options, requested: true };
    if (options.metafile !== undefined && options.metafile !== false) return null;
    const descriptors = Object.getOwnPropertyDescriptors(options);
    descriptors.metafile = { value: true, enumerable: true, configurable: true, writable: true };
    return { options: Object.create(Object.getPrototypeOf(options), descriptors), requested: false };
  }

  function esbuildOutputs(options, result, defaultWorkingDir) {
    if (!result || !result.metafile || !result.metafile.outputs) return [];
    const workDir = options.absWorkingDir ? path.resolve(options.absWorkingDir) : defaultWorkingDir;
    const root = projectRoot(workDir);
    const memory = new Map((result.outputFiles || []).map((file) => [path.resolve(file.path), file.contents]));
    const outputs = [];
    for (const [outputKey, output] of Object.entries(result.metafile.outputs)) {
      const packages = new Map();
      for (const [inputKey, input] of Object.entries(output.inputs || {})) {
        if (!(input && input.bytesInOutput > 0)) continue;
        addPackage(packages, thirdPartyPackage(path.resolve(workDir, inputKey), root));
      }
      if (packages.size === 0) continue;
      const outputPath = path.resolve(workDir, outputKey);
      let digest = null;
      if (options.write !== false) digest = fileDigest(outputPath);
      else if (memory.has(outputPath)) digest = sha256(memory.get(outputPath));
      if (digest) outputs.push({ path: outputPath, digest, packages: sortedPackages(packages) });
    }
    return outputs;
  }

  function finishEsbuild(forced, result, defaultWorkingDir) {
    observe("esbuild", () => esbuildOutputs(forced.options, result, defaultWorkingDir));
    if (!forced.requested && result && typeof result === "object") result.metafile = undefined;
    return result;
  }

  // Replaced members keep the kind and attributes of the original property,
  // so getters of esbuild's CommonJS exports stay getters.
  function replaceMember(descriptors, name, value) {
    const original = descriptors[name];
    if (!original) throw new Error(`no own "${name}" export`);
    descriptors[name] = original.get || original.set
      ? { get: () => value, enumerable: original.enumerable, configurable: original.configurable }
      : { value, enumerable: original.enumerable, configurable: original.configurable, writable: original.writable };
  }

  function wrapEsbuildObject(original, resolveDefault, defaultWorkingDir) {
    const descriptors = Object.getOwnPropertyDescriptors(original);
    const originalBuild = original.build;
    const originalContext = original.context;
    if (typeof originalBuild !== "function" || typeof originalContext !== "function") throw new Error("build or context is not a function");
    replaceMember(descriptors, "build", function build(options) {
      const forced = forceMetafile(options);
      if (!forced) return originalBuild(options);
      return originalBuild(forced.options).then((result) => finishEsbuild(forced, result, defaultWorkingDir));
    });
    replaceMember(descriptors, "context", function context(options) {
      const forced = forceMetafile(options);
      if (!forced) return originalContext(options);
      return originalContext(forced.options).then((ctx) => {
        if (!ctx || typeof ctx.rebuild !== "function") return ctx;
        const originalRebuild = ctx.rebuild;
        ctx.rebuild = function rebuild() {
          return originalRebuild.call(ctx).then((result) => finishEsbuild(forced, result, defaultWorkingDir));
        };
        return ctx;
      });
    });
    if (resolveDefault && descriptors.default) {
      const { enumerable, configurable } = descriptors.default;
      descriptors.default = { get: resolveDefault, enumerable, configurable };
    }
    return Object.create(Object.getPrototypeOf(original), descriptors);
  }

  // esbuild 0.24 exports its API twice: as module.exports and as the distinct
  // object behind "default", whose own "default" refers to itself.
  function wrapEsbuildApi(exportsObject, defaultWorkingDir) {
    if (!exportsObject || typeof exportsObject !== "object") throw new Error("exports are not an object");
    const defaultObject = Object.prototype.hasOwnProperty.call(exportsObject, "default") ? exportsObject.default : undefined;
    const separateDefault = defaultObject !== null && typeof defaultObject === "object" && defaultObject !== exportsObject;
    let wrappedDefault;
    const resolveDefault = separateDefault ? () => wrappedDefault : defaultObject === exportsObject ? () => wrappedExports : null;
    const wrappedExports = wrapEsbuildObject(exportsObject, resolveDefault, defaultWorkingDir);
    if (separateDefault) {
      wrappedDefault = wrapEsbuildObject(defaultObject, defaultObject.default === defaultObject ? () => wrappedDefault : null, defaultWorkingDir);
    }
    return wrappedExports;
  }

  // esbuild resolves relative paths against the working directory of the
  // moment it was loaded, which is when it is wrapped.
  function wrapEsbuild(original) {
    try {
      return wrapEsbuildApi(original, process.cwd());
    } catch (err) {
      warn(`esbuild exports are not recognized, its builds are not observed: ${err.message}`);
      return original;
    }
  }

  globalThis[instrumentKey] = { wrapRollup, wrapEsbuild };

  function packageEntry(url, relativeEntry, packageName) {
    if (!url.startsWith("file:") || url.includes("?")) return null;
    let file;
    try {
      file = fileURLToPath(url);
    } catch {
      return null;
    }
    const segments = relativeEntry.split("/");
    if (!file.endsWith(path.sep + segments.join(path.sep))) return null;
    let root = file;
    for (let i = 0; i < segments.length; i++) root = path.dirname(root);
    const manifest = readManifest(root);
    if (!manifest || manifest.name !== packageName) return null;
    return { file, manifest };
  }

  const warnedVersions = new Set();

  // Only versions whose result metadata the observer was verified against are
  // wrapped: Rollup 4 and esbuild 0.24.
  function supportedVersion(entry, toolName, isSupported) {
    const match = /^(\d+)\.(\d+)\./.exec(String(entry.manifest.version));
    if (match && isSupported(Number(match[1]), Number(match[2]))) return entry;
    const key = `${toolName}@${entry.manifest.version}`;
    if (!warnedVersions.has(key)) {
      warnedVersions.add(key);
      warn(`${toolName} ${entry.manifest.version} is not supported, its output is not observed`);
    }
    return null;
  }

  function rollupEntry(url, relativeEntry) {
    const entry = packageEntry(url, relativeEntry, "rollup");
    return entry && supportedVersion(entry, "Rollup", (major) => major === 4);
  }

  function rollupESMEntry(url) {
    return rollupEntry(url, "dist/es/rollup.js");
  }

  function rollupCommonJSEntry(url) {
    return rollupEntry(url, "dist/rollup.js");
  }

  function esbuildEntry(url) {
    const entry = packageEntry(url, "lib/main.js", "esbuild");
    if (!entry || typeof entry.manifest.main !== "string" || path.posix.normalize(entry.manifest.main) !== "lib/main.js") return null;
    return supportedVersion(entry, "esbuild", (major, minor) => major === 0 && minor === 24);
  }

  const instrument = `globalThis[Symbol.for(${JSON.stringify(instrumentKey.description)})]`;

  // The statement is appended to the source Node.js evaluates; the installed
  // file is not modified.
  function appendToCommonJS(result, file, statement) {
    if (result.format && result.format !== "commonjs") return result;
    let source = result.source;
    if (source == null) source = fs.readFileSync(file, "utf8");
    else if (typeof source !== "string") source = Buffer.from(source instanceof ArrayBuffer ? new Uint8Array(source) : source).toString("utf8");
    return { ...result, format: "commonjs", source: `${source}\n;${statement}\n` };
  }

  registerHooks({
    resolve(specifier, context, nextResolve) {
      const result = nextResolve(specifier, context);
      if (context.parentURL && context.parentURL.endsWith(rollupFacadeSuffix)) return result;
      if (!rollupESMEntry(result.url)) return result;
      return { ...result, url: result.url + rollupFacadeSuffix };
    },
    load(url, context, nextLoad) {
      if (url.endsWith(rollupFacadeSuffix)) {
        const originalURL = JSON.stringify(url.slice(0, -rollupFacadeSuffix.length));
        return {
          format: "module",
          shortCircuit: true,
          source: [
            `import * as original from ${originalURL};`,
            `export * from ${originalURL};`,
            `export const rollup = ${instrument}.wrapRollup(original.rollup);`,
          ].join("\n"),
        };
      }
      const result = nextLoad(url, context);
      const rollup = rollupCommonJSEntry(url);
      if (rollup) return appendToCommonJS(result, rollup.file, `exports.rollup = ${instrument}.wrapRollup(exports.rollup);`);
      const esbuild = esbuildEntry(url);
      if (esbuild) return appendToCommonJS(result, esbuild.file, `module.exports = ${instrument}.wrapEsbuild(module.exports);`);
      return result;
    },
  });
};
