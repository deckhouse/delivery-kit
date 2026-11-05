// werf JavaScript bundle observer bootstrap, preloaded with NODE_OPTIONS=--require.
// It must stay parseable by every Node.js release that reads NODE_OPTIONS, so it
// uses no syntax newer than ES5 and loads the observer only on runtimes it supports.
"use strict";

(function () {
  var stateKey = typeof Symbol === "function" ? Symbol.for("werf.jsObserver") : "__werfJsObserver";
  if (global[stateKey]) return;
  global[stateKey] = true;

  var fs = require("fs");
  var path = require("path");
  var settings = require("./settings.json");

  var warnedAboutLog = false;

  function openLog() {
    var dir = path.dirname(settings.logPath);
    var uid = process.getuid();
    try {
      fs.mkdirSync(dir, 448);
    } catch (err) {
      if (err.code !== "EEXIST") throw err;
    }
    // The directory is private to the user that created it, so a log written by
    // a different user or replaced with a symlink is never followed.
    var dirStat = fs.lstatSync(dir);
    if (!dirStat.isDirectory() || dirStat.uid !== uid || (dirStat.mode & 63) !== 0) {
      throw new Error("refusing unsafe directory " + dir);
    }
    var c = fs.constants;
    var fd = fs.openSync(settings.logPath, c.O_WRONLY | c.O_APPEND | c.O_CREAT | c.O_NOFOLLOW, 384);
    try {
      var fileStat = fs.fstatSync(fd);
      if (!fileStat.isFile() || fileStat.uid !== uid || fileStat.nlink !== 1 || (fileStat.mode & 63) !== 0) {
        throw new Error("refusing unsafe file " + settings.logPath);
      }
    } catch (err) {
      fs.closeSync(fd);
      throw err;
    }
    return fd;
  }

  function writeLine(line) {
    var data = Buffer.from(line, "utf8");
    var fd = openLog();
    try {
      // A single append keeps lines from concurrent Node processes whole.
      var written = 0;
      while (written < data.length) {
        written += fs.writeSync(fd, data, written, data.length - written);
      }
    } finally {
      fs.closeSync(fd);
    }
  }

  function appendLine(line) {
    try {
      writeLine(line);
    } catch (err) {
      if (warnedAboutLog) return;
      warnedAboutLog = true;
      process.stderr.write("werf: JavaScript bundle observer cannot record evidence: " + err.message + "\n");
    }
  }

  var registerHooks = require("module").registerHooks;
  if (typeof registerHooks !== "function") {
    appendLine(JSON.stringify({
      version: settings.protocolVersion,
      warning: "Node.js " + process.version + " has no module.registerHooks, JavaScript bundles built by this process are not observed"
    }) + "\n");
    return;
  }

  require("./observer.cjs")({ registerHooks: registerHooks, appendLine: appendLine, settings: settings });
})();
