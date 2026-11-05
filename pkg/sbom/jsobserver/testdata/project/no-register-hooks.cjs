"use strict";

// Simulates a Node.js release older than module.registerHooks.
delete require("node:module").registerHooks;
