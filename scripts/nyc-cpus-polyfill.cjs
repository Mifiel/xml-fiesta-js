/** Ensures os.cpus() is non-empty so nyc/p-map never uses concurrency 0 (e.g. some sandboxes). */
const os = require("os");
const orig = os.cpus.bind(os);
os.cpus = function cpus() {
  const c = orig();
  return c.length > 0
    ? c
    : [{ model: "", speed: 0, times: { user: 0, nice: 0, sys: 0, idle: 0, irq: 0 } }];
};
