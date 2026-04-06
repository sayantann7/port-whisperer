/**
 * macOS (Darwin) platform implementation
 * Uses lsof and ps commands for port and process information
 */

import { execSync } from "child_process";
import { basename } from "path";

/**
 * Get all listening TCP ports with process info using lsof
 * @returns {Array<{port: number, pid: number, processName: string}>}
 */
export function getListeningPortsRaw() {
  let raw;
  try {
    raw = execSync("lsof -iTCP -sTCP:LISTEN -P -n 2>/dev/null", {
      encoding: "utf8",
      timeout: 10000,
    });
  } catch {
    return [];
  }

  const lines = raw.trim().split("\n").slice(1);
  const portMap = new Map();
  const entries = [];

  for (const line of lines) {
    const parts = line.split(/\s+/);
    if (parts.length < 9) continue;

    const processName = parts[0];
    const pid = parseInt(parts[1], 10);
    const nameField = parts[8];

    const portMatch = nameField.match(/:(\d+)$/);
    if (!portMatch) continue;
    const port = parseInt(portMatch[1], 10);

    if (portMap.has(port)) continue;
    portMap.set(port, true);
    entries.push({ port, pid, processName });
  }

  return entries;
}

/**
 * Batch-fetch process info for multiple PIDs using ps
 * @param {number[]} pids - Array of process IDs
 * @returns {Map<number, {ppid: number, stat: string, rss: number, lstart: string, command: string}>}
 */
export function batchProcessInfo(pids) {
  const map = new Map();
  if (pids.length === 0) return map;

  try {
    const pidList = pids.join(",");
    const raw = execSync(
      `ps -p ${pidList} -o pid=,ppid=,stat=,rss=,lstart=,command= 2>/dev/null`,
      {
        encoding: "utf8",
        timeout: 5000,
      }
    ).trim();

    for (const line of raw.split("\n")) {
      if (!line.trim()) continue;
      // Format: PID PPID STAT RSS DOW MON DD HH:MM:SS YYYY COMMAND...
      const m = line
        .trim()
        .match(
          /^(\d+)\s+(\d+)\s+(\S+)\s+(\d+)\s+\w+\s+(\w+\s+\d+\s+[\d:]+\s+\d+)\s+(.*)$/
        );
      if (!m) continue;
      map.set(parseInt(m[1], 10), {
        ppid: parseInt(m[2], 10),
        stat: m[3],
        rss: parseInt(m[4], 10),
        lstart: m[5],
        command: m[6],
      });
    }
  } catch {}
  return map;
}

/**
 * Batch-fetch working directory for multiple PIDs using lsof
 * @param {number[]} pids - Array of process IDs
 * @returns {Map<number, string>} - Map of PID to cwd path
 */
export function batchCwd(pids) {
  const map = new Map();
  if (pids.length === 0) return map;

  try {
    const pidList = pids.join(",");
    const raw = execSync(`lsof -a -d cwd -p ${pidList} 2>/dev/null`, {
      encoding: "utf8",
      timeout: 10000,
    }).trim();

    const lines = raw.split("\n").slice(1); // skip header
    for (const line of lines) {
      const parts = line.split(/\s+/);
      if (parts.length < 9) continue;
      const pid = parseInt(parts[1], 10);
      const path = parts.slice(8).join(" ");
      if (path && path.startsWith("/")) {
        map.set(pid, path);
      }
    }
  } catch {}
  return map;
}

/**
 * Get all running processes with resource usage
 * @returns {Array<{pid: number, processName: string, cpu: number, memPercent: number, rss: number, lstart: string, command: string}>}
 */
export function getAllProcessesRaw() {
  let raw;
  try {
    raw = execSync(
      "ps -eo pid=,pcpu=,pmem=,rss=,lstart=,command= 2>/dev/null",
      { encoding: "utf8", timeout: 5000 }
    ).trim();
  } catch {
    return [];
  }

  const entries = [];
  const seen = new Set();

  for (const line of raw.split("\n")) {
    if (!line.trim()) continue;
    const m = line
      .trim()
      .match(
        /^(\d+)\s+([\d.]+)\s+([\d.]+)\s+(\d+)\s+\w+\s+(\w+\s+\d+\s+[\d:]+\s+\d+)\s+(.*)$/
      );
    if (!m) continue;

    const pid = parseInt(m[1], 10);
    if (pid <= 1 || pid === process.pid || seen.has(pid)) continue;
    seen.add(pid);

    const command = m[6];
    const processName = basename(command.split(/\s+/)[0]);

    entries.push({
      pid,
      processName,
      cpu: parseFloat(m[2]),
      memPercent: parseFloat(m[3]),
      rss: parseInt(m[4], 10),
      lstart: m[5],
      command,
    });
  }

  return entries;
}

/**
 * Get process tree (ancestors) for a given PID
 * @param {number} pid - Process ID
 * @returns {Array<{pid: number, ppid: number, name: string}>}
 */
export function getProcessTree(pid) {
  const tree = [];
  try {
    // Get all processes in one call and walk the tree in memory
    const raw = execSync("ps -eo pid=,ppid=,comm= 2>/dev/null", {
      encoding: "utf8",
      timeout: 5000,
    }).trim();

    const processes = new Map();
    for (const line of raw.split("\n")) {
      const parts = line.trim().split(/\s+/);
      if (parts.length < 3) continue;
      const p = parseInt(parts[0], 10);
      const pp = parseInt(parts[1], 10);
      processes.set(p, { pid: p, ppid: pp, name: parts.slice(2).join(" ") });
    }

    let currentPid = pid;
    let depth = 0;
    while (currentPid > 1 && depth < 8) {
      const proc = processes.get(currentPid);
      if (!proc) break;
      tree.push(proc);
      currentPid = proc.ppid;
      depth++;
    }
  } catch {}
  return tree;
}
