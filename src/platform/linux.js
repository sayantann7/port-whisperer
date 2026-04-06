/**
 * Linux platform implementation
 * Uses ss/netstat and /proc filesystem for port and process information
 */

import { execSync } from "child_process";
import { existsSync, readFileSync, readdirSync, readlinkSync } from "fs";
import { basename, join } from "path";

/**
 * Check if a command exists on the system
 */
function commandExists(cmd) {
  try {
    execSync(`which ${cmd} 2>/dev/null`, { encoding: "utf8" });
    return true;
  } catch {
    return false;
  }
}

/**
 * Get all listening TCP ports with process info using ss or netstat
 * @returns {Array<{port: number, pid: number, processName: string}>}
 */
export function getListeningPortsRaw() {
  const entries = [];
  const portMap = new Map();

  // Try ss first (modern Linux), fallback to netstat
  if (commandExists("ss")) {
    try {
      // ss -tlnp: TCP listening, numeric, show process
      const raw = execSync("ss -tlnp 2>/dev/null", {
        encoding: "utf8",
        timeout: 10000,
      });

      const lines = raw.trim().split("\n").slice(1); // skip header
      for (const line of lines) {
        // Example: LISTEN 0 128 0.0.0.0:3000 0.0.0.0:* users:(("node",pid=12345,fd=19))
        const parts = line.split(/\s+/);
        if (parts.length < 5) continue;

        // Extract port from local address (e.g., "0.0.0.0:3000" or "[::]:3000")
        const localAddr = parts[3];
        const portMatch = localAddr.match(/:(\d+)$/);
        if (!portMatch) continue;
        const port = parseInt(portMatch[1], 10);

        if (portMap.has(port)) continue;

        // Extract PID and process name from users field
        // Format: users:(("node",pid=12345,fd=19))
        const usersField = parts.slice(5).join(" ");
        const pidMatch = usersField.match(/pid=(\d+)/);
        const nameMatch = usersField.match(/\("([^"]+)"/);

        if (pidMatch) {
          const pid = parseInt(pidMatch[1], 10);
          const processName = nameMatch ? nameMatch[1] : getProcessNameFromProc(pid);
          portMap.set(port, true);
          entries.push({ port, pid, processName });
        }
      }
    } catch {}
  }

  // Fallback to netstat if ss didn't work or not available
  if (entries.length === 0 && commandExists("netstat")) {
    try {
      // netstat -tlnp: TCP listening, numeric, show program
      const raw = execSync("netstat -tlnp 2>/dev/null", {
        encoding: "utf8",
        timeout: 10000,
      });

      const lines = raw.trim().split("\n");
      for (const line of lines) {
        if (!line.includes("LISTEN")) continue;

        // Example: tcp 0 0 0.0.0.0:3000 0.0.0.0:* LISTEN 12345/node
        const parts = line.split(/\s+/);
        if (parts.length < 7) continue;

        // Extract port from local address
        const localAddr = parts[3];
        const portMatch = localAddr.match(/:(\d+)$/);
        if (!portMatch) continue;
        const port = parseInt(portMatch[1], 10);

        if (portMap.has(port)) continue;

        // Extract PID/process from last field (e.g., "12345/node" or "-")
        const pidProgram = parts[parts.length - 1];
        const pidProgMatch = pidProgram.match(/^(\d+)\/(.+)$/);

        if (pidProgMatch) {
          const pid = parseInt(pidProgMatch[1], 10);
          const processName = pidProgMatch[2];
          portMap.set(port, true);
          entries.push({ port, pid, processName });
        }
      }
    } catch {}
  }

  return entries;
}

/**
 * Get process name from /proc/<pid>/comm
 */
function getProcessNameFromProc(pid) {
  try {
    const commPath = `/proc/${pid}/comm`;
    if (existsSync(commPath)) {
      return readFileSync(commPath, "utf8").trim();
    }
  } catch {}
  return "unknown";
}

/**
 * Batch-fetch process info for multiple PIDs using /proc filesystem
 * @param {number[]} pids - Array of process IDs
 * @returns {Map<number, {ppid: number, stat: string, rss: number, lstart: string, command: string}>}
 */
export function batchProcessInfo(pids) {
  const map = new Map();
  if (pids.length === 0) return map;

  for (const pid of pids) {
    try {
      const procDir = `/proc/${pid}`;
      if (!existsSync(procDir)) continue;

      // Read /proc/<pid>/stat for ppid and state
      const statContent = readFileSync(`${procDir}/stat`, "utf8");
      // Format: pid (comm) state ppid pgrp session tty_nr tpgid flags minflt cminflt majflt cmajflt utime stime...
      // Handle process names with spaces/parens by finding the last )
      const lastParen = statContent.lastIndexOf(")");
      const afterComm = statContent.slice(lastParen + 2).split(" ");
      const stat = afterComm[0] || "?";
      const ppid = parseInt(afterComm[1], 10) || 0;

      // Read /proc/<pid>/statm for memory (field 1 = RSS in pages)
      let rss = 0;
      try {
        const statmContent = readFileSync(`${procDir}/statm`, "utf8");
        const rssPages = parseInt(statmContent.split(" ")[1], 10) || 0;
        rss = rssPages * 4; // Convert pages to KB (assuming 4KB pages)
      } catch {}

      // Read /proc/<pid>/cmdline for full command
      let command = "";
      try {
        command = readFileSync(`${procDir}/cmdline`, "utf8")
          .split("\0")
          .filter(Boolean)
          .join(" ");
      } catch {}

      // Get start time from /proc/<pid>/stat
      // This is complex; use ps for reliable lstart
      let lstart = "";
      try {
        const psOutput = execSync(`ps -p ${pid} -o lstart= 2>/dev/null`, {
          encoding: "utf8",
          timeout: 2000,
        }).trim();
        lstart = psOutput;
      } catch {}

      map.set(pid, {
        ppid,
        stat,
        rss,
        lstart,
        command: command || getProcessNameFromProc(pid),
      });
    } catch {}
  }

  return map;
}

/**
 * Batch-fetch working directory for multiple PIDs using /proc/<pid>/cwd
 * @param {number[]} pids - Array of process IDs
 * @returns {Map<number, string>} - Map of PID to cwd path
 */
export function batchCwd(pids) {
  const map = new Map();
  if (pids.length === 0) return map;

  for (const pid of pids) {
    try {
      const cwdLink = `/proc/${pid}/cwd`;
      if (existsSync(cwdLink)) {
        const cwd = readlinkSync(cwdLink);
        if (cwd && cwd.startsWith("/")) {
          map.set(pid, cwd);
        }
      }
    } catch {
      // Permission denied or process no longer exists
    }
  }

  return map;
}

/**
 * Get all running processes with resource usage
 * @returns {Array<{pid: number, processName: string, cpu: number, memPercent: number, rss: number, lstart: string, command: string}>}
 */
export function getAllProcessesRaw() {
  let raw;
  try {
    // Linux ps syntax is similar to macOS but lstart format may differ
    raw = execSync(
      "ps -eo pid=,pcpu=,pmem=,rss=,lstart=,cmd= 2>/dev/null",
      { encoding: "utf8", timeout: 5000 }
    ).trim();
  } catch {
    return [];
  }

  const entries = [];
  const seen = new Set();

  for (const line of raw.split("\n")) {
    if (!line.trim()) continue;
    // Format: PID %CPU %MEM RSS DOW MON DD HH:MM:SS YYYY COMMAND...
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
  const processes = new Map();

  // Build process map from /proc
  try {
    const procDirs = readdirSync("/proc").filter((d) => /^\d+$/.test(d));
    for (const dir of procDirs) {
      try {
        const p = parseInt(dir, 10);
        const statContent = readFileSync(`/proc/${dir}/stat`, "utf8");
        
        // Extract comm (process name in parentheses)
        const commStart = statContent.indexOf("(");
        const commEnd = statContent.lastIndexOf(")");
        const name = statContent.slice(commStart + 1, commEnd);
        
        // Extract ppid (field after state, which is after comm)
        const afterComm = statContent.slice(commEnd + 2).split(" ");
        const ppid = parseInt(afterComm[1], 10) || 0;
        
        processes.set(p, { pid: p, ppid, name });
      } catch {}
    }
  } catch {}

  // Walk up the tree
  let currentPid = pid;
  let depth = 0;
  while (currentPid > 1 && depth < 8) {
    const proc = processes.get(currentPid);
    if (!proc) break;
    tree.push(proc);
    currentPid = proc.ppid;
    depth++;
  }

  return tree;
}
