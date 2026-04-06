/**
 * Windows platform implementation
 * Uses netstat and wmic/PowerShell for port and process information
 */

import { execSync } from "child_process";
import { basename, dirname } from "path";

/**
 * Execute a command and return output, handling Windows specifics
 */
function exec(cmd, timeout = 10000) {
  try {
    return execSync(cmd, {
      encoding: "utf8",
      timeout,
      windowsHide: true,
      stdio: ["pipe", "pipe", "pipe"],
    }).trim();
  } catch {
    return "";
  }
}

/**
 * Get all listening TCP ports with process info using netstat
 * @returns {Array<{port: number, pid: number, processName: string}>}
 */
export function getListeningPortsRaw() {
  const entries = [];
  const portMap = new Map();

  // Use netstat -ano to get listening ports with PIDs
  const raw = exec("netstat -ano -p TCP");
  if (!raw) return entries;

  const lines = raw.split("\r\n").filter((l) => l.includes("LISTENING"));
  const pidsToResolve = new Set();

  for (const line of lines) {
    // Example: TCP    0.0.0.0:3000           0.0.0.0:0              LISTENING       12345
    const parts = line.trim().split(/\s+/);
    if (parts.length < 5) continue;

    const localAddr = parts[1];
    const portMatch = localAddr.match(/:(\d+)$/);
    if (!portMatch) continue;
    const port = parseInt(portMatch[1], 10);

    if (portMap.has(port)) continue;

    const pid = parseInt(parts[parts.length - 1], 10);
    if (isNaN(pid) || pid === 0) continue;

    portMap.set(port, true);
    pidsToResolve.add(pid);
    entries.push({ port, pid, processName: "" });
  }

  // Batch resolve process names using wmic
  const processNames = getProcessNames([...pidsToResolve]);
  for (const entry of entries) {
    entry.processName = processNames.get(entry.pid) || "unknown";
  }

  return entries;
}

/**
 * Get process names for multiple PIDs using wmic
 * @param {number[]} pids
 * @returns {Map<number, string>}
 */
function getProcessNames(pids) {
  const map = new Map();
  if (pids.length === 0) return map;

  // Try wmic first
  const pidList = pids.join(",");
  const raw = exec(
    `wmic process where "ProcessId=${pids[0]}${pids.slice(1).map((p) => ` or ProcessId=${p}`).join("")}" get ProcessId,Name /format:csv`,
    5000
  );

  if (raw) {
    const lines = raw.split("\r\n").filter((l) => l.includes(","));
    for (const line of lines) {
      const parts = line.split(",");
      if (parts.length >= 3) {
        const name = parts[1];
        const pid = parseInt(parts[2], 10);
        if (!isNaN(pid)) {
          map.set(pid, name.replace(/\.exe$/i, ""));
        }
      }
    }
  }

  // Fallback: try tasklist for any missing PIDs
  for (const pid of pids) {
    if (!map.has(pid)) {
      const taskOutput = exec(`tasklist /FI "PID eq ${pid}" /FO CSV /NH`, 2000);
      if (taskOutput) {
        const match = taskOutput.match(/"([^"]+)"/);
        if (match) {
          map.set(pid, match[1].replace(/\.exe$/i, ""));
        }
      }
    }
  }

  return map;
}

/**
 * Batch-fetch process info for multiple PIDs using wmic
 * @param {number[]} pids - Array of process IDs
 * @returns {Map<number, {ppid: number, stat: string, rss: number, lstart: string, command: string}>}
 */
export function batchProcessInfo(pids) {
  const map = new Map();
  if (pids.length === 0) return map;

  // Use wmic to get process details
  const pidCondition = pids.map((p) => `ProcessId=${p}`).join(" or ");
  const raw = exec(
    `wmic process where "(${pidCondition})" get ProcessId,ParentProcessId,WorkingSetSize,CreationDate,CommandLine,Name /format:csv`,
    10000
  );

  if (!raw) return map;

  const lines = raw.split("\r\n").filter((l) => l.trim() && l.includes(","));
  
  for (const line of lines) {
    // CSV format: Node,CommandLine,CreationDate,Name,ParentProcessId,ProcessId,WorkingSetSize
    const parts = parseCSVLine(line);
    if (parts.length < 7) continue;

    const commandLine = parts[1] || "";
    const creationDate = parts[2] || "";
    const name = parts[3] || "";
    const ppid = parseInt(parts[4], 10) || 0;
    const pid = parseInt(parts[5], 10);
    const workingSetSize = parseInt(parts[6], 10) || 0;

    if (isNaN(pid)) continue;

    // Convert WorkingSetSize (bytes) to KB
    const rss = Math.round(workingSetSize / 1024);

    // Parse CreationDate (format: 20240406123045.123456+000)
    let lstart = "";
    if (creationDate) {
      const dateMatch = creationDate.match(/^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})/);
      if (dateMatch) {
        const [, year, month, day, hour, min, sec] = dateMatch;
        lstart = `${month}/${day}/${year} ${hour}:${min}:${sec}`;
      }
    }

    map.set(pid, {
      ppid,
      stat: "R", // Windows doesn't have Unix-style stat; assume running
      rss,
      lstart,
      command: commandLine || name,
    });
  }

  return map;
}

/**
 * Parse a CSV line handling quoted fields
 */
function parseCSVLine(line) {
  const parts = [];
  let current = "";
  let inQuotes = false;

  for (let i = 0; i < line.length; i++) {
    const char = line[i];
    if (char === '"') {
      inQuotes = !inQuotes;
    } else if (char === "," && !inQuotes) {
      parts.push(current);
      current = "";
    } else {
      current += char;
    }
  }
  parts.push(current);
  return parts;
}

/**
 * Batch-fetch working directory for multiple PIDs
 * Note: Windows doesn't provide easy access to other processes' CWD
 * We attempt to extract it from the command line path
 * @param {number[]} pids - Array of process IDs
 * @returns {Map<number, string>} - Map of PID to cwd path (best effort)
 */
export function batchCwd(pids) {
  const map = new Map();
  if (pids.length === 0) return map;

  // Get command lines and try to extract directory from executable path
  const pidCondition = pids.map((p) => `ProcessId=${p}`).join(" or ");
  const raw = exec(
    `wmic process where "(${pidCondition})" get ProcessId,ExecutablePath /format:csv`,
    5000
  );

  if (!raw) return map;

  const lines = raw.split("\r\n").filter((l) => l.trim() && l.includes(","));
  
  for (const line of lines) {
    const parts = parseCSVLine(line);
    if (parts.length < 3) continue;

    const execPath = parts[1] || "";
    const pid = parseInt(parts[2], 10);

    if (isNaN(pid) || !execPath) continue;

    // Use the directory containing the executable as a proxy for CWD
    // This isn't perfect but gives us something to work with
    const dir = dirname(execPath);
    if (dir && dir !== ".") {
      map.set(pid, dir);
    }
  }

  return map;
}

/**
 * Get all running processes with resource usage
 * @returns {Array<{pid: number, processName: string, cpu: number, memPercent: number, rss: number, lstart: string, command: string}>}
 */
export function getAllProcessesRaw() {
  const entries = [];
  const seen = new Set();

  // Use wmic to get all processes with details
  const raw = exec(
    "wmic process get ProcessId,Name,WorkingSetSize,CreationDate,CommandLine /format:csv",
    15000
  );

  if (!raw) return entries;

  // Get CPU usage separately using wmic path win32_perfformatteddata_perfproc_process
  const cpuMap = new Map();
  const cpuRaw = exec(
    "wmic path Win32_PerfFormattedData_PerfProc_Process get IDProcess,PercentProcessorTime /format:csv",
    10000
  );
  
  if (cpuRaw) {
    const cpuLines = cpuRaw.split("\r\n").filter((l) => l.includes(","));
    for (const line of cpuLines) {
      const parts = parseCSVLine(line);
      if (parts.length >= 3) {
        const pid = parseInt(parts[1], 10);
        const cpu = parseFloat(parts[2]) || 0;
        if (!isNaN(pid)) {
          cpuMap.set(pid, cpu);
        }
      }
    }
  }

  // Get total physical memory for calculating percentage
  let totalMemKB = 0;
  const memRaw = exec("wmic OS get TotalVisibleMemorySize /value");
  const memMatch = memRaw.match(/TotalVisibleMemorySize=(\d+)/);
  if (memMatch) {
    totalMemKB = parseInt(memMatch[1], 10);
  }

  const lines = raw.split("\r\n").filter((l) => l.trim() && l.includes(","));

  for (const line of lines) {
    // CSV format: Node,CommandLine,CreationDate,Name,ProcessId,WorkingSetSize
    const parts = parseCSVLine(line);
    if (parts.length < 6) continue;

    const commandLine = parts[1] || "";
    const creationDate = parts[2] || "";
    const name = parts[3] || "";
    const pid = parseInt(parts[4], 10);
    const workingSetSize = parseInt(parts[5], 10) || 0;

    if (isNaN(pid) || pid <= 4 || pid === process.pid || seen.has(pid)) continue;
    seen.add(pid);

    const rss = Math.round(workingSetSize / 1024);
    const cpu = cpuMap.get(pid) || 0;
    const memPercent = totalMemKB > 0 ? (rss / totalMemKB) * 100 : 0;

    let lstart = "";
    if (creationDate) {
      const dateMatch = creationDate.match(/^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})/);
      if (dateMatch) {
        const [, year, month, day, hour, min, sec] = dateMatch;
        lstart = `${month}/${day}/${year} ${hour}:${min}:${sec}`;
      }
    }

    const processName = name.replace(/\.exe$/i, "");

    entries.push({
      pid,
      processName,
      cpu,
      memPercent,
      rss,
      lstart,
      command: commandLine || name,
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

  // Get all processes with parent info
  const raw = exec(
    "wmic process get ProcessId,ParentProcessId,Name /format:csv",
    10000
  );

  if (!raw) return tree;

  const lines = raw.split("\r\n").filter((l) => l.trim() && l.includes(","));
  
  for (const line of lines) {
    const parts = parseCSVLine(line);
    if (parts.length < 4) continue;

    const name = parts[1] || "";
    const ppid = parseInt(parts[2], 10) || 0;
    const p = parseInt(parts[3], 10);

    if (!isNaN(p)) {
      processes.set(p, {
        pid: p,
        ppid,
        name: name.replace(/\.exe$/i, ""),
      });
    }
  }

  // Walk up the tree
  let currentPid = pid;
  let depth = 0;
  while (currentPid > 0 && depth < 8) {
    const proc = processes.get(currentPid);
    if (!proc) break;
    tree.push(proc);
    currentPid = proc.ppid;
    depth++;
  }

  return tree;
}
