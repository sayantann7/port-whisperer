/**
 * Platform abstraction layer for port-whisperer
 * Detects OS and provides unified interface for platform-specific operations
 */

import { platform } from "os";

// Dynamically import the correct platform module
const platformName = platform();

let platformModule;

if (platformName === "darwin") {
  platformModule = await import("./darwin.js");
} else if (platformName === "linux") {
  platformModule = await import("./linux.js");
} else if (platformName === "win32") {
  platformModule = await import("./win32.js");
} else {
  throw new Error(`Unsupported platform: ${platformName}`);
}

/**
 * Get all listening TCP ports with process info
 * @returns {Array<{port: number, pid: number, processName: string}>}
 */
export function getListeningPortsRaw() {
  return platformModule.getListeningPortsRaw();
}

/**
 * Batch-fetch process info for multiple PIDs
 * @param {number[]} pids - Array of process IDs
 * @returns {Map<number, {ppid: number, stat: string, rss: number, lstart: string, command: string}>}
 */
export function batchProcessInfo(pids) {
  return platformModule.batchProcessInfo(pids);
}

/**
 * Batch-fetch working directory for multiple PIDs
 * @param {number[]} pids - Array of process IDs
 * @returns {Map<number, string>} - Map of PID to cwd path
 */
export function batchCwd(pids) {
  return platformModule.batchCwd(pids);
}

/**
 * Get all running processes with resource usage
 * @returns {Array<{pid: number, processName: string, cpu: number, memPercent: number, rss: number, lstart: string, command: string}>}
 */
export function getAllProcessesRaw() {
  return platformModule.getAllProcessesRaw();
}

/**
 * Get process tree (ancestors) for a given PID
 * @param {number} pid - Process ID
 * @returns {Array<{pid: number, ppid: number, name: string}>}
 */
export function getProcessTree(pid) {
  return platformModule.getProcessTree(pid);
}

/**
 * Check if current platform is supported
 * @returns {boolean}
 */
export function isSupported() {
  return ["darwin", "linux", "win32"].includes(platformName);
}

/**
 * Get current platform name
 * @returns {string}
 */
export function getPlatform() {
  return platformName;
}
