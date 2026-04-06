import { execSync } from "child_process";
import { existsSync, readFileSync } from "fs";
import { join, dirname, basename } from "path";
import {
  getListeningPortsRaw,
  batchProcessInfo,
  batchCwd,
  getAllProcessesRaw,
  getProcessTree as platformGetProcessTree,
  getPlatform,
} from "./platform/index.js";

/**
 * Batch-fetch docker container info mapped by host port.
 * Returns Map<port, { name, image }>
 */
function batchDockerInfo() {
  const map = new Map();
  const isWindows = getPlatform() === "win32";
  const nullDevice = isWindows ? "NUL" : "/dev/null";
  
  try {
    const raw = execSync(
      `docker ps --format "{{.Ports}}\t{{.Names}}\t{{.Image}}" 2>${nullDevice}`,
      {
        encoding: "utf8",
        timeout: 5000,
        windowsHide: true,
      },
    ).trim();

    for (const line of raw.split("\n")) {
      if (!line.trim()) continue;
      const [portsStr, name, image] = line.split("\t");
      if (!portsStr || !name) continue;

      // Parse port mappings like "0.0.0.0:5432->5432/tcp, [::]:5432->5432/tcp"
      const portMatches = portsStr.matchAll(
        /(?:\d+\.\d+\.\d+\.\d+|::):(\d+)->/g,
      );
      const seen = new Set();
      for (const m of portMatches) {
        const port = parseInt(m[1], 10);
        if (!seen.has(port)) {
          seen.add(port);
          map.set(port, { name, image });
        }
      }
    }
  } catch {}
  return map;
}

/**
 * Parse lsof output to get all listening ports with process info.
 * When detailed=false (default for table view), skips expensive per-process lookups.
 */
export function getListeningPorts(detailed = false) {
  const entries = getListeningPortsRaw();
  if (entries.length === 0) return [];

  // Deduplicate PIDs for batch calls
  const uniquePids = [...new Set(entries.map((e) => e.pid))];

  // Batch calls instead of N*6 individual calls
  const psMap = batchProcessInfo(uniquePids);
  const cwdMap = batchCwd(uniquePids);
  const hasDocker = entries.some(
    (e) => e.processName.startsWith("com.docke") || e.processName === "docker",
  );
  const dockerMap = hasDocker ? batchDockerInfo() : new Map();

  const results = entries.map(({ port, pid, processName }) => {
    const ps = psMap.get(pid);
    const cwd = cwdMap.get(pid);

    const info = {
      port,
      pid,
      processName,
      rawName: processName,
      command: ps ? ps.command : "",
      cwd: null,
      projectName: null,
      framework: null,
      uptime: null,
      startTime: null,
      status: "healthy",
      memory: null,
      gitBranch: null,
      processTree: [],
    };

    // Status from batched ps
    if (ps) {
      if (ps.stat.includes("Z")) info.status = "zombie";
      else if (ps.ppid === 1 && isDevProcess(processName, ps.command))
        info.status = "orphaned";

      if (ps.rss > 0) info.memory = formatMemory(ps.rss);

      if (ps.lstart) {
        info.startTime = new Date(ps.lstart);
        if (!isNaN(info.startTime.getTime())) {
          info.uptime = formatUptime(Date.now() - info.startTime.getTime());
        }
      }

      // Framework detection from command line (no extra shell call)
      if (!info.framework) {
        info.framework = detectFrameworkFromCommand(ps.command, processName);
      }
    }

    // Docker container detection
    const docker = dockerMap.get(port);
    if (docker) {
      info.projectName = docker.name;
      info.framework = detectFrameworkFromImage(docker.image);
      info.processName = "docker";
    }

    // Cwd + project + framework from batched lsof (skip if docker already set)
    if (cwd && !docker) {
      const projectRoot = findProjectRoot(cwd);
      info.cwd = projectRoot;
      info.projectName = basename(projectRoot);
      info.framework = info.framework || detectFramework(projectRoot);

      if (detailed) {
        try {
          const isWindows = getPlatform() === "win32";
          const nullDevice = isWindows ? "NUL" : "/dev/null";
          info.gitBranch = execSync(
            `git -C "${info.cwd}" rev-parse --abbrev-ref HEAD 2>${nullDevice}`,
            {
              encoding: "utf8",
              timeout: 3000,
              windowsHide: true,
            },
          ).trim();
        } catch {}
      }
    }

    // Process tree only in detailed mode
    if (detailed) {
      info.processTree = platformGetProcessTree(pid);
    }

    return info;
  });

  return results.sort((a, b) => a.port - b.port);
}

/**
 * Check if a process looks like a dev server vs a regular system app.
 * Used for orphan detection and filtering the table view.
 */
export function isDevProcess(processName, command) {
  const name = (processName || "").toLowerCase();
  const cmd = (command || "").toLowerCase();

  // Known system/desktop apps — not dev processes
  // Includes macOS, Windows, and Linux system processes
  const systemApps = [
    // Cross-platform apps
    "spotify",
    "tableplus",
    "postman",
    "linear",
    "cursor",
    "slack",
    "discord",
    "firefox",
    "chrome",
    "google",
    "figma",
    "notion",
    "zoom",
    "teams",
    "code",
    // macOS specific
    "raycast",
    "controlce",
    "rapportd",
    "superhuma",
    "setappage",
    "safari",
    "iterm2",
    "warp",
    "arc",
    "loginwindow",
    "windowserver",
    "systemuise",
    "kernel_task",
    "launchd",
    "mdworker",
    "mds_stores",
    "cfprefsd",
    "coreaudio",
    "corebrightne",
    "airportd",
    "bluetoothd",
    "sharingd",
    "usernoted",
    "notificationc",
    "cloudd",
    // Windows specific
    "system",
    "svchost",
    "csrss",
    "wininit",
    "services",
    "lsass",
    "smss",
    "explorer",
    "dwm",
    "taskhostw",
    "runtimebroker",
    "searchhost",
    "startmenuex",
    "shellexper",
    "sihost",
    "ctfmon",
    "fontdrvhost",
    "conhost",
    "dllhost",
    "searchindex",
    "securityheal",
    "msedge",
    "onedrive",
    "windowstermi",
    // Linux specific
    "systemd",
    "kthreadd",
    "ksoftirqd",
    "kworker",
    "rcu_sched",
    "migration",
    "watchdog",
    "cpuhp",
    "netns",
    "kauditd",
    "khungtaskd",
    "oom_reaper",
    "writeback",
    "kcompactd",
    "ksmd",
    "khugepaged",
    "kintegrityd",
    "kblockd",
    "blkcg_punt",
    "tpm_dev_wq",
    "ata_sff",
    "md",
    "edac-poller",
    "devfreq_wq",
    "watchdogd",
    "kswapd",
    "kthrotld",
    "irq",
    "acpi_thermal",
    "nvme-wq",
    "scsi_eh",
    "scsi_tmf",
    "dm_bufio_cac",
    "jbd2",
    "ext4-rsv-con",
    "kstrp",
    "charger_mana",
    "cryptd",
    "gnome-shell",
    "gdm",
    "xdg-desktop",
    "pulseaudio",
    "pipewire",
    "dbus-daemon",
    "gvfsd",
    "tracker-miner",
    "evolution-cal",
    "goa-daemon",
    "gnome-keyring",
  ];
  for (const app of systemApps) {
    if (name.toLowerCase().startsWith(app)) return false;
  }

  // Dev process names (exact match on basename)
  const devNames = new Set([
    "node",
    "python",
    "python3",
    "ruby",
    "java",
    "go",
    "cargo",
    "deno",
    "bun",
    "php",
    "uvicorn",
    "gunicorn",
    "flask",
    "rails",
    "npm",
    "npx",
    "yarn",
    "pnpm",
    "tsc",
    "tsx",
    "esbuild",
    "rollup",
    "turbo",
    "nx",
    "jest",
    "vitest",
    "mocha",
    "pytest",
    "cypress",
    "playwright",
    "rustc",
    "dotnet",
    "gradle",
    "mvn",
    "mix",
    "elixir",
  ]);
  if (devNames.has(name)) return true;

  // Docker processes (prefix match)
  if (
    name.startsWith("com.docke") ||
    name === "docker" ||
    name === "docker-sandbox"
  )
    return true;

  // Command-line keyword matching (only match as whole words or clear prefixes)
  const cmdIndicators = [
    /\bnode\b/,
    /\bnext[\s-]/,
    /\bvite\b/,
    /\bnuxt\b/,
    /\bwebpack\b/,
    /\bremix\b/,
    /\bastro\b/,
    /\bgulp\b/,
    /\bng serve\b/,
    /\bgatsb/,
    /\bflask\b/,
    /\bdjango\b|manage\.py/,
    /\buvicorn\b/,
    /\brails\b/,
    /\bcargo\b/,
  ];
  for (const re of cmdIndicators) {
    if (re.test(cmd)) return true;
  }

  return false;
}

/**
 * Get detailed info for a specific port
 */
export function getPortDetails(targetPort) {
  const ports = getListeningPorts(true);
  return ports.find((p) => p.port === targetPort) || null;
}

function detectFrameworkFromImage(image) {
  if (!image) return "Docker";
  const img = image.toLowerCase();
  if (img.includes("postgres")) return "PostgreSQL";
  if (img.includes("redis")) return "Redis";
  if (img.includes("mysql") || img.includes("mariadb")) return "MySQL";
  if (img.includes("mongo")) return "MongoDB";
  if (img.includes("nginx")) return "nginx";
  if (img.includes("localstack")) return "LocalStack";
  if (img.includes("rabbitmq")) return "RabbitMQ";
  if (img.includes("kafka")) return "Kafka";
  if (img.includes("elasticsearch") || img.includes("opensearch"))
    return "Elasticsearch";
  if (img.includes("minio")) return "MinIO";
  return "Docker";
}

function findProjectRoot(dir) {
  const markers = [
    "package.json",
    "Cargo.toml",
    "go.mod",
    "pyproject.toml",
    "Gemfile",
    "pom.xml",
    "build.gradle",
  ];
  let current = dir;
  let depth = 0;
  const isWindows = getPlatform() === "win32";
  // Root detection: "/" on Unix, drive letter root on Windows (e.g., "C:\")
  const isRoot = isWindows
    ? (path) => /^[A-Za-z]:\\?$/.test(path) || path === dirname(path)
    : (path) => path === "/";
  
  while (!isRoot(current) && depth < 15) {
    for (const marker of markers) {
      if (existsSync(join(current, marker))) return current;
    }
    const parent = dirname(current);
    if (parent === current) break; // Safety check
    current = parent;
    depth++;
  }
  return dir;
}

function detectFramework(projectRoot) {
  const pkgPath = join(projectRoot, "package.json");
  if (existsSync(pkgPath)) {
    try {
      const pkg = JSON.parse(readFileSync(pkgPath, "utf8"));
      const allDeps = { ...pkg.dependencies, ...pkg.devDependencies };

      if (allDeps["next"]) return "Next.js";
      if (allDeps["nuxt"] || allDeps["nuxt3"]) return "Nuxt";
      if (allDeps["@sveltejs/kit"]) return "SvelteKit";
      if (allDeps["svelte"]) return "Svelte";
      if (allDeps["@remix-run/react"] || allDeps["remix"]) return "Remix";
      if (allDeps["astro"]) return "Astro";
      if (allDeps["vite"]) return "Vite";
      if (allDeps["@angular/core"]) return "Angular";
      if (allDeps["vue"]) return "Vue";
      if (allDeps["react"]) return "React";
      if (allDeps["express"]) return "Express";
      if (allDeps["fastify"]) return "Fastify";
      if (allDeps["hono"]) return "Hono";
      if (allDeps["koa"]) return "Koa";
      if (allDeps["nestjs"] || allDeps["@nestjs/core"]) return "NestJS";
      if (allDeps["gatsby"]) return "Gatsby";
      if (allDeps["webpack-dev-server"]) return "Webpack";
      if (allDeps["esbuild"]) return "esbuild";
      if (allDeps["parcel"]) return "Parcel";
    } catch {}
  }

  if (
    existsSync(join(projectRoot, "vite.config.ts")) ||
    existsSync(join(projectRoot, "vite.config.js"))
  )
    return "Vite";
  if (
    existsSync(join(projectRoot, "next.config.js")) ||
    existsSync(join(projectRoot, "next.config.mjs"))
  )
    return "Next.js";
  if (existsSync(join(projectRoot, "angular.json"))) return "Angular";
  if (existsSync(join(projectRoot, "Cargo.toml"))) return "Rust";
  if (existsSync(join(projectRoot, "go.mod"))) return "Go";
  if (existsSync(join(projectRoot, "manage.py"))) return "Django";
  if (existsSync(join(projectRoot, "Gemfile"))) return "Ruby";

  return null;
}

function detectFrameworkFromCommand(command, processName) {
  if (!command) return detectFrameworkFromName(processName);
  const cmd = command.toLowerCase();

  if (cmd.includes("next")) return "Next.js";
  if (cmd.includes("vite")) return "Vite";
  if (cmd.includes("nuxt")) return "Nuxt";
  if (cmd.includes("angular") || cmd.includes("ng serve")) return "Angular";
  if (cmd.includes("webpack")) return "Webpack";
  if (cmd.includes("remix")) return "Remix";
  if (cmd.includes("astro")) return "Astro";
  if (cmd.includes("gatsby")) return "Gatsby";
  if (cmd.includes("flask")) return "Flask";
  if (cmd.includes("django") || cmd.includes("manage.py")) return "Django";
  if (cmd.includes("uvicorn")) return "FastAPI";
  if (cmd.includes("rails")) return "Rails";
  if (cmd.includes("cargo") || cmd.includes("rustc")) return "Rust";

  return detectFrameworkFromName(processName);
}

function detectFrameworkFromName(processName) {
  const name = (processName || "").toLowerCase();
  if (name === "node") return "Node.js";
  if (name === "python" || name === "python3") return "Python";
  if (name === "ruby") return "Ruby";
  if (name === "java") return "Java";
  if (name === "go") return "Go";
  return null;
}

/**
 * Extract a short, human-readable description from a full command string.
 */
function summarizeCommand(command, processName) {
  const cmd = command || "";

  // For scripts with arguments, show the meaningful part
  // e.g. "node /Users/foo/project/server.js --port 3000" -> "server.js"
  // e.g. "/usr/bin/python3 manage.py runserver" -> "manage.py runserver"
  // Handle both forward slash and backslash for cross-platform
  const parts = cmd.split(/\s+/);
  const meaningful = [];
  for (let i = 0; i < parts.length; i++) {
    const part = parts[i];
    // Skip the binary path itself
    if (i === 0) continue;
    // Skip flags
    if (part.startsWith("-")) continue;
    // Get basename of file paths (handle both / and \)
    if (part.includes("/") || part.includes("\\")) {
      meaningful.push(basename(part));
    } else {
      meaningful.push(part);
    }
    if (meaningful.length >= 3) break;
  }

  if (meaningful.length > 0) return meaningful.join(" ");

  // Fallback: use the binary basename
  return processName;
}

/**
 * Get all running processes (like ps aux but structured).
 * Used by `ports ps` command.
 */
export function getAllProcesses() {
  const entries = getAllProcessesRaw();
  if (entries.length === 0) return [];

  // Batch cwd lookup — only for non-Docker processes (Docker cwd is useless)
  const nonDockerEntries = entries.filter(
    (e) =>
      !e.processName.startsWith("com.docke") &&
      !e.processName.startsWith("Docker") &&
      e.processName !== "docker" &&
      e.processName !== "docker-sandbox",
  );
  const cwdMap = batchCwd(nonDockerEntries.map((e) => e.pid));

  return entries.map((e) => {
    const cwd = cwdMap.get(e.pid);
    const info = {
      pid: e.pid,
      processName: e.processName,
      command: e.command,
      description: summarizeCommand(e.command, e.processName),
      cpu: e.cpu,
      memory: e.rss > 0 ? formatMemory(e.rss) : null,
      cwd: null,
      projectName: null,
      framework: null,
      uptime: null,
    };

    if (e.lstart) {
      const startTime = new Date(e.lstart);
      if (!isNaN(startTime.getTime())) {
        info.uptime = formatUptime(Date.now() - startTime.getTime());
      }
    }

    info.framework = detectFrameworkFromCommand(e.command, e.processName);

    if (cwd) {
      const projectRoot = findProjectRoot(cwd);
      info.cwd = projectRoot;
      info.projectName = basename(projectRoot);
      info.framework = info.framework || detectFramework(projectRoot);
    }

    return info;
  });
}

export function findOrphanedProcesses() {
  const ports = getListeningPorts();
  return ports.filter((p) => p.status === "orphaned" || p.status === "zombie");
}

export function pidExists(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

export function killProcess(pid, signal = "SIGTERM") {
  try {
    process.kill(pid, signal);
    return true;
  } catch {
    return false;
  }
}

/**
 * Resolve kill target: prefer listener on port (1-65535), else treat as PID.
 */
export function resolveKillTarget(n) {
  if (!Number.isInteger(n) || n < 1) return null;
  if (n <= 65535) {
    const info = getPortDetails(n);
    if (info) return { pid: info.pid, via: "port", port: n, info };
  }
  if (pidExists(n)) return { pid: n, via: "pid" };
  return null;
}

export function watchPorts(callback, intervalMs = 2000) {
  let previousPorts = new Set();

  const check = () => {
    const current = getListeningPorts();
    const currentSet = new Set(current.map((p) => p.port));

    for (const p of current) {
      if (!previousPorts.has(p.port)) {
        callback("new", p);
      }
    }

    for (const port of previousPorts) {
      if (!currentSet.has(port)) {
        callback("removed", { port });
      }
    }

    previousPorts = currentSet;
  };

  check();
  return setInterval(check, intervalMs);
}

function formatUptime(ms) {
  const seconds = Math.floor(ms / 1000);
  const minutes = Math.floor(seconds / 60);
  const hours = Math.floor(minutes / 60);
  const days = Math.floor(hours / 24);

  if (days > 0) return `${days}d ${hours % 24}h`;
  if (hours > 0) return `${hours}h ${minutes % 60}m`;
  if (minutes > 0) return `${minutes}m ${seconds % 60}s`;
  return `${seconds}s`;
}

function formatMemory(rssKB) {
  if (rssKB > 1048576) return `${(rssKB / 1048576).toFixed(1)} GB`;
  if (rssKB > 1024) return `${(rssKB / 1024).toFixed(1)} MB`;
  return `${rssKB} KB`;
}
