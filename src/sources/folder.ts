import { type Dirent, readdirSync, realpathSync, statSync } from "node:fs";
import { isAbsolute, join, relative, sep } from "node:path";
import { SourceError, type SourceApi, type SourceType } from "../source-type.js";
import { parseDuration } from "../util.js";

/**
 * A folder: reports every new or changed file once it has stopped changing.
 * For things that drop files: a scanner, an export, a download folder.
 *
 * It scans on the host's poll rather than through `fs.watch`, so the shared
 * rules hold for it unchanged: the first scan is the starting point and
 * reports nothing, an unchanged scan does nothing, a failed scan backs off
 * and shows in the status. A file counts as complete when two scans in a row
 * see the same size and modification time.
 *
 * Events: `added` `{ file, size }` for a file not seen before, `changed`
 * `{ file, size }` for one whose content changed. `file` is relative to the
 * folder. Symbolic links are never followed.
 */

/** Paths that change all the time without anyone having done anything worth reporting. */
const DEFAULT_IGNORE =
  "(^|/)(\\.git|\\.hg|\\.svn|node_modules|__pycache__|\\.venv|\\.DS_Store)(/|$)|(~|\\.swp|\\.tmp|\\.part|\\.crdownload)$";
const MIN_INTERVAL_MS = 1_000;
const DEFAULT_MAX_FILES = 10_000;
const MAX_MAX_FILES = 100_000;

/** A shell-style name mask ("*.pdf", "*.{png,jpg}", "a?.txt"; several separated by commas) as a test. Case-insensitive. */
export function maskTest(mask: string): RegExp {
  const one = (glob: string) =>
    glob
      .trim()
      .replace(/[.+^$()|[\]\\]/g, "\\$&")
      .replace(/\*/g, "[^/]*")
      .replace(/\?/g, "[^/]")
      .replace(/\{([^{}]*)\}/g, (_m, list: string) => `(?:${list.split(",").map((x) => x.trim()).join("|")})`);
  // Commas separate masks, except inside braces.
  const parts = mask.split(/,(?![^{]*\})/).map(one).filter(Boolean);
  return new RegExp(`^(?:${parts.join("|")})$`, "i");
}

interface FolderMemory {
  /** file -> "size:mtimeMs" last reported (or taken as the starting point). */
  reported: Record<string, string>;
  /** file -> signature seen at the last scan but not yet stable. */
  pending: Record<string, string>;
}

export const folderSourceType: SourceType = {
  summary: "a folder: reports every new or changed file in it once the file has stopped changing",
  options: {
    dir: { type: "string", required: true, description: "the folder to watch, as an absolute path" },
    mask: { type: "string", description: 'only files whose name matches, e.g. "*.pdf", "*.{png,jpg}"' },
    pattern: { type: "string", description: "only files whose path relative to the folder matches this regular expression" },
    ignore: { type: "string", description: "never paths matching this regular expression (default: version control, dependencies, editor leftovers)" },
    recursive: { type: "boolean", description: "also look in folders inside it (default true)" },
    every: { type: "string", description: 'how often to scan, at least "1s" (default "5s")' },
    maxFiles: { type: "number", description: `refuse a scan that finds more files than this (default ${DEFAULT_MAX_FILES})` },
  },
  plan(o) {
    const dir = String(o.dir);
    if (!isAbsolute(dir)) throw new Error(`folder: "dir" must be an absolute path`);
    let real: string;
    try {
      real = realpathSync(dir);
      if (!statSync(real).isDirectory()) throw new Error("not a folder");
    } catch {
      throw new Error(`folder: ${dir} is not a folder that exists`);
    }
    for (const key of ["pattern", "ignore"] as const) if (o[key] !== undefined) new RegExp(String(o[key]));
    if (o.mask !== undefined) maskTest(String(o.mask));
    const every = (o.every as string | undefined) ?? "5s";
    if (parseDuration(every) < MIN_INTERVAL_MS) throw new Error(`folder: "every" must be at least "1s"`);
    const maxFiles = (o.maxFiles as number | undefined) ?? DEFAULT_MAX_FILES;
    if (!Number.isInteger(maxFiles) || maxFiles < 1 || maxFiles > MAX_MAX_FILES) throw new Error(`folder: "maxFiles" must be an integer from 1 to ${MAX_MAX_FILES}`);
    const only = [o.mask ? `files named ${o.mask}` : "", o.pattern ? `paths matching ${o.pattern}` : ""].filter(Boolean).join(", ");
    return {
      options: { ...o, dir: real, every, maxFiles, recursive: o.recursive !== false },
      does: [`scan ${real}${o.recursive === false ? "" : " and the folders inside it"} every ${every} and report new and changed files${only ? ` (${only})` : ""}`],
      opens: true,
    };
  },
  start(api: SourceApi) {
    const o = api.options as { dir: string; mask?: string; pattern?: string; ignore?: string; recursive: boolean; every: string; maxFiles: number };
    const root = o.dir;
    const mask = o.mask ? maskTest(o.mask) : undefined;
    const pattern = o.pattern ? new RegExp(o.pattern, "i") : undefined;
    const ignore = new RegExp(o.ignore ?? DEFAULT_IGNORE, "i");

    const scan = (): Map<string, { size: number; sig: string }> => {
      const found = new Map<string, { size: number; sig: string }>();
      const walk = (dir: string) => {
        let entries: Dirent[];
        try {
          entries = readdirSync(dir, { withFileTypes: true });
        } catch {
          if (dir === root) throw new SourceError("the folder cannot be read");
          return;
        }
        for (const entry of entries) {
          const full = join(dir, entry.name);
          const rel = relative(root, full).split(sep).join("/");
          if (ignore.test(rel)) continue;
          // Never follow a link: it may lead out of the folder.
          if (entry.isSymbolicLink()) continue;
          if (entry.isDirectory()) {
            if (o.recursive) walk(full);
            continue;
          }
          if (!entry.isFile()) continue;
          if (mask && !mask.test(entry.name)) continue;
          if (pattern && !pattern.test(rel)) continue;
          let size: number;
          let mtimeMs: number;
          try {
            ({ size, mtimeMs } = statSync(full));
          } catch {
            continue;
          }
          found.set(rel, { size, sig: `${size}:${mtimeMs}` });
          if (found.size > o.maxFiles) throw new SourceError(`more than ${o.maxFiles} files; narrow the folder, mask or pattern`);
        }
      };
      walk(root);
      return found;
    };

    api.poll(o.every, async () => {
      const files = scan();
      const memory = await api.state.get<FolderMemory>("files");
      if (!memory) {
        // The first scan is the starting point: what is there already is not news.
        await api.state.set("files", {
          reported: Object.fromEntries([...files].map(([f, v]) => [f, v.sig])),
          pending: {},
        } satisfies FolderMemory);
        api.status(`watching ${files.size} files`);
        return;
      }
      let dirty = false;
      try {
        for (const [file, { size, sig }] of files) {
          if (memory.reported[file] === sig) {
            if (memory.pending[file] !== undefined) {
              delete memory.pending[file];
              dirty = true;
            }
            continue;
          }
          // Still growing, or empty: wait for a scan that sees it unchanged.
          if (memory.pending[file] !== sig || size === 0) {
            memory.pending[file] = sig;
            dirty = true;
            continue;
          }
          const name = memory.reported[file] === undefined ? "added" : "changed";
          await api.emit(name, { file, size }, { dedupKey: `file:${file}:${sig}` });
          memory.reported[file] = sig;
          delete memory.pending[file];
          dirty = true;
        }
        for (const file of Object.keys(memory.reported)) {
          if (!files.has(file)) {
            delete memory.reported[file];
            dirty = true;
          }
        }
        for (const file of Object.keys(memory.pending)) {
          if (!files.has(file)) {
            delete memory.pending[file];
            dirty = true;
          }
        }
      } finally {
        // An unchanged scan writes nothing.
        if (dirty) await api.state.set("files", memory);
      }
      api.status(`watching ${files.size} files`);
    });
  },
};
