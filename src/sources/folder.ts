import { type Dir, lstatSync, opendirSync, realpathSync, statSync } from "node:fs";
import { isAbsolute, join } from "node:path";
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
 *
 * Where it reads is pinned: the folder's device and inode are taken when the
 * source starts, and every folder entered is checked by `lstat` (not a link,
 * the same device and inode before and after it is read) and by `realpath`
 * (still inside the folder, at the path it was found by). A scan that sees
 * any of that change fails instead of reporting. The residual race: a folder
 * swapped for another and swapped back between those two checks is not
 * seen; Node has no `openat`/`fdopendir` to read through a pinned handle.
 *
 * Every scan is bounded: files (`maxFiles`), folders (`maxDirectories`),
 * depth (`maxDepth`) and directory entries read of any kind (`maxEntries`).
 * Directories are streamed a batch at a time, and a scan stops at the next
 * entry once the source stops. Over a bound, the scan fails; it never
 * truncates.
 */

/** Paths that change all the time without anyone having done anything worth reporting. */
const DEFAULT_IGNORE =
  "(^|/)(\\.git|\\.hg|\\.svn|node_modules|__pycache__|\\.venv|\\.DS_Store)(/|$)|(~|\\.swp|\\.tmp|\\.part|\\.crdownload)$";
const MIN_INTERVAL_MS = 1_000;
const DEFAULT_MAX_FILES = 10_000;
const MAX_MAX_FILES = 100_000;
const DEFAULT_MAX_DIRECTORIES = 1_000;
const MAX_MAX_DIRECTORIES = 100_000;
const DEFAULT_MAX_DEPTH = 32;
const MAX_MAX_DEPTH = 256;
const DEFAULT_MAX_ENTRIES = 100_000;
const MAX_MAX_ENTRIES = 1_000_000;
/** Entries read between yields to the event loop, so a stop can land mid-scan. */
const YIELD_EVERY = 256;

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
    maxDirectories: { type: "number", description: `refuse a scan that finds more folders than this (default ${DEFAULT_MAX_DIRECTORIES})` },
    maxDepth: { type: "number", description: `refuse a scan that finds folders nested deeper than this (default ${DEFAULT_MAX_DEPTH})` },
    maxEntries: {
      type: "number",
      description: `refuse a scan that reads more directory entries than this, ignored ones included (default ${DEFAULT_MAX_ENTRIES})`,
    },
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
    const bound = (key: string, fallback: number, max: number) => {
      const v = (o[key] as number | undefined) ?? fallback;
      if (!Number.isInteger(v) || v < 1 || v > max) throw new Error(`folder: "${key}" must be an integer from 1 to ${max}`);
      return v;
    };
    const maxFiles = bound("maxFiles", DEFAULT_MAX_FILES, MAX_MAX_FILES);
    const maxDirectories = bound("maxDirectories", DEFAULT_MAX_DIRECTORIES, MAX_MAX_DIRECTORIES);
    const maxDepth = bound("maxDepth", DEFAULT_MAX_DEPTH, MAX_MAX_DEPTH);
    const maxEntries = bound("maxEntries", DEFAULT_MAX_ENTRIES, MAX_MAX_ENTRIES);
    const only = [o.mask ? `files named ${o.mask}` : "", o.pattern ? `paths matching ${o.pattern}` : ""].filter(Boolean).join(", ");
    return {
      options: { ...o, dir: real, every, maxFiles, maxDirectories, maxDepth, maxEntries, recursive: o.recursive !== false },
      does: [
        `scan ${real}${o.recursive === false ? "" : " and the folders inside it"} every ${every} and report new and changed files${only ? ` (${only})` : ""}`,
        `fail a scan that finds more than ${maxFiles} files, ${maxDirectories} folders, ${maxEntries} entries or folders ${maxDepth} deep, or sees the folder replaced`,
      ],
      opens: true,
    };
  },
  start(api: SourceApi) {
    const o = api.options as {
      dir: string;
      mask?: string;
      pattern?: string;
      ignore?: string;
      recursive: boolean;
      every: string;
      maxFiles: number;
      maxDirectories: number;
      maxDepth: number;
      maxEntries: number;
    };
    const root = o.dir;
    const mask = o.mask ? maskTest(o.mask) : undefined;
    const pattern = o.pattern ? new RegExp(o.pattern, "i") : undefined;
    const ignore = new RegExp(o.ignore ?? DEFAULT_IGNORE, "i");

    type Identity = { dev: number; ino: number };
    const replaced = () => new SourceError("the folder, or a folder inside it, was replaced while it was watched");
    /** The folder at `path` is a real folder (no link anywhere on the way), the very one seen before. */
    const verify = (path: string, expected: Identity | undefined): Identity => {
      let st: ReturnType<typeof lstatSync>;
      let real: string;
      try {
        st = lstatSync(path);
        real = realpathSync(path);
      } catch {
        if (path === root) throw new SourceError("the folder cannot be read");
        throw replaced();
      }
      if (!st.isDirectory() || real !== path) throw replaced();
      if (expected && (st.dev !== expected.dev || st.ino !== expected.ino)) throw replaced();
      return { dev: st.dev, ino: st.ino };
    };
    // Pinned when the source starts: a later scan reads this folder or nothing.
    const pinned = verify(root, undefined);

    const scan = async (signal: AbortSignal): Promise<Map<string, { size: number; sig: string }>> => {
      const found = new Map<string, { size: number; sig: string }>();
      const queue: Array<{ path: string; rel: string; depth: number; id: Identity }> = [{ path: root, rel: "", depth: 0, id: pinned }];
      let directories = 0;
      let entries = 0;
      const stopped = () => {
        if (signal.aborted) throw new Error("stopped");
      };
      for (let next = queue.shift(); next; next = queue.shift()) {
        const { path, rel, depth, id } = next;
        verify(path, id);
        let dir: Dir;
        try {
          dir = opendirSync(path);
        } catch {
          if (path === root) throw new SourceError("the folder cannot be read");
          continue;
        }
        try {
          for (let entry = dir.readSync(); entry; entry = dir.readSync()) {
            stopped();
            entries++;
            if (entries > o.maxEntries) throw new SourceError(`more than ${o.maxEntries} entries; narrow the folder or the ignore list`);
            if (entries % YIELD_EVERY === 0) {
              await new Promise<void>((resolve) => setImmediate(resolve));
              stopped();
            }
            const childRel = rel ? `${rel}/${entry.name}` : entry.name;
            if (ignore.test(childRel)) continue;
            // Never follow a link: it may lead out of the folder.
            if (entry.isSymbolicLink()) continue;
            const full = join(path, entry.name);
            if (entry.isDirectory()) {
              if (!o.recursive) continue;
              if (depth + 1 > o.maxDepth) throw new SourceError(`folders nested more than ${o.maxDepth} deep; narrow the folder`);
              directories++;
              if (directories > o.maxDirectories) throw new SourceError(`more than ${o.maxDirectories} folders; narrow the folder or the ignore list`);
              let st: ReturnType<typeof lstatSync>;
              try {
                st = lstatSync(full);
              } catch {
                continue;
              }
              // Replaced by a link or a file since it was listed: not followed.
              if (!st.isDirectory()) continue;
              queue.push({ path: full, rel: childRel, depth: depth + 1, id: { dev: st.dev, ino: st.ino } });
              continue;
            }
            if (!entry.isFile()) continue;
            if (mask && !mask.test(entry.name)) continue;
            if (pattern && !pattern.test(childRel)) continue;
            let st: ReturnType<typeof lstatSync>;
            try {
              st = lstatSync(full);
            } catch {
              continue;
            }
            if (!st.isFile()) continue;
            found.set(childRel, { size: st.size, sig: `${st.size}:${st.mtimeMs}` });
            if (found.size > o.maxFiles) throw new SourceError(`more than ${o.maxFiles} files; narrow the folder, mask or pattern`);
          }
        } finally {
          try {
            dir.closeSync();
          } catch {
            // Already closed.
          }
        }
        // Still the same folder, at the same place, now that it has been read.
        verify(path, id);
      }
      return found;
    };

    api.poll(o.every, async (signal) => {
      const files = await scan(signal);
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
