import { constants, createReadStream } from "node:fs";
import {
  copyFile,
  cp,
  lstat,
  mkdir,
  open,
  readdir,
  readFile,
  rename,
  rm,
  stat,
  unlink,
} from "node:fs/promises";
import path from "node:path";
import { randomUUID } from "node:crypto";

import { AppError } from "../../errors.js";
import { encodeCursor, decodeCursor, sha256 } from "../../utils/json.js";
import { SafePathResolver } from "./safe-path.js";

type Cursor = { path: string; index: number };

export class FilesystemService {
  readonly resolver: SafePathResolver;

  constructor(
    roots: string[],
    private readonly maxFileBytes: number,
    private readonly trashRoot: string,
    private readonly allowTrash: boolean,
  ) {
    this.resolver = new SafePathResolver(roots);
  }

  async listDirectory(input: string, cursor?: string, limit = 100): Promise<unknown> {
    const resolved = await this.resolver.resolve(input, { mustExist: true });
    const parsed = cursor ? decodeCursor<Cursor>(cursor) : { path: resolved, index: 0 };
    if (parsed.path !== resolved || !Number.isInteger(parsed.index) || parsed.index < 0) {
      throw new AppError("INVALID_INPUT", "cursor does not belong to this directory");
    }
    const entries = await readdir(resolved, { withFileTypes: true });
    entries.sort((a, b) => a.name.localeCompare(b.name, undefined, { sensitivity: "base" }));
    const bounded = Math.min(Math.max(limit, 1), 500);
    const page = entries.slice(parsed.index, parsed.index + bounded).map((entry) => ({
      name: entry.name,
      type: entry.isDirectory()
        ? "directory"
        : entry.isFile()
          ? "file"
          : entry.isSymbolicLink()
            ? "symlink"
            : "other",
    }));
    const nextIndex = parsed.index + page.length;
    return {
      path: resolved,
      entries: page,
      nextCursor:
        nextIndex < entries.length ? encodeCursor({ path: resolved, index: nextIndex }) : null,
      total: entries.length,
    };
  }

  async readFile(input: string, offset = 0, length = 64 * 1024): Promise<unknown> {
    const resolved = await this.resolver.resolve(input, { mustExist: true });
    const info = await stat(resolved);
    if (!info.isFile()) throw new AppError("INVALID_INPUT", "path is not a regular file");
    if (info.size > this.maxFileBytes)
      throw new AppError("LIMIT_EXCEEDED", "file exceeds configured size limit");
    if (!Number.isInteger(offset) || offset < 0 || !Number.isInteger(length) || length < 1) {
      throw new AppError("INVALID_INPUT", "offset and length must be positive byte ranges");
    }
    const bounded = Math.min(length, this.maxFileBytes, 1024 * 1024);
    const handle = await open(resolved, "r");
    try {
      const buffer = Buffer.alloc(Math.min(bounded, Math.max(0, info.size - offset)));
      const { bytesRead } = await handle.read(buffer, 0, buffer.length, offset);
      const data = buffer.subarray(0, bytesRead);
      const binary = data.includes(0) && !(data[0] === 0xff && data[1] === 0xfe);
      const encoding = binary
        ? "base64"
        : data[0] === 0xff && data[1] === 0xfe
          ? "utf16le"
          : "utf8";
      const content = binary
        ? data.toString("base64")
        : data.toString(encoding === "utf16le" ? "utf16le" : "utf8").replace(/^\uFEFF/u, "");
      const nextOffset = offset + bytesRead;
      return {
        path: resolved,
        offset,
        bytesRead,
        size: info.size,
        encoding,
        content,
        sha256: await this.hashFile(resolved),
        nextOffset: nextOffset < info.size ? nextOffset : null,
        truncated: nextOffset < info.size,
      };
    } finally {
      await handle.close();
    }
  }

  async readMultipleFiles(paths: string[], offset = 0, length = 64 * 1024): Promise<unknown> {
    const results: unknown[] = [];
    for (const item of paths.slice(0, 32)) {
      try {
        results.push(await this.readFile(item, offset, length));
      } catch (error) {
        results.push({
          path: item,
          error: error instanceof AppError ? error.code : "INTERNAL_ERROR",
        });
      }
    }
    return { results };
  }

  async getFileInfo(input: string): Promise<unknown> {
    const resolved = await this.resolver.resolve(input, { mustExist: true });
    const info = await lstat(resolved);
    return {
      path: resolved,
      type: info.isDirectory()
        ? "directory"
        : info.isFile()
          ? "file"
          : info.isSymbolicLink()
            ? "symlink"
            : "other",
      size: info.size,
      createdAt: info.birthtime.toISOString(),
      modifiedAt: info.mtime.toISOString(),
      readOnly: (info.mode & 0o200) === 0,
    };
  }

  async createDirectory(input: string): Promise<unknown> {
    const first = await this.resolver.resolve(input, { mustExist: false });
    const verified = await this.resolver.resolve(first, { mustExist: false });
    await mkdir(verified, { recursive: true });
    return { path: await this.resolver.resolve(verified, { mustExist: true }), created: true };
  }

  async writeFile(
    input: string,
    content: string,
    encoding: "utf8" | "base64",
    overwrite: boolean,
  ): Promise<unknown> {
    const target = await this.resolver.resolve(input, { mustExist: false });
    const bytes = Buffer.from(content, encoding);
    if (bytes.length > this.maxFileBytes)
      throw new AppError("LIMIT_EXCEEDED", "content exceeds configured file-size limit");
    await mkdir(path.win32.dirname(target), { recursive: true });
    const verified = await this.resolver.resolve(target, { mustExist: false });
    if (!overwrite) {
      try {
        await lstat(verified);
        throw new AppError("CONFLICT", "target already exists");
      } catch (error) {
        if (error instanceof AppError) throw error;
        if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
      }
    }
    await this.atomicWrite(verified, bytes, overwrite);
    return { path: verified, bytes: bytes.length, sha256: sha256(bytes) };
  }

  async editBlock(input: string, search: string, replacement: string): Promise<unknown> {
    const target = await this.resolver.resolve(input, { mustExist: true });
    const info = await stat(target);
    if (info.size > this.maxFileBytes)
      throw new AppError("LIMIT_EXCEEDED", "file exceeds configured size limit");
    const content = await readFile(target, "utf8");
    let count = 0;
    let index = content.indexOf(search);
    while (index >= 0) {
      count += 1;
      index = content.indexOf(search, index + Math.max(1, search.length));
    }
    if (count !== 1)
      throw new AppError("CONFLICT", `exact-match edit requires one match; found ${count}`);
    const next = content.replace(search, replacement);
    const verified = await this.resolver.resolve(target, { mustExist: true });
    await this.atomicWrite(verified, Buffer.from(next, "utf8"), true);
    return {
      path: verified,
      replacements: 1,
      sha256: sha256(next),
      bytes: Buffer.byteLength(next),
    };
  }

  async copy(sourceInput: string, destinationInput: string, overwrite: boolean): Promise<unknown> {
    const source = await this.resolver.resolve(sourceInput, { mustExist: true });
    const destination = await this.resolver.resolve(destinationInput, { mustExist: false });
    const verifiedSource = await this.resolver.resolve(source, { mustExist: true });
    const verifiedDestination = await this.resolver.resolve(destination, { mustExist: false });
    const info = await stat(verifiedSource);
    if (info.isDirectory()) {
      if (
        path.win32
          .normalize(verifiedDestination)
          .toLowerCase()
          .startsWith(
            `${path.win32
              .normalize(verifiedSource)
              .replace(/[\\/]+$/u, "")
              .toLowerCase()}\\`,
          )
      ) {
        throw new AppError("INVALID_PATH", "a directory cannot be copied into its own descendant");
      }
      await this.assertTreeHasNoLinks(verifiedSource);
      await cp(verifiedSource, verifiedDestination, {
        recursive: true,
        errorOnExist: !overwrite,
        force: overwrite,
        verbatimSymlinks: false,
      });
    } else {
      await mkdir(path.win32.dirname(verifiedDestination), { recursive: true });
      await copyFile(verifiedSource, verifiedDestination, overwrite ? 0 : constants.COPYFILE_EXCL);
    }
    return { source: verifiedSource, destination: verifiedDestination };
  }

  async move(sourceInput: string, destinationInput: string): Promise<unknown> {
    const source = await this.resolver.resolve(sourceInput, { mustExist: true });
    const destination = await this.resolver.resolve(destinationInput, { mustExist: false });
    const verifiedSource = await this.resolver.resolve(source, { mustExist: true });
    const verifiedDestination = await this.resolver.resolve(destination, { mustExist: false });
    if (
      path.win32
        .normalize(verifiedDestination)
        .toLowerCase()
        .startsWith(
          `${path.win32
            .normalize(verifiedSource)
            .replace(/[\\/]+$/u, "")
            .toLowerCase()}\\`,
        )
    ) {
      throw new AppError("INVALID_PATH", "a path cannot be moved into its own descendant");
    }
    try {
      await lstat(verifiedDestination);
      throw new AppError("CONFLICT", "destination already exists");
    } catch (error) {
      if (error instanceof AppError) throw error;
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    }
    await mkdir(path.win32.dirname(verifiedDestination), { recursive: true });
    await rename(verifiedSource, verifiedDestination);
    return { source: verifiedSource, destination: verifiedDestination };
  }

  async trash(input: string, confirmationPath: string): Promise<unknown> {
    if (!this.allowTrash)
      throw new AppError("POLICY_DENIED", "recoverable trash is disabled for this profile");
    const target = await this.resolver.resolve(input, { mustExist: true });
    if (
      path.win32.normalize(target).toLowerCase() !==
      path.win32.normalize(confirmationPath).toLowerCase()
    ) {
      throw new AppError(
        "INVALID_INPUT",
        "confirmationPath must exactly match the canonical target",
      );
    }
    await mkdir(this.trashRoot, { recursive: true });
    const name = `${Date.now()}-${randomUUID()}-${path.win32.basename(target)}`;
    const destination = path.win32.join(this.trashRoot, name);
    const verified = await this.resolver.resolve(target, { mustExist: true });
    await rename(verified, destination);
    return { originalPath: verified, quarantinePath: destination, recoverable: true };
  }

  private async atomicWrite(target: string, bytes: Buffer, overwrite: boolean): Promise<void> {
    const temp = path.win32.join(path.win32.dirname(target), `.radlina-${randomUUID()}.tmp`);
    const handle = await open(temp, "wx", 0o600);
    try {
      await handle.writeFile(bytes);
      await handle.sync();
    } finally {
      await handle.close();
    }
    try {
      if (overwrite) {
        await rename(temp, target);
      } else {
        await copyFile(temp, target, constants.COPYFILE_EXCL);
        const targetHandle = await open(target, "r+");
        try {
          await targetHandle.sync();
        } finally {
          await targetHandle.close();
        }
        await unlink(temp);
      }
    } catch (error) {
      await rm(temp, { force: true });
      throw error;
    }
  }

  private async hashFile(filePath: string): Promise<string> {
    const hash = await import("node:crypto").then(({ createHash }) => createHash("sha256"));
    for await (const chunk of createReadStream(filePath)) {
      const value: unknown = chunk;
      if (!(value instanceof Uint8Array))
        throw new AppError("INTERNAL_ERROR", "unexpected file stream data");
      hash.update(value);
    }
    return hash.digest("hex");
  }

  private async assertTreeHasNoLinks(root: string): Promise<void> {
    const pending = [root];
    let visited = 0;
    while (pending.length > 0) {
      const current = pending.pop();
      if (!current) break;
      for (const entry of await readdir(current, { withFileTypes: true })) {
        visited += 1;
        if (visited > 100_000)
          throw new AppError("LIMIT_EXCEEDED", "directory tree is too large to copy safely");
        if (entry.isSymbolicLink()) {
          throw new AppError(
            "INVALID_PATH",
            "directory copies containing symbolic links or junctions are not allowed",
          );
        }
        if (entry.isDirectory()) pending.push(path.win32.join(current, entry.name));
        else if (!entry.isFile())
          throw new AppError(
            "INVALID_PATH",
            "directory copy contains an unsupported filesystem entry",
          );
      }
    }
  }
}
