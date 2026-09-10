import { open, readFile, rm } from "node:fs/promises";

interface LockRecord {
  pid: number;
  createdAt: string;
}

function processExists(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return (error as NodeJS.ErrnoException).code === "EPERM";
  }
}

export async function acquireUserLock(lockPath: string): Promise<() => Promise<void>> {
  for (let attempt = 0; attempt < 2; attempt += 1) {
    try {
      const handle = await open(lockPath, "wx", 0o600);
      const record: LockRecord = { pid: process.pid, createdAt: new Date().toISOString() };
      await handle.writeFile(`${JSON.stringify(record)}\n`, "utf8");
      await handle.close();
      return async () => rm(lockPath, { force: true });
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") {
        throw error;
      }

      const record = JSON.parse(await readFile(lockPath, "utf8")) as LockRecord;
      if (processExists(record.pid)) {
        throw new Error(`This user vault is already unlocked by process ${record.pid}`);
      }
      await rm(lockPath, { force: true });
    }
  }

  throw new Error("Unable to acquire the user vault lock");
}
