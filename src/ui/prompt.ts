import { stdin, stdout } from "node:process";

export async function promptLine(label: string): Promise<string> {
  if (!stdin.isTTY || !stdout.isTTY) {
    throw new Error(`${label} requires an interactive terminal`);
  }

  return new Promise((resolve, reject) => {
    let value = "";
    stdout.write(label);
    stdin.setRawMode(true);
    stdin.resume();
    stdin.setEncoding("utf8");

    const cleanup = (): void => {
      stdin.off("data", onData);
      stdin.setRawMode(false);
      stdin.pause();
    };

    const onData = (chunk: string): void => {
      for (const character of chunk) {
        if (character === "\r" || character === "\n") {
          cleanup();
          stdout.write("\n");
          resolve(value);
          return;
        }
        if (character === "\u0003") {
          cleanup();
          stdout.write("\n");
          reject(new Error("Cancelled"));
          return;
        }
        if (character === "\u007f") {
          value = value.slice(0, -1);
          continue;
        }
        if (character >= " ") {
          value += character;
        }
      }
    };

    stdin.on("data", onData);
  });
}

export async function readPassword(label = "Password: "): Promise<string> {
  return promptLine(label);
}
