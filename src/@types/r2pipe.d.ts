declare module 'r2pipe' {
  interface R2PipeInstance {
    cmd(command: string, callback: (err: Error | null, output: string) => void): void;
    cmdj(command: string, callback: (err: Error | null, output: unknown) => void): void;
    quit(): void;
  }

  function open(path: string, callback: (err: Error | null, r2: R2PipeInstance) => void): void;
  function open(
    path: string,
    flags: readonly string[],
    callback: (err: Error | null, r2: R2PipeInstance) => void,
  ): void;

  export default {
    open,
  };
}
