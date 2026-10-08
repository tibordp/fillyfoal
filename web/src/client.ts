// The page's side of the worker: requests as promises, progress as events.

import type { Api, Method, ProgressEvent, Request, Response } from "./types";

export class CancelledError extends Error {}

type Pending = { resolve: (v: unknown) => void; reject: (e: unknown) => void };

class Client {
  private worker = new Worker(new URL("./worker.ts", import.meta.url), {
    type: "module",
  });
  private next = 1;
  private pending = new Map<number, Pending>();
  private progressListeners = new Set<(p: ProgressEvent) => void>();
  readonly ready: Promise<void>;

  constructor() {
    let markReady: () => void;
    this.ready = new Promise((r) => (markReady = r));
    this.worker.onmessage = (e: MessageEvent<Response>) => {
      const msg = e.data;
      if ("event" in msg) {
        if (msg.event === "ready") markReady();
        else for (const l of this.progressListeners) l(msg.progress);
        return;
      }
      const p = this.pending.get(msg.id);
      if (!p) return;
      this.pending.delete(msg.id);
      if (msg.ok) p.resolve(msg.result);
      else
        p.reject(
          msg.cancelled ? new CancelledError(msg.error) : new Error(msg.error),
        );
    };
  }

  call<M extends Method>(method: M, args: Api[M][0]): Promise<Api[M][1]> {
    const id = this.next++;
    const request: Request<M> = { id, method, args };
    return new Promise((resolve, reject) => {
      this.pending.set(id, {
        resolve: resolve as (v: unknown) => void,
        reject,
      });
      this.worker.postMessage(request);
    });
  }

  onProgress(listener: (p: ProgressEvent) => void) {
    this.progressListeners.add(listener);
    return () => {
      this.progressListeners.delete(listener);
    };
  }
}

export const client = new Client();
