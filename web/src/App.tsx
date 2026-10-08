import { useCallback, useEffect, useRef, useState } from "react";

import { Explorer, FileIcon } from "./Explorer";
import { Landing } from "./Landing";
import { client } from "./client";

export function App() {
  const [file, setFile] = useState<File | null>(null);
  const [dragging, setDragging] = useState(false);
  const [ready, setReady] = useState(false);
  const [formatCount, setFormatCount] = useState<number | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    client.ready.then(() => {
      setReady(true);
      client.call("formats", { name: "" }).then((f) => setFormatCount(f.length));
    });
  }, []);

  useEffect(() => {
    document.title = file ? `${file.name} — fillyfoal` : "fillyfoal — see inside any file";
  }, [file]);

  const open = useCallback(() => inputRef.current?.click(), []);

  // A file dropped anywhere opens.
  useEffect(() => {
    let depth = 0;
    const hasFiles = (e: DragEvent) => !!e.dataTransfer?.types.includes("Files");
    const enter = (e: DragEvent) => {
      if (!hasFiles(e)) return;
      depth++;
      setDragging(true);
    };
    const leave = () => {
      depth = Math.max(0, depth - 1);
      if (depth === 0) setDragging(false);
    };
    const over = (e: DragEvent) => {
      if (hasFiles(e)) e.preventDefault();
    };
    const drop = (e: DragEvent) => {
      e.preventDefault();
      depth = 0;
      setDragging(false);
      const f = e.dataTransfer?.files[0];
      if (f) setFile(f);
    };
    window.addEventListener("dragenter", enter);
    window.addEventListener("dragleave", leave);
    window.addEventListener("dragover", over);
    window.addEventListener("drop", drop);
    return () => {
      window.removeEventListener("dragenter", enter);
      window.removeEventListener("dragleave", leave);
      window.removeEventListener("dragover", over);
      window.removeEventListener("drop", drop);
    };
  }, []);

  // A file pasted (copied in the file manager) opens too.
  useEffect(() => {
    const paste = (e: ClipboardEvent) => {
      const f = e.clipboardData?.files[0];
      if (f) setFile(f);
    };
    window.addEventListener("paste", paste);
    return () => window.removeEventListener("paste", paste);
  }, []);

  // `?url=…` opens a file fetched from there (downloaded in full, then
  // dissected here like any other).
  const [fetchError, setFetchError] = useState<string | null>(null);
  useEffect(() => {
    const url = new URLSearchParams(location.search).get("url");
    if (!url) return;
    (async () => {
      try {
        const response = await fetch(url);
        if (!response.ok) throw new Error(`${response.status} ${response.statusText}`);
        const blob = await response.blob();
        const name = decodeURIComponent(new URL(url, location.href).pathname.split("/").pop() || "download");
        setFile(new File([blob], name));
      } catch (e) {
        setFetchError(`Couldn't fetch ${url}: ${e instanceof Error ? e.message : e}`);
      }
    })();
  }, []);

  const trySelf = async () => {
    const response = await fetch(await client.call("engineUrl", {}));
    const blob = await response.blob();
    setFile(new File([blob], "fillyfoal_wasm_bg.wasm", { type: "application/wasm" }));
  };

  return (
    <>
      <input
        ref={inputRef}
        type="file"
        hidden
        onChange={(e) => {
          const f = e.target.files?.[0];
          if (f) setFile(f);
          e.target.value = "";
        }}
      />
      {file ? (
        <Explorer file={file} onOpen={open} onClose={() => setFile(null)} />
      ) : (
        <Landing
          ready={ready}
          formatCount={formatCount}
          onOpen={open}
          onTrySelf={() => void trySelf()}
          onOpenFile={setFile}
          error={fetchError}
        />
      )}
      {dragging && (
        <div className="drop-veil">
          <div className="drop-veil-card">
            <FileIcon />
            Drop to look inside
          </div>
        </div>
      )}
    </>
  );
}
