import { useEffect, useLayoutEffect, useState, type RefObject } from "react";

/// How long work may run before it shows as in progress: shorter work would
/// only flash an indicator on and off.
export const BUSY_GRACE_MS = 200;

/// `active`, once it has stayed true for `BUSY_GRACE_MS`; false as soon as it
/// isn't.
export function useAfterGrace(active: boolean): boolean {
  const [shown, setShown] = useState(false);
  useEffect(() => {
    if (!active) {
      setShown(false);
      return;
    }
    const timeout = setTimeout(() => setShown(true), BUSY_GRACE_MS);
    return () => clearTimeout(timeout);
  }, [active]);
  return active && shown;
}

/// The element's client height, kept up to date.
export function useHeight(ref: RefObject<HTMLElement | null>, deps: unknown[] = []) {
  const [height, setHeight] = useState(0);
  useLayoutEffect(() => {
    const el = ref.current;
    if (!el) return;
    setHeight(el.clientHeight);
    const observer = new ResizeObserver(() => setHeight(el.clientHeight));
    observer.observe(el);
    return () => observer.disconnect();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);
  return height;
}

/// A value kept in localStorage, falling back to `initial` where storage
/// isn't available.
export function useStored<T>(key: string, initial: T) {
  const [value, setValue] = useState<T>(() => {
    try {
      const stored = localStorage.getItem(key);
      return stored === null ? initial : (JSON.parse(stored) as T);
    } catch {
      return initial;
    }
  });
  useEffect(() => {
    try {
      localStorage.setItem(key, JSON.stringify(value));
    } catch {
      // Not kept, then.
    }
  }, [key, value]);
  return [value, setValue] as const;
}
