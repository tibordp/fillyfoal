import { useEffect, useLayoutEffect, useRef, useState } from "react";

export type MenuItem =
  | {
      label: string;
      shortcut?: string;
      disabled?: boolean;
      checked?: boolean;
      onSelect: () => void;
    }
  | "separator";

/// A context menu at a point; arrow keys move, Enter picks, Escape or a click
/// elsewhere closes it.
export function ContextMenu({
  x,
  y,
  items,
  onClose,
}: {
  x: number;
  y: number;
  items: MenuItem[];
  onClose: () => void;
}) {
  const ref = useRef<HTMLDivElement>(null);
  const [pos, setPos] = useState({ x, y });
  const [active, setActive] = useState(-1);

  useLayoutEffect(() => {
    const el = ref.current;
    if (!el) return;
    const r = el.getBoundingClientRect();
    setPos({
      x: Math.max(4, Math.min(x, window.innerWidth - r.width - 4)),
      y: Math.max(4, Math.min(y, window.innerHeight - r.height - 4)),
    });
    el.focus();
  }, [x, y]);

  useEffect(() => {
    const down = (e: PointerEvent) => {
      if (!ref.current?.contains(e.target as Node)) onClose();
    };
    const blur = () => onClose();
    window.addEventListener("pointerdown", down, true);
    window.addEventListener("blur", blur);
    window.addEventListener("resize", blur);
    return () => {
      window.removeEventListener("pointerdown", down, true);
      window.removeEventListener("blur", blur);
      window.removeEventListener("resize", blur);
    };
  }, [onClose]);

  const enabled = items
    .map((item, i) => (item !== "separator" && !item.disabled ? i : -1))
    .filter((i) => i >= 0);

  const pick = (i: number) => {
    const item = items[i];
    if (item === "separator" || item.disabled) return;
    onClose();
    item.onSelect();
  };

  const onKeyDown = (e: React.KeyboardEvent) => {
    e.stopPropagation();
    const at = enabled.indexOf(active);
    switch (e.key) {
      case "ArrowDown":
        setActive(enabled[(at + 1) % enabled.length]);
        break;
      case "ArrowUp":
        setActive(enabled[(at - 1 + enabled.length) % enabled.length]);
        break;
      case "Enter":
      case " ":
        if (active >= 0) pick(active);
        break;
      case "Escape":
      case "Tab":
        onClose();
        break;
      default:
        return;
    }
    e.preventDefault();
  };

  return (
    <div
      ref={ref}
      className="menu"
      role="menu"
      tabIndex={-1}
      style={{ left: pos.x, top: pos.y }}
      onKeyDown={onKeyDown}
      onContextMenu={(e) => e.preventDefault()}
    >
      {items.map((item, i) =>
        item === "separator" ? (
          <div key={i} className="menu-separator" role="separator" />
        ) : (
          <div
            key={i}
            role={item.checked === undefined ? "menuitem" : "menuitemcheckbox"}
            aria-checked={item.checked}
            aria-disabled={item.disabled || undefined}
            className="menu-item"
            data-active={i === active || undefined}
            onPointerEnter={() => !item.disabled && setActive(i)}
            onPointerLeave={() => setActive(-1)}
            onClick={() => pick(i)}
          >
            <span className="menu-check">{item.checked ? "✓" : ""}</span>
            <span className="menu-label">{item.label}</span>
            {item.shortcut && <kbd className="menu-shortcut">{item.shortcut}</kbd>}
          </div>
        ),
      )}
    </div>
  );
}
