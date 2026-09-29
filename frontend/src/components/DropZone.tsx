import { FilePlus2, FolderUp, UploadCloud } from "lucide-react";
import { useRef, useState, type DragEvent } from "react";
import { Button, cx } from "./ui";

export interface Picked {
  file: File;
  /** Its path in the dropped folder, or its name. */
  name: string;
}

const MAX_ENTRIES = 5000;

/** Files dropped or chosen: single files, several, a .zip, or whole folders (read recursively,
 * each file named by its path in the folder, as the server expects). */
export function DropZone({
  onFiles,
  disabled,
  vendors,
  hint,
}: {
  onFiles: (files: Picked[]) => void;
  disabled?: boolean;
  /** The installed vendor packs, by name. */
  vendors?: string[];
  /** In place of the default explanation; a short one keeps the zone compact. */
  hint?: string;
}) {
  const [over, setOver] = useState(false);
  const files = useRef<HTMLInputElement>(null);
  const folder = useRef<HTMLInputElement>(null);

  const onDrop = async (e: DragEvent) => {
    e.preventDefault();
    setOver(false);
    if (disabled) return;
    const entries = [...e.dataTransfer.items]
      .map((item) => item.webkitGetAsEntry?.())
      .filter((x): x is FileSystemEntry => Boolean(x));
    if (entries.length) onFiles(await readEntries(entries));
    else onFiles([...e.dataTransfer.files].map((file) => ({ file, name: file.name })));
  };

  const fromInput = (list: FileList | null) => {
    if (!list) return;
    onFiles([...list].map((file) => ({ file, name: file.webkitRelativePath || file.name })));
  };

  return (
    <div
      onDragOver={(e) => {
        e.preventDefault();
        if (!disabled) setOver(true);
      }}
      onDragLeave={() => setOver(false)}
      onDrop={onDrop}
      className={cx(
        "flex flex-col items-center justify-center rounded-xl border-2 border-dashed px-6 text-center transition-colors",
        hint ? "py-6" : "py-12",
        over ? "border-brass bg-brass-soft" : "border-line-strong bg-surface",
        disabled && "opacity-60",
      )}
    >
      <div
        className={cx(
          "flex items-center justify-center rounded-2xl transition-colors",
          hint ? "mb-2 size-10" : "mb-4 size-14",
          over ? "bg-brass text-on-brass" : "bg-brass-soft text-brass-ink",
        )}
      >
        <UploadCloud className="size-7" aria-hidden />
      </div>
      <div className="text-[16px] font-semibold">
        {over ? "Drop to add them" : "Drop configuration files, folders or a .zip"}
      </div>
      <div className="mt-1.5 max-w-lg text-[13.5px] leading-relaxed text-muted">
        {hint ?? (
          <>
            Running configurations, and optionally each device's{" "}
            <span className="font-mono text-[12.5px] text-text">show version</span> or{" "}
            <span className="font-mono text-[12.5px] text-text">show inventory</span> output for its
            serial number and hardware. The vendor is recognised from each file itself.
          </>
        )}
      </div>
      <div className={cx("flex gap-2", hint ? "mt-3" : "mt-5")}>
        <Button disabled={disabled} onClick={() => files.current?.click()}>
          <FilePlus2 /> Choose files
        </Button>
        <Button disabled={disabled} onClick={() => folder.current?.click()}>
          <FolderUp /> Choose a folder
        </Button>
      </div>
      {vendors && vendors.length > 0 && (
        <div className="mt-4 max-w-xl text-[12px] leading-relaxed text-faint">
          Recognises {vendors.join(" · ")}
        </div>
      )}
      <input
        ref={files}
        type="file"
        multiple
        hidden
        onChange={(e) => {
          fromInput(e.target.files);
          e.target.value = "";
        }}
      />
      <input
        ref={folder}
        type="file"
        hidden
        // @ts-expect-error: not in React's types, supported by every current browser
        webkitdirectory=""
        onChange={(e) => {
          fromInput(e.target.files);
          e.target.value = "";
        }}
      />
    </div>
  );
}

async function readEntries(roots: FileSystemEntry[]): Promise<Picked[]> {
  const out: Picked[] = [];
  const queue = [...roots];
  for (let entry = queue.shift(); entry && out.length < MAX_ENTRIES; entry = queue.shift()) {
    if (entry.isFile) {
      const file = await new Promise<File>((resolve, reject) =>
        (entry as FileSystemFileEntry).file(resolve, reject),
      );
      out.push({ file, name: entry.fullPath.replace(/^\/+/, "") || file.name });
    } else if (entry.isDirectory) {
      const reader = (entry as FileSystemDirectoryEntry).createReader();
      // readEntries answers in batches until it returns none.
      for (;;) {
        const batch = await new Promise<FileSystemEntry[]>((resolve, reject) =>
          reader.readEntries(resolve, reject),
        );
        if (!batch.length) break;
        queue.push(...batch);
      }
    }
  }
  return out;
}
