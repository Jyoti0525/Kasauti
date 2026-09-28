import { FolderUp, UploadCloud } from "lucide-react";
import { useRef, useState, type DragEvent } from "react";
import { cx } from "./ui";

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
}: {
  onFiles: (files: Picked[]) => void;
  disabled?: boolean;
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
        "flex flex-col items-center justify-center rounded-xl border-2 border-dashed px-6 py-10 text-center transition-colors",
        over ? "border-gold bg-gold-soft" : "border-line bg-surface",
        disabled && "opacity-60",
      )}
    >
      <UploadCloud className="mb-3 size-10 text-faint" aria-hidden />
      <div className="font-medium">Drop configuration files, folders or a .zip here</div>
      <div className="mt-1 max-w-lg text-sm text-muted">
        Running configurations, and optionally each device's{" "}
        <span className="font-mono">show version</span> /{" "}
        <span className="font-mono">show inventory</span> output for its serial number and hardware.
        The vendor is recognised from the file itself.
      </div>
      <div className="mt-4 flex gap-2">
        <button
          type="button"
          disabled={disabled}
          onClick={() => files.current?.click()}
          className="rounded-lg border border-line bg-surface px-3 py-1.5 text-sm font-medium hover:bg-surface-2"
        >
          Choose files
        </button>
        <button
          type="button"
          disabled={disabled}
          onClick={() => folder.current?.click()}
          className="inline-flex items-center gap-1.5 rounded-lg border border-line bg-surface px-3 py-1.5 text-sm font-medium hover:bg-surface-2"
        >
          <FolderUp className="size-4" aria-hidden /> Choose a folder
        </button>
      </div>
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
