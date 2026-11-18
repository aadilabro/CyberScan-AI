import { FileUp, X } from 'lucide-react';
import { ChangeEvent, useRef, useState } from 'react';

interface FileUploadProps {
  onFileSelected: (file: File | null) => void;
}

export default function FileUpload({ onFileSelected }: FileUploadProps) {
  const inputRef = useRef<HTMLInputElement | null>(null);
  const [selectedName, setSelectedName] = useState<string | null>(null);

  const handleChange = (event: ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0] ?? null;
    setSelectedName(file?.name ?? null);
    onFileSelected(file);
  };

  const clearSelection = () => {
    setSelectedName(null);
    onFileSelected(null);
    if (inputRef.current) {
      inputRef.current.value = '';
    }
  };

  return (
    <div className="space-y-3">
      <div
        onClick={() => inputRef.current?.click()}
        className="flex cursor-pointer items-center justify-center gap-3 rounded-2xl border border-dashed border-slate-700 bg-slate-950/60 px-4 py-8 text-center transition hover:border-emerald-500/60 hover:bg-slate-900"
      >
        <FileUp className="h-5 w-5 text-emerald-400" />
        <span className="text-sm font-medium text-slate-200">Upload suspicious file</span>
      </div>

      <input
        ref={inputRef}
        type="file"
        className="hidden"
        onChange={handleChange}
        accept=".exe,.dll,.pdf,.zip,.js,.apk,.doc,.docx,.rar,.7z,.png,.jpg,.jpeg"
      />

      {selectedName ? (
        <div className="flex items-center justify-between rounded-xl border border-slate-700 bg-slate-900/80 px-3 py-2 text-sm text-slate-300">
          <span className="max-w-[220px] truncate">{selectedName}</span>
          <button
            type="button"
            onClick={clearSelection}
            className="ml-2 rounded-md border border-slate-600 p-1 text-slate-300 transition hover:border-rose-400 hover:text-rose-300"
            aria-label="Remove selected file"
          >
            <X className="h-4 w-4" />
          </button>
        </div>
      ) : null}
    </div>
  );
}
