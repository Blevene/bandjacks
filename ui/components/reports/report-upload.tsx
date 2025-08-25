"use client";

import { useState, useRef, DragEvent } from "react";
import { Card, CardContent } from "@/components/ui/card";
import { 
  Upload, 
  FileText, 
  X, 
  FileWarning,
  Loader2
} from "lucide-react";
import { cn } from "@/lib/utils";

interface ReportUploadProps {
  onFileSelect: (file: File) => void;
  onTextChange?: (text: string) => void;
  acceptedFormats?: string[];
  disabled?: boolean;
  showTextInput?: boolean;
  value?: {
    file?: File | null;
    text?: string;
  };
  className?: string;
}

export function ReportUpload({
  onFileSelect,
  onTextChange,
  acceptedFormats = [".pdf", ".txt", ".md", ".markdown"],
  disabled = false,
  showTextInput = true,
  value,
  className = "",
}: ReportUploadProps) {
  const [isDragging, setIsDragging] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const validateFile = (file: File): boolean => {
    setError(null);
    
    const fileExt = file.name.substring(file.name.lastIndexOf(".")).toLowerCase();
    if (!acceptedFormats.includes(fileExt)) {
      setError(`Invalid file type. Accepted formats: ${acceptedFormats.join(", ")}`);
      return false;
    }

    // Check file size (max 10MB)
    const maxSize = 10 * 1024 * 1024; // 10MB
    if (file.size > maxSize) {
      setError("File size must be less than 10MB");
      return false;
    }

    return true;
  };

  const handleFileSelect = (file: File) => {
    if (validateFile(file)) {
      onFileSelect(file);
      if (onTextChange) {
        onTextChange(""); // Clear text when file is selected
      }
    }
  };

  const handleDragEnter = (e: DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    e.stopPropagation();
    if (!disabled) {
      setIsDragging(true);
    }
  };

  const handleDragLeave = (e: DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);
  };

  const handleDragOver = (e: DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    e.stopPropagation();
  };

  const handleDrop = (e: DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);

    if (disabled) return;

    const files = Array.from(e.dataTransfer.files);
    if (files.length > 0) {
      handleFileSelect(files[0]);
    }
  };

  const handleFileInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const files = e.target.files;
    if (files && files.length > 0) {
      handleFileSelect(files[0]);
    }
  };

  const handleClearFile = () => {
    if (fileInputRef.current) {
      fileInputRef.current.value = "";
    }
    onFileSelect(null as any); // Clear the file
    setError(null);
  };

  const handleTextChange = (e: React.ChangeEvent<HTMLTextAreaElement>) => {
    if (onTextChange) {
      onTextChange(e.target.value);
      if (e.target.value && value?.file) {
        // Clear file when text is entered
        handleClearFile();
      }
    }
  };

  return (
    <div className={cn("space-y-4", className)}>
      {/* File Upload Zone */}
      <div
        className={cn(
          "border-2 border-dashed rounded-lg p-6 text-center transition-colors",
          isDragging && "border-primary bg-primary/5",
          !disabled && "hover:border-primary/50 cursor-pointer",
          disabled && "opacity-50 cursor-not-allowed",
          error && "border-red-500"
        )}
        onDragEnter={handleDragEnter}
        onDragLeave={handleDragLeave}
        onDragOver={handleDragOver}
        onDrop={handleDrop}
        onClick={() => !disabled && fileInputRef.current?.click()}
      >
        <input
          ref={fileInputRef}
          type="file"
          accept={acceptedFormats.join(",")}
          onChange={handleFileInputChange}
          disabled={disabled}
          className="hidden"
        />

        {value?.file ? (
          <div className="flex flex-col items-center gap-2">
            <FileText className="h-8 w-8 text-primary" />
            <div className="flex items-center gap-2">
              <span className="text-sm font-medium">{value.file.name}</span>
              <button
                onClick={(e) => {
                  e.stopPropagation();
                  handleClearFile();
                }}
                className="p-1 hover:bg-muted rounded"
                disabled={disabled}
              >
                <X className="h-4 w-4" />
              </button>
            </div>
            <span className="text-xs text-muted-foreground">
              {(value.file.size / 1024).toFixed(1)} KB
            </span>
          </div>
        ) : (
          <div className="flex flex-col items-center gap-2">
            {disabled ? (
              <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
            ) : (
              <Upload className="h-8 w-8 text-muted-foreground" />
            )}
            <span className="text-sm font-medium">
              {disabled ? "Processing..." : "Click to upload or drag and drop"}
            </span>
            <span className="text-xs text-muted-foreground">
              {acceptedFormats.map(f => f.toUpperCase().replace(".", "")).join(", ")} files up to 10MB
            </span>
          </div>
        )}

        {error && (
          <div className="mt-2 flex items-center justify-center gap-2 text-red-500">
            <FileWarning className="h-4 w-4" />
            <span className="text-sm">{error}</span>
          </div>
        )}
      </div>

      {/* Text Input Section */}
      {showTextInput && (
        <>
          <div className="relative">
            <div className="absolute inset-0 flex items-center">
              <span className="w-full border-t" />
            </div>
            <div className="relative flex justify-center text-xs uppercase">
              <span className="bg-background px-2 text-muted-foreground">
                Or paste text
              </span>
            </div>
          </div>

          <textarea
            value={value?.text || ""}
            onChange={handleTextChange}
            placeholder="Paste threat intelligence report text here..."
            disabled={disabled}
            className={cn(
              "w-full h-48 p-3 text-sm border rounded-md bg-muted/50 font-mono",
              disabled && "opacity-50 cursor-not-allowed"
            )}
          />
        </>
      )}
    </div>
  );
}

interface UploadProgressProps {
  progress: number;
  message?: string;
  className?: string;
}

export function UploadProgress({
  progress,
  message = "Uploading...",
  className = "",
}: UploadProgressProps) {
  return (
    <Card className={className}>
      <CardContent className="pt-6">
        <div className="space-y-2">
          <div className="flex items-center justify-between text-sm">
            <span className="text-muted-foreground">{message}</span>
            <span className="font-medium">{Math.round(progress)}%</span>
          </div>
          <div className="w-full bg-muted rounded-full h-2 overflow-hidden">
            <div
              className="h-full bg-primary transition-all duration-300"
              style={{ width: `${progress}%` }}
            />
          </div>
        </div>
      </CardContent>
    </Card>
  );
}