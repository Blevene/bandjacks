"use client";

import { useState, useEffect, useRef } from "react";
import { Search, X, Loader2 } from "lucide-react";
import { cn } from "@/lib/utils";

interface SearchBarProps {
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
  onClear?: () => void;
  onSearch?: (value: string) => void;
  showIcon?: boolean;
  loading?: boolean;
  debounceMs?: number;
  autoFocus?: boolean;
  className?: string;
}

export function SearchBar({
  value,
  onChange,
  placeholder = "Search...",
  onClear,
  onSearch,
  showIcon = true,
  loading = false,
  debounceMs = 0,
  autoFocus = false,
  className = "",
}: SearchBarProps) {
  const [internalValue, setInternalValue] = useState(value);
  const debounceTimer = useRef<NodeJS.Timeout | undefined>(undefined);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    setInternalValue(value);
  }, [value]);

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const newValue = e.target.value;
    setInternalValue(newValue);

    if (debounceMs > 0) {
      clearTimeout(debounceTimer.current);
      debounceTimer.current = setTimeout(() => {
        onChange(newValue);
      }, debounceMs);
    } else {
      onChange(newValue);
    }
  };

  const handleClear = () => {
    setInternalValue("");
    onChange("");
    onClear?.();
    inputRef.current?.focus();
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Enter" && onSearch) {
      e.preventDefault();
      onSearch(internalValue);
    }
    if (e.key === "Escape") {
      handleClear();
    }
  };

  return (
    <div className={cn("relative", className)}>
      {showIcon && (
        <div className="absolute left-3 top-1/2 transform -translate-y-1/2">
          {loading ? (
            <Loader2 className="h-4 w-4 text-muted-foreground animate-spin" />
          ) : (
            <Search className="h-4 w-4 text-muted-foreground" />
          )}
        </div>
      )}
      <input
        ref={inputRef}
        type="text"
        value={internalValue}
        onChange={handleChange}
        onKeyDown={handleKeyDown}
        placeholder={placeholder}
        autoFocus={autoFocus}
        className={cn(
          "w-full px-3 py-1.5 border rounded-md bg-background",
          showIcon && "pl-9",
          internalValue && "pr-8",
          className
        )}
      />
      {internalValue && (
        <button
          onClick={handleClear}
          className="absolute right-2 top-1/2 transform -translate-y-1/2 p-1 hover:bg-muted rounded"
          type="button"
        >
          <X className="h-3 w-3 text-muted-foreground" />
        </button>
      )}
    </div>
  );
}

interface SearchInputProps extends Omit<SearchBarProps, 'value' | 'onChange'> {
  onSubmit: (value: string) => void;
  defaultValue?: string;
}

export function SearchInput({
  onSubmit,
  defaultValue = "",
  placeholder = "Search and press Enter...",
  ...props
}: SearchInputProps) {
  const [value, setValue] = useState(defaultValue);

  const handleSearch = (searchValue: string) => {
    if (searchValue.trim()) {
      onSubmit(searchValue);
    }
  };

  return (
    <SearchBar
      value={value}
      onChange={setValue}
      onSearch={handleSearch}
      placeholder={placeholder}
      {...props}
    />
  );
}

interface SearchWithFiltersProps {
  searchValue: string;
  onSearchChange: (value: string) => void;
  filters?: React.ReactNode;
  placeholder?: string;
  className?: string;
}

export function SearchWithFilters({
  searchValue,
  onSearchChange,
  filters,
  placeholder = "Search...",
  className = "",
}: SearchWithFiltersProps) {
  return (
    <div className={cn("flex items-center gap-4", className)}>
      <SearchBar
        value={searchValue}
        onChange={onSearchChange}
        placeholder={placeholder}
        className="flex-1 max-w-sm"
        debounceMs={300}
      />
      {filters && (
        <div className="flex items-center gap-2">
          {filters}
        </div>
      )}
    </div>
  );
}