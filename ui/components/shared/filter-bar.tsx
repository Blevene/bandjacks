"use client";

import { Filter, X, RotateCcw } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";

export interface FilterOption {
  label: string;
  value: string;
}

export interface FilterConfig {
  id: string;
  label: string;
  type: "select" | "range" | "checkbox" | "radio";
  options?: FilterOption[];
  value: any;
  onChange: (value: any) => void;
  min?: number;
  max?: number;
  step?: number;
}

interface FilterBarProps {
  filters: FilterConfig[];
  onReset?: () => void;
  showActiveCount?: boolean;
  collapsible?: boolean;
  className?: string;
}

export function FilterBar({
  filters,
  onReset,
  showActiveCount = true,
  collapsible = false,
  className = "",
}: FilterBarProps) {
  const activeFilters = filters.filter(f => {
    if (f.type === "checkbox") return f.value === true;
    if (f.type === "select" || f.type === "radio") return f.value && f.value !== "all";
    if (f.type === "range") return f.value !== f.min;
    return false;
  });

  const renderFilter = (filter: FilterConfig) => {
    switch (filter.type) {
      case "select":
        return (
          <div key={filter.id} className="flex items-center gap-2">
            <label className="text-sm font-medium">{filter.label}:</label>
            <select
              value={filter.value}
              onChange={(e) => filter.onChange(e.target.value)}
              className="px-3 py-1 border rounded-md text-sm"
            >
              {filter.options?.map((option) => (
                <option key={option.value} value={option.value}>
                  {option.label}
                </option>
              ))}
            </select>
          </div>
        );

      case "checkbox":
        return (
          <label key={filter.id} className="flex items-center gap-2 cursor-pointer">
            <input
              type="checkbox"
              checked={filter.value}
              onChange={(e) => filter.onChange(e.target.checked)}
              className="rounded"
            />
            <span className="text-sm">{filter.label}</span>
          </label>
        );

      case "radio":
        return (
          <div key={filter.id} className="flex items-center gap-2">
            <span className="text-sm font-medium">{filter.label}:</span>
            <div className="flex gap-3">
              {filter.options?.map((option) => (
                <label key={option.value} className="flex items-center gap-1 cursor-pointer">
                  <input
                    type="radio"
                    name={filter.id}
                    value={option.value}
                    checked={filter.value === option.value}
                    onChange={(e) => filter.onChange(e.target.value)}
                  />
                  <span className="text-sm">{option.label}</span>
                </label>
              ))}
            </div>
          </div>
        );

      case "range":
        return (
          <div key={filter.id} className="flex items-center gap-2">
            <label className="text-sm font-medium">{filter.label}:</label>
            <input
              type="number"
              min={filter.min}
              max={filter.max}
              step={filter.step}
              value={filter.value}
              onChange={(e) => filter.onChange(Number(e.target.value))}
              className="w-20 px-2 py-1 border rounded-md text-sm"
            />
          </div>
        );

      default:
        return null;
    }
  };

  return (
    <div className={cn("space-y-3", className)}>
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4 flex-wrap">
          {filters.map(renderFilter)}
        </div>
        
        <div className="flex items-center gap-2">
          {showActiveCount && activeFilters.length > 0 && (
            <Badge variant="secondary" className="text-xs">
              {activeFilters.length} active
            </Badge>
          )}
          {onReset && activeFilters.length > 0 && (
            <button
              onClick={onReset}
              className="flex items-center gap-1 px-2 py-1 text-sm text-muted-foreground hover:text-foreground transition-colors"
            >
              <RotateCcw className="h-3 w-3" />
              Reset
            </button>
          )}
        </div>
      </div>
    </div>
  );
}

interface SimpleFilterProps {
  label: string;
  value: string;
  options: FilterOption[];
  onChange: (value: string) => void;
  className?: string;
}

export function SimpleFilter({
  label,
  value,
  options,
  onChange,
  className = "",
}: SimpleFilterProps) {
  return (
    <div className={cn("flex items-center gap-2", className)}>
      <label className="text-sm font-medium">{label}:</label>
      <select
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className="px-3 py-1 border rounded-md text-sm"
      >
        {options.map((option) => (
          <option key={option.value} value={option.value}>
            {option.label}
          </option>
        ))}
      </select>
    </div>
  );
}

interface ActiveFiltersProps {
  filters: Array<{
    id: string;
    label: string;
    onRemove: () => void;
  }>;
  onClearAll?: () => void;
  className?: string;
}

export function ActiveFilters({
  filters,
  onClearAll,
  className = "",
}: ActiveFiltersProps) {
  if (filters.length === 0) return null;

  return (
    <div className={cn("flex items-center gap-2 flex-wrap", className)}>
      <span className="text-sm text-muted-foreground">Active filters:</span>
      {filters.map((filter) => (
        <Badge key={filter.id} variant="secondary" className="gap-1">
          {filter.label}
          <button
            onClick={filter.onRemove}
            className="ml-1 hover:text-foreground"
          >
            <X className="h-3 w-3" />
          </button>
        </Badge>
      ))}
      {onClearAll && (
        <button
          onClick={onClearAll}
          className="text-xs text-muted-foreground hover:text-foreground"
        >
          Clear all
        </button>
      )}
    </div>
  );
}