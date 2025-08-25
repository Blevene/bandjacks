import { Badge } from "@/components/ui/badge";
import { LucideIcon } from "lucide-react";
import { cn } from "@/lib/utils";

export interface Tab {
  id: string;
  label: string;
  icon?: LucideIcon;
  badge?: string | number;
  disabled?: boolean;
}

interface TabsNavigationProps {
  tabs: Tab[];
  activeTab: string;
  onChange: (tabId: string) => void;
  variant?: "default" | "pills" | "underline";
  size?: "sm" | "md" | "lg";
  className?: string;
}

const sizeMap = {
  sm: "text-xs px-3 py-1.5",
  md: "text-sm px-4 py-2",
  lg: "text-base px-5 py-2.5",
};

export function TabsNavigation({
  tabs,
  activeTab,
  onChange,
  variant = "underline",
  size = "md",
  className = "",
}: TabsNavigationProps) {
  const baseClass = "flex items-center gap-2 font-medium transition-colors";
  const sizeClass = sizeMap[size];

  const getTabClass = (tab: Tab) => {
    const isActive = activeTab === tab.id;
    const isDisabled = tab.disabled;

    if (variant === "pills") {
      return cn(
        baseClass,
        sizeClass,
        "rounded-md",
        isActive
          ? "bg-primary text-primary-foreground"
          : "text-muted-foreground hover:text-foreground hover:bg-muted",
        isDisabled && "opacity-50 cursor-not-allowed"
      );
    }

    if (variant === "underline") {
      return cn(
        baseClass,
        sizeClass,
        isActive
          ? "border-b-2 border-primary text-foreground"
          : "text-muted-foreground hover:text-foreground",
        isDisabled && "opacity-50 cursor-not-allowed"
      );
    }

    // Default variant
    return cn(
      baseClass,
      sizeClass,
      "rounded-md",
      isActive
        ? "bg-muted text-foreground"
        : "text-muted-foreground hover:text-foreground hover:bg-muted/50",
      isDisabled && "opacity-50 cursor-not-allowed"
    );
  };

  const containerClass = variant === "underline" 
    ? "flex gap-2 border-b" 
    : "flex gap-2";

  return (
    <div className={cn(containerClass, className)}>
      {tabs.map((tab) => (
        <button
          key={tab.id}
          onClick={() => !tab.disabled && onChange(tab.id)}
          disabled={tab.disabled}
          className={getTabClass(tab)}
        >
          {tab.icon && <tab.icon className="h-4 w-4" />}
          {tab.label}
          {tab.badge !== undefined && (
            <Badge 
              variant="secondary" 
              className={cn(
                "ml-1",
                size === "sm" && "text-xs px-1.5 py-0",
                size === "md" && "text-xs px-2 py-0.5",
                size === "lg" && "text-sm px-2.5 py-0.5"
              )}
            >
              {tab.badge}
            </Badge>
          )}
        </button>
      ))}
    </div>
  );
}

interface TabPanelProps {
  tabId: string;
  activeTab: string;
  children: React.ReactNode;
  className?: string;
}

export function TabPanel({
  tabId,
  activeTab,
  children,
  className = "",
}: TabPanelProps) {
  if (tabId !== activeTab) return null;

  return (
    <div className={cn("animate-in fade-in-0 duration-200", className)}>
      {children}
    </div>
  );
}

interface TabsContainerProps {
  tabs: Tab[];
  activeTab: string;
  onTabChange: (tabId: string) => void;
  children: React.ReactNode;
  variant?: "default" | "pills" | "underline";
  className?: string;
  contentClassName?: string;
}

export function TabsContainer({
  tabs,
  activeTab,
  onTabChange,
  children,
  variant = "underline",
  className = "",
  contentClassName = "",
}: TabsContainerProps) {
  return (
    <div className={cn("space-y-4", className)}>
      <TabsNavigation
        tabs={tabs}
        activeTab={activeTab}
        onChange={onTabChange}
        variant={variant}
      />
      <div className={contentClassName}>
        {children}
      </div>
    </div>
  );
}