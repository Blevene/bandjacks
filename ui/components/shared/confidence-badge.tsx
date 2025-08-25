import { Badge } from "@/components/ui/badge";
import { CheckCircle, AlertTriangle, XCircle } from "lucide-react";
import { cn } from "@/lib/utils";

interface ConfidenceBadgeProps {
  confidence: number;
  showIcon?: boolean;
  showPercentage?: boolean;
  size?: "sm" | "md" | "lg";
  className?: string;
}

export function ConfidenceBadge({
  confidence,
  showIcon = true,
  showPercentage = true,
  size = "md",
  className = "",
}: ConfidenceBadgeProps) {
  const getConfidenceColor = () => {
    if (confidence >= 80) return "text-green-500";
    if (confidence >= 50) return "text-yellow-500";
    return "text-red-500";
  };

  const getConfidenceIcon = () => {
    if (!showIcon) return null;
    
    const iconSize = size === "sm" ? "h-3 w-3" : size === "md" ? "h-4 w-4" : "h-5 w-5";
    
    if (confidence >= 80) {
      return <CheckCircle className={cn(iconSize, "text-green-500")} />;
    }
    if (confidence >= 50) {
      return <AlertTriangle className={cn(iconSize, "text-yellow-500")} />;
    }
    return <XCircle className={cn(iconSize, "text-red-500")} />;
  };

  const getTextSize = () => {
    switch (size) {
      case "sm":
        return "text-xs";
      case "lg":
        return "text-base";
      default:
        return "text-sm";
    }
  };

  return (
    <div className={cn("flex items-center gap-1", className)}>
      {getConfidenceIcon()}
      {showPercentage && (
        <span className={cn(getTextSize(), "font-medium", getConfidenceColor())}>
          {Math.round(confidence)}%
        </span>
      )}
    </div>
  );
}

interface ConfidenceLevelBadgeProps {
  confidence: number;
  variant?: "default" | "outline" | "secondary";
  className?: string;
}

export function ConfidenceLevelBadge({
  confidence,
  variant = "outline",
  className = "",
}: ConfidenceLevelBadgeProps) {
  const getLevel = () => {
    if (confidence >= 80) return { label: "High", color: "border-green-500 text-green-500" };
    if (confidence >= 50) return { label: "Medium", color: "border-yellow-500 text-yellow-500" };
    return { label: "Low", color: "border-red-500 text-red-500" };
  };

  const level = getLevel();

  return (
    <Badge 
      variant={variant} 
      className={cn(level.color, className)}
    >
      {level.label} ({Math.round(confidence)}%)
    </Badge>
  );
}