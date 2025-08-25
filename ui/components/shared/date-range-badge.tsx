import { Badge } from "@/components/ui/badge";
import { Calendar, Clock } from "lucide-react";
import { format, differenceInDays, differenceInMonths, differenceInYears, parseISO } from "date-fns";
import { cn } from "@/lib/utils";

interface DateRangeBadgeProps {
  startDate?: string;
  endDate?: string;
  format?: "short" | "long" | "relative";
  showDuration?: boolean;
  showIcon?: boolean;
  variant?: "default" | "secondary" | "outline";
  className?: string;
}

export function DateRangeBadge({
  startDate,
  endDate,
  format: dateFormat = "short",
  showDuration = true,
  showIcon = true,
  variant = "outline",
  className = "",
}: DateRangeBadgeProps) {
  if (!startDate && !endDate) {
    return (
      <Badge variant={variant} className={cn("text-muted-foreground", className)}>
        {showIcon && <Clock className="h-3 w-3 mr-1" />}
        No dates available
      </Badge>
    );
  }

  const formatDate = (dateStr: string) => {
    const date = parseISO(dateStr);
    switch (dateFormat) {
      case "long":
        return format(date, "MMMM d, yyyy");
      case "relative":
        return format(date, "MMM d");
      default:
        return format(date, "MMM yyyy");
    }
  };

  const getDuration = () => {
    if (!startDate || !endDate || !showDuration) return null;
    
    const start = parseISO(startDate);
    const end = parseISO(endDate);
    
    const days = differenceInDays(end, start);
    const months = differenceInMonths(end, start);
    const years = differenceInYears(end, start);
    
    if (years > 0) {
      return `${years} year${years > 1 ? 's' : ''}`;
    } else if (months > 0) {
      return `${months} month${months > 1 ? 's' : ''}`;
    } else {
      return `${days} day${days !== 1 ? 's' : ''}`;
    }
  };

  const duration = getDuration();
  
  if (startDate && endDate) {
    return (
      <Badge variant={variant} className={className}>
        {showIcon && <Calendar className="h-3 w-3 mr-1" />}
        {formatDate(startDate)} - {formatDate(endDate)}
        {duration && (
          <span className="ml-1 text-xs opacity-70">
            ({duration})
          </span>
        )}
      </Badge>
    );
  }

  // Only one date available
  const singleDate = startDate || endDate;
  const label = startDate ? "Since" : "Until";
  
  return (
    <Badge variant={variant} className={className}>
      {showIcon && <Calendar className="h-3 w-3 mr-1" />}
      {label} {formatDate(singleDate!)}
    </Badge>
  );
}

interface TimelineBadgeProps {
  firstSeen?: string;
  lastSeen?: string;
  className?: string;
}

export function TimelineBadge({
  firstSeen,
  lastSeen,
  className = "",
}: TimelineBadgeProps) {
  return (
    <DateRangeBadge
      startDate={firstSeen}
      endDate={lastSeen}
      format="short"
      showDuration={true}
      showIcon={true}
      variant="outline"
      className={className}
    />
  );
}

interface DurationDisplayProps {
  startDate?: string;
  endDate?: string;
  prefix?: string;
  className?: string;
}

export function DurationDisplay({
  startDate,
  endDate,
  prefix = "Duration:",
  className = "",
}: DurationDisplayProps) {
  if (!startDate || !endDate) {
    return <span className={cn("text-sm text-muted-foreground", className)}>Unknown duration</span>;
  }

  const start = parseISO(startDate);
  const end = parseISO(endDate);
  
  const days = differenceInDays(end, start);
  const months = differenceInMonths(end, start);
  const years = differenceInYears(end, start);
  
  let duration = "";
  if (years > 0) {
    const remainingMonths = months - (years * 12);
    duration = `${years}y${remainingMonths > 0 ? ` ${remainingMonths}m` : ''}`;
  } else if (months > 0) {
    const remainingDays = days - (months * 30); // Approximate
    duration = `${months}m${remainingDays > 0 ? ` ${remainingDays}d` : ''}`;
  } else {
    duration = `${days}d`;
  }

  return (
    <span className={cn("text-sm", className)}>
      {prefix && <span className="text-muted-foreground mr-1">{prefix}</span>}
      <span className="font-medium">{duration}</span>
    </span>
  );
}