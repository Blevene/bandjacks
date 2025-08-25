import { LucideIcon } from "lucide-react";
import Link from "next/link";
import { cn } from "@/lib/utils";

interface EmptyStateProps {
  icon: LucideIcon;
  title: string;
  description?: string;
  action?: {
    label: string;
    href?: string;
    onClick?: () => void;
  };
  size?: "sm" | "md" | "lg";
  className?: string;
}

const sizeMap = {
  sm: {
    icon: "h-8 w-8",
    title: "text-base",
    description: "text-xs",
    padding: "py-8",
  },
  md: {
    icon: "h-12 w-12",
    title: "text-lg",
    description: "text-sm",
    padding: "py-12",
  },
  lg: {
    icon: "h-16 w-16",
    title: "text-xl",
    description: "text-base",
    padding: "py-16",
  },
};

export function EmptyState({
  icon: Icon,
  title,
  description,
  action,
  size = "md",
  className = "",
}: EmptyStateProps) {
  const sizes = sizeMap[size];

  const actionButton = action && (
    <button
      onClick={action.onClick}
      className="mt-4 px-4 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90"
    >
      {action.label}
    </button>
  );

  return (
    <div className={cn(`text-center ${sizes.padding}`, className)}>
      <Icon className={cn(sizes.icon, "text-muted-foreground mx-auto mb-4")} />
      <p className={cn(sizes.title, "font-medium")}>{title}</p>
      {description && (
        <p className={cn(sizes.description, "text-muted-foreground mt-2")}>
          {description}
        </p>
      )}
      {action && (
        action.href ? (
          <Link href={action.href}>
            {actionButton}
          </Link>
        ) : (
          actionButton
        )
      )}
    </div>
  );
}

interface EmptyCardProps extends EmptyStateProps {
  bordered?: boolean;
}

export function EmptyCard({
  bordered = true,
  ...props
}: EmptyCardProps) {
  return (
    <div className={cn(
      "rounded-lg",
      bordered && "border bg-card",
      props.className
    )}>
      <EmptyState {...props} />
    </div>
  );
}