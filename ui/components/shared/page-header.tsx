import { ChevronRight } from "lucide-react";
import { LucideIcon } from "lucide-react";
import Link from "next/link";
import { cn } from "@/lib/utils";

export interface BreadcrumbItem {
  label: string;
  href?: string;
}

interface PageHeaderProps {
  title: string;
  description?: string;
  icon?: LucideIcon;
  iconColor?: string;
  actions?: React.ReactNode;
  breadcrumbs?: BreadcrumbItem[];
  className?: string;
}

export function PageHeader({
  title,
  description,
  icon: Icon,
  iconColor = "text-primary",
  actions,
  breadcrumbs,
  className = "",
}: PageHeaderProps) {
  return (
    <div className={cn("space-y-2", className)}>
      {breadcrumbs && breadcrumbs.length > 0 && (
        <Breadcrumbs items={breadcrumbs} />
      )}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight flex items-center gap-3">
            {Icon && <Icon className={cn("h-8 w-8", iconColor)} />}
            {title}
          </h1>
          {description && (
            <p className="text-muted-foreground mt-2">{description}</p>
          )}
        </div>
        {actions && (
          <div className="flex items-center gap-2">
            {actions}
          </div>
        )}
      </div>
    </div>
  );
}

interface BreadcrumbsProps {
  items: BreadcrumbItem[];
  separator?: LucideIcon;
  className?: string;
}

export function Breadcrumbs({
  items,
  separator: Separator = ChevronRight,
  className = "",
}: BreadcrumbsProps) {
  return (
    <nav className={cn("flex items-center gap-2 text-sm text-muted-foreground", className)}>
      {items.map((item, index) => (
        <div key={index} className="flex items-center gap-2">
          {item.href ? (
            <Link href={item.href} className="hover:text-foreground transition-colors">
              {item.label}
            </Link>
          ) : (
            <span className="text-foreground">{item.label}</span>
          )}
          {index < items.length - 1 && (
            <Separator className="h-4 w-4" />
          )}
        </div>
      ))}
    </nav>
  );
}

interface SimplePageHeaderProps {
  title: string;
  description?: string;
  action?: {
    label: string;
    icon?: LucideIcon;
    onClick?: () => void;
    href?: string;
  };
  className?: string;
}

export function SimplePageHeader({
  title,
  description,
  action,
  className = "",
}: SimplePageHeaderProps) {
  const actionButton = action && (
    <button
      onClick={action.onClick}
      className="flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90"
    >
      {action.icon && <action.icon className="h-4 w-4" />}
      {action.label}
    </button>
  );

  return (
    <div className={cn("flex items-center justify-between", className)}>
      <div>
        <h1 className="text-3xl font-bold tracking-tight">{title}</h1>
        {description && (
          <p className="text-muted-foreground">{description}</p>
        )}
      </div>
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