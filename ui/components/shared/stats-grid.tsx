import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { LucideIcon, TrendingUp, TrendingDown } from "lucide-react";
import { cn } from "@/lib/utils";

export interface StatCard {
  title: string;
  value: string | number;
  description?: string;
  icon?: LucideIcon;
  iconColor?: string;
  trend?: {
    value: number;
    isPositive?: boolean;
    label?: string;
  };
  badge?: React.ReactNode;
}

interface StatsGridProps {
  stats: StatCard[];
  columns?: 3 | 4 | 5 | 6;
  className?: string;
}

const columnMap = {
  3: "md:grid-cols-3",
  4: "md:grid-cols-4",
  5: "md:grid-cols-5",
  6: "md:grid-cols-6",
};

export function StatsGrid({
  stats,
  columns = 4,
  className = "",
}: StatsGridProps) {
  return (
    <div className={cn(`grid gap-4 ${columnMap[columns]}`, className)}>
      {stats.map((stat, index) => (
        <StatCardComponent key={index} {...stat} />
      ))}
    </div>
  );
}

interface StatCardComponentProps extends StatCard {
  className?: string;
}

export function StatCardComponent({
  title,
  value,
  description,
  icon: Icon,
  iconColor = "text-muted-foreground",
  trend,
  badge,
  className = "",
}: StatCardComponentProps) {
  const getTrendIcon = () => {
    if (!trend) return null;
    
    const isPositive = trend.isPositive ?? trend.value > 0;
    const TrendIcon = isPositive ? TrendingUp : TrendingDown;
    const color = isPositive ? "text-green-500" : "text-red-500";
    
    return (
      <div className={cn("flex items-center gap-1", color)}>
        <TrendIcon className="h-4 w-4" />
        <span className="text-xs font-medium">
          {Math.abs(trend.value)}%
          {trend.label && ` ${trend.label}`}
        </span>
      </div>
    );
  };

  return (
    <Card className={className}>
      <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
        <CardTitle className="text-sm font-medium">{title}</CardTitle>
        {Icon && <Icon className={cn("h-4 w-4", iconColor)} />}
      </CardHeader>
      <CardContent>
        <div className="flex items-baseline justify-between">
          <div>
            <div className="text-2xl font-bold">{value}</div>
            {description && (
              <p className="text-xs text-muted-foreground mt-1">
                {description}
              </p>
            )}
          </div>
          {badge}
        </div>
        {getTrendIcon()}
      </CardContent>
    </Card>
  );
}

interface CompactStatsProps {
  stats: Array<{
    label: string;
    value: string | number;
    icon?: LucideIcon;
  }>;
  separator?: boolean;
  className?: string;
}

export function CompactStats({
  stats,
  separator = true,
  className = "",
}: CompactStatsProps) {
  return (
    <div className={cn("flex items-center gap-4", className)}>
      {stats.map((stat, index) => (
        <div key={index} className="flex items-center gap-2">
          {stat.icon && <stat.icon className="h-4 w-4 text-muted-foreground" />}
          <div>
            <span className="font-semibold">{stat.value}</span>
            <span className="text-sm text-muted-foreground ml-1">{stat.label}</span>
          </div>
          {separator && index < stats.length - 1 && (
            <div className="h-4 w-px bg-border ml-4" />
          )}
        </div>
      ))}
    </div>
  );
}