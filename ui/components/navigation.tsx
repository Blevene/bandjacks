"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { cn } from "@/lib/utils";
import {
  Home,
  Search,
  Database,
  Upload,
  Shield,
  GitBranch,
  CheckSquare,
  Settings,
  Layers,
  AlertCircle,
  FileText,
  Target,
} from "lucide-react";

const navigation = [
  { name: "Dashboard", href: "/", icon: Home },
  { name: "Catalog", href: "/catalog", icon: Database },
  { name: "Ingest", href: "/ingest", icon: Upload },
  { name: "Reports", href: "/reports", icon: FileText },
  { name: "Campaigns", href: "/campaigns", icon: Target },
  { name: "Search", href: "/search", icon: Search },
  { name: "Techniques", href: "/techniques", icon: Layers },
  { name: "Detections", href: "/detections/strategies", icon: Shield },
  { name: "Flows", href: "/flows", icon: GitBranch },
  { name: "Review", href: "/review", icon: CheckSquare },
];

export function Navigation() {
  const pathname = usePathname();

  return (
    <nav className="flex flex-col w-64 border-r bg-card">
      <div className="p-4 border-b">
        <h1 className="text-xl font-bold flex items-center gap-2">
          <AlertCircle className="h-6 w-6 text-primary" />
          Bandjacks
        </h1>
        <p className="text-sm text-muted-foreground mt-1">
          Threat Intelligence Platform
        </p>
      </div>
      
      <div className="flex-1 p-4">
        <ul className="space-y-2">
          {navigation.map((item) => {
            const isActive = pathname === item.href || 
                           (item.href !== "/" && pathname.startsWith(item.href));
            
            return (
              <li key={item.name}>
                <Link
                  href={item.href}
                  className={cn(
                    "flex items-center gap-3 px-3 py-2 rounded-md text-sm font-medium transition-colors",
                    isActive
                      ? "bg-primary text-primary-foreground"
                      : "text-muted-foreground hover:bg-accent hover:text-accent-foreground"
                  )}
                >
                  <item.icon className="h-4 w-4" />
                  {item.name}
                </Link>
              </li>
            );
          })}
        </ul>
      </div>
      
      <div className="p-4 border-t">
        <Link
          href="/settings"
          className="flex items-center gap-3 px-3 py-2 rounded-md text-sm font-medium text-muted-foreground hover:bg-accent hover:text-accent-foreground transition-colors"
        >
          <Settings className="h-4 w-4" />
          Settings
        </Link>
      </div>
    </nav>
  );
}