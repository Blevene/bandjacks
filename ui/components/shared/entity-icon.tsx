import {
  Shield,
  Users,
  Package,
  Target,
  GitBranch,
  FileText,
  Activity,
  Server,
  Database,
  AlertTriangle,
  Eye,
} from "lucide-react";
import { LucideIcon } from "lucide-react";

export type EntityType = 
  | "attack-pattern"
  | "intrusion-set"
  | "tool"
  | "malware"
  | "campaign"
  | "report"
  | "attack-flow"
  | "vulnerability"
  | "indicator"
  | "mitigation"
  | "data-source"
  | "data-component";

interface EntityIconProps {
  type: EntityType;
  size?: "sm" | "md" | "lg";
  className?: string;
}

const iconMap: Record<EntityType, { icon: LucideIcon; color: string }> = {
  "attack-pattern": { icon: Shield, color: "text-blue-500" },
  "intrusion-set": { icon: Users, color: "text-red-500" },
  "tool": { icon: Package, color: "text-purple-500" },
  "malware": { icon: Package, color: "text-purple-600" },
  "campaign": { icon: Target, color: "text-orange-500" },
  "report": { icon: FileText, color: "text-gray-500" },
  "attack-flow": { icon: GitBranch, color: "text-green-500" },
  "vulnerability": { icon: AlertTriangle, color: "text-yellow-500" },
  "indicator": { icon: Eye, color: "text-indigo-500" },
  "mitigation": { icon: Shield, color: "text-green-600" },
  "data-source": { icon: Database, color: "text-cyan-500" },
  "data-component": { icon: Server, color: "text-cyan-600" },
};

const sizeMap = {
  sm: "h-4 w-4",
  md: "h-5 w-5",
  lg: "h-6 w-6",
};

export function EntityIcon({ type, size = "md", className = "" }: EntityIconProps) {
  const config = iconMap[type] || { icon: Activity, color: "text-gray-500" };
  const Icon = config.icon;
  const sizeClass = sizeMap[size];
  
  return <Icon className={`${sizeClass} ${config.color} ${className}`} />;
}

export function getEntityTypeName(type: EntityType): string {
  const typeNames: Record<EntityType, string> = {
    "attack-pattern": "Technique",
    "intrusion-set": "Threat Actor",
    "tool": "Tool",
    "malware": "Malware",
    "campaign": "Campaign",
    "report": "Report",
    "attack-flow": "Attack Flow",
    "vulnerability": "Vulnerability",
    "indicator": "Indicator",
    "mitigation": "Mitigation",
    "data-source": "Data Source",
    "data-component": "Data Component",
  };
  
  return typeNames[type] || type;
}