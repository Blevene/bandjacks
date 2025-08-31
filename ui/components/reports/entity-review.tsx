"use client";

import { useState } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Label } from "@/components/ui/label";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Bug,
  Shield,
  Users,
  Target,
  Wrench,
  CheckCircle,
  XCircle,
  Edit,
  AlertTriangle,
  Info,
} from "lucide-react";
import type { ExtractedEntities, Entity } from "@/lib/report-types";

interface EntityReviewProps {
  entities?: ExtractedEntities;
  onReviewComplete?: (reviewedEntities: ExtractedEntities) => void;
  readOnly?: boolean;
}

export function EntityReview({ entities, onReviewComplete, readOnly = false }: EntityReviewProps) {
  const [reviewedEntities, setReviewedEntities] = useState<ExtractedEntities>(entities || {});
  const [editingEntity, setEditingEntity] = useState<{ type: string; index: number; entity: Entity } | null>(null);
  const [activeTab, setActiveTab] = useState<string>("malware");

  if (!entities) {
    return (
      <Alert>
        <Info className="h-4 w-4" />
        <AlertDescription>
          No entities were extracted from this report.
        </AlertDescription>
      </Alert>
    );
  }

  const getEntityIcon = (type: string) => {
    switch (type) {
      case "malware":
        return <Bug className="h-4 w-4" />;
      case "software":
      case "tool":
        return <Wrench className="h-4 w-4" />;
      case "threat_actors":
      case "threat_actor":
        return <Users className="h-4 w-4" />;
      case "campaigns":
      case "campaign":
        return <Target className="h-4 w-4" />;
      default:
        return <Shield className="h-4 w-4" />;
    }
  };

  const getStatusBadge = (status?: string) => {
    switch (status) {
      case "approved":
        return <Badge variant="default" className="bg-green-500">Approved</Badge>;
      case "rejected":
        return <Badge variant="destructive">Rejected</Badge>;
      case "edited":
        return <Badge variant="secondary">Edited</Badge>;
      default:
        return <Badge variant="outline">Pending Review</Badge>;
    }
  };

  const handleApprove = (type: string, index: number) => {
    const updatedEntities = { ...reviewedEntities };
    const entityList = updatedEntities[type as keyof ExtractedEntities] as Entity[];
    if (entityList && entityList[index]) {
      entityList[index].review_status = "approved";
      entityList[index].verified = true;
      setReviewedEntities(updatedEntities);
    }
  };

  const handleReject = (type: string, index: number) => {
    const updatedEntities = { ...reviewedEntities };
    const entityList = updatedEntities[type as keyof ExtractedEntities] as Entity[];
    if (entityList && entityList[index]) {
      entityList[index].review_status = "rejected";
      entityList[index].verified = false;
      setReviewedEntities(updatedEntities);
    }
  };

  const handleEdit = (type: string, index: number) => {
    const entityList = reviewedEntities[type as keyof ExtractedEntities] as Entity[];
    if (entityList && entityList[index]) {
      setEditingEntity({ type, index, entity: { ...entityList[index] } });
    }
  };

  const handleSaveEdit = () => {
    if (!editingEntity) return;

    const updatedEntities = { ...reviewedEntities };
    const entityList = updatedEntities[editingEntity.type as keyof ExtractedEntities] as Entity[];
    if (entityList) {
      entityList[editingEntity.index] = {
        ...editingEntity.entity,
        review_status: "edited",
        verified: true,
      };
      setReviewedEntities(updatedEntities);
    }
    setEditingEntity(null);
  };

  const renderEntityCard = (entity: Entity, type: string, index: number) => (
    <Card key={`${type}-${index}`} className="mb-3">
      <CardHeader className="pb-3">
        <div className="flex items-start justify-between">
          <div className="flex items-center gap-2">
            {getEntityIcon(type)}
            <CardTitle className="text-lg">{entity.name}</CardTitle>
            {entity.aliases && entity.aliases.length > 0 && (
              <span className="text-sm text-muted-foreground">
                (aka: {entity.aliases.join(", ")})
              </span>
            )}
          </div>
          {getStatusBadge(entity.review_status)}
        </div>
      </CardHeader>
      <CardContent>
        {entity.description && (
          <p className="text-sm text-muted-foreground mb-3">{entity.description}</p>
        )}
        
        {entity.evidence && entity.evidence.length > 0 && (
          <div className="mb-3">
            <Label className="text-xs font-semibold">Evidence:</Label>
            <div className="mt-1 space-y-1">
              {entity.evidence.slice(0, 2).map((ev, i) => (
                <p key={i} className="text-xs text-muted-foreground italic">
                  "{ev.length > 100 ? ev.substring(0, 100) + '...' : ev}"
                </p>
              ))}
            </div>
          </div>
        )}

        {entity.line_refs && entity.line_refs.length > 0 && (
          <div className="mb-3">
            <Label className="text-xs font-semibold">Line References:</Label>
            <p className="text-xs text-muted-foreground">
              Lines: {entity.line_refs.slice(0, 5).join(", ")}
              {entity.line_refs.length > 5 && ` ... (+${entity.line_refs.length - 5} more)`}
            </p>
          </div>
        )}

        {!readOnly && (
          <div className="flex gap-2 mt-4">
            <Button
              size="sm"
              variant={entity.review_status === "approved" ? "default" : "outline"}
              onClick={() => handleApprove(type, index)}
              className="flex-1"
            >
              <CheckCircle className="h-3 w-3 mr-1" />
              Approve
            </Button>
            <Button
              size="sm"
              variant={entity.review_status === "rejected" ? "destructive" : "outline"}
              onClick={() => handleReject(type, index)}
              className="flex-1"
            >
              <XCircle className="h-3 w-3 mr-1" />
              Reject
            </Button>
            <Button
              size="sm"
              variant="outline"
              onClick={() => handleEdit(type, index)}
            >
              <Edit className="h-3 w-3 mr-1" />
              Edit
            </Button>
          </div>
        )}

        {entity.review_notes && (
          <Alert className="mt-3">
            <AlertTriangle className="h-3 w-3" />
            <AlertDescription className="text-xs">
              Review Note: {entity.review_notes}
            </AlertDescription>
          </Alert>
        )}
      </CardContent>
    </Card>
  );

  const entityTypes = [
    { key: "malware", label: "Malware", icon: Bug },
    { key: "software", label: "Software/Tools", icon: Wrench },
    { key: "threat_actors", label: "Threat Actors", icon: Users },
    { key: "campaigns", label: "Campaigns", icon: Target },
  ];

  const getEntityCount = (type: string) => {
    const entityList = reviewedEntities[type as keyof ExtractedEntities];
    return Array.isArray(entityList) ? entityList.length : 0;
  };

  return (
    <>
      <div className="space-y-4">
        {/* Summary Stats */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          {entityTypes.map(({ key, label, icon: Icon }) => {
            const count = getEntityCount(key);
            const approved = (reviewedEntities[key as keyof ExtractedEntities] as Entity[] || [])
              .filter(e => e.review_status === "approved").length;
            
            return (
              <Card key={key}>
                <CardHeader className="pb-2">
                  <div className="flex items-center justify-between">
                    <CardTitle className="text-sm font-medium">{label}</CardTitle>
                    <Icon className="h-4 w-4 text-muted-foreground" />
                  </div>
                </CardHeader>
                <CardContent>
                  <div className="text-2xl font-bold">{count}</div>
                  {!readOnly && count > 0 && (
                    <p className="text-xs text-muted-foreground">
                      {approved} approved
                    </p>
                  )}
                </CardContent>
              </Card>
            );
          })}
        </div>

        {/* Entity Tabs */}
        <Tabs value={activeTab} onValueChange={setActiveTab}>
          <TabsList className="grid w-full grid-cols-4">
            {entityTypes.map(({ key, label }) => (
              <TabsTrigger key={key} value={key} disabled={getEntityCount(key) === 0}>
                {label} ({getEntityCount(key)})
              </TabsTrigger>
            ))}
          </TabsList>

          {entityTypes.map(({ key }) => (
            <TabsContent key={key} value={key} className="space-y-3">
              {getEntityCount(key) === 0 ? (
                <Alert>
                  <Info className="h-4 w-4" />
                  <AlertDescription>
                    No {key.replace('_', ' ')} entities found in this report.
                  </AlertDescription>
                </Alert>
              ) : (
                <>
                  {(reviewedEntities[key as keyof ExtractedEntities] as Entity[] || []).map((entity, index) =>
                    renderEntityCard(entity, key, index)
                  )}
                </>
              )}
            </TabsContent>
          ))}
        </Tabs>

        {/* Submit Review Button */}
        {!readOnly && onReviewComplete && (
          <div className="flex justify-end gap-2 pt-4">
            <Button
              variant="outline"
              onClick={() => setReviewedEntities(entities || {})}
            >
              Reset
            </Button>
            <Button
              onClick={() => onReviewComplete(reviewedEntities)}
              className="bg-blue-600 hover:bg-blue-700"
            >
              Submit Entity Review
            </Button>
          </div>
        )}
      </div>

      {/* Edit Dialog */}
      <Dialog open={!!editingEntity} onOpenChange={() => setEditingEntity(null)}>
        <DialogContent className="sm:max-w-[500px]">
          <DialogHeader>
            <DialogTitle>Edit Entity</DialogTitle>
            <DialogDescription>
              Make changes to the extracted entity information.
            </DialogDescription>
          </DialogHeader>
          {editingEntity && (
            <div className="space-y-4">
              <div>
                <Label htmlFor="name">Entity Name</Label>
                <Input
                  id="name"
                  value={editingEntity.entity.name}
                  onChange={(e) =>
                    setEditingEntity({
                      ...editingEntity,
                      entity: { ...editingEntity.entity, name: e.target.value },
                    })
                  }
                />
              </div>
              <div>
                <Label htmlFor="type">Entity Type</Label>
                <Select
                  value={editingEntity.entity.type}
                  onValueChange={(value) =>
                    setEditingEntity({
                      ...editingEntity,
                      entity: { ...editingEntity.entity, type: value as Entity["type"] },
                    })
                  }
                >
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="malware">Malware</SelectItem>
                    <SelectItem value="tool">Tool/Software</SelectItem>
                    <SelectItem value="threat_actor">Threat Actor</SelectItem>
                    <SelectItem value="campaign">Campaign</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div>
                <Label htmlFor="aliases">Aliases (comma-separated)</Label>
                <Input
                  id="aliases"
                  value={editingEntity.entity.aliases?.join(", ") || ""}
                  onChange={(e) =>
                    setEditingEntity({
                      ...editingEntity,
                      entity: {
                        ...editingEntity.entity,
                        aliases: e.target.value.split(",").map((a) => a.trim()).filter(Boolean),
                      },
                    })
                  }
                />
              </div>
              <div>
                <Label htmlFor="notes">Review Notes</Label>
                <Textarea
                  id="notes"
                  value={editingEntity.entity.review_notes || ""}
                  onChange={(e) =>
                    setEditingEntity({
                      ...editingEntity,
                      entity: { ...editingEntity.entity, review_notes: e.target.value },
                    })
                  }
                  placeholder="Add any notes about this entity..."
                />
              </div>
            </div>
          )}
          <DialogFooter>
            <Button variant="outline" onClick={() => setEditingEntity(null)}>
              Cancel
            </Button>
            <Button onClick={handleSaveEdit}>Save Changes</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}