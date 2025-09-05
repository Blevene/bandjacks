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
import type { ExtractedEntities, Entity, CategorizedEntities, categorizeEntities } from "@/lib/report-types";

interface EntityReviewProps {
  entities?: ExtractedEntities;
  onReviewComplete?: (reviewedEntities: ExtractedEntities) => void;
  readOnly?: boolean;
}

// No transformation needed - entities now come in structured format directly

export function EntityReview({ entities, onReviewComplete, readOnly = false }: EntityReviewProps) {
  const [reviewedEntities, setReviewedEntities] = useState<ExtractedEntities>(entities || { entities: [], extraction_status: 'not_attempted' });
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
      case "tool":
        return <Wrench className="h-4 w-4" />;
      case "group":
        return <Users className="h-4 w-4" />;
      case "campaign":
        return <Target className="h-4 w-4" />;
      case "target":
        return <Shield className="h-4 w-4" />;
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

  const handleApprove = (index: number) => {
    const updatedEntities = { ...reviewedEntities };
    if (updatedEntities.entities && updatedEntities.entities[index]) {
      updatedEntities.entities[index].review_status = "approved";
      updatedEntities.entities[index].verified = true;
      setReviewedEntities(updatedEntities);
    }
  };

  const handleReject = (index: number) => {
    const updatedEntities = { ...reviewedEntities };
    if (updatedEntities.entities && updatedEntities.entities[index]) {
      updatedEntities.entities[index].review_status = "rejected";
      updatedEntities.entities[index].verified = false;
      setReviewedEntities(updatedEntities);
    }
  };

  const handleEdit = (index: number) => {
    if (reviewedEntities.entities && reviewedEntities.entities[index]) {
      setEditingEntity({ type: reviewedEntities.entities[index].type, index, entity: { ...reviewedEntities.entities[index] } });
    }
  };

  const handleSaveEdit = () => {
    if (!editingEntity || !reviewedEntities.entities) return;

    const updatedEntities = { ...reviewedEntities };
    updatedEntities.entities[editingEntity.index] = {
      ...editingEntity.entity,
      review_status: "edited",
      verified: true,
    };
    setReviewedEntities(updatedEntities);
    setEditingEntity(null);
  };

  const renderEntityCard = (entity: Entity, index: number) => (
    <Card key={`entity-${index}`} className="mb-3">
      <CardHeader className="pb-3">
        <div className="flex items-start justify-between">
          <div className="flex items-center gap-2">
            {getEntityIcon(entity.type)}
            <CardTitle className="text-lg">{entity.name}</CardTitle>
            <Badge variant="outline" className="text-xs">
              {entity.type}
            </Badge>
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
        
        {entity.evidence && Array.isArray(entity.evidence) && entity.evidence.length > 0 && (
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

        {entity.line_refs && Array.isArray(entity.line_refs) && entity.line_refs.length > 0 && (
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
              onClick={() => handleApprove(index)}
              className="flex-1"
            >
              <CheckCircle className="h-3 w-3 mr-1" />
              Approve
            </Button>
            <Button
              size="sm"
              variant={entity.review_status === "rejected" ? "destructive" : "outline"}
              onClick={() => handleReject(index)}
              className="flex-1"
            >
              <XCircle className="h-3 w-3 mr-1" />
              Reject
            </Button>
            <Button
              size="sm"
              variant="outline"
              onClick={() => handleEdit(index)}
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
    { key: "tool", label: "Tools", icon: Wrench },
    { key: "group", label: "Threat Actors", icon: Users },
    { key: "campaign", label: "Campaigns", icon: Target },
    { key: "target", label: "Targets", icon: Shield },
  ];

  const getEntityCount = (type: string) => {
    return reviewedEntities.entities?.filter(e => e.type === type).length || 0;
  };

  const getEntitiesByType = (type: string) => {
    return reviewedEntities.entities?.filter(e => e.type === type) || [];
  };

  return (
    <>
      <div className="space-y-4">
        {/* Summary Stats */}
        <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
          {entityTypes.map(({ key, label, icon: Icon }) => {
            const entitiesOfType = getEntitiesByType(key);
            const count = entitiesOfType.length;
            const approved = entitiesOfType.filter(e => e.review_status === "approved").length;
            
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
          <TabsList className="grid w-full grid-cols-5">
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
                    No {key} entities found in this report.
                  </AlertDescription>
                </Alert>
              ) : (
                <>
                  {getEntitiesByType(key).map((entity, index) => {
                    const globalIndex = reviewedEntities.entities?.findIndex(e => e === entity) || index;
                    return renderEntityCard(entity, globalIndex);
                  })}
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
              onClick={() => setReviewedEntities(entities || { entities: [], extraction_status: 'not_attempted' })}
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
                    <SelectItem value="group">Threat Actor/Group</SelectItem>
                    <SelectItem value="campaign">Campaign</SelectItem>
                    <SelectItem value="target">Target</SelectItem>
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