"use client";

import { useState, useEffect, useCallback } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Slider } from "@/components/ui/slider";
import { Alert, AlertDescription } from "@/components/ui/alert";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  Search,
  Filter,
  ChevronDown,
  ChevronUp,
  CheckCircle,
  XCircle,
  Edit,
  Save,
  RefreshCw,
  Keyboard,
  AlertTriangle,
  Info,
} from "lucide-react";
import type { Report, ReviewableItem, UnifiedReviewState, UnifiedReviewDecision } from "@/lib/report-types";
import {
  createUnifiedReviewState,
  filterReviewableItems,
  groupReviewableItems,
  calculateReviewProgress,
  validateReviewDecisions,
  applyReviewDecision,
  getReviewKeyboardShortcuts,
} from "@/lib/review-utils";
import { ReviewItemCard } from "./review-item-card";
import { ReviewProgress } from "./review-progress";

interface UnifiedReviewProps {
  report: Report;
  onSubmit: (decisions: UnifiedReviewDecision[], globalNotes: string) => Promise<void>;
  readOnly?: boolean;
}

export function UnifiedReview({ report, onSubmit, readOnly = false }: UnifiedReviewProps) {
  const [state, setState] = useState<UnifiedReviewState>(() => createUnifiedReviewState(report));
  const [selectedItems, setSelectedItems] = useState<Set<string>>(new Set());
  const [expandedItems, setExpandedItems] = useState<Set<string>>(new Set());
  const [searchTerm, setSearchTerm] = useState("");
  const [showFilters, setShowFilters] = useState(false);
  const [showKeyboardShortcuts, setShowKeyboardShortcuts] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [currentItemIndex, setCurrentItemIndex] = useState(0);

  // Filter items based on search and state
  const filteredItems = filterReviewableItems(
    state.items.filter(item => 
      searchTerm === "" || 
      item.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      item.evidence.some(e => e.toLowerCase().includes(searchTerm.toLowerCase()))
    ),
    state
  );

  const groupedItems = groupReviewableItems(filteredItems);
  const progress = calculateReviewProgress(state.items);

  // Keyboard shortcuts
  useEffect(() => {
    const handleKeyPress = (e: KeyboardEvent) => {
      if (readOnly || e.target instanceof HTMLInputElement || e.target instanceof HTMLTextAreaElement) {
        return;
      }

      const currentItem = filteredItems[currentItemIndex];
      if (!currentItem) return;

      switch (e.key.toLowerCase()) {
        case 'a':
          handleReviewAction(currentItem.id, 'approve');
          break;
        case 'r':
          handleReviewAction(currentItem.id, 'reject');
          break;
        case 'e':
          // Trigger edit for current item
          break;
        case ' ':
          e.preventDefault();
          if (e.shiftKey) {
            setCurrentItemIndex(Math.max(0, currentItemIndex - 1));
          } else {
            setCurrentItemIndex(Math.min(filteredItems.length - 1, currentItemIndex + 1));
          }
          break;
        case 'enter':
          toggleExpanded(currentItem.id);
          break;
        case 'f':
          if (e.ctrlKey || e.metaKey) {
            e.preventDefault();
            setShowFilters(!showFilters);
          }
          break;
        case '?':
          setShowKeyboardShortcuts(true);
          break;
      }
    };

    window.addEventListener('keydown', handleKeyPress);
    return () => window.removeEventListener('keydown', handleKeyPress);
  }, [currentItemIndex, filteredItems, readOnly, showFilters]);

  const handleReviewAction = (itemId: string, action: 'approve' | 'reject' | 'edit') => {
    const decision: UnifiedReviewDecision = {
      item_id: itemId,
      action,
      timestamp: new Date().toISOString(),
    };

    const newDecisions = new Map(state.decisions);
    newDecisions.set(itemId, decision);

    // Update item status
    const updatedItems = state.items.map(item => 
      item.id === itemId ? applyReviewDecision(item, decision) : item
    );

    setState({
      ...state,
      items: updatedItems,
      decisions: newDecisions,
    });
  };

  const handleEditSave = (itemId: string, editedValues: Partial<ReviewableItem>) => {
    const decision: UnifiedReviewDecision = {
      item_id: itemId,
      action: 'edit',
      edited_value: editedValues,
      timestamp: new Date().toISOString(),
      notes: editedValues.review_notes,
    };

    const newDecisions = new Map(state.decisions);
    newDecisions.set(itemId, decision);

    // Update item
    const updatedItems = state.items.map(item => 
      item.id === itemId ? { ...item, ...editedValues, review_status: 'edited' } : item
    );

    setState({
      ...state,
      items: updatedItems,
      decisions: newDecisions,
    });
  };

  const handleBulkAction = (action: 'approve' | 'reject') => {
    const newDecisions = new Map(state.decisions);
    const updatedItems = [...state.items];

    selectedItems.forEach(itemId => {
      const decision: UnifiedReviewDecision = {
        item_id: itemId,
        action,
        timestamp: new Date().toISOString(),
      };
      newDecisions.set(itemId, decision);

      const itemIndex = updatedItems.findIndex(item => item.id === itemId);
      if (itemIndex !== -1) {
        updatedItems[itemIndex] = applyReviewDecision(updatedItems[itemIndex], decision);
      }
    });

    setState({
      ...state,
      items: updatedItems,
      decisions: newDecisions,
    });

    setSelectedItems(new Set());
  };

  const toggleSelected = (itemId: string, selected: boolean) => {
    const newSelected = new Set(selectedItems);
    if (selected) {
      newSelected.add(itemId);
    } else {
      newSelected.delete(itemId);
    }
    setSelectedItems(newSelected);
  };

  const toggleExpanded = (itemId: string) => {
    const newExpanded = new Set(expandedItems);
    if (newExpanded.has(itemId)) {
      newExpanded.delete(itemId);
    } else {
      newExpanded.add(itemId);
    }
    setExpandedItems(newExpanded);
  };

  const handleSubmit = async () => {
    const validation = validateReviewDecisions(state.decisions);
    if (!validation.valid) {
      // Show validation errors
      return;
    }

    setSubmitting(true);
    try {
      const decisions = Array.from(state.decisions.values());
      await onSubmit(decisions, state.globalNotes);
    } finally {
      setSubmitting(false);
    }
  };

  const renderItemsList = (items: ReviewableItem[]) => (
    <ScrollArea className="h-[600px]">
      <div className="space-y-2 pr-4">
        {items.map((item, index) => (
          <ReviewItemCard
            key={item.id}
            item={item}
            isSelected={selectedItems.has(item.id)}
            isExpanded={expandedItems.has(item.id)}
            onSelect={(selected) => toggleSelected(item.id, selected)}
            onExpand={(expanded) => toggleExpanded(item.id)}
            onReviewAction={(action) => handleReviewAction(item.id, action)}
            onEditSave={(edited) => handleEditSave(item.id, edited)}
            readOnly={readOnly}
          />
        ))}
      </div>
    </ScrollArea>
  );

  return (
    <div className="space-y-4">
      {/* Header with progress */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="md:col-span-2">
          <Card>
            <CardHeader>
              <CardTitle>Unified Report Review</CardTitle>
              <CardDescription>
                Review all extracted entities, techniques, and attack flow steps in one place
              </CardDescription>
            </CardHeader>
            <CardContent>
              {/* Search and filters */}
              <div className="space-y-4">
                <div className="flex gap-2">
                  <div className="relative flex-1">
                    <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
                    <Input
                      placeholder="Search items..."
                      value={searchTerm}
                      onChange={(e) => setSearchTerm(e.target.value)}
                      className="pl-9"
                    />
                  </div>
                  <Button
                    variant="outline"
                    onClick={() => setShowFilters(!showFilters)}
                  >
                    <Filter className="h-4 w-4 mr-2" />
                    Filters
                    {showFilters ? <ChevronUp className="h-4 w-4 ml-2" /> : <ChevronDown className="h-4 w-4 ml-2" />}
                  </Button>
                  <Button
                    variant="outline"
                    onClick={() => setShowKeyboardShortcuts(true)}
                  >
                    <Keyboard className="h-4 w-4" />
                  </Button>
                </div>

                {/* Filters panel */}
                {showFilters && (
                  <Card>
                    <CardContent className="pt-4">
                      <div className="grid grid-cols-3 gap-4">
                        <div>
                          <Label>Type</Label>
                          <Select
                            value={state.filterType || 'all'}
                            onValueChange={(value) => setState({ ...state, filterType: value as any })}
                          >
                            <SelectTrigger>
                              <SelectValue />
                            </SelectTrigger>
                            <SelectContent>
                              <SelectItem value="all">All Types</SelectItem>
                              <SelectItem value="entity">Entities</SelectItem>
                              <SelectItem value="technique">Techniques</SelectItem>
                              <SelectItem value="flow_step">Flow Steps</SelectItem>
                            </SelectContent>
                          </Select>
                        </div>
                        <div>
                          <Label>Status</Label>
                          <Select
                            value={state.filterStatus || 'all'}
                            onValueChange={(value) => setState({ ...state, filterStatus: value as any })}
                          >
                            <SelectTrigger>
                              <SelectValue />
                            </SelectTrigger>
                            <SelectContent>
                              <SelectItem value="all">All Status</SelectItem>
                              <SelectItem value="pending">Pending Only</SelectItem>
                              <SelectItem value="reviewed">Reviewed Only</SelectItem>
                            </SelectContent>
                          </Select>
                        </div>
                        <div>
                          <Label>Min Confidence: {state.filterConfidence || 0}%</Label>
                          <Slider
                            value={[state.filterConfidence || 0]}
                            onValueChange={([value]) => setState({ ...state, filterConfidence: value })}
                            min={0}
                            max={100}
                            step={10}
                            className="mt-2"
                          />
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                )}

                {/* Bulk actions */}
                {selectedItems.size > 0 && !readOnly && (
                  <Alert>
                    <Info className="h-4 w-4" />
                    <AlertDescription className="flex items-center justify-between">
                      <span>{selectedItems.size} items selected</span>
                      <div className="flex gap-2">
                        <Button
                          size="sm"
                          variant="default"
                          onClick={() => handleBulkAction('approve')}
                        >
                          <CheckCircle className="h-4 w-4 mr-1" />
                          Approve All
                        </Button>
                        <Button
                          size="sm"
                          variant="destructive"
                          onClick={() => handleBulkAction('reject')}
                        >
                          <XCircle className="h-4 w-4 mr-1" />
                          Reject All
                        </Button>
                      </div>
                    </AlertDescription>
                  </Alert>
                )}
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Progress sidebar */}
        <ReviewProgress items={state.items} />
      </div>

      {/* Main review interface */}
      <Tabs defaultValue="all" className="w-full">
        <TabsList className="grid w-full grid-cols-5">
          <TabsTrigger value="all">
            All Items ({filteredItems.length})
          </TabsTrigger>
          <TabsTrigger value="entities">
            Entities ({groupedItems.byType.entities.length})
          </TabsTrigger>
          <TabsTrigger value="techniques">
            Techniques ({groupedItems.byType.techniques.length})
          </TabsTrigger>
          <TabsTrigger value="flow">
            Flow Steps ({groupedItems.byType.flowSteps.length})
          </TabsTrigger>
          <TabsTrigger value="summary">
            Summary
          </TabsTrigger>
        </TabsList>

        <TabsContent value="all" className="mt-4">
          {renderItemsList(filteredItems)}
        </TabsContent>

        <TabsContent value="entities" className="mt-4">
          {Object.entries(groupedItems.entities).length > 0 ? (
            <div className="space-y-4">
              {Object.entries(groupedItems.entities).map(([category, items]) => (
                <div key={category}>
                  <h3 className="text-sm font-medium mb-2 capitalize">{category}</h3>
                  {renderItemsList(items)}
                </div>
              ))}
            </div>
          ) : (
            <Alert>
              <Info className="h-4 w-4" />
              <AlertDescription>No entities to review</AlertDescription>
            </Alert>
          )}
        </TabsContent>

        <TabsContent value="techniques" className="mt-4">
          {groupedItems.byType.techniques.length > 0 ? (
            renderItemsList(groupedItems.byType.techniques)
          ) : (
            <Alert>
              <Info className="h-4 w-4" />
              <AlertDescription>No techniques to review</AlertDescription>
            </Alert>
          )}
        </TabsContent>

        <TabsContent value="flow" className="mt-4">
          {groupedItems.byType.flowSteps.length > 0 ? (
            renderItemsList(groupedItems.byType.flowSteps)
          ) : (
            <Alert>
              <Info className="h-4 w-4" />
              <AlertDescription>No flow steps to review</AlertDescription>
            </Alert>
          )}
        </TabsContent>

        <TabsContent value="summary" className="mt-4">
          <Card>
            <CardHeader>
              <CardTitle>Review Summary</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <Label>Total Items</Label>
                  <p className="text-2xl font-bold">{progress.total}</p>
                </div>
                <div>
                  <Label>Reviewed</Label>
                  <p className="text-2xl font-bold">{progress.reviewed}</p>
                </div>
                <div>
                  <Label>Approved</Label>
                  <p className="text-2xl font-bold text-green-500">{progress.approved}</p>
                </div>
                <div>
                  <Label>Rejected</Label>
                  <p className="text-2xl font-bold text-red-500">{progress.rejected}</p>
                </div>
              </div>

              <div>
                <Label>Global Review Notes</Label>
                <Textarea
                  value={state.globalNotes}
                  onChange={(e) => setState({ ...state, globalNotes: e.target.value })}
                  placeholder="Add any overall notes about this review..."
                  className="mt-2"
                  rows={4}
                />
              </div>

              {!readOnly && (
                <div className="flex justify-end gap-2">
                  <Button
                    variant="outline"
                    onClick={() => setState(createUnifiedReviewState(report))}
                  >
                    <RefreshCw className="h-4 w-4 mr-2" />
                    Reset Review
                  </Button>
                  <Button
                    onClick={handleSubmit}
                    disabled={submitting || state.decisions.size === 0}
                  >
                    <Save className="h-4 w-4 mr-2" />
                    Submit Review ({state.decisions.size} decisions)
                  </Button>
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      {/* Keyboard shortcuts dialog */}
      <Dialog open={showKeyboardShortcuts} onOpenChange={setShowKeyboardShortcuts}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Keyboard Shortcuts</DialogTitle>
            <DialogDescription>
              Use these shortcuts to speed up your review process
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-2">
            {Object.entries(getReviewKeyboardShortcuts()).map(([key, description]) => (
              <div key={key} className="flex justify-between">
                <kbd className="px-2 py-1 bg-muted rounded text-sm font-mono">{key}</kbd>
                <span className="text-sm text-muted-foreground">{description}</span>
              </div>
            ))}
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
}