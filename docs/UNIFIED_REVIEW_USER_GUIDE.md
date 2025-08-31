# Unified Review System - User Guide

## Table of Contents
1. [Introduction](#introduction)
2. [Getting Started](#getting-started)
3. [Review Interface Overview](#review-interface-overview)
4. [Review Workflow](#review-workflow)
5. [Keyboard Shortcuts](#keyboard-shortcuts)
6. [Best Practices](#best-practices)
7. [Common Tasks](#common-tasks)
8. [Troubleshooting](#troubleshooting)

## Introduction

The Unified Review System streamlines the review process for threat intelligence extractions by combining entities (threat actors, malware, tools, campaigns), MITRE ATT&CK techniques, and attack flow steps into a single, cohesive interface.

### Key Benefits
- **Single Interface**: Review all extraction types in one place
- **Faster Reviews**: Keyboard shortcuts and bulk operations speed up the process
- **Better Context**: See relationships between entities, techniques, and flows
- **Progress Tracking**: Visual indicators show review completion status
- **Atomic Saves**: All decisions saved together, preventing partial states

## Getting Started

### Accessing the Review Interface

1. Navigate to a report that needs review
2. Click the "Review" button or navigate to `/reports/{report-id}/review`
3. The unified review interface will load with all extracted items

### Understanding Review Items

Each extracted item is presented as a card showing:
- **Item Type**: Icon indicates entity, technique, or flow step
- **Name**: The extracted item's name or identifier
- **Confidence Score**: AI confidence level (0-100%)
- **Evidence**: Supporting text from the source document
- **Line References**: Links to source document locations
- **Status Badge**: Shows pending/approved/rejected/edited status

## Review Interface Overview

### Main Components

#### 1. Navigation Tabs
- **All Items**: Shows everything needing review
- **Entities**: Filter to only threat actors, malware, tools, campaigns
- **Techniques**: Filter to only MITRE ATT&CK techniques
- **Flow Steps**: Filter to only attack sequence steps
- **Summary**: Overview of review progress and statistics

#### 2. Control Bar
- **Search**: Find items by name or evidence text
- **Filters**: Filter by status, confidence level, or type
- **Bulk Actions**: Select multiple items for batch operations
- **Sort Options**: Sort by type, confidence, name, or status

#### 3. Progress Sidebar
- **Overall Progress**: Percentage of items reviewed
- **Status Breakdown**: Count of approved/rejected/edited/pending
- **Type Progress**: Progress for each item type
- **Time Tracking**: Shows time spent reviewing

#### 4. Item List
- Scrollable list of review cards
- Expandable evidence sections
- Inline action buttons
- Selection checkboxes for bulk operations

## Review Workflow

### Step-by-Step Process

#### 1. Initial Assessment
1. Start with the "All Items" tab to see everything
2. Sort by confidence (high to low) to prioritize reliable extractions
3. Review the summary tab to understand the scope

#### 2. Review Individual Items
For each item:
1. **Read the name and type** to understand what was extracted
2. **Check the confidence score** - higher scores indicate more reliable extractions
3. **Expand evidence** to see supporting text from the document
4. **Click line references** to view source context if needed
5. **Make a decision**:
   - ✅ **Approve**: Extraction is correct
   - ❌ **Reject**: Extraction is incorrect or irrelevant
   - ✏️ **Edit**: Extraction needs modification

#### 3. Edit Items (When Needed)
1. Click the Edit button (or press 'E')
2. Modify the item details in the dialog:
   - Update name or description
   - Adjust confidence score
   - Add review notes
3. Save changes

#### 4. Bulk Operations (For Efficiency)
1. Use checkboxes to select multiple similar items
2. Click "Bulk Actions" dropdown
3. Choose "Approve All" or "Reject All"
4. Confirm the action

#### 5. Submit Review
1. Review the Summary tab to ensure completeness
2. Add any global notes about the review
3. Click "Submit Review" button
4. Confirm submission in the dialog

### Review States

- **Pending** (Gray): Not yet reviewed
- **Approved** (Green): Accepted as correct
- **Rejected** (Red): Marked as incorrect
- **Edited** (Blue): Modified from original

## Keyboard Shortcuts

Speed up your review with these shortcuts:

| Key | Action | When to Use |
|-----|--------|-------------|
| **A** | Approve current item | Item is correct |
| **R** | Reject current item | Item is incorrect |
| **E** | Edit current item | Item needs changes |
| **Space** | Next item | Move forward |
| **Shift+Space** | Previous item | Move backward |
| **Enter** | Expand/collapse evidence | Need more context |
| **F** | Toggle filters | Show/hide filter panel |
| **S** | Submit review | Ready to save |
| **?** | Show shortcuts help | Need reminder |
| **Ctrl+A** | Select all visible | Bulk operations |
| **Esc** | Close dialogs | Cancel current action |

## Best Practices

### 1. Review Order Strategy

**High Confidence First**
- Start with items above 80% confidence
- These are usually correct and quick to approve
- Builds momentum and reduces remaining count

**By Type**
- Review all entities first (context building)
- Then techniques (behavioral patterns)
- Finally flow steps (attack sequence)

**Problem Items Last**
- Save low-confidence items for the end
- More time to consider difficult cases
- Can reject in bulk if needed

### 2. Evidence Evaluation

**Strong Evidence**
- Direct technique ID mentions (T1566.001)
- Explicit tool/malware names
- Clear attack descriptions
- Multiple supporting quotes

**Weak Evidence**
- Generic terms without context
- Single word mentions
- Ambiguous references
- Low confidence scores (<40%)

### 3. Editing Guidelines

**When to Edit**
- Correct minor typos in names
- Merge duplicate entities
- Adjust overly high/low confidence
- Add clarifying notes

**When to Reject**
- Completely wrong extraction
- Generic terms (e.g., "malware", "tool")
- Out of scope items
- Duplicate of already approved item

### 4. Using Bulk Operations

**Good Candidates**
- Multiple variants of same entity
- Obviously correct high-confidence items
- Clear false positives
- Duplicate extractions

**Review Individually**
- Mixed confidence items
- Complex techniques
- Critical flow steps
- First occurrence of an entity

## Common Tasks

### Reviewing a Large Report (>50 items)

1. **Phase 1: Quick Wins** (First 15 minutes)
   - Sort by confidence (descending)
   - Bulk approve items >90% confidence
   - Bulk reject obvious false positives

2. **Phase 2: Entities** (Next 20 minutes)
   - Switch to Entities tab
   - Review threat actors and campaigns first (context)
   - Then malware and tools

3. **Phase 3: Techniques** (Next 30 minutes)
   - Switch to Techniques tab
   - Verify technique IDs match descriptions
   - Check evidence quality
   - Edit to fix minor issues

4. **Phase 4: Flow Steps** (Next 20 minutes)
   - Switch to Flow Steps tab
   - Verify sequence makes sense
   - Check technique assignments
   - Ensure temporal order

5. **Phase 5: Final Review** (Last 10 minutes)
   - Return to All Items tab
   - Review remaining pending items
   - Check Summary tab
   - Add global notes
   - Submit review

### Handling Duplicate Extractions

1. Identify duplicates by sorting by name
2. Select all duplicates with checkboxes
3. Keep the one with highest confidence
4. Bulk reject the others
5. Add note explaining the deduplication

### Reviewing Low-Confidence Items

1. Filter by confidence <50%
2. Expand evidence for each item
3. Check for:
   - Contextual support in surrounding text
   - Corroboration from other extractions
   - Relevance to report theme
4. When in doubt, reject rather than approve

### Adding Context with Notes

Use review notes to:
- Explain why an item was rejected
- Clarify ambiguous entities
- Link related items
- Flag items for follow-up
- Document assumptions made

Example notes:
- "Rejected: Generic malware reference without specific family"
- "Lazarus Group - confirmed via infrastructure overlap described on page 5"
- "T1055 confirmed but specific sub-technique unclear"
- "Flow step order uncertain, placed based on typical attack pattern"

## Troubleshooting

### Common Issues and Solutions

#### Review Not Loading
- **Problem**: Review interface shows loading spinner indefinitely
- **Solution**: 
  1. Refresh the page
  2. Check if report extraction is complete
  3. Verify you have review permissions

#### Can't Submit Review
- **Problem**: Submit button is disabled or throws error
- **Solution**:
  1. Ensure at least one item has been reviewed
  2. Check for required fields in edited items
  3. Verify no validation errors shown
  4. Try saving draft first (if available)

#### Lost Review Progress
- **Problem**: Decisions not saved after browser crash
- **Solution**:
  1. Reviews auto-save every 30 seconds (if enabled)
  2. Check for draft recovery on page reload
  3. Use Submit Review frequently for important reviews

#### Keyboard Shortcuts Not Working
- **Problem**: Shortcuts don't trigger actions
- **Solution**:
  1. Click in the review area to ensure focus
  2. Check if a dialog is open (Esc to close)
  3. Verify shortcuts are enabled in settings
  4. Try using button clicks instead

#### Evidence Not Expanding
- **Problem**: Can't see full evidence text
- **Solution**:
  1. Click the evidence toggle button
  2. Use Enter key when item is selected
  3. Check if browser JavaScript is enabled

### Performance Tips

#### For Large Reports (>100 items)
- Use filters to work on subsets
- Disable auto-expand of evidence
- Use bulk operations when possible
- Submit review in batches if allowed

#### For Slow Loading
- Clear browser cache
- Close unnecessary tabs
- Use a modern browser (Chrome, Firefox, Edge)
- Check network connection

### Getting Help

If you encounter issues not covered here:

1. **Check Documentation**: Review the technical documentation
2. **Contact Support**: Use the feedback button in the interface
3. **Report Bugs**: Include:
   - Report ID
   - Browser and version
   - Steps to reproduce
   - Screenshots if applicable

## Tips for Efficient Reviewing

### Speed Techniques

1. **Learn the Shortcuts**: Memorize the top 5 shortcuts (A, R, E, Space, Enter)
2. **Use Filters Strategically**: Work on one type at a time
3. **Trust High Confidence**: Don't over-analyze >90% confidence items
4. **Batch Similar Items**: Group review similar entities
5. **Set a Rhythm**: Develop a consistent review pattern

### Quality Techniques

1. **Read Evidence First**: Always check supporting text
2. **Verify Technique IDs**: Ensure IDs match descriptions
3. **Check Relationships**: Verify entities relate to techniques
4. **Validate Sequences**: Ensure flow steps make logical sense
5. **Document Decisions**: Use notes for non-obvious choices

### Time Management

- **Allocate Time by Count**: 1-2 minutes per item average
- **Set Milestones**: Complete X items every 15 minutes
- **Take Breaks**: 5-minute break every 30 items
- **Track Progress**: Use the progress sidebar
- **Don't Perfectionist**: Good enough is often sufficient

## Advanced Features

### Custom Filters

Create complex filters by combining:
- Type + Status (e.g., "Pending Entities")
- Confidence ranges (e.g., "40-60% confidence")
- Search + Type (e.g., "Lazarus in Entities")

### Review Templates

For common report types:
1. APT Reports: Focus on threat actors and campaigns
2. Malware Analysis: Prioritize techniques and tools
3. Incident Response: Emphasize flow sequences
4. Threat Briefs: Quick review of high-confidence only

### Collaboration Features (Future)

- Share review sessions
- Compare reviewer decisions
- Consensus building tools
- Review quality metrics

## Conclusion

The Unified Review System is designed to make the review process as efficient and accurate as possible. By following this guide and developing your own review rhythm, you can process threat intelligence extractions quickly while maintaining high quality standards.

Remember:
- Use keyboard shortcuts to speed up reviews
- Trust high-confidence extractions
- Focus on evidence quality
- Submit reviews frequently to save progress
- When in doubt, reject rather than approve incorrectly

Happy reviewing!