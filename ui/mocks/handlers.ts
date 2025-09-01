import { http, HttpResponse } from 'msw'

const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8001'

export const handlers = [
  // Simulation endpoints
  http.post('*/v1/simulation/paths', async ({ request }) => {
    const body = await request.json() as any
    return HttpResponse.json({
      simulation_id: 'sim-test-123',
      request: body,
      paths: [
        {
          path_id: 'path-1',
          steps: [
            { technique_id: 'T1055', technique_name: 'Process Injection', probability: 0.8 },
            { technique_id: 'T1003', technique_name: 'OS Credential Dumping', probability: 0.7 },
          ],
          total_probability: 0.56,
          complexity_score: 3.5,
          covered_tactics: ['persistence', 'privilege-escalation'],
          confidence_score: 0.75,
        },
      ],
      summary: { 
        paths_returned: 1, 
        method: body.method || 'deterministic',
        max_depth: body.max_depth || 5
      },
      created_at: new Date().toISOString(),
    })
  }),

  http.post('*/v1/simulation/predict', async () => {
    return HttpResponse.json({
      current_state: ['T1055'],
      predictions: [
        {
          technique_id: 'T1003',
          technique_name: 'OS Credential Dumping',
          probability: 0.75,
          tactic: 'credential-access',
          rationale: 'Common next step after process injection',
          historical_frequency: 0.65,
        },
        {
          technique_id: 'T1078',
          technique_name: 'Valid Accounts',
          probability: 0.60,
          tactic: 'persistence',
          rationale: 'Often follows credential access',
          historical_frequency: 0.55,
        },
      ],
      confidence: 0.8,
      analysis: 'Based on historical attack patterns',
    })
  }),

  // Detection strategies
  http.get('*/v1/detections/strategies', ({ request }) => {
    const url = new URL(request.url)
    const techniqueId = url.searchParams.get('technique_id')
    
    return HttpResponse.json([
      {
        stix_id: 'x-detection-strategy--123',
        name: 'Process Injection Detection',
        det_id: 'DS0001',
        description: 'Detects various process injection techniques',
        x_mitre_version: '1.0',
        x_mitre_domains: ['enterprise-attack'],
        analytics_count: 5,
        detected_techniques: techniqueId ? [techniqueId] : ['T1055', 'T1003'],
      },
      {
        stix_id: 'x-detection-strategy--456',
        name: 'Credential Access Monitoring',
        det_id: 'DS0002',
        description: 'Monitors credential access attempts',
        x_mitre_version: '1.0',
        x_mitre_domains: ['enterprise-attack'],
        analytics_count: 3,
        detected_techniques: ['T1003', 'T1078'],
      },
    ])
  }),

  // Coverage endpoint
  http.get('*/v1/coverage/technique/:techniqueId', ({ params }) => {
    return HttpResponse.json({
      technique_id: params.techniqueId,
      name: 'Process Injection',
      detection_coverage: {
        total_strategies: 5,
        active_strategies: 3,
        coverage_percentage: 60,
      },
      gaps: ['Memory-based injection variants'],
    })
  }),

  // Report ingestion
  http.post('*/v1/reports/ingest', async () => {
    return HttpResponse.json({
      report_id: 'report-test-123',
      techniques: ['T1055', 'T1003', 'T1078'],
      relationships: [
        { source: 'T1055', target: 'T1003', type: 'followed-by' },
      ],
      flow_id: 'flow-test-123',
      confidence_scores: {
        T1055: 0.85,
        T1003: 0.75,
        T1078: 0.65,
      },
    })
  }),

  http.post('*/v1/reports/ingest/upload', async () => {
    return HttpResponse.json({
      report_id: 'report-upload-123',
      techniques: ['T1055', 'T1003'],
      relationships: [],
      flow_id: 'flow-upload-123',
      status: 'success',
    })
  }),

  // Search endpoints
  http.post('*/v1/search/ttx', async ({ request }) => {
    const body = await request.json() as any
    return HttpResponse.json({
      query: body.query,
      results: [
        {
          stix_id: 'attack-pattern--123',
          external_id: 'T1055',
          name: 'Process Injection',
          description: 'Process injection is a method...',
          score: 0.95,
          confidence: 0.85,
        },
      ],
      total: 1,
    })
  }),

  // Active Learning endpoints
  http.get('*/v1/active-learning/queue', () => {
    return HttpResponse.json([
      {
        queue_id: 'queue-1',
        item_type: 'flow_edge',
        item_id: 'edge-1',
        confidence: 0.45,
        uncertainty_score: 0.55,
        source_context: {
          source: 'T1055',
          target: 'T1003',
          flow_id: 'flow-123',
          probability: 0.45,
        },
        status: 'pending',
        priority: 55,
        created: new Date().toISOString(),
        updated: new Date().toISOString(),
      },
      {
        queue_id: 'queue-2',
        item_type: 'mapping',
        item_id: 'mapping-1',
        confidence: 0.60,
        uncertainty_score: 0.40,
        source_context: {
          source_text: 'The attacker used process hollowing',
          technique_name: 'Process Injection',
          technique_id: 'T1055',
        },
        status: 'pending',
        priority: 40,
        created: new Date().toISOString(),
        updated: new Date().toISOString(),
      },
    ])
  }),

  http.get('*/v1/active-learning/statistics', () => {
    return HttpResponse.json({
      by_status: {
        pending: 15,
        reviewed: 45,
        rejected: 5,
      },
      by_type: {
        flow_edge: 20,
        mapping: 25,
        extraction: 10,
        detection: 10,
      },
      total: 65,
      confidence_stats: {
        average: 0.65,
        min: 0.30,
        max: 0.95,
        stdev: 0.15,
      },
    })
  }),

  http.post('*/v1/active-learning/review', async () => {
    return HttpResponse.json({
      success: true,
      message: 'Review decision recorded',
    })
  }),

  // Feedback endpoints
  http.post('*/v1/feedback/quality', async () => {
    return HttpResponse.json({
      feedback_id: 'feedback-123',
      scores_recorded: 1,
      average_overall: 4.0,
      message: 'Feedback recorded successfully',
    })
  }),

  // STIX/Catalog endpoints
  http.get('*/v1/catalog/attack/releases', () => {
    return HttpResponse.json([
      {
        collection: 'enterprise-attack',
        version: '14.0',
        modified: '2023-10-31T00:00:00.000Z',
        url: 'https://github.com/mitre-attack/attack-stix-data',
      },
      {
        collection: 'enterprise-attack',
        version: '13.1',
        modified: '2023-04-27T00:00:00.000Z',
        url: 'https://github.com/mitre-attack/attack-stix-data',
      },
    ])
  }),

  http.post('*/v1/stix/load/attack', async () => {
    return HttpResponse.json({
      inserted: 1250,
      updated: 150,
      rejected: [],
      provenance: {
        collection: 'enterprise-attack',
        version: '14.0',
        modified: '2023-10-31T00:00:00.000Z',
        url: 'https://github.com/mitre-attack/attack-stix-data',
      },
    })
  }),

  // Default 404 handler for unmatched routes
  http.get('*', () => {
    return new HttpResponse(null, { status: 404 })
  }),
]