"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __generator = (this && this.__generator) || function (thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g = Object.create((typeof Iterator === "function" ? Iterator : Object).prototype);
    return g.next = verb(0), g["throw"] = verb(1), g["return"] = verb(2), typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (g && (g = 0, op[0] && (_ = 0)), _) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.handlers = void 0;
var msw_1 = require("msw");
var API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';
exports.handlers = [
    // Simulation endpoints
    msw_1.http.post("".concat(API_URL, "/v1/simulation/paths"), function (_a) { return __awaiter(void 0, [_a], void 0, function (_b) {
        var body;
        var request = _b.request;
        return __generator(this, function (_c) {
            switch (_c.label) {
                case 0: return [4 /*yield*/, request.json()];
                case 1:
                    body = _c.sent();
                    return [2 /*return*/, msw_1.HttpResponse.json({
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
                        })];
            }
        });
    }); }),
    msw_1.http.post("".concat(API_URL, "/v1/simulation/predict"), function () { return __awaiter(void 0, void 0, void 0, function () {
        return __generator(this, function (_a) {
            return [2 /*return*/, msw_1.HttpResponse.json({
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
                })];
        });
    }); }),
    // Detection strategies
    msw_1.http.get("".concat(API_URL, "/v1/detections/strategies"), function (_a) {
        var request = _a.request;
        var url = new URL(request.url);
        var techniqueId = url.searchParams.get('technique_id');
        return msw_1.HttpResponse.json([
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
        ]);
    }),
    // Coverage endpoint
    msw_1.http.get("".concat(API_URL, "/v1/coverage/technique/:techniqueId"), function (_a) {
        var params = _a.params;
        return msw_1.HttpResponse.json({
            technique_id: params.techniqueId,
            name: 'Process Injection',
            detection_coverage: {
                total_strategies: 5,
                active_strategies: 3,
                coverage_percentage: 60,
            },
            gaps: ['Memory-based injection variants'],
        });
    }),
    // Report ingestion
    msw_1.http.post("".concat(API_URL, "/v1/reports/ingest"), function () { return __awaiter(void 0, void 0, void 0, function () {
        return __generator(this, function (_a) {
            return [2 /*return*/, msw_1.HttpResponse.json({
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
                })];
        });
    }); }),
    msw_1.http.post("".concat(API_URL, "/v1/reports/ingest/upload"), function () { return __awaiter(void 0, void 0, void 0, function () {
        return __generator(this, function (_a) {
            return [2 /*return*/, msw_1.HttpResponse.json({
                    report_id: 'report-upload-123',
                    techniques: ['T1055', 'T1003'],
                    relationships: [],
                    flow_id: 'flow-upload-123',
                    status: 'success',
                })];
        });
    }); }),
    // Search endpoints
    msw_1.http.post("".concat(API_URL, "/v1/search/ttx"), function (_a) { return __awaiter(void 0, [_a], void 0, function (_b) {
        var body;
        var request = _b.request;
        return __generator(this, function (_c) {
            switch (_c.label) {
                case 0: return [4 /*yield*/, request.json()];
                case 1:
                    body = _c.sent();
                    return [2 /*return*/, msw_1.HttpResponse.json({
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
                        })];
            }
        });
    }); }),
    // Active Learning endpoints
    msw_1.http.get("".concat(API_URL, "/v1/active-learning/queue"), function () {
        return msw_1.HttpResponse.json([
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
        ]);
    }),
    msw_1.http.get("".concat(API_URL, "/v1/active-learning/statistics"), function () {
        return msw_1.HttpResponse.json({
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
        });
    }),
    msw_1.http.post("".concat(API_URL, "/v1/active-learning/review"), function () { return __awaiter(void 0, void 0, void 0, function () {
        return __generator(this, function (_a) {
            return [2 /*return*/, msw_1.HttpResponse.json({
                    success: true,
                    message: 'Review decision recorded',
                })];
        });
    }); }),
    // Feedback endpoints
    msw_1.http.post("".concat(API_URL, "/v1/feedback/quality"), function () { return __awaiter(void 0, void 0, void 0, function () {
        return __generator(this, function (_a) {
            return [2 /*return*/, msw_1.HttpResponse.json({
                    feedback_id: 'feedback-123',
                    scores_recorded: 1,
                    average_overall: 4.0,
                    message: 'Feedback recorded successfully',
                })];
        });
    }); }),
    // STIX/Catalog endpoints
    msw_1.http.get("".concat(API_URL, "/v1/catalog/attack/releases"), function () {
        return msw_1.HttpResponse.json([
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
        ]);
    }),
    msw_1.http.post("".concat(API_URL, "/v1/stix/load/attack"), function () { return __awaiter(void 0, void 0, void 0, function () {
        return __generator(this, function (_a) {
            return [2 /*return*/, msw_1.HttpResponse.json({
                    inserted: 1250,
                    updated: 150,
                    rejected: [],
                    provenance: {
                        collection: 'enterprise-attack',
                        version: '14.0',
                        modified: '2023-10-31T00:00:00.000Z',
                        url: 'https://github.com/mitre-attack/attack-stix-data',
                    },
                })];
        });
    }); }),
    // Default 404 handler for unmatched routes
    msw_1.http.get('*', function () {
        return new msw_1.HttpResponse(null, { status: 404 });
    }),
];
