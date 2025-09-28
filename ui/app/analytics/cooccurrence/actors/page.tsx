'use client'

import { useEffect, useState } from 'react';
import { api } from '@/lib/api';

type ActorResponse = {
  intrusion_set_id: string;
  intrusion_set_name?: string;
  total_episodes: number;
  total_techniques: number;
  top_pairs: Array<{
    technique_a: string;
    technique_b: string;
    name_a: string;
    name_b: string;
    external_id_a?: string | null;
    external_id_b?: string | null;
    count: number;
    confidence_a_to_b: number;
    confidence_b_to_a: number;
    lift: number;
    pmi: number;
    npmi: number;
    jaccard: number;
  }>;
  signature_bundles: Array<{
    techniques: string[];
    technique_names: string[];
    support: number;
    confidence: number;
    lift: number;
    tactics: string[];
  }>;
};

export default function ActorCooccurrencePage() {
  const [actorId, setActorId] = useState(''); // STIX id or selected id
  const [actorQuery, setActorQuery] = useState(''); // name search
  const [actorSuggestions, setActorSuggestions] = useState<any[]>([]);
  const [showSuggestions, setShowSuggestions] = useState(false);
  const [suggesting, setSuggesting] = useState(false);
  const [minSupport, setMinSupport] = useState(1);
  const [metric, setMetric] = useState<'npmi' | 'lift' | 'confidence'>('npmi');
  const [data, setData] = useState<ActorResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function load() {
    if (!actorId) return;
    setLoading(true);
    setError(null);
    try {
      // Resolve actor name if not provided
      if (!actorQuery) {
        try {
          const info = await api.reports.getActorById(actorId);
          const name = info.data?.name || '';
          if (name) setActorQuery(name);
        } catch {}
      }
      const res = await api.cooccurrence.postActor({ intrusion_set_id: actorId, min_support: minSupport, metric_filter: metric });
      setData(res.data);
    } catch (e: any) {
      setError(e?.message || 'Failed to load');
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    // no auto-load until an actor is provided
  }, []);

  // Debounced actor name search
  useEffect(() => {
    const q = actorQuery.trim();
    if (!q) {
      setActorSuggestions([]);
      return;
    }
    setSuggesting(true);
    const t = setTimeout(async () => {
      try {
        // Use reports attribution search for now to ensure compatibility
        const res = await api.reports.searchAttributionCandidates(q);
        const results = res.data?.results || [];
        setActorSuggestions(results);
        setShowSuggestions(true);

        // Auto-resolve STIX id when there is an exact name/alias match
        const lower = q.toLowerCase();
        const exact = results.find((s: any) => {
          const name = (s?.name || '').toLowerCase();
          const aliases: string[] = Array.isArray(s?.aliases) ? s.aliases : [];
          return name === lower || aliases.some(a => (a || '').toLowerCase() === lower);
        });
        if (exact && !actorId) {
          setActorId(exact.id || exact.stix_id || '');
        }
      } catch {
        setActorSuggestions([]);
      } finally {
        setSuggesting(false);
      }
    }, 300);
    return () => clearTimeout(t);
  }, [actorQuery]);

  // Debounced STIX ID resolve to name (search-ahead)
  useEffect(() => {
    const id = actorId.trim();
    if (!id) return;
    const t = setTimeout(async () => {
      try {
        const res = await api.actors.getById(id);
        const name = res.data?.name || '';
        if (name && !actorQuery) {
          setActorQuery(name);
        }
      } catch {
        // ignore 404 or network errors for ahead lookup
      }
    }, 350);
    return () => clearTimeout(t);
  }, [actorId]);

  return (
    <div className="mx-auto max-w-6xl p-6 space-y-6">
      <div className="flex items-end justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-xl font-semibold">Actor Insights</h1>
          <p className="text-sm text-gray-500 dark:text-gray-400">Top pairs and bundles for a selected intrusion set</p>
        </div>
        <div className="flex items-center gap-2 relative">
          <div className="flex flex-col">
            <div className="flex items-center gap-1">
              <input value={actorId} onChange={(e) => setActorId(e.target.value)} placeholder="Intrusion Set STIX ID" className="h-9 rounded-md border px-3 text-sm bg-transparent w-80" />
              <input
                value={actorQuery}
                onChange={(e) => setActorQuery(e.target.value)}
                placeholder="Search actor by name or alias"
                className="h-9 rounded-md border px-3 text-sm bg-transparent w-72"
                onFocus={() => actorQuery && setShowSuggestions(true)}
                onBlur={() => setTimeout(() => setShowSuggestions(false), 150)}
              />
            </div>
            <div className="text-[11px] text-gray-500 mt-1">
              <span className="mr-3">Actor name: {actorQuery || '—'}</span>
              <span>STIX: {actorId || '—'}</span>
            </div>
          </div>
          {showSuggestions && (actorSuggestions.length > 0 || suggesting) && (
            <div className="absolute top-10 left-0 z-10 w-[36rem] rounded-md border bg-background shadow">
              {suggesting && <div className="px-3 py-2 text-xs text-gray-500">Searching…</div>}
              {!suggesting && actorSuggestions.map((s: any, idx: number) => (
                <button
                  type="button"
                  key={idx}
                  onMouseDown={(e) => e.preventDefault()}
                  onClick={() => {
                    setActorId(s?.id || s?.stix_id || '');
                    setActorQuery(s?.name || '');
                    setShowSuggestions(false);
                  }}
                  className="block w-full text-left px-3 py-2 hover:bg-accent"
                >
                  <div className="text-sm">{s?.name || s?.id}</div>
                  {Array.isArray(s?.aliases) && s.aliases.length > 0 && (
                    <div className="text-[11px] text-gray-500">Aliases: {s.aliases.slice(0,5).join(', ')}</div>
                  )}
                </button>
              ))}
            </div>
          )}
          <label className="text-xs text-gray-500">min_support</label>
          <input type="number" value={minSupport} onChange={(e) => setMinSupport(parseInt(e.target.value || '1', 10))} className="h-9 w-24 rounded-md border px-3 text-sm bg-transparent" />
          <select value={metric} onChange={(e) => setMetric(e.target.value as any)} className="h-9 rounded-md border px-2 text-sm bg-transparent">
            <option value="npmi">Sort: NPMI</option>
            <option value="lift">Sort: Lift</option>
            <option value="confidence">Sort: Confidence</option>
          </select>
          <button onClick={load} className="h-9 rounded-md bg-black text-white dark:bg-white dark:text-black px-3 text-sm">Run</button>
        </div>
      </div>

      {error && <div className="text-sm text-red-600">{error}</div>}
      {loading && <div className="text-sm text-gray-500">Loading…</div>}

      {data && (
        <div className="space-y-6">
          <div className="rounded-lg border p-4">
            <div className="text-sm text-gray-500">Actor</div>
            <div className="text-lg font-medium">{actorQuery || data.intrusion_set_name || data.intrusion_set_id}</div>
            <div className="text-xs text-gray-400 mt-1">episodes: {data.total_episodes} · techniques: {data.total_techniques}</div>
          </div>

          <div className="space-y-2">
            <h2 className="text-base font-semibold">Top pairs</h2>
            <div className="overflow-x-auto rounded-lg border">
              <table className="min-w-full text-sm">
                <thead className="bg-gray-50 dark:bg-gray-900/50">
                  <tr>
                    <th className="px-3 py-2 text-left">Technique A</th>
                    <th className="px-3 py-2 text-left">Technique B</th>
                    <th className="px-3 py-2 text-right">Count</th>
                    <th className="px-3 py-2 text-right">Conf A→B</th>
                    <th className="px-3 py-2 text-right">Conf B→A</th>
                    <th className="px-3 py-2 text-right">Lift</th>
                    <th className="px-3 py-2 text-right">PMI</th>
                    <th className="px-3 py-2 text-right">NPMI</th>
                    <th className="px-3 py-2 text-right">Jaccard</th>
                  </tr>
                </thead>
                <tbody>
                  {data.top_pairs.map((p, idx) => (
                    <tr key={idx} className="border-t">
                      <td className="px-3 py-2">
                        <div className="text-sm font-medium">{p.name_a}</div>
                        {p.external_id_a && <div className="text-[11px] text-gray-500">{p.external_id_a}</div>}
                        <div className="text-[11px] text-gray-500">{p.technique_a}</div>
                      </td>
                      <td className="px-3 py-2">
                        <div className="text-sm font-medium">{p.name_b}</div>
                        {p.external_id_b && <div className="text-[11px] text-gray-500">{p.external_id_b}</div>}
                        <div className="text-[11px] text-gray-500">{p.technique_b}</div>
                      </td>
                      <td className="px-3 py-2 text-right">{p.count}</td>
                      <td className="px-3 py-2 text-right">{p.confidence_a_to_b}</td>
                      <td className="px-3 py-2 text-right">{p.confidence_b_to_a}</td>
                      <td className="px-3 py-2 text-right">{p.lift.toFixed(2)}</td>
                      <td className="px-3 py-2 text-right">{p.pmi.toFixed(3)}</td>
                      <td className="px-3 py-2 text-right">{p.npmi.toFixed(3)}</td>
                      <td className="px-3 py-2 text-right">{p.jaccard.toFixed(3)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          <div className="space-y-2">
            <h2 className="text-base font-semibold">Signature bundles</h2>
            <div className="overflow-x-auto rounded-lg border">
              <table className="min-w-full text-sm">
                <thead className="bg-gray-50 dark:bg-gray-900/50">
                  <tr>
                    <th className="px-3 py-2 text-left">Techniques</th>
                    <th className="px-3 py-2 text-right">Support</th>
                    <th className="px-3 py-2 text-right">Confidence</th>
                    <th className="px-3 py-2 text-right">Lift</th>
                    <th className="px-3 py-2 text-left">Tactics</th>
                  </tr>
                </thead>
                <tbody>
                  {data.signature_bundles.map((b, idx) => (
                    <tr key={idx} className="border-t">
                      <td className="px-3 py-2">
                        <div className="flex flex-wrap gap-2">
                          {b.technique_names.map((name, i) => (
                            <span key={i} className="rounded-md border px-2 py-0.5 text-xs">{name}</span>
                          ))}
                        </div>
                      </td>
                      <td className="px-3 py-2 text-right">{b.support}</td>
                      <td className="px-3 py-2 text-right">{b.confidence.toFixed(3)}</td>
                      <td className="px-3 py-2 text-right">{b.lift.toFixed(2)}</td>
                      <td className="px-3 py-2">{b.tactics.join(', ')}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}


