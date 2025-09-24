'use client'

import { useEffect, useMemo, useState } from 'react';
import { api } from '@/lib/api';

export default function ConditionalCooccurrencePage() {
  const [techId, setTechId] = useState('T1007'); // display value (T-code or STIX)
  const [selectedStixId, setSelectedStixId] = useState(''); // resolved STIX id from autocomplete
  const [limit, setLimit] = useState(25);
  const [rows, setRows] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [minCount, setMinCount] = useState<number>(0);
  const [minProb, setMinProb] = useState<number>(0);
  const [sortBy, setSortBy] = useState<'probability' | 'count' | 'name'>('probability');
  const [search, setSearch] = useState<string>('');

  // Autocomplete state
  const [techQuery, setTechQuery] = useState<string>('');
  const [suggestions, setSuggestions] = useState<any[]>([]);
  const [suggesting, setSuggesting] = useState<boolean>(false);
  const [showSuggestions, setShowSuggestions] = useState<boolean>(false);

  async function load() {
    if (!techId && !selectedStixId) return;
    setLoading(true);
    setError(null);
    try {
      const idToQuery = selectedStixId || techId; // prefer resolved STIX id if available
      const res = await api.cooccurrence.getConditional(idToQuery, limit);
      setRows(res.data?.results ?? []);
    } catch (e: any) {
      setError(e?.message || 'Failed to load');
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Debounced technique autocomplete
  useEffect(() => {
    const q = techQuery.trim();
    if (!q) {
      setSuggestions([]);
      return;
    }
    setSuggesting(true);
    const t = setTimeout(async () => {
      try {
        const res = await api.search.ttx(q, 8, ['AttackPattern']);
        const results = res.data?.results || [];
        setSuggestions(results);
        setShowSuggestions(true);
      } catch (e) {
        setSuggestions([]);
      } finally {
        setSuggesting(false);
      }
    }, 300);
    return () => clearTimeout(t);
  }, [techQuery]);

  const filtered = useMemo(() => {
    let r = rows;
    if (minCount > 0) r = r.filter((x: any) => (x.co_occurrence_count ?? 0) >= minCount);
    if (minProb > 0) r = r.filter((x: any) => (x.probability ?? 0) >= minProb);
    if (search) {
      const q = search.toLowerCase();
      r = r.filter((x: any) =>
        (x.co_technique_name || '').toLowerCase().includes(q) ||
        (x.co_technique_external_id || '').toLowerCase().includes(q) ||
        (x.co_technique || '').toLowerCase().includes(q)
      );
    }
    if (sortBy === 'probability') return [...r].sort((a, b) => (b.probability ?? 0) - (a.probability ?? 0));
    if (sortBy === 'count') return [...r].sort((a, b) => (b.co_occurrence_count ?? 0) - (a.co_occurrence_count ?? 0));
    return [...r].sort((a, b) => (a.co_technique_name || '').localeCompare(b.co_technique_name || ''));
  }, [rows, minCount, minProb, sortBy, search]);

  return (
    <div className="mx-auto max-w-6xl p-6 space-y-6">
      <div className="flex items-end justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-xl font-semibold">Conditional Co-occurrence</h1>
          <p className="text-sm text-gray-500 dark:text-gray-400">P(B|A) for techniques co-occurring with a given technique</p>
        </div>
        <div className="flex items-center gap-2 relative">
          <div className="flex flex-col">
            <div className="flex items-center gap-1">
            <input
              value={techId}
              onChange={(e) => { setTechId(e.target.value); setSelectedStixId(''); }}
              placeholder="Technique (T-code or STIX)"
              className="h-9 rounded-md border px-3 text-sm bg-transparent w-40"
            />
            <input
              value={techQuery}
              onChange={(e) => setTechQuery(e.target.value)}
              placeholder="Search technique name"
              className="h-9 rounded-md border px-3 text-sm bg-transparent w-56"
              onFocus={() => techQuery && setShowSuggestions(true)}
              onBlur={() => setTimeout(() => setShowSuggestions(false), 150)}
            />
            </div>
            <div className="text-[11px] text-gray-500 mt-1">
              <span className="mr-3">Name: {techQuery || '—'}</span>
              <span className="mr-3">T-code: {techId || '—'}</span>
              <span>STIX: {selectedStixId || '—'}</span>
            </div>
          </div>
          {showSuggestions && (suggestions?.length > 0 || suggesting) && (
            <div className="absolute top-10 left-0 z-10 w-[24rem] rounded-md border bg-background shadow">
              {suggesting && <div className="px-3 py-2 text-xs text-gray-500">Searching…</div>}
              {!suggesting && suggestions.map((s: any, idx: number) => {
                const id = s?.stix_id || s?.id || s?.technique_id || '';
                const name = s?.name || s?.title || id;
                const ext = s?.external_id || s?.externalId || '';
                return (
                  <button
                    type="button"
                    key={idx}
                    onMouseDown={(e) => e.preventDefault()}
                    onClick={() => {
                      setTechId(ext || id); // display T-code (or STIX) in the left box
                      setSelectedStixId(id); // keep resolved STIX id for API calls
                      setTechQuery(name); // keep the selected technique name visible in the search box
                      setShowSuggestions(false);
                    }}
                    className="block w-full text-left px-3 py-2 hover:bg-accent"
                  >
                    <div className="text-sm">{name}</div>
                    <div className="text-[11px] text-gray-500">{ext || id}</div>
                  </button>
                );
              })}
            </div>
          )}
          <label className="text-xs text-gray-500">limit</label>
          <input type="number" value={limit} onChange={(e) => setLimit(parseInt(e.target.value || '25', 10))} className="h-9 w-24 rounded-md border px-3 text-sm bg-transparent" />
          <label className="text-xs text-gray-500">min_count</label>
          <input type="number" value={minCount} onChange={(e) => setMinCount(parseInt(e.target.value || '0', 10))} className="h-9 w-24 rounded-md border px-3 text-sm bg-transparent" />
          <label className="text-xs text-gray-500">min_p</label>
          <input type="number" step="0.01" value={minProb} onChange={(e) => setMinProb(parseFloat(e.target.value || '0'))} className="h-9 w-24 rounded-md border px-3 text-sm bg-transparent" />
          <select value={sortBy} onChange={(e) => setSortBy(e.target.value as any)} className="h-9 rounded-md border px-2 text-sm bg-transparent">
            <option value="probability">Sort: P(B|A)</option>
            <option value="count">Sort: Count</option>
            <option value="name">Sort: Name</option>
          </select>
          <div className="flex flex-col">
            <input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Search B name/T-code/STIX" className="h-9 rounded-md border px-3 text-sm bg-transparent w-56" />
            <div className="text-[11px] text-gray-500 mt-1">B filter: {search || '—'}</div>
          </div>
          <button onClick={load} className="h-9 rounded-md bg-black text-white dark:bg-white dark:text-black px-3 text-sm">Run</button>
        </div>
      </div>

      {error && <div className="text-sm text-red-600">{error}</div>}
      {loading && <div className="text-sm text-gray-500">Loading…</div>}

      <div className="overflow-x-auto rounded-lg border">
        <table className="min-w-full text-sm">
          <thead className="bg-gray-50 dark:bg-gray-900/50">
            <tr>
              <th className="px-3 py-2 text-left">Co-technique</th>
              <th className="px-3 py-2 text-right">Episodes with A</th>
              <th className="px-3 py-2 text-right">Co-occurrence</th>
              <th className="px-3 py-2 text-right">P(B|A)</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((r: any, idx: number) => (
              <tr key={idx} className="border-t">
                <td className="px-3 py-2">
                  <div className="text-sm font-medium">{r.co_technique_name}</div>
                  {r.co_technique_external_id && (
                    <div className="text-[11px] text-gray-500">{r.co_technique_external_id}</div>
                  )}
                  <div className="text-[11px] text-gray-500">{r.co_technique}</div>
                </td>
                <td className="px-3 py-2 text-right">{r.episodes_with_given}</td>
                <td className="px-3 py-2 text-right">{r.co_occurrence_count}</td>
                <td className="px-3 py-2 text-right">{Number(r.probability).toFixed(3)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}


