"use client";

import { useEffect, useMemo, useState } from 'react';
import { api } from '@/lib/api';

type Pair = {
  technique_a: string;
  technique_b: string;
  name_a: string;
  name_b: string;
  external_id_a?: string | null;
  external_id_b?: string | null;
  count: number;
  lift: number;
  pmi: number;
  npmi: number;
  jaccard: number;
};

export default function CooccurrencePairsPage() {
  const [minSupport, setMinSupport] = useState<number>(2);
  const [minEpisodes, setMinEpisodes] = useState<number>(2);
  const [limit, setLimit] = useState<number>(50);
  const [sortBy, setSortBy] = useState<'npmi' | 'lift' | 'count'>('npmi');

  const [pairs, setPairs] = useState<Pair[]>([]);
  const [stats, setStats] = useState<{ total_pairs?: number; episode_count?: number; technique_count?: number } | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  async function load() {
    setLoading(true);
    setError(null);
    try {
      const res = await api.cooccurrence.postGlobal({
        min_support: minSupport,
        min_episodes_per_pair: minEpisodes,
        limit,
      });
      const data = res.data as any;
      setPairs((data?.pairs ?? []) as Pair[]);
      setStats({
        total_pairs: data?.total_pairs,
        episode_count: data?.episode_count,
        technique_count: data?.technique_count,
      });
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

  const sorted = useMemo(() => {
    const arr = [...pairs];
    if (sortBy === 'npmi') return arr.sort((a, b) => (b.npmi ?? 0) - (a.npmi ?? 0));
    if (sortBy === 'lift') return arr.sort((a, b) => (b.lift ?? 0) - (a.lift ?? 0));
    return arr.sort((a, b) => (b.count ?? 0) - (a.count ?? 0));
  }, [pairs, sortBy]);

  return (
    <div className="mx-auto max-w-6xl p-6 space-y-6">
      <div className="flex items-end justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-xl font-semibold">Pairs Explorer</h1>
          <p className="text-sm text-gray-500 dark:text-gray-400">Global co-occurring technique pairs</p>
          {stats && (
            <p className="text-xs text-gray-400 mt-1">episodes: {stats.episode_count ?? '-'} · techniques: {stats.technique_count ?? '-'} · pairs: {stats.total_pairs ?? '-'}</p>
          )}
        </div>
        <div className="flex items-center gap-2">
          <label className="text-xs text-gray-500">min_support</label>
          <input type="number" value={minSupport} onChange={(e) => setMinSupport(parseInt(e.target.value || '0', 10))} className="h-9 w-24 rounded-md border px-3 text-sm bg-transparent" />
          <label className="text-xs text-gray-500">min_episodes</label>
          <input type="number" value={minEpisodes} onChange={(e) => setMinEpisodes(parseInt(e.target.value || '0', 10))} className="h-9 w-24 rounded-md border px-3 text-sm bg-transparent" />
          <label className="text-xs text-gray-500">limit</label>
          <input type="number" value={limit} onChange={(e) => setLimit(parseInt(e.target.value || '0', 10))} className="h-9 w-24 rounded-md border px-3 text-sm bg-transparent" />
          <select value={sortBy} onChange={(e) => setSortBy(e.target.value as any)} className="h-9 rounded-md border px-2 text-sm bg-transparent">
            <option value="npmi">Sort: NPMI</option>
            <option value="lift">Sort: Lift</option>
            <option value="count">Sort: Count</option>
          </select>
          <button onClick={load} className="h-9 rounded-md bg-black text-white dark:bg-white dark:text-black px-3 text-sm">Apply</button>
        </div>
      </div>

      {error && <div className="text-sm text-red-600">{error}</div>}
      {loading && <div className="text-sm text-gray-500">Loading…</div>}

      <div className="overflow-x-auto rounded-lg border">
        <table className="min-w-full text-sm">
          <thead className="bg-gray-50 dark:bg-gray-900/50">
            <tr>
              <th className="px-3 py-2 text-left">Technique A</th>
              <th className="px-3 py-2 text-left">Technique B</th>
              <th className="px-3 py-2 text-right">Count</th>
              <th className="px-3 py-2 text-right">Lift</th>
              <th className="px-3 py-2 text-right">PMI</th>
              <th className="px-3 py-2 text-right">NPMI</th>
              <th className="px-3 py-2 text-right">Jaccard</th>
            </tr>
          </thead>
          <tbody>
            {sorted.map((p: Pair, idx: number) => (
              <tr key={idx} className="border-t">
                <td className="px-3 py-2">
                  <div className="text-sm font-medium">{p.name_a}</div>
                  {p.external_id_a && (
                    <div className="text-[11px] text-gray-500">{p.external_id_a}</div>
                  )}
                  <div className="text-[11px] text-gray-500">{p.technique_a}</div>
                </td>
                <td className="px-3 py-2">
                  <div className="text-sm font-medium">{p.name_b}</div>
                  {p.external_id_b && (
                    <div className="text-[11px] text-gray-500">{p.external_id_b}</div>
                  )}
                  <div className="text-[11px] text-gray-500">{p.technique_b}</div>
                </td>
                <td className="px-3 py-2 text-right">{p.count}</td>
                <td className="px-3 py-2 text-right">{Number(p.lift).toFixed(2)}</td>
                <td className="px-3 py-2 text-right">{Number(p.pmi).toFixed(3)}</td>
                <td className="px-3 py-2 text-right">{Number(p.npmi).toFixed(3)}</td>
                <td className="px-3 py-2 text-right">{Number(p.jaccard).toFixed(3)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}


