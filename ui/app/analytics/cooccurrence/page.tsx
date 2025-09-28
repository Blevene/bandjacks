import { api } from '@/lib/api';

export const dynamic = 'force-dynamic';
export const revalidate = 0;

export default async function CooccurrenceHubPage() {
  let episodes: number | undefined;
  let techniques: number | undefined;
  let intrusionSets: number | undefined;

  try {
    // Prefer lightweight stats endpoint for totals
    const statsRes = await api.analytics.getStatistics();
    const s = statsRes.data || {};
    episodes = s?.attack_flows?.total_flows || s?.attack_flows?.total || s?.attack_flows || undefined;
    techniques = s?.attack_patterns?.techniques || s?.attack_patterns?.total || s?.attack_patterns || undefined;
    intrusionSets = s?.threat_groups?.total || s?.threat_groups || undefined;
  } catch (e) {
    // leave KPIs as placeholders; page still renders
  }

  return (
    <div className="mx-auto max-w-6xl p-6 space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Co-occurrence Analytics</h1>
        <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">
          Explore technique co-occurrence across episodes, drill into actor-specific patterns,
          and discover frequent bundles that inform hunting, detection, and response.
        </p>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div className="rounded-lg border p-4">
          <div className="text-xs text-gray-500">Episodes</div>
          <div className="text-xl font-semibold">{episodes ?? '—'}</div>
        </div>
        <div className="rounded-lg border p-4">
          <div className="text-xs text-gray-500">Techniques in scope</div>
          <div className="text-xl font-semibold">{techniques ?? '—'}</div>
        </div>
        <div className="rounded-lg border p-4">
          <div className="text-xs text-gray-500">Intrusion sets</div>
          <div className="text-xl font-semibold">{intrusionSets ?? '—'}</div>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <a href="/analytics/cooccurrence/pairs" className="rounded-lg border p-4 hover:bg-gray-50 dark:hover:bg-gray-900">
          <h2 className="font-medium">Pairs Explorer</h2>
          <p className="text-sm text-gray-500 dark:text-gray-400">Global co-occurring technique pairs with NPMI/Lift.</p>
        </a>
        <a href="/analytics/cooccurrence/conditional" className="rounded-lg border p-4 hover:bg-gray-50 dark:hover:bg-gray-900">
          <h2 className="font-medium">Conditional Explorer</h2>
          <p className="text-sm text-gray-500 dark:text-gray-400">Given technique A, see P(B|A) and counts.</p>
        </a>
        <a href="/analytics/cooccurrence/actors" className="rounded-lg border p-4 hover:bg-gray-50 dark:hover:bg-gray-900">
          <h2 className="font-medium">Actor Insights</h2>
          <p className="text-sm text-gray-500 dark:text-gray-400">Top pairs and bundles per intrusion set.</p>
        </a>
        <a href="/analytics/cooccurrence/bundles" className="rounded-lg border p-4 hover:bg-gray-50 dark:hover:bg-gray-900">
          <h2 className="font-medium">Bundles Explorer</h2>
          <p className="text-sm text-gray-500 dark:text-gray-400">Frequent technique bundles with coverage.</p>
        </a>
        <a href="/analytics/cooccurrence/bridging" className="rounded-lg border p-4 hover:bg-gray-50 dark:hover:bg-gray-900">
          <h2 className="font-medium">Bridging Techniques</h2>
          <p className="text-sm text-gray-500 dark:text-gray-400">Techniques used across many actors.</p>
        </a>
      </div>
    </div>
  );
}


