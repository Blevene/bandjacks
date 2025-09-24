export default function CooccurrenceHubPage() {
  return (
    <div className="mx-auto max-w-6xl p-6 space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Co-occurrence Analytics</h1>
        <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">
          Explore technique co-occurrence across episodes, by actor, and within bundles.
        </p>
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


