import workerSource from './miner.worker.js?raw';

export function createMinerWorker() {
  const blob = new Blob([workerSource], { type: 'text/javascript' });
  const url = URL.createObjectURL(blob);
  const w = new Worker(url, { type: 'module' });
  // Safe to revoke immediately; the worker has already started fetching the URL.
  URL.revokeObjectURL(url);
  return w;
}
