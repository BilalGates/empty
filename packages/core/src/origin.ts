export function normalizeOrigin(input: string): string {
  const url = new URL(input);
  if (url.protocol !== 'https:' && url.hostname !== 'localhost' && url.hostname !== '127.0.0.1') throw new Error('Only secure origins are supported');
  if (url.username || url.password) throw new Error('Credentials in URL are not allowed');
  return url.origin.toLowerCase();
}

export function matchesOrigin(candidate: string, savedOrigins: readonly string[]): boolean {
  let normalized: string;
  try { normalized = normalizeOrigin(candidate); } catch { return false; }
  return savedOrigins.some(saved => {
    try { return normalizeOrigin(saved) === normalized; } catch { return false; }
  });
}

