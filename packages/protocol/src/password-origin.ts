/** Exact V1 wire origin grammar; no URL repair, IDNA conversion, or path stripping. */
export function isCanonicalPasswordOrigin(value: string): boolean {
  if (typeof value !== 'string' || value.length > 2048) return false;
  const match = /^(https?):\/\/([a-z0-9.-]+)(?::([1-9][0-9]{0,4}))?$/.exec(value);
  if (!match) return false;
  const [, scheme, host, portText] = match;
  if (!scheme || !host || host.length > 253) return false;
  const labels = host.split('.');
  const numericHost = /^[0-9.]+$/.test(host);
  if (numericHost) {
    if (labels.length !== 4 || labels.some(label => !/^(0|[1-9][0-9]{0,2})$/.test(label) || Number(label) > 255)) return false;
  } else {
    if (host !== 'localhost' && (labels.length < 2 || !/^[a-z]/.test(labels.at(-1)!))) return false;
    if (labels.some(label => label.length < 1 || label.length > 63 || label.startsWith('xn--') ||
        !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label))) return false;
  }
  if (scheme === 'http' && host !== 'localhost' && host !== '127.0.0.1') return false;
  if (portText) {
    const port = Number(portText);
    if (port < 1 || port > 65535 || (scheme === 'https' && port === 443) || (scheme === 'http' && port === 80)) return false;
  }
  return true;
}
