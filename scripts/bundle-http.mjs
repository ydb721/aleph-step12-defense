const INTEGER_HEADER = /^\d{1,20}$/u;

const safeHeader = (response, name) => {
  try {
    const value = response?.headers?.get(name);
    return typeof value === 'string' && INTEGER_HEADER.test(value) ? value : 'unknown';
  } catch {
    return 'unknown';
  }
};

const failureType = (status, remaining, retryAfter) => {
  if (remaining === '0') return 'primary_rate_limit';
  if (status === 429 || retryAfter !== 'unknown') return 'retry_later';
  return 'access_forbidden';
};

export async function fetchPublic(url, label) {
  let response;
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 10_000);
  try {
    response = await fetch(url, {
      method: 'GET',
      signal: controller.signal,
      headers: {
        Accept: 'application/vnd.github+json',
        'User-Agent': 'BYTE-BACK-step12-bundle',
      },
    });
  } catch {
    throw new Error(`${label} 공개 HTTPS GET에 실패했습니다.`);
  } finally {
    clearTimeout(timeout);
  }
  if (!response?.ok) {
    const status = response?.status ?? 'network';
    if (status === 403 || status === 429) {
      const remaining = safeHeader(response, 'x-ratelimit-remaining');
      const reset = safeHeader(response, 'x-ratelimit-reset');
      const retryAfter = safeHeader(response, 'retry-after');
      const type = failureType(status, remaining, retryAfter);
      throw new Error(`${label} 공개 HTTPS GET 거부: HTTP ${status}; type=${type}; remaining=${remaining}; reset=${reset}; retryAfter=${retryAfter}.`);
    }
    throw new Error(`${label} 공개 HTTPS GET이 HTTP ${status}로 실패했습니다.`);
  }
  return response;
}
