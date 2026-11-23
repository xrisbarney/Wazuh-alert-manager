import type { EnrichmentResult } from '../../../common';
import {
  EnrichmentProvider,
  EnrichmentSourceError,
  LookupContext,
  buildResult,
  clampScore,
  fetchSource,
  parseJsonBody,
  verdictFromScore,
} from './provider';

/**
 * AbuseIPDB v2 `check` endpoint (IP addresses only). The abuse confidence
 * score (0-100) is the result score; >= 75 is malicious, >= 25 suspicious,
 * anything below is clean (the service has seen the address and scores it low).
 */
export const ABUSEIPDB_ENDPOINT = 'https://api.abuseipdb.com/api/v2/check';
export const ABUSEIPDB_MAX_AGE_DAYS = 90;

export const abuseIpDbProvider: EnrichmentProvider = {
  kind: 'abuseipdb',
  async lookup({ source, type, value, now }: LookupContext): Promise<EnrichmentResult> {
    if (type !== 'ip') throw new EnrichmentSourceError('AbuseIPDB only looks up IP addresses.');
    if (!source.apiKey) throw new EnrichmentSourceError(`${source.name}: no API key is configured.`);
    const url = `${ABUSEIPDB_ENDPOINT}?ipAddress=${encodeURIComponent(value)}&maxAgeInDays=${ABUSEIPDB_MAX_AGE_DAYS}`;
    const response = await fetchSource(source, url, {
      method: 'GET',
      headers: { Key: source.apiKey, Accept: 'application/json' },
    });
    const body = parseJsonBody(response, source.name);
    const data = body && typeof body === 'object' ? body.data : null;
    if (!data || typeof data !== 'object') {
      const errors = Array.isArray(body?.errors) ? body.errors.map((e: any) => e?.detail).filter(Boolean).join('; ') : '';
      throw new EnrichmentSourceError(`${source.name}: unexpected response${errors ? `: ${errors}` : ''}.`);
    }
    const score = clampScore(data.abuseConfidenceScore);
    const reports = Number(data.totalReports) || 0;
    const tags: string[] = [];
    if (typeof data.countryCode === 'string' && data.countryCode) tags.push(`country:${data.countryCode}`);
    if (typeof data.usageType === 'string' && data.usageType) tags.push(data.usageType);
    if (typeof data.isp === 'string' && data.isp) tags.push(`isp:${data.isp}`);
    if (data.isTor === true) tags.push('tor');
    if (data.isWhitelisted === true) tags.push('whitelisted');
    const last = typeof data.lastReportedAt === 'string' && data.lastReportedAt ? `, last ${data.lastReportedAt}` : '';
    return buildResult(
      source,
      {
        verdict: verdictFromScore(score),
        score,
        tags,
        link: `https://www.abuseipdb.com/check/${encodeURIComponent(value)}`,
        summary: `Abuse confidence ${score ?? '?'}% (${reports} report${reports === 1 ? '' : 's'} in ${ABUSEIPDB_MAX_AGE_DAYS} days${last})`,
      },
      now
    );
  },
};
