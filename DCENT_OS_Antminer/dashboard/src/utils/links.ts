/** Shared destinations for every dashboard support surface. */
export const DCENT_FUND_CANONICAL_URL = 'https://d-central.tech/fund/';
export const DCENT_DOCS_URL = '/#/help';

export function fundContributeUrl(placement: string): string {
  return `${DCENT_FUND_CANONICAL_URL}go?source=dcent_os&placement=${encodeURIComponent(placement)}`;
}
