import type { HeaterTargetResponse } from '../api/types';

export function heaterTargetFeedback(result: HeaterTargetResponse): { message: string; tone: 'success' | 'warning' | 'error' } {
  if (result.status !== 'ok') return { message: result.message || 'Failed to save power target', tone: 'error' };
  if (result.applied_runtime === true) return { message: result.message, tone: 'success' };
  return { message: result.runtime?.message || 'Target saved; live application has not been confirmed.', tone: 'warning' };
}
