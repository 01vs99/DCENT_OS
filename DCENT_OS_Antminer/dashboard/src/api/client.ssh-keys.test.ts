import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('./credentials', () => ({
  getSessionToken: () => 'fixture-admin-session',
  setSessionToken: vi.fn(),
  getVolatilePassword: () => null,
  setVolatilePassword: vi.fn(),
}));
import { api } from './client';

const status = { available: true, scope: 'classic_aml_nvdata', reason: null,
  fingerprints: ['SHA256:public-fixture'], operator_disabled: false, root_password_changed: false };
const fetchMock = vi.fn();
beforeEach(() => { fetchMock.mockReset(); vi.stubGlobal('fetch', fetchMock); });
afterEach(() => vi.unstubAllGlobals());

describe('SSH key client contract', () => {
  it('uses the admin bearer for exact read-only key status', async () => {
    fetchMock.mockResolvedValue(new Response(JSON.stringify(status), { status: 200 }));
    expect(await api.getSshKeyStatus()).toEqual(status);
    const [path, init] = fetchMock.mock.calls[0];
    expect(path).toBe('/api/system/ssh/keys');
    expect(new Headers(init.headers).get('Authorization')).toBe('Bearer fixture-admin-session');
    expect(init.method ?? 'GET').toBe('GET');
  });

  it('keeps saved-key and activation-failure fields distinct', async () => {
    const result = { status, persisted: true, durable: true, activation: 'failed', activation_error: 'inert fixture refusal' };
    fetchMock.mockResolvedValue(new Response(JSON.stringify(result), { status: 200 }));
    expect(await api.enrollSshKeys('ssh-ed25519 public-fixture', true)).toEqual(result);
    const [path, init] = fetchMock.mock.calls[0];
    expect(path).toBe('/api/system/ssh/keys');
    expect(init.method).toBe('POST');
    expect(new Headers(init.headers).get('Authorization')).toBe('Bearer fixture-admin-session');
    expect(JSON.parse(init.body)).toEqual({ public_keys: 'ssh-ed25519 public-fixture', enable_ssh: true });
  });

  it('surfaces refusal without falling back to another endpoint or password login', async () => {
    fetchMock.mockResolvedValue(new Response(JSON.stringify({ error: 'Admin session required' }), { status: 403 }));
    await expect(api.enrollSshKeys('ssh-ed25519 public-fixture', true)).rejects.toMatchObject({ status: 403 });
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });
});
