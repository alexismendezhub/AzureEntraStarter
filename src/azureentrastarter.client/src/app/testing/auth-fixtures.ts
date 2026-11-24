import { AuthResponse } from '../core/models';

export function authResponse(token = 'access-1', roles: string[] = [], minutes = 10): AuthResponse {
  return {
    accessToken: token,
    expiresAtUtc: new Date(Date.now() + minutes * 60_000).toISOString(),
    sessionExpiresAtUtc: new Date(Date.now() + 12 * 3_600_000).toISOString(),
    user: {
      id: 'user-1',
      displayName: 'Pat Doe',
      email: 'pat@contoso.example',
      tenantId: '11111111-1111-1111-1111-111111111111',
      objectId: '33333333-3333-3333-3333-333333333333',
      roles,
    },
  };
}
