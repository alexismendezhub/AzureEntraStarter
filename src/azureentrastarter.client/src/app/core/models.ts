export interface UserInfo {
  id: string;
  displayName: string;
  email: string;
  tenantId: string;
  objectId: string;
  roles: string[];
}

export interface AuthResponse {
  accessToken: string;
  expiresAtUtc: string;
  sessionExpiresAtUtc: string;
  user: UserInfo;
}

export interface AuthConfig {
  entraEnabled: boolean;
}

export interface LogoutResponse {
  microsoftSignOutUrl: string | null;
}
