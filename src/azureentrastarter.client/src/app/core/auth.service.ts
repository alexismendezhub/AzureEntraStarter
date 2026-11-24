import { HttpClient, HttpHeaders, HttpResponse } from '@angular/common/http';
import { Injectable, OnDestroy, computed, inject, signal } from '@angular/core';
import { Router } from '@angular/router';
import { Observable, catchError, finalize, firstValueFrom, map, of, shareReplay, switchMap, tap, timer } from 'rxjs';
import { HOME_URL, XSRF_COOKIE_NAME, XSRF_HEADER_NAME } from './auth.constants';
import { AuthConfig, AuthResponse, LogoutResponse, UserInfo } from './models';
import { NavigationService } from './navigation.service';

/** Only a local path is ever used after sign-in (the server applies the same rule). */
export function safeReturnUrl(value: string | null | undefined): string {
  return value && value.startsWith('/') && !value.startsWith('//') && !value.includes('\\') ? value : HOME_URL;
}

/**
 * The browser side of the session. The access token lives only in memory (never in Web Storage); a page reload gets a
 * new one through the HttpOnly refresh cookie, which JavaScript never sees.
 */
@Injectable({ providedIn: 'root' })
export class AuthService implements OnDestroy {
  private readonly http = inject(HttpClient);
  private readonly router = inject(Router);
  private readonly navigation = inject(NavigationService);
  private refreshing?: Observable<string | null>;
  private renewTimer?: ReturnType<typeof setTimeout>;

  readonly config = signal<AuthConfig>({ entraEnabled: false });
  readonly token = signal<string | null>(null);
  readonly user = signal<UserInfo | null>(null);
  readonly sessionExpiresAt = signal<Date | null>(null);
  readonly isAuthenticated = computed(() => !!this.token() && !!this.user());

  /** Runs once at startup: what sign-in offers, then a silent refresh if this browser has a session. */
  async initialize(): Promise<void> {
    try {
      this.config.set(await firstValueFrom(this.http.get<AuthConfig>('/api/auth/config')));
    } catch {
      this.config.set({ entraEnabled: false });
    }
    try {
      await firstValueFrom(this.refresh());
    } catch {
      this.clear();
    }
  }

  hasRole(role: string): boolean {
    return !!this.user()?.roles.includes(role);
  }

  /** Full-page navigation to the server, which redirects to Microsoft. */
  signIn(returnUrl: string = HOME_URL, prompt?: 'login' | 'select_account'): void {
    const params = new URLSearchParams({ returnUrl: safeReturnUrl(returnUrl) });
    if (prompt) params.set('prompt', prompt);
    this.navigation.assign(`/api/auth/entra/start?${params.toString()}`);
  }

  /** Exchanges the one-time ticket the server put in the URL fragment for this browser's session. */
  completeSignIn(ticket: string): Observable<AuthResponse> {
    return this.http.post<AuthResponse>('/api/auth/entra/exchange', { ticket }).pipe(tap((r) => this.store(r)));
  }

  /**
   * Rotates the refresh cookie and gets a new access token. Concurrent callers share one request. Resolves to null when
   * there is no session (the server has cleared its cookies).
   */
  refresh(): Observable<string | null> {
    if (this.refreshing) return this.refreshing;
    const attempt = (retry: boolean): Observable<string | null> => {
      const xsrf = this.navigation.cookie(XSRF_COOKIE_NAME);
      // No XSRF cookie: this browser has no session, so there is nothing to refresh (and no noisy 403).
      if (!xsrf) {
        this.clear();
        return of(null);
      }
      return this.http
        .post<AuthResponse>('/api/auth/refresh', {}, { observe: 'response', headers: new HttpHeaders({ [XSRF_HEADER_NAME]: xsrf }) })
        .pipe(
          switchMap((response: HttpResponse<AuthResponse>) => {
            if (response.status === 200 && response.body) {
              this.store(response.body);
              return of(response.body.accessToken);
            }
            // 204 with the cookies still present: another tab rotated them a moment ago; try once with the new ones.
            if (retry && this.navigation.cookie(XSRF_COOKIE_NAME)) return timer(150).pipe(switchMap(() => attempt(false)));
            this.clear();
            return of(null);
          }),
        );
    };
    this.refreshing = attempt(true).pipe(
      catchError(() => {
        this.clear();
        return of(null);
      }),
      finalize(() => (this.refreshing = undefined)),
      shareReplay({ bufferSize: 1, refCount: false }),
    );
    return this.refreshing;
  }

  /** Ends the session here (and at Microsoft when the server is configured to). */
  logout(): Observable<void> {
    const xsrf = this.navigation.cookie(XSRF_COOKIE_NAME);
    const headers = xsrf ? new HttpHeaders({ [XSRF_HEADER_NAME]: xsrf }) : undefined;
    return this.http.post<LogoutResponse | null>('/api/auth/logout', {}, { headers }).pipe(
      catchError(() => of(null)),
      map((response) => {
        this.clear();
        if (response?.microsoftSignOutUrl) this.navigation.assign(response.microsoftSignOutUrl);
        else void this.router.navigateByUrl('/signed-out');
      }),
    );
  }

  clear(): void {
    clearTimeout(this.renewTimer);
    this.token.set(null);
    this.user.set(null);
    this.sessionExpiresAt.set(null);
  }

  ngOnDestroy(): void {
    clearTimeout(this.renewTimer);
  }

  private store(response: AuthResponse): void {
    this.token.set(response.accessToken);
    this.user.set(response.user);
    this.sessionExpiresAt.set(new Date(response.sessionExpiresAtUtc));
    // Renew a minute before the access token expires, so requests rarely meet a 401.
    clearTimeout(this.renewTimer);
    const delay = new Date(response.expiresAtUtc).getTime() - Date.now() - 60_000;
    this.renewTimer = setTimeout(() => this.refresh().subscribe(), Math.max(delay, 5_000));
  }
}
