import { HttpClient, provideHttpClient, withInterceptors } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { Router, provideRouter } from '@angular/router';
import { firstValueFrom } from 'rxjs';
import { authResponse } from '../testing/auth-fixtures';
import { FakeNavigation } from '../testing/fake-navigation';
import { XSRF_COOKIE_NAME } from './auth.constants';
import { authInterceptor } from './auth.interceptor';
import { AuthService } from './auth.service';
import { NavigationService } from './navigation.service';

describe('authInterceptor', () => {
  let http: HttpTestingController;
  let client: HttpClient;
  let auth: AuthService;
  let nav: FakeNavigation;

  beforeEach(async () => {
    TestBed.configureTestingModule({
      providers: [
        provideRouter([]),
        provideHttpClient(withInterceptors([authInterceptor])),
        provideHttpClientTesting(),
        { provide: NavigationService, useClass: FakeNavigation },
      ],
    });
    http = TestBed.inject(HttpTestingController);
    client = TestBed.inject(HttpClient);
    auth = TestBed.inject(AuthService);
    nav = TestBed.inject(NavigationService) as FakeNavigation;
    const signIn = firstValueFrom(auth.completeSignIn('ticket'));
    http.expectOne('/api/auth/entra/exchange').flush(authResponse('token-1'));
    await signIn;
  });

  afterEach(() => {
    auth.clear();
    http.verify();
  });

  it('sends the bearer token to this application\'s API only', () => {
    client.get('/api/sample/hello').subscribe();
    client.get('https://graph.microsoft.com/v1.0/me').subscribe();
    client.get('/assets/x.json').subscribe();
    expect(http.expectOne('/api/sample/hello').request.headers.get('Authorization')).toBe('Bearer token-1');
    expect(http.expectOne('https://graph.microsoft.com/v1.0/me').request.headers.has('Authorization')).toBeFalse();
    expect(http.expectOne('/assets/x.json').request.headers.has('Authorization')).toBeFalse();
  });

  it('never sends the bearer token to the session endpoints', () => {
    client.post('/api/auth/logout', {}).subscribe();
    expect(http.expectOne('/api/auth/logout').request.headers.has('Authorization')).toBeFalse();
  });

  it('on 401 refreshes once and replays the request with the new token', async () => {
    nav.cookies.set(XSRF_COOKIE_NAME, 'x');
    const result = firstValueFrom(client.get<{ ok: boolean }>('/api/sample/hello'));
    http.expectOne('/api/sample/hello').flush(null, { status: 401, statusText: 'Unauthorized' });
    http.expectOne('/api/auth/refresh').flush(authResponse('token-2'));
    const replay = http.expectOne('/api/sample/hello');
    expect(replay.request.headers.get('Authorization')).toBe('Bearer token-2');
    replay.flush({ ok: true });
    expect(await result).toEqual({ ok: true });
  });

  it('when the session is gone it goes to sign-in and keeps the error', async () => {
    const router = TestBed.inject(Router);
    spyOn(router, 'navigate').and.resolveTo(true);
    const result = firstValueFrom(client.get('/api/sample/hello')).catch((e) => e.status);
    http.expectOne('/api/sample/hello').flush(null, { status: 401, statusText: 'Unauthorized' });
    // No XSRF cookie: nothing to refresh, so no refresh request.
    expect(await result).toBe(401);
    expect(router.navigate).toHaveBeenCalledWith(['/login'], { queryParams: { returnUrl: '/' } });
    expect(auth.isAuthenticated()).toBeFalse();
  });

  it('does not refresh for a 403 (missing role) or for a failing session endpoint', async () => {
    nav.cookies.set(XSRF_COOKIE_NAME, 'x');
    const forbidden = firstValueFrom(client.get('/api/admin/users')).catch((e) => e.status);
    http.expectOne('/api/admin/users').flush(null, { status: 403, statusText: 'Forbidden' });
    expect(await forbidden).toBe(403);
    const exchange = firstValueFrom(client.post('/api/auth/entra/exchange', {})).catch((e) => e.status);
    http.expectOne('/api/auth/entra/exchange').flush(null, { status: 401, statusText: 'Unauthorized' });
    expect(await exchange).toBe(401);
    http.expectNone('/api/auth/refresh');
  });
});
