import { provideHttpClient, withInterceptors } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { TestBed, fakeAsync, flushMicrotasks, tick } from '@angular/core/testing';
import { Router, provideRouter } from '@angular/router';
import { firstValueFrom } from 'rxjs';
import { authResponse } from '../testing/auth-fixtures';
import { FakeNavigation } from '../testing/fake-navigation';
import { XSRF_COOKIE_NAME, XSRF_HEADER_NAME } from './auth.constants';
import { authInterceptor } from './auth.interceptor';
import { AuthService, safeReturnUrl } from './auth.service';
import { NavigationService } from './navigation.service';

describe('AuthService', () => {
  let http: HttpTestingController;
  let auth: AuthService;
  let nav: FakeNavigation;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [
        provideRouter([]),
        provideHttpClient(withInterceptors([authInterceptor])),
        provideHttpClientTesting(),
        { provide: NavigationService, useClass: FakeNavigation },
      ],
    });
    http = TestBed.inject(HttpTestingController);
    auth = TestBed.inject(AuthService);
    nav = TestBed.inject(NavigationService) as FakeNavigation;
  });

  afterEach(() => {
    auth.clear();
    http.verify();
  });

  it('accepts only local return URLs', () => {
    expect(safeReturnUrl('/profile?x=1')).toBe('/profile?x=1');
    expect(safeReturnUrl('//evil.example')).toBe('/');
    expect(safeReturnUrl('https://evil.example')).toBe('/');
    expect(safeReturnUrl('/\\evil.example')).toBe('/');
    expect(safeReturnUrl(null)).toBe('/');
  });

  it('starts the Microsoft sign-in on the server with a safe return URL', () => {
    auth.signIn('/admin');
    auth.signIn('//evil.example', 'select_account');
    expect(nav.assigned).toEqual([
      '/api/auth/entra/start?returnUrl=%2Fadmin',
      '/api/auth/entra/start?returnUrl=%2F&prompt=select_account',
    ]);
  });

  it('on startup loads the config and does not refresh without a session cookie', async () => {
    const done = auth.initialize();
    http.expectOne('/api/auth/config').flush({ entraEnabled: true });
    await done;
    expect(auth.config().entraEnabled).toBeTrue();
    expect(auth.isAuthenticated()).toBeFalse();
    http.expectNone('/api/auth/refresh');
  });

  it('on startup restores the session through the refresh cookie, sending the XSRF header', async () => {
    nav.cookies.set(XSRF_COOKIE_NAME, 'xsrf-value');
    const done = auth.initialize();
    http.expectOne('/api/auth/config').flush({ entraEnabled: true });
    await new Promise((r) => setTimeout(r));
    const req = http.expectOne('/api/auth/refresh');
    expect(req.request.method).toBe('POST');
    expect(req.request.headers.get(XSRF_HEADER_NAME)).toBe('xsrf-value');
    expect(req.request.headers.has('Authorization')).toBeFalse();
    req.flush(authResponse('restored', ['Admin']));
    await done;
    expect(auth.token()).toBe('restored');
    expect(auth.hasRole('Admin')).toBeTrue();
    expect(auth.hasRole('Other')).toBeFalse();
  });

  it('keeps the sign-in page usable when the config cannot be read', async () => {
    const done = auth.initialize();
    http.expectOne('/api/auth/config').flush({}, { status: 500, statusText: 'Error' });
    await done;
    expect(auth.config().entraEnabled).toBeFalse();
  });

  it('shares one refresh between concurrent callers', async () => {
    nav.cookies.set(XSRF_COOKIE_NAME, 'x');
    const a = firstValueFrom(auth.refresh());
    const b = firstValueFrom(auth.refresh());
    http.expectOne('/api/auth/refresh').flush(authResponse('new-token'));
    expect(await a).toBe('new-token');
    expect(await b).toBe('new-token');
  });

  it('signs out locally when the server ends the session (204 and cookies cleared)', async () => {
    nav.cookies.set(XSRF_COOKIE_NAME, 'x');
    const result = firstValueFrom(auth.refresh());
    nav.cookies.delete(XSRF_COOKIE_NAME);
    http.expectOne('/api/auth/refresh').flush(null, { status: 204, statusText: 'No Content' });
    expect(await result).toBeNull();
    expect(auth.isAuthenticated()).toBeFalse();
  });

  it('retries once when another tab rotated the credential a moment ago', fakeAsync(() => {
    nav.cookies.set(XSRF_COOKIE_NAME, 'old');
    let token: string | null | undefined;
    auth.refresh().subscribe((t) => (token = t));
    nav.cookies.set(XSRF_COOKIE_NAME, 'new');
    http.expectOne('/api/auth/refresh').flush(null, { status: 204, statusText: 'No Content' });
    tick(150);
    const retry = http.expectOne('/api/auth/refresh');
    expect(retry.request.headers.get(XSRF_HEADER_NAME)).toBe('new');
    retry.flush(authResponse('after-retry'));
    flushMicrotasks();
    expect(token).toBe('after-retry');
    auth.clear();
  }));

  it('exchanges the one-time ticket for the session', async () => {
    const done = firstValueFrom(auth.completeSignIn('the-ticket'));
    const req = http.expectOne('/api/auth/entra/exchange');
    expect(req.request.body).toEqual({ ticket: 'the-ticket' });
    expect(req.request.headers.has('Authorization')).toBeFalse();
    req.flush(authResponse());
    await done;
    expect(auth.user()?.displayName).toBe('Pat Doe');
    expect(auth.sessionExpiresAt()).toBeInstanceOf(Date);
  });

  it('signs out with the XSRF header and goes to the signed-out page', async () => {
    const router = TestBed.inject(Router);
    spyOn(router, 'navigateByUrl').and.resolveTo(true);
    nav.cookies.set(XSRF_COOKIE_NAME, 'x');
    const done = firstValueFrom(auth.logout());
    const req = http.expectOne('/api/auth/logout');
    expect(req.request.headers.get(XSRF_HEADER_NAME)).toBe('x');
    req.flush({ microsoftSignOutUrl: null });
    await done;
    expect(router.navigateByUrl).toHaveBeenCalledWith('/signed-out');
    expect(nav.assigned).toEqual([]);
  });

  it('continues to Microsoft when the server asks for a Microsoft sign-out', async () => {
    const done = firstValueFrom(auth.logout());
    http.expectOne('/api/auth/logout').flush({ microsoftSignOutUrl: 'https://login.microsoftonline.com/common/oauth2/v2.0/logout?x=1' });
    await done;
    expect(nav.assigned).toEqual(['https://login.microsoftonline.com/common/oauth2/v2.0/logout?x=1']);
  });

  it('clears the local session even when the sign-out request fails', async () => {
    const response = authResponse();
    const exchange = firstValueFrom(auth.completeSignIn('t'));
    http.expectOne('/api/auth/entra/exchange').flush(response);
    await exchange;
    const done = firstValueFrom(auth.logout());
    http.expectOne('/api/auth/logout').flush({}, { status: 500, statusText: 'Error' });
    await done;
    expect(auth.isAuthenticated()).toBeFalse();
  });
});
