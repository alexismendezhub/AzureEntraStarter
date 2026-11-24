import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { ActivatedRouteSnapshot, Router, RouterStateSnapshot, UrlTree, provideRouter } from '@angular/router';
import { firstValueFrom } from 'rxjs';
import { authResponse } from '../testing/auth-fixtures';
import { authGuard, roleGuard } from './auth.guard';
import { AuthService } from './auth.service';

describe('guards', () => {
  let auth: AuthService;
  let http: HttpTestingController;
  const state = { url: '/admin' } as RouterStateSnapshot;
  const route = (data: Record<string, unknown> = {}) => ({ data }) as unknown as ActivatedRouteSnapshot;
  const run = (guard: typeof authGuard, r: ActivatedRouteSnapshot) => TestBed.runInInjectionContext(() => guard(r, state));

  async function signIn(roles: string[]) {
    const done = firstValueFrom(auth.completeSignIn('t'));
    http.expectOne('/api/auth/entra/exchange').flush(authResponse('t', roles));
    await done;
  }

  beforeEach(() => {
    TestBed.configureTestingModule({ providers: [provideRouter([]), provideHttpClient(), provideHttpClientTesting()] });
    auth = TestBed.inject(AuthService);
    http = TestBed.inject(HttpTestingController);
  });

  afterEach(() => auth.clear());

  it('sends anonymous users to sign-in with the page they asked for', () => {
    const result = run(authGuard, route()) as UrlTree;
    expect(TestBed.inject(Router).serializeUrl(result)).toBe('/login?returnUrl=%2Fadmin');
    expect(TestBed.inject(Router).serializeUrl(run(roleGuard, route({ role: 'Admin' })) as UrlTree)).toBe('/login?returnUrl=%2Fadmin');
  });

  it('lets signed-in users through', async () => {
    await signIn([]);
    expect(run(authGuard, route())).toBeTrue();
  });

  it('requires the role named in the route data', async () => {
    await signIn(['Reader']);
    expect(TestBed.inject(Router).serializeUrl(run(roleGuard, route({ role: 'Admin' })) as UrlTree)).toBe('/');
    auth.clear();
    await signIn(['Admin']);
    expect(run(roleGuard, route({ role: 'Admin' }))).toBeTrue();
  });
});
