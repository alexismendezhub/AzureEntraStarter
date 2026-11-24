import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { ActivatedRoute, Router, convertToParamMap, provideRouter } from '@angular/router';
import { AuthService } from '../core/auth.service';
import { NavigationService } from '../core/navigation.service';
import { authResponse } from '../testing/auth-fixtures';
import { FakeNavigation } from '../testing/fake-navigation';
import { LoginComponent, SSO_ERRORS } from './login.component';

describe('LoginComponent', () => {
  let http: HttpTestingController;
  let nav: FakeNavigation;
  let router: Router;

  function create(query: Record<string, string> = {}, fragment: string | null = null, entraEnabled = true) {
    TestBed.resetTestingModule();
    TestBed.configureTestingModule({
      imports: [LoginComponent],
      providers: [
        provideRouter([]),
        provideHttpClient(),
        provideHttpClientTesting(),
        { provide: NavigationService, useClass: FakeNavigation },
        { provide: ActivatedRoute, useValue: { snapshot: { queryParamMap: convertToParamMap(query), fragment } } },
      ],
    });
    http = TestBed.inject(HttpTestingController);
    nav = TestBed.inject(NavigationService) as FakeNavigation;
    router = TestBed.inject(Router);
    spyOn(router, 'navigateByUrl').and.resolveTo(true);
    TestBed.inject(AuthService).config.set({ entraEnabled });
    const fixture = TestBed.createComponent(LoginComponent);
    fixture.detectChanges();
    return fixture;
  }

  afterEach(() => {
    TestBed.inject(AuthService).clear();
    http.verify();
  });

  it('offers Microsoft sign-in and keeps the requested page', () => {
    const fixture = create({ returnUrl: '/admin' });
    (fixture.nativeElement.querySelector('[data-testid="sign-in"]') as HTMLButtonElement).click();
    (fixture.nativeElement.querySelector('[data-testid="other-account"]') as HTMLButtonElement).click();
    expect(nav.assigned).toEqual([
      '/api/auth/entra/start?returnUrl=%2Fadmin',
      '/api/auth/entra/start?returnUrl=%2Fadmin&prompt=select_account',
    ]);
  });

  it('never forwards an outside return URL', () => {
    const fixture = create({ returnUrl: '//evil.example' });
    (fixture.nativeElement.querySelector('[data-testid="sign-in"]') as HTMLButtonElement).click();
    expect(nav.assigned).toEqual(['/api/auth/entra/start?returnUrl=%2F']);
  });

  it('explains the coarse reason of a failed sign-in, never a raw message', () => {
    const fixture = create({ ssoError: 'sso_personal_account' });
    expect(fixture.nativeElement.querySelector('[role="alert"]').textContent).toContain(SSO_ERRORS['sso_personal_account']);
    const other = create({ ssoError: '<script>alert(1)</script>' });
    expect(other.nativeElement.querySelector('[role="alert"]').textContent).toContain(SSO_ERRORS['sso_failed']);
  });

  it('completes the sign-in with the ticket, removes it from the address bar and goes to the return URL', async () => {
    const fixture = create({}, 'ticket=abc&returnUrl=%2Fprofile');
    expect(nav.fragmentCleared).toBeTrue();
    expect(fixture.nativeElement.textContent).toContain('Completing sign-in');
    const req = http.expectOne('/api/auth/entra/exchange');
    expect(req.request.body).toEqual({ ticket: 'abc' });
    req.flush(authResponse());
    await fixture.whenStable();
    expect(router.navigateByUrl).toHaveBeenCalledWith('/profile');
  });

  it('refuses an outside return URL from the fragment', async () => {
    const fixture = create({}, 'ticket=abc&returnUrl=https%3A%2F%2Fevil.example');
    http.expectOne('/api/auth/entra/exchange').flush(authResponse());
    await fixture.whenStable();
    expect(router.navigateByUrl).toHaveBeenCalledWith('/');
  });

  it('shows an error when the ticket is refused', () => {
    const fixture = create({}, 'ticket=used');
    http.expectOne('/api/auth/entra/exchange').flush(null, { status: 401, statusText: 'Unauthorized' });
    fixture.detectChanges();
    expect(fixture.nativeElement.querySelector('[role="alert"]').textContent).toContain(SSO_ERRORS['ticket_failed']);
    expect(router.navigateByUrl).not.toHaveBeenCalled();
  });

  it('says so when Microsoft Entra is not configured', () => {
    const fixture = create({}, null, false);
    expect(fixture.nativeElement.querySelector('[data-testid="not-configured"]')).not.toBeNull();
    expect(fixture.nativeElement.querySelector('[data-testid="sign-in"]')).toBeNull();
  });
});
