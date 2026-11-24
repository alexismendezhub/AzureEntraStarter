import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { firstValueFrom } from 'rxjs';
import { AppComponent } from './app.component';
import { AuthService } from './core/auth.service';
import { NavigationService } from './core/navigation.service';
import { authResponse } from './testing/auth-fixtures';
import { FakeNavigation } from './testing/fake-navigation';

describe('AppComponent', () => {
  let http: HttpTestingController;
  let auth: AuthService;

  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [AppComponent],
      providers: [provideRouter([]), provideHttpClient(), provideHttpClientTesting(), { provide: NavigationService, useClass: FakeNavigation }],
    });
    http = TestBed.inject(HttpTestingController);
    auth = TestBed.inject(AuthService);
  });

  afterEach(() => auth.clear());

  async function signIn(roles: string[]) {
    const done = firstValueFrom(auth.completeSignIn('t'));
    http.expectOne('/api/auth/entra/exchange').flush(authResponse('t', roles));
    await done;
  }

  it('shows Sign in to anonymous visitors', () => {
    const fixture = TestBed.createComponent(AppComponent);
    fixture.detectChanges();
    expect(fixture.nativeElement.querySelector('[data-testid="sign-in-link"]')).not.toBeNull();
    expect(fixture.nativeElement.querySelector('[data-testid="sign-out"]')).toBeNull();
  });

  it('shows the user and the Users link only with the Admin role', async () => {
    await signIn(['Reader']);
    const fixture = TestBed.createComponent(AppComponent);
    fixture.detectChanges();
    expect(fixture.nativeElement.textContent).toContain('Pat Doe');
    expect(fixture.nativeElement.querySelector('[data-testid="admin-link"]')).toBeNull();

    auth.clear();
    await signIn(['Admin']);
    fixture.detectChanges();
    expect(fixture.nativeElement.querySelector('[data-testid="admin-link"]')).not.toBeNull();
  });

  it('shows the project name in the home link, with no logo', () => {
    const fixture = TestBed.createComponent(AppComponent);
    fixture.detectChanges();
    const brand: HTMLAnchorElement = fixture.nativeElement.querySelector('[data-testid="brand"]');
    expect(brand.getAttribute('href')).toBe('/');
    expect(brand.textContent?.trim()).toBe('AzureEntraStarter');
    expect(brand.querySelector('img')).toBeNull();
  });
});
