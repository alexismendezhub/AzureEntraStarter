import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { firstValueFrom } from 'rxjs';
import { AuthService } from '../core/auth.service';
import { authResponse } from '../testing/auth-fixtures';
import { AdminComponent } from './admin.component';
import { HomeComponent } from './home.component';
import { ProfileComponent } from './profile.component';

describe('pages', () => {
  let http: HttpTestingController;
  let auth: AuthService;

  beforeEach(async () => {
    TestBed.configureTestingModule({ providers: [provideRouter([]), provideHttpClient(), provideHttpClientTesting()] });
    http = TestBed.inject(HttpTestingController);
    auth = TestBed.inject(AuthService);
    const done = firstValueFrom(auth.completeSignIn('t'));
    http.expectOne('/api/auth/entra/exchange').flush(authResponse('t', ['Admin']));
    await done;
  });

  afterEach(() => {
    auth.clear();
    http.verify();
  });

  it('home calls the protected API', () => {
    const fixture = TestBed.createComponent(HomeComponent);
    fixture.detectChanges();
    (fixture.nativeElement.querySelector('[data-testid="call-api"]') as HTMLButtonElement).click();
    http.expectOne('/api/sample/hello').flush({ message: 'Hello, Pat Doe.' });
    fixture.detectChanges();
    expect(fixture.nativeElement.querySelector('[data-testid="api-message"]').textContent).toContain('Hello, Pat Doe.');
  });

  it('profile shows the immutable identity and the roles', () => {
    const fixture = TestBed.createComponent(ProfileComponent);
    fixture.detectChanges();
    const text = fixture.nativeElement.textContent as string;
    expect(text).toContain('33333333-3333-3333-3333-333333333333');
    expect(text).toContain('11111111-1111-1111-1111-111111111111');
    expect(text).toContain('Admin');
  });

  it('admin lists users and disables one, but never offers to disable itself', () => {
    const fixture = TestBed.createComponent(AdminComponent);
    fixture.detectChanges();
    http.expectOne('/api/admin/users').flush([
      { id: 'user-1', displayName: 'Pat Doe', email: 'pat@contoso.example', tenantId: 't', disabled: false, lastSignInAtUtc: null },
      { id: 'user-2', displayName: 'Sam Roe', email: 'sam@contoso.example', tenantId: 't', disabled: false, lastSignInAtUtc: null },
    ]);
    fixture.detectChanges();
    expect(fixture.nativeElement.querySelector('[data-testid="toggle-user-1"]')).toBeNull();
    (fixture.nativeElement.querySelector('[data-testid="toggle-user-2"]') as HTMLButtonElement).click();
    const req = http.expectOne('/api/admin/users/user-2/disabled');
    expect(req.request.body).toEqual({ disabled: true });
    req.flush(null);
    http.expectOne('/api/admin/users').flush([]);
  });
});
