import { Component, OnInit, inject, signal } from '@angular/core';
import { ActivatedRoute, Router } from '@angular/router';
import { AuthService, safeReturnUrl } from '../core/auth.service';
import { NavigationService } from '../core/navigation.service';

/** What each coarse reason from the server means for the user. Never the provider's own message. */
export const SSO_ERRORS: Record<string, string> = {
  sso_denied: 'The sign-in was cancelled at Microsoft.',
  sso_session_expired: 'The sign-in took too long or was started in another window. Please try again.',
  sso_not_allowed: 'This account is not allowed to use this application.',
  sso_personal_account: 'Personal Microsoft accounts cannot sign in. Use your work or school account.',
  sso_not_registered: 'This account is not registered in this application. Ask an administrator for access.',
  sso_failed: 'Microsoft sign-in failed. Please try again.',
  ticket_failed: 'The sign-in could not be completed. Please try again.',
};

@Component({
  selector: 'app-login',
  template: `
    <section class="card">
      <h1>Sign in</h1>
      @if (error()) {
        <p class="error" role="alert">{{ error() }}</p>
      }
      @if (completing()) {
        <p role="status">Completing sign-in…</p>
      } @else if (auth.config().entraEnabled) {
        <p>Use your organization's Microsoft account.</p>
        <button type="button" class="microsoft" (click)="signIn()" data-testid="sign-in">
          <span class="logo" aria-hidden="true">
            <span style="background:#f25022"></span><span style="background:#7fba00"></span>
            <span style="background:#00a4ef"></span><span style="background:#ffb900"></span>
          </span>
          Sign in with Microsoft
        </button>
        <p><button type="button" class="link" (click)="signIn('select_account')" data-testid="other-account">Use another account</button></p>
      } @else {
        <p class="notice" data-testid="not-configured">
          Microsoft Entra sign-in is not configured on the server. See "Register the application in Microsoft Entra" in the README.
        </p>
      }
    </section>
  `,
})
export class LoginComponent implements OnInit {
  protected readonly auth = inject(AuthService);
  private readonly route = inject(ActivatedRoute);
  private readonly router = inject(Router);
  private readonly navigation = inject(NavigationService);

  protected readonly error = signal<string | null>(null);
  protected readonly completing = signal(false);

  ngOnInit(): void {
    const ssoError = this.route.snapshot.queryParamMap.get('ssoError');
    if (ssoError) this.error.set(SSO_ERRORS[ssoError] ?? SSO_ERRORS['sso_failed']);

    // Back from Microsoft: /login#ticket=…&returnUrl=…
    const fragment = new URLSearchParams(this.route.snapshot.fragment ?? '');
    const ticket = fragment.get('ticket');
    if (!ticket) return;
    // The ticket works once; it must not stay in the address bar or the history.
    this.navigation.clearFragment();
    this.completing.set(true);
    const returnUrl = safeReturnUrl(fragment.get('returnUrl'));
    this.auth.completeSignIn(ticket).subscribe({
      next: () => void this.router.navigateByUrl(returnUrl),
      error: () => {
        this.completing.set(false);
        this.error.set(SSO_ERRORS['ticket_failed']);
      },
    });
  }

  signIn(prompt?: 'select_account'): void {
    this.auth.signIn(safeReturnUrl(this.route.snapshot.queryParamMap.get('returnUrl')), prompt);
  }
}
