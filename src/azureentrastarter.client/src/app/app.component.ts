import { Component, inject } from '@angular/core';
import { RouterLink, RouterOutlet } from '@angular/router';
import { ADMIN_ROLE } from './core/auth.constants';
import { AuthService } from './core/auth.service';

@Component({
  selector: 'app-root',
  imports: [RouterOutlet, RouterLink],
  template: `
    <nav>
      <a routerLink="/" class="brand" data-testid="brand">AzureEntraStarter</a>
      @if (auth.user(); as user) {
        <a routerLink="/profile">Profile</a>
        @if (auth.hasRole(adminRole)) {
          <a routerLink="/admin" data-testid="admin-link">Users</a>
        }
        <span class="spacer"></span>
        <span>{{ user.displayName }}</span>
        <button type="button" class="secondary" (click)="logout()" data-testid="sign-out">Sign out</button>
      } @else {
        <span class="spacer"></span>
        <a routerLink="/login" data-testid="sign-in-link">Sign in</a>
      }
    </nav>
    <main>
      <router-outlet />
    </main>
  `,
})
export class AppComponent {
  protected readonly auth = inject(AuthService);
  protected readonly adminRole = ADMIN_ROLE;

  logout(): void {
    this.auth.logout().subscribe();
  }
}
