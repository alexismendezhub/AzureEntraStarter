import { DatePipe } from '@angular/common';
import { HttpClient } from '@angular/common/http';
import { Component, OnInit, inject, signal } from '@angular/core';
import { AuthService } from '../core/auth.service';

export interface AdminUser {
  id: string;
  displayName: string;
  email: string;
  tenantId: string;
  disabled: boolean;
  lastSignInAtUtc: string | null;
}

@Component({
  selector: 'app-admin',
  imports: [DatePipe],
  template: `
    <section class="card">
      <h1>Users</h1>
      <p>Visible to the Entra app role <code>Admin</code>. Disabling a user ends its sessions at once.</p>
      @if (error()) {
        <p class="error" role="alert">{{ error() }}</p>
      }
      <table>
        <thead><tr><th>Name</th><th>Email</th><th>Last sign-in</th><th></th></tr></thead>
        <tbody>
          @for (u of users(); track u.id) {
            <tr>
              <td>{{ u.displayName }}</td>
              <td>{{ u.email }}</td>
              <td>{{ u.lastSignInAtUtc | date: 'short' }}</td>
              <td>
                @if (u.id !== auth.user()?.id) {
                  <button type="button" class="secondary" (click)="toggle(u)" [attr.data-testid]="'toggle-' + u.id">
                    {{ u.disabled ? 'Enable' : 'Disable' }}
                  </button>
                }
              </td>
            </tr>
          }
        </tbody>
      </table>
    </section>
  `,
})
export class AdminComponent implements OnInit {
  protected readonly auth = inject(AuthService);
  private readonly http = inject(HttpClient);
  protected readonly users = signal<AdminUser[]>([]);
  protected readonly error = signal<string | null>(null);

  ngOnInit(): void {
    this.load();
  }

  toggle(user: AdminUser): void {
    this.http.post(`/api/admin/users/${encodeURIComponent(user.id)}/disabled`, { disabled: !user.disabled }).subscribe({
      next: () => this.load(),
      error: () => this.error.set('The change was refused.'),
    });
  }

  private load(): void {
    this.http.get<AdminUser[]>('/api/admin/users').subscribe({
      next: (users) => this.users.set(users),
      error: () => this.error.set('The user list could not be loaded.'),
    });
  }
}
