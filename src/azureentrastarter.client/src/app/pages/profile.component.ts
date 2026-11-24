import { DatePipe } from '@angular/common';
import { Component, inject } from '@angular/core';
import { AuthService } from '../core/auth.service';

@Component({
  selector: 'app-profile',
  imports: [DatePipe],
  template: `
    @if (auth.user(); as user) {
      <section class="card">
        <h1>Profile</h1>
        <dl>
          <dt>Name</dt><dd>{{ user.displayName }}</dd>
          <dt>Email</dt><dd>{{ user.email }}</dd>
          <dt>Directory (tid)</dt><dd><code>{{ user.tenantId }}</code></dd>
          <dt>Object id (oid)</dt><dd><code>{{ user.objectId }}</code></dd>
          <dt>App roles</dt><dd>{{ user.roles.length ? user.roles.join(', ') : 'none' }}</dd>
          <dt>Session ends</dt><dd>{{ auth.sessionExpiresAt() | date: 'medium' }}</dd>
        </dl>
        <p>Your identity in this application is the pair directory id + object id. Your email and name are display data
          refreshed at each sign-in.</p>
      </section>
    }
  `,
})
export class ProfileComponent {
  protected readonly auth = inject(AuthService);
}
