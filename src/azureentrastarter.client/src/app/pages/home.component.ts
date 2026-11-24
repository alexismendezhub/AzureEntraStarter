import { HttpClient } from '@angular/common/http';
import { Component, inject, signal } from '@angular/core';
import { RouterLink } from '@angular/router';
import { AuthService } from '../core/auth.service';

@Component({
  selector: 'app-home',
  imports: [RouterLink],
  template: `
    <section class="card">
      <h1>AzureEntraStarter</h1>
      <p>ASP.NET Core + Angular with sign-in through Microsoft Entra ID only.</p>
      @if (auth.user(); as user) {
        <p>Signed in as <strong>{{ user.displayName }}</strong> ({{ user.email }}).</p>
        <button type="button" (click)="callApi()" data-testid="call-api">Call a protected API</button>
        @if (apiMessage()) {
          <p data-testid="api-message">{{ apiMessage() }}</p>
        }
      } @else {
        <p><a routerLink="/login">Sign in</a> to call the protected API.</p>
      }
    </section>
  `,
})
export class HomeComponent {
  protected readonly auth = inject(AuthService);
  private readonly http = inject(HttpClient);
  protected readonly apiMessage = signal<string | null>(null);

  callApi(): void {
    this.http.get<{ message: string }>('/api/sample/hello').subscribe({
      next: (r) => this.apiMessage.set(r.message),
      error: () => this.apiMessage.set('The API refused the request.'),
    });
  }
}
