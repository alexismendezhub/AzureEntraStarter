import { Component } from '@angular/core';
import { RouterLink } from '@angular/router';

@Component({
  selector: 'app-signed-out',
  imports: [RouterLink],
  template: `
    <section class="card">
      <h1>You have signed out</h1>
      <p>On a shared computer, also close the browser. <a routerLink="/login">Sign in again</a></p>
    </section>
  `,
})
export class SignedOutComponent {}
