import { DOCUMENT } from '@angular/common';
import { Injectable, inject } from '@angular/core';

/** Full-page navigation and history access, behind a service so tests can observe it. */
@Injectable({ providedIn: 'root' })
export class NavigationService {
  private readonly document = inject(DOCUMENT);

  /** Leaves the SPA (to the server's sign-in start or to Microsoft's sign-out page). */
  assign(url: string): void {
    this.document.location.assign(url);
  }

  /** Removes the one-time ticket from the address bar and the history entry. */
  clearFragment(): void {
    const { pathname, search } = this.document.location;
    this.document.defaultView?.history.replaceState(null, '', pathname + search);
  }

  cookie(name: string): string | null {
    const prefix = name + '=';
    const found = this.document.cookie.split(';').map((c) => c.trim()).find((c) => c.startsWith(prefix));
    return found ? decodeURIComponent(found.substring(prefix.length)) : null;
  }
}
