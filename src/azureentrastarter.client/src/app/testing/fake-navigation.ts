import { Injectable } from '@angular/core';
import { NavigationService } from '../core/navigation.service';

/** Records full-page navigations and serves cookies from a map instead of document.cookie. */
@Injectable()
export class FakeNavigation extends NavigationService {
  readonly assigned: string[] = [];
  readonly cookies = new Map<string, string>();
  fragmentCleared = false;

  override assign(url: string): void {
    this.assigned.push(url);
  }

  override clearFragment(): void {
    this.fragmentCleared = true;
  }

  override cookie(name: string): string | null {
    return this.cookies.get(name) ?? null;
  }
}
