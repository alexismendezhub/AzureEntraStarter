import { inject } from '@angular/core';
import { CanActivateFn, Router } from '@angular/router';
import { AuthService } from './auth.service';

/** Signed-in users only; anyone else goes to sign-in and comes back to the page they asked for. */
export const authGuard: CanActivateFn = (_route, state) => {
  const auth = inject(AuthService);
  return auth.isAuthenticated() ? true : inject(Router).createUrlTree(['/login'], { queryParams: { returnUrl: state.url } });
};

/**
 * Route data { role: 'Admin' }: hides pages the user cannot use. This is only UX; the API enforces the same role on
 * every request.
 */
export const roleGuard: CanActivateFn = (route, state) => {
  const auth = inject(AuthService);
  const router = inject(Router);
  if (!auth.isAuthenticated()) return router.createUrlTree(['/login'], { queryParams: { returnUrl: state.url } });
  const role = route.data['role'] as string | undefined;
  return role && auth.hasRole(role) ? true : router.createUrlTree(['/']);
};
