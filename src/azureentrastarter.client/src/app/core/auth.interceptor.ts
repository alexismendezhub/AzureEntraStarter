import { HttpErrorResponse, HttpInterceptorFn } from '@angular/common/http';
import { inject } from '@angular/core';
import { Router } from '@angular/router';
import { catchError, switchMap, throwError } from 'rxjs';
import { AuthService } from './auth.service';

/** Endpoints that never carry the bearer token and never trigger a refresh: they create, rotate or end the session. */
const SESSION_ENDPOINTS = ['/api/auth/config', '/api/auth/entra/exchange', '/api/auth/refresh', '/api/auth/logout'];
const isSessionEndpoint = (url: string) => SESSION_ENDPOINTS.includes(url.split('?', 1)[0]);

export const authInterceptor: HttpInterceptorFn = (req, next) => {
  const auth = inject(AuthService);
  const router = inject(Router);
  // The token is only ever attached to this application's own API (relative /api/ URLs), never to another origin.
  const ownApi = req.url.startsWith('/api/');
  const sessionEndpoint = isSessionEndpoint(req.url);
  const token = auth.token();
  const sent = token && ownApi && !sessionEndpoint ? req.clone({ setHeaders: { Authorization: `Bearer ${token}` } }) : req;

  return next(sent).pipe(
    catchError((error: HttpErrorResponse) => {
      if (error.status !== 401 || !ownApi || sessionEndpoint) return throwError(() => error);
      // Expired access token or revoked session: rotate once through the refresh cookie and replay the request.
      return auth.refresh().pipe(
        switchMap((freshToken) => {
          if (!freshToken) {
            void router.navigate(['/login'], { queryParams: { returnUrl: router.url } });
            return throwError(() => error);
          }
          return next(req.clone({ setHeaders: { Authorization: `Bearer ${freshToken}` } }));
        }),
      );
    }),
  );
};
