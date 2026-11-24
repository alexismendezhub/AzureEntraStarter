import { provideHttpClient, withInterceptors } from '@angular/common/http';
import { ApplicationConfig, inject, provideAppInitializer, provideBrowserGlobalErrorListeners, provideZoneChangeDetection } from '@angular/core';
import { provideRouter } from '@angular/router';
import { routes } from './app.routes';
import { authInterceptor } from './core/auth.interceptor';
import { AuthService } from './core/auth.service';

export const appConfig: ApplicationConfig = {
  providers: [
    provideBrowserGlobalErrorListeners(),
    provideZoneChangeDetection({ eventCoalescing: true }),
    provideRouter(routes),
    // No withXsrfConfiguration: the XSRF header is added explicitly, only to /api/auth/refresh and /api/auth/logout.
    provideHttpClient(withInterceptors([authInterceptor])),
    // Restores the session (refresh cookie) before the first route is guarded.
    provideAppInitializer(() => inject(AuthService).initialize()),
  ],
};
