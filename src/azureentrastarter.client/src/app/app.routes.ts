import { Routes } from '@angular/router';
import { ADMIN_ROLE } from './core/auth.constants';
import { authGuard, roleGuard } from './core/auth.guard';
import { AdminComponent } from './pages/admin.component';
import { HomeComponent } from './pages/home.component';
import { LoginComponent } from './pages/login.component';
import { ProfileComponent } from './pages/profile.component';
import { SignedOutComponent } from './pages/signed-out.component';

export const routes: Routes = [
  { path: '', component: HomeComponent, title: 'AzureEntraStarter' },
  { path: 'login', component: LoginComponent, title: 'Sign in' },
  { path: 'signed-out', component: SignedOutComponent, title: 'Signed out' },
  { path: 'profile', component: ProfileComponent, canActivate: [authGuard], title: 'Profile' },
  { path: 'admin', component: AdminComponent, canActivate: [roleGuard], data: { role: ADMIN_ROLE }, title: 'Users' },
  { path: '**', redirectTo: '' },
];
