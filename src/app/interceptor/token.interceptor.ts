import { HttpErrorResponse, HttpInterceptorFn } from '@angular/common/http';
import { inject } from '@angular/core';
import { AuthService } from '../services/auth.service';
import { catchError, throwError } from 'rxjs';
import { Router } from '@angular/router';

export const tokenInterceptor: HttpInterceptorFn = (req, next) => {
  const authService = inject(AuthService);
  const router = inject(Router);

  // Rutas que NO necesitan token de autorización
  const publicRoutes = [
    '/account/login',
    '/account/register',
    '/account/forgot-password',
    '/account/reset-password',
    '/account/refresh-token',
    '/api/roles'
  ];

  // Verificar si la URL actual es una ruta pública
  const isPublicRoute = publicRoutes.some(route => req.url.includes(route));

  console.log('Request URL:', req.url);
  console.log('Is public route:', isPublicRoute);
  console.log('Token:', authService.getToken());

  // Si es ruta pública, enviar sin token
  if (isPublicRoute) {
    console.log('Sending request without token (public route)');
    return next(req);
  }

  // Si no es ruta pública pero no hay token, continuar sin token
  if (!authService.getToken()) {
    console.log('No token available for private route');
    return next(req);
  }

  // Agregar token para rutas privadas
  const cloned = req.clone({
    headers: req.headers.set(
      'Authorization',
      'Bearer ' + authService.getToken()
    ),
  });

  console.log('Sending request with token');

  return next(cloned).pipe(
    catchError((err: HttpErrorResponse) => {
      if (err.status === 401) {
        console.log('401 error, attempting token refresh');
        authService
          .refreshToken({
            email: authService.getUserDetail()?.email,
            token: authService.getToken() || '',
            refreshToken: authService.getRefreshToken() || '',
          })
          .subscribe({
            next: (response) => {
              if (response.isSuccess) {
                localStorage.setItem('user', JSON.stringify(response));
                const cloned = req.clone({
                  setHeaders: {
                    Authorization: `Bearer ${response.token}`,
                  },
                });
                location.reload();
              }
            },
            error: () => {
              authService.logout();
              router.navigate(['/login']);
            },
          });
      }
      return throwError(() => err);
    })
  );
};
