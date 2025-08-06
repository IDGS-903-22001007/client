import { HttpErrorResponse, HttpInterceptorFn, HttpRequest } from '@angular/common/http';
import { inject } from '@angular/core';
import { AuthService } from '../services/auth.service';
import { catchError, switchMap, throwError } from 'rxjs';
import { Router } from '@angular/router';
import { of } from 'rxjs';

export const tokenInterceptor: HttpInterceptorFn = (req, next) => {
  const authService = inject(AuthService);
  const router = inject(Router);

  // Rutas públicas
  const publicRoutes = [
    '/account/login',
    '/account/register',
    '/account/forgot-password',
    '/account/reset-password',
    '/account/refresh-token'
  ];

  const isPublicRoute = publicRoutes.some(route => req.url.includes(route));
  const isRolesRequest = req.url.includes('/api/roles');
  const hasToken = !!authService.getToken();

  console.log('Request URL:', req.url);
  console.log('Is public route:', isPublicRoute);
  console.log('Is roles request:', isRolesRequest);
  console.log('Has token:', hasToken);

  // Si es pública, no se clona con token
  if (isPublicRoute) return next(req);

  // Para roles sin token, continuar sin token
  if (isRolesRequest && !hasToken) return next(req);

  // Si no hay token para ruta privada, continuar sin token
  if (!hasToken) return next(req);

  // Si hay token, agregarlo
  const clonedReq = req.clone({
    headers: req.headers.set('Authorization', 'Bearer ' + authService.getToken()),
  });

  return next(clonedReq).pipe(
    catchError((err: HttpErrorResponse) => {
      if (err.status === 401) {
        console.log('401 detectado: intentando refresh de token...');

        const email = authService.getUserDetail()?.email;
        const token = authService.getToken();
        const refreshToken = authService.getRefreshToken();

        if (!email || !token || !refreshToken) {
          authService.logout();
          router.navigate(['/login']);
          return throwError(() => err);
        }

        return authService.refreshToken({ email, token, refreshToken }).pipe(
          switchMap((response) => {
            if (response.isSuccess) {
              localStorage.setItem('user', JSON.stringify(response));
              const retryReq = req.clone({
                setHeaders: {
                  Authorization: `Bearer ${response.token}`,
                },
              });
              return next(retryReq);
            } else {
              authService.logout();
              router.navigate(['/login']);
              return throwError(() => err);
            }
          }),
          catchError(() => {
            authService.logout();
            router.navigate(['/login']);
            return throwError(() => err);
          })
        );
      }

      return throwError(() => err);
    })
  );
};
