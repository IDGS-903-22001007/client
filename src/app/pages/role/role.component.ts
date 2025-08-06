import { Component, inject } from '@angular/core';
import { RoleFormComponent } from '../../components/role-form/role-form.component';
import { RoleService } from '../../services/role.service';
import { RoleCreateRequest } from '../../interfaces/role-create-request';
import { MatSnackBar, MatSnackBarModule } from '@angular/material/snack-bar';
import { HttpErrorResponse } from '@angular/common/http';
import { RoleListComponent } from '../../components/role-list/role-list.component';
import { AsyncPipe } from '@angular/common';
import { MatSelectModule } from '@angular/material/select';
import { MatInputModule } from '@angular/material/input';
import { AuthService } from '../../services/auth.service';
import { catchError, of } from 'rxjs';
import { Role } from '../../interfaces/role';

@Component({
  selector: 'app-role',
  standalone: true,
  imports: [
    RoleFormComponent,
    MatSelectModule,
    MatInputModule,
    RoleListComponent,
    AsyncPipe,
    MatSnackBarModule,
  ],
  templateUrl: './role.component.html',
  styleUrl: './role.component.css',
})
export class RoleComponent {
  roleService = inject(RoleService);
  authService = inject(AuthService);
  errorMessage = '';
  role: RoleCreateRequest = {} as RoleCreateRequest;
  selectedUser: string = '';
  selectedRole: string = '';
  snackBar = inject(MatSnackBar);

  // Roles predefinidos como fallback
  defaultRoles: Role[] = [
    { id: '1', name: 'User', totalUsers: 0 },
    { id: '2', name: 'Admin', totalUsers: 0 },
    { id: '3', name: 'Manager', totalUsers: 0 }
  ];

  roles$ = this.roleService.getRoles().pipe(
    catchError(error => {
      console.log('Error loading roles from server, using default roles:', error);
      this.snackBar.open('Using default roles (server error)', 'Close', {
        duration: 3000,
      });
      return of(this.defaultRoles);
    })
  );

  users$ = this.authService.getAll();

  createRole(role: RoleCreateRequest) {
    this.roleService.createRole(role).subscribe({
      next: (response: { message: string }) => {
        this.refreshRoles();
        this.snackBar.open('Role Created Successfully', 'Ok', {
          duration: 3000,
        });
      },
      error: (error: HttpErrorResponse) => {
        if (error.status == 400) {
          this.errorMessage = error.error;
        }
      },
    });
  }

  refreshRoles() {
    this.roles$ = this.roleService.getRoles().pipe(
      catchError(error => {
        console.log('Error refreshing roles, using default roles:', error);
        return of(this.defaultRoles);
      })
    );
  }

  deleteRole(id: string) {
    this.roleService.delete(id).subscribe({
      next: (response) => {
        this.roles$ = this.roleService.getRoles();
        this.snackBar.open('Role Deleted Successfully', 'Close', {
          duration: 3000,
        });
      },
      error: (error: HttpErrorResponse) => {
        this.snackBar.open(error.message, 'Close', {
          duration: 3000,
        });
      },
    });
  }

  assignRole() {
    this.roleService
      .assignRole(this.selectedUser, this.selectedRole)
      .subscribe({
        next: (response) => {
          this.refreshRoles();
          this.snackBar.open('Role Assign Successfully', 'Close', {
            duration: 3000,
          });
        },
        error: (error: HttpErrorResponse) => {
          this.snackBar.open(error.message, 'Close', {
            duration: 3000,
          });
        },
      });
  }
}
