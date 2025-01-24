import { Navigate, useLocation } from 'react-router-dom';
import { useIsAuthenticated, useHasRole } from '../lib/auth';

interface AuthGuardProps {
  children: React.ReactNode;
  requiredRoles?: string[];
}

export const AuthGuard = ({ children, requiredRoles = [] }: AuthGuardProps) => {
  const isAuthenticated = useIsAuthenticated();
  const location = useLocation();
  const hasRequiredRoles = requiredRoles.length === 0 || 
    requiredRoles.some(role => useHasRole(role));

  if (!isAuthenticated) {
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  if (!hasRequiredRoles) {
    return <Navigate to="/unauthorized" replace />;
  }

  return <>{children}</>;
};