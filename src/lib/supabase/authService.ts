/**
 * Supabase Authentication & Profile Service
 * Handles registration (name, email, password), sign-in, session persistence,
 * logout, password reset, and profile hydration via Supabase Auth.
 *
 * Security guarantees:
 * - Never stores passwords in localStorage or custom tables.
 * - Never exposes or uses privileged service_role keys.
 * - Preserves guest access cleanly when Supabase is unconfigured or unavailable.
 */

import { SupabaseClient, User } from '@supabase/supabase-js';
import { AuthChangeEventType, AuthUserProfile } from '../../types';
import { supabase } from './client';

export interface AuthServiceDependencies {
  client?: SupabaseClient | null;
  redirectOrigin?: string;
}

export interface RegisterInput {
  name: string;
  email: string;
  password: string;
}

export interface LoginInput {
  email: string;
  password: string;
}

export interface AuthActionResult {
  success: boolean;
  user?: AuthUserProfile | null;
  requiresEmailConfirmation?: boolean;
  message?: string;
  error?: string;
}

const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;

export function validateDisplayName(name: string): string | null {
  const trimmed = (name || '').trim();
  if (!trimmed) return 'Please enter your full name.';
  if (trimmed.length < 2) return 'Name must be at least 2 characters long.';
  if (trimmed.length > 80) return 'Name must be 80 characters or fewer.';
  return null;
}

export function validateEmailAddress(email: string): string | null {
  const trimmed = (email || '').trim();
  if (!trimmed) return 'Please enter your email address.';
  if (!EMAIL_REGEX.test(trimmed)) return 'Please enter a valid email address.';
  return null;
}

export function validatePasswordStrength(password: string): string | null {
  if (!password) return 'Please enter a password.';
  if (password.length < 8) return 'Password must be at least 8 characters long.';
  if (!/[A-Za-z]/.test(password) || !/[0-9]/.test(password)) {
    return 'Password must include at least one letter and one number.';
  }
  return null;
}

function getRedirectUrl(deps?: AuthServiceDependencies): string | undefined {
  if (deps?.redirectOrigin) return deps.redirectOrigin;
  try {
    if (typeof window !== 'undefined' && window.location?.origin) {
      return window.location.origin;
    }
  } catch {
    // ignore in non-browser contexts
  }
  return undefined;
}

export function detectPasswordRecoveryInUrl(): boolean {
  try {
    if (typeof window === 'undefined') return false;
    const hash = window.location.hash || '';
    const search = window.location.search || '';
    return hash.includes('type=recovery') || search.includes('type=recovery');
  } catch {
    return false;
  }
}

function formatSupabaseAuthError(err: any, fallbackMessage: string): string {
  const raw = String(err?.message || err?.error_description || '').trim();
  const lower = raw.toLowerCase();

  if (!raw) return fallbackMessage;
  if (lower.includes('invalid login credentials')) {
    return 'Incorrect email or password. Please check your credentials and try again.';
  }
  if (lower.includes('email not confirmed')) {
    return 'Your email address is not confirmed yet. Please check your inbox for the confirmation link.';
  }
  if (lower.includes('already registered') || lower.includes('already exists')) {
    return 'An account with this email already exists. Try signing in or resetting your password.';
  }
  if (lower.includes('rate limit') || err?.status === 429) {
    return 'Too many authentication attempts. Please wait a minute and try again.';
  }
  if (lower.includes('failed to fetch') || lower.includes('enotfound') || lower.includes('network')) {
    return 'Could not reach Supabase Auth. Check your network connection and VITE_SUPABASE_URL.';
  }
  if (lower.includes('same password') || lower.includes('different from the old password')) {
    return 'New password must be different from your previous password.';
  }
  return raw;
}

function mapAuthUserFallback(user: User, displayNameOverride?: string): AuthUserProfile {
  const email = user.email || '';
  const metaName =
    typeof user.user_metadata?.display_name === 'string'
      ? user.user_metadata.display_name.trim()
      : '';
  const fallbackName = email ? email.split('@')[0] : 'VerifyBeforeBuy User';
  return {
    id: user.id,
    email,
    displayName: (displayNameOverride || metaName || fallbackName).trim(),
    avatarUrl:
      typeof user.user_metadata?.avatar_url === 'string'
        ? user.user_metadata.avatar_url
        : undefined,
    createdAt: user.created_at,
    emailConfirmed: Boolean(user.email_confirmed_at),
  };
}

async function hydrateProfile(
  client: SupabaseClient,
  user: User,
  displayNameOverride?: string
): Promise<AuthUserProfile> {
  const base = mapAuthUserFallback(user, displayNameOverride);
  try {
    const { data, error } = await client
      .from('profiles')
      .select('id, email, display_name, avatar_url, created_at')
      .eq('id', user.id)
      .maybeSingle();

    if (!error && data) {
      return {
        id: user.id,
        email: data.email || base.email,
        displayName: (data.display_name || base.displayName).trim(),
        avatarUrl: data.avatar_url || base.avatarUrl,
        createdAt: data.created_at || base.createdAt,
        emailConfirmed: base.emailConfirmed,
      };
    }

    // Best-effort profile bootstrap if handle_new_user trigger hasn't run or table was migrated later
    if (!error && !data) {
      await client
        .from('profiles')
        .upsert(
          {
            id: user.id,
            email: base.email,
            display_name: base.displayName,
          },
          { onConflict: 'id' }
        );
    }
  } catch {
    // Non-fatal: metadata fallback keeps auth functional even before profiles table migration
  }
  return base;
}

export class AuthService {
  public static isAuthAvailable(deps: AuthServiceDependencies = {}): boolean {
    const client = deps.client !== undefined ? deps.client : supabase;
    return client !== null;
  }

  public static async getSessionProfile(
    deps: AuthServiceDependencies = {}
  ): Promise<{ user: AuthUserProfile | null; error?: string }> {
    const client = deps.client !== undefined ? deps.client : supabase;
    if (!client) {
      return { user: null };
    }

    try {
      const { data, error } = await client.auth.getSession();
      if (error) {
        return { user: null, error: formatSupabaseAuthError(error, 'Failed to read active session.') };
      }
      const sessionUser = data?.session?.user;
      if (!sessionUser) {
        return { user: null };
      }
      const profile = await hydrateProfile(client, sessionUser);
      return { user: profile };
    } catch (err: any) {
      return {
        user: null,
        error: formatSupabaseAuthError(err, 'Unable to verify authentication session.'),
      };
    }
  }

  public static async signUp(
    input: RegisterInput,
    deps: AuthServiceDependencies = {}
  ): Promise<AuthActionResult> {
    const nameError = validateDisplayName(input.name);
    if (nameError) return { success: false, error: nameError };

    const emailError = validateEmailAddress(input.email);
    if (emailError) return { success: false, error: emailError };

    const passwordError = validatePasswordStrength(input.password);
    if (passwordError) return { success: false, error: passwordError };

    const client = deps.client !== undefined ? deps.client : supabase;
    if (!client) {
      return {
        success: false,
        error:
          'Supabase Authentication is not configured in this environment. Continue in Guest mode or configure VITE_SUPABASE_URL and VITE_SUPABASE_ANON_KEY.',
      };
    }

    const trimmedName = input.name.trim();
    const normalizedEmail = input.email.trim().toLowerCase();
    const redirectTo = getRedirectUrl(deps);

    try {
      const { data, error } = await client.auth.signUp({
        email: normalizedEmail,
        password: input.password,
        options: {
          data: { display_name: trimmedName },
          ...(redirectTo ? { emailRedirectTo: redirectTo } : {}),
        },
      });

      if (error) {
        return {
          success: false,
          error: formatSupabaseAuthError(error, 'Registration failed. Please try again.'),
        };
      }

      if (data?.session && data?.user) {
        const profile = await hydrateProfile(client, data.user, trimmedName);
        return {
          success: true,
          user: profile,
          requiresEmailConfirmation: false,
          message: 'Account created and signed in.',
        };
      }

      if (data?.user) {
        return {
          success: true,
          user: null,
          requiresEmailConfirmation: true,
          message:
            'Account created! Please check your email inbox and click the confirmation link before signing in.',
        };
      }

      return {
        success: false,
        error: 'Registration could not be completed. Please try again.',
      };
    } catch (err: any) {
      return {
        success: false,
        error: formatSupabaseAuthError(err, 'Registration request failed.'),
      };
    }
  }

  public static async signIn(
    input: LoginInput,
    deps: AuthServiceDependencies = {}
  ): Promise<AuthActionResult> {
    const emailError = validateEmailAddress(input.email);
    if (emailError) return { success: false, error: emailError };

    if (!input.password) {
      return { success: false, error: 'Please enter your password.' };
    }

    const client = deps.client !== undefined ? deps.client : supabase;
    if (!client) {
      return {
        success: false,
        error:
          'Supabase Authentication is not configured in this environment. Continue in Guest mode or configure VITE_SUPABASE_URL and VITE_SUPABASE_ANON_KEY.',
      };
    }

    const normalizedEmail = input.email.trim().toLowerCase();

    try {
      const { data, error } = await client.auth.signInWithPassword({
        email: normalizedEmail,
        password: input.password,
      });

      if (error) {
        return {
          success: false,
          error: formatSupabaseAuthError(error, 'Sign in failed. Please try again.'),
        };
      }

      if (!data?.user) {
        return { success: false, error: 'No authenticated user was returned.' };
      }

      const profile = await hydrateProfile(client, data.user);
      return {
        success: true,
        user: profile,
        message: 'Signed in successfully.',
      };
    } catch (err: any) {
      return {
        success: false,
        error: formatSupabaseAuthError(err, 'Sign in request failed.'),
      };
    }
  }

  public static async signOut(deps: AuthServiceDependencies = {}): Promise<AuthActionResult> {
    const client = deps.client !== undefined ? deps.client : supabase;
    if (!client) {
      return { success: true, user: null, message: 'Signed out.' };
    }

    try {
      const { error } = await client.auth.signOut();
      if (error) {
        return {
          success: false,
          error: formatSupabaseAuthError(error, 'Sign out failed.'),
        };
      }
      return { success: true, user: null, message: 'Signed out safely.' };
    } catch (err: any) {
      return {
        success: false,
        error: formatSupabaseAuthError(err, 'Sign out failed.'),
      };
    }
  }

  public static async requestPasswordReset(
    email: string,
    deps: AuthServiceDependencies = {}
  ): Promise<AuthActionResult> {
    const emailError = validateEmailAddress(email);
    if (emailError) return { success: false, error: emailError };

    const client = deps.client !== undefined ? deps.client : supabase;
    if (!client) {
      return {
        success: false,
        error:
          'Supabase Authentication is not configured. Configure VITE_SUPABASE_URL and VITE_SUPABASE_ANON_KEY to send password reset emails.',
      };
    }

    const normalizedEmail = email.trim().toLowerCase();
    const redirectTo = getRedirectUrl(deps);

    try {
      const { error } = await client.auth.resetPasswordForEmail(
        normalizedEmail,
        redirectTo ? { redirectTo } : undefined
      );
      if (error) {
        return {
          success: false,
          error: formatSupabaseAuthError(error, 'Unable to send password reset email.'),
        };
      }
      return {
        success: true,
        message:
          'If an account exists for that email, a password reset link has been sent. Check your inbox.',
      };
    } catch (err: any) {
      return {
        success: false,
        error: formatSupabaseAuthError(err, 'Password reset request failed.'),
      };
    }
  }

  public static async updatePassword(
    newPassword: string,
    deps: AuthServiceDependencies = {}
  ): Promise<AuthActionResult> {
    const passwordError = validatePasswordStrength(newPassword);
    if (passwordError) return { success: false, error: passwordError };

    const client = deps.client !== undefined ? deps.client : supabase;
    if (!client) {
      return {
        success: false,
        error: 'Supabase Authentication is not configured.',
      };
    }

    try {
      const { data, error } = await client.auth.updateUser({
        password: newPassword,
      });

      if (error) {
        return {
          success: false,
          error: formatSupabaseAuthError(error, 'Unable to update password.'),
        };
      }

      const profile = data?.user ? await hydrateProfile(client, data.user) : null;
      return {
        success: true,
        user: profile,
        message: 'Your password has been updated successfully.',
      };
    } catch (err: any) {
      return {
        success: false,
        error: formatSupabaseAuthError(err, 'Password update failed.'),
      };
    }
  }

  public static onAuthStateChange(
    callback: (event: AuthChangeEventType, user: AuthUserProfile | null) => void,
    deps: AuthServiceDependencies = {}
  ): { unsubscribe: () => void } {
    const client = deps.client !== undefined ? deps.client : supabase;
    if (!client) {
      return { unsubscribe: () => {} };
    }

    const { data } = client.auth.onAuthStateChange(async (event, session) => {
      const mappedEvent = event as AuthChangeEventType;
      if (session?.user) {
        const profile = await hydrateProfile(client, session.user);
        callback(mappedEvent, profile);
      } else {
        callback(mappedEvent, null);
      }
    });

    return {
      unsubscribe: () => {
        try {
          data?.subscription?.unsubscribe();
        } catch {
          // ignore
        }
      },
    };
  }
}
