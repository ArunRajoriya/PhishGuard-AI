import { api } from "./api"

export interface LoginRequest {
  email: string
  password: string
}

export interface RegisterRequest {
  email: string
  password: string
}

export interface AuthUser {
  id: number
  email: string
  role: string
  is_active: boolean
  created_at: string
}

export interface AuthResponse {
  success: boolean
  access_token: string
  token_type: string
  user: AuthUser
  request_id: string
}

export async function login(
  email: string,
  password: string,
): Promise<AuthResponse> {
  const response = await api.post<AuthResponse>(
    "/api/v1/auth/login",
    {
      email,
      password,
    },
  )

  localStorage.setItem(
    "access_token",
    response.data.access_token,
  )

  return response.data
}

export async function register(
  email: string,
  password: string,
): Promise<AuthResponse> {
  const response = await api.post<AuthResponse>(
    "/api/v1/auth/register",
    {
      email,
      password,
    },
  )

  localStorage.setItem(
    "access_token",
    response.data.access_token,
  )

  return response.data
}

export function logout(): void {
  localStorage.removeItem("access_token")
}

export function isAuthenticated(): boolean {
  return Boolean(
    localStorage.getItem("access_token"),
  )
}