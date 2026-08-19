import { DEFAULT_POST_LOGIN_PATH, getLoginGotoFromSearch } from "./loginGoto";

export function buildSSOLoginURL(apiBaseUrl: string, search: string): string {
  const postLoginPath = getLoginGotoFromSearch(search) ?? DEFAULT_POST_LOGIN_PATH;
  const normalizedApiBase = apiBaseUrl.replace(/\/+$/, "");
  return `${normalizedApiBase}/session/sso/start?goto=${encodeURIComponent(postLoginPath)}`;
}