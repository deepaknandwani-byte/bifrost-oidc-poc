import { describe, expect, it } from "vitest";
import { buildSSOLoginURL } from "./ssoLogin";

describe("buildSSOLoginURL", () => {
  it("preserves a valid post-login workspace goto", () => {
    const url = buildSSOLoginURL("http://localhost:8080/api", "?goto=%2Fworkspace%2Fproviders");

    expect(url).toBe("http://localhost:8080/api/session/sso/start?goto=%2Fworkspace%2Fproviders");
  });

  it("falls back to workspace for unsafe goto values", () => {
    const url = buildSSOLoginURL("/api/", "?goto=https%3A%2F%2Fevil.example.com");

    expect(url).toBe("/api/session/sso/start?goto=%2Fworkspace");
  });
});