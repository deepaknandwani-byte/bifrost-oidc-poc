import { afterEach, describe, expect, it, vi } from "vitest";
import { getApiBaseUrl, getExampleBaseUrl, getWebSocketUrl } from "./port";

function stubBrowserLocation(url: string) {
	const parsed = new URL(url);
	vi.stubGlobal("window", {
		location: {
			protocol: parsed.protocol,
			host: parsed.host,
			port: parsed.port,
		},
	});
}

describe("port utils", () => {
	afterEach(() => {
		vi.unstubAllEnvs();
		vi.unstubAllGlobals();
	});

	it("uses the Go backend when running direct Vite development on port 3000", () => {
		vi.stubEnv("NODE_ENV", "development");
		stubBrowserLocation("http://localhost:3000/login");

		expect(getApiBaseUrl()).toBe("http://localhost:8080/api");
		expect(getExampleBaseUrl()).toBe("http://localhost:8080");
		expect(getWebSocketUrl("/ws")).toBe("ws://localhost:8080/ws");
	});

	it("uses same-origin URLs when dev UI is served through the Go server or ngrok", () => {
		vi.stubEnv("NODE_ENV", "development");
		stubBrowserLocation("https://example.ngrok-free.app/login");

		expect(getApiBaseUrl()).toBe("https://example.ngrok-free.app/api");
		expect(getExampleBaseUrl()).toBe("https://example.ngrok-free.app");
		expect(getWebSocketUrl("/ws")).toBe("wss://example.ngrok-free.app/ws");
	});
});
