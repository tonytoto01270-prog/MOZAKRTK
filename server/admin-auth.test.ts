import { describe, expect, it } from "vitest";

function configuredAdminCredentials() {
  return {
    username: process.env.ADMIN_USERNAME || "",
    password: process.env.ADMIN_PASSWORD || "",
  };
}

describe("admin credentials", () => {
  it("loads the supplied admin secret configuration", () => {
    const credentials = configuredAdminCredentials();
    expect(credentials.username).toBe("alton");
    expect(credentials.password).toBe("alton112233");
  });
});
