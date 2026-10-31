import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";
import { sha256Hex } from "../../shared/sha256";

test("sha256Hex matches node:crypto", () => {
  const samples = ["", "a", "password", "words ".repeat(200), "café 🙂 密码"];
  for (const value of samples) {
    assert.equal(
      sha256Hex(value),
      createHash("sha256").update(value).digest("hex"),
    );
  }
});
