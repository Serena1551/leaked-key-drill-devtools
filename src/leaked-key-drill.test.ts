import assert from "node:assert/strict";
import { rotationDecision, verifyWebhookSignature } from "./leaked-key-drill.ts";

assert.equal(rotationDecision({ keyId: "k", temporaryProjectId: "p", search: "blast radius", graceHours: 4 }), "rotate");
assert.equal(rotationDecision({ keyId: "k", temporaryProjectId: "p", search: "blast radius", graceHours: 0 }), "hold");
assert.equal(verifyWebhookSignature("release-42", "2e17f6b86de1157f616517fe1c34a2940e5b8fe8781e9925e3c16379d0f2644c", "hook-secret"), true);
console.log("leaked-key drill decisions: pass");
