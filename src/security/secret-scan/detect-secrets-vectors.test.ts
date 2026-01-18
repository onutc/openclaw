import { describe, expect, it } from "vitest";

import { hexEntropy, shannonEntropy } from "./entropy.js";
import { scanText } from "./scan.js";

describe("detect-secrets vectors (adapted)", () => {
  const detect = (value: string) => scanText(value, { config: { mode: "block" } });

  it("flags high entropy base64/base64url strings", () => {
    const base64 =
      "c3VwZXIgbG9uZyBzdHJpbmcgc2hvdWxkIGNhdXNlIGVub3VnaCBlbnRyb3B5";
    const base64url =
      "I6FwzQZFL9l-44nviI1F04OTmorMaVQf9GS4Oe07qxL_vNkW6CRas4Lo42vqJMT0M6riJfma_f-pTAuoX2U=";
    expect(detect(base64).blocked).toBe(true);
    expect(detect(base64url).blocked).toBe(true);
  });

  it("does not flag low entropy strings", () => {
    const base64Short = "c3VwZXIgc2VjcmV0IHZhbHVl";
    const hexLow = "aaaaaa";
    expect(detect(base64Short).blocked).toBe(false);
    expect(detect(hexLow).blocked).toBe(false);
  });

  it("reduces entropy for numeric hex strings", () => {
    const value = "0123456789";
    expect(hexEntropy(value)).toBeLessThan(shannonEntropy(value));
  });

  it("does not adjust entropy when hex includes letters", () => {
    const value = "12345a";
    expect(hexEntropy(value)).toBeCloseTo(shannonEntropy(value));
  });

  it("detects common tokens (GitHub, Telegram, Slack)", () => {
    const github = ["ghp_", "wWPw5k4aXcaT4fNP0UcnZwJUVFk6LO0pINUx"].join("");
    const telegram = ["110201543", ":AAHdqTcvCH1vGWJxfSe1ofSAs0K5PALDsaw"].join("");
    const slack = ["xoxb-", "34532454-e039d02840a0b9379c"].join("");
    expect(detect(github).blocked).toBe(true);
    expect(detect(telegram).blocked).toBe(true);
    expect(detect(slack).blocked).toBe(true);
  });

  it("detects Slack webhook URLs", () => {
    const webhook = [
      "https://hooks.slack.com/services/",
      "Txxxxxxxx",
      "/",
      "Bxxxxxxxx",
      "/",
      "xxxxxxxxxxxxxxxxxxxxxxxx",
    ].join("");
    expect(detect(webhook).blocked).toBe(true);
  });

  it("detects private key blocks", () => {
    const pem = [
      "-----BEGIN PRIVATE KEY-----",
      "ABCDEF1234567890",
      "ZYXWVUT987654321",
      "-----END PRIVATE KEY-----",
    ].join("\n");
    expect(detect(pem).blocked).toBe(true);
  });

  it("detects keyword-style assignments and comparisons", () => {
    const withSpaces = 'password = "value with quotes and spaces"';
    const goAssign = 'password := "mysecretvalue"';
    const unquoted = "db_pass := abc123";
    const reverseCompare = 'if ("supersecret" == my_password) {';
    const bareQuoted = 'private_key "hopenobodyfindsthisone";';
    expect(detect(withSpaces).blocked).toBe(true);
    expect(detect(goAssign).blocked).toBe(true);
    expect(detect(unquoted).blocked).toBe(true);
    expect(detect(reverseCompare).blocked).toBe(true);
    expect(detect(bareQuoted).blocked).toBe(true);
  });

  it("ignores keyword false positives", () => {
    const empty = 'password = ""';
    const fake = 'password = "somefakekey"';
    const template = "password: ${link}";
    const symbols = 'password = ",.:-"';
    expect(detect(empty).blocked).toBe(false);
    expect(detect(fake).blocked).toBe(false);
    expect(detect(template).blocked).toBe(false);
    expect(detect(symbols).blocked).toBe(false);
  });
});
