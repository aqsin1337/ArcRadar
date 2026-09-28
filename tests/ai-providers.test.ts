import { describe, expect, it, vi } from "vitest";
import { postJson } from "@/lib/ai/http";
import { AnthropicProvider } from "@/lib/ai/providers/anthropic";
import { extractJson } from "@/lib/ai/providers/common";
import { DeepSeekProvider } from "@/lib/ai/providers/deepseek";
import { GroqProvider } from "@/lib/ai/providers/groq";
import { OllamaProvider } from "@/lib/ai/providers/ollama";
import { OpenAiProvider } from "@/lib/ai/providers/openai";
import { AiProviderError, type AiCompleteRequest } from "@/lib/ai/types";
import { z } from "zod";

/** A fetch stand-in that records what was asked and answers with `respond`. */
function fakeFetch(respond: (url: URL, init: RequestInit) => Response | Promise<Response>) {
  const calls: { url: URL; init: RequestInit }[] = [];
  const impl = vi.fn(async (input: URL | string | Request, init?: RequestInit) => {
    const url = input instanceof URL ? input : new URL(String(input));
    calls.push({ url, init: init ?? {} });
    return respond(url, init ?? {});
  }) as unknown as typeof fetch;
  return { impl, calls };
}

const json = (body: unknown, init: ResponseInit = {}) =>
  new Response(JSON.stringify(body), {
    status: 200,
    headers: { "content-type": "application/json" },
    ...init,
  });

async function failureOf(promise: Promise<unknown>): Promise<AiProviderError> {
  try {
    await promise;
  } catch (error) {
    expect(error).toBeInstanceOf(AiProviderError);
    return error as AiProviderError;
  }
  throw new Error("expected the call to fail");
}

const BASE = "https://api.example-provider.test";
const baseRequest = (extra: Partial<Parameters<typeof postJson>[0]> & { impl: typeof fetch }) => ({
  baseUrl: BASE,
  path: "/thing",
  headers: { "x-key": "SECRET-KEY-123" },
  body: { hello: "world" },
  signal: new AbortController().signal,
  fetchImpl: extra.impl,
  ...extra,
});

describe("postJson", () => {
  it("sends one POST with the key in a header, never following redirects or caching", async () => {
    const { impl, calls } = fakeFetch(() => json({ ok: true }));
    const body = await postJson(baseRequest({ impl }));

    expect(body).toEqual({ ok: true });
    expect(calls).toHaveLength(1);
    const [{ url, init }] = calls;
    expect(url.href).toBe(`${BASE}/thing`);
    expect(init).toMatchObject({ method: "POST", redirect: "manual", cache: "no-store" });
    expect(init.headers).toMatchObject({ "x-key": "SECRET-KEY-123", accept: "application/json" });
    expect(init.body).toBe(JSON.stringify({ hello: "world" }));
    expect(String(init.body)).not.toContain("SECRET-KEY-123");
  });

  it("refuses a plain http base by default", async () => {
    const { impl } = fakeFetch(() => json({}));
    const failure = await failureOf(
      postJson(baseRequest({ impl, baseUrl: "http://api.example-provider.test" })),
    );
    expect(failure.reason).toBe("bad_response");
    expect(impl).not.toHaveBeenCalled();
  });

  it("allows plain http only when allowInsecure is set (the local-Ollama case)", async () => {
    const { impl } = fakeFetch(() => json({ ok: true }));
    const body = await postJson(
      baseRequest({ impl, baseUrl: "http://127.0.0.1:11434", allowInsecure: true }),
    );
    expect(body).toEqual({ ok: true });
  });

  it("never sends a request that would resolve outside the provider's own origin", async () => {
    const { impl, calls } = fakeFetch(() => json({}));
    // A base address with no path lets a leading "@" turn a path into a user-info host escape --
    // the same trick src/lib/intel/http.ts's getJson is tested against.
    const error = await failureOf(
      postJson(
        baseRequest({ impl, baseUrl: "https://api.example-provider.test", path: "@evil.test/x" }),
      ),
    );
    expect(error.reason).toBe("bad_response");
    expect(calls).toHaveLength(0);
  });

  it("maps 401/403 to auth, 429 to rate_limited (with Retry-After), 5xx to unavailable", async () => {
    const { impl: unauthorized } = fakeFetch(() => new Response("{}", { status: 401 }));
    expect((await failureOf(postJson(baseRequest({ impl: unauthorized })))).reason).toBe("auth");

    const { impl: limited } = fakeFetch(
      () => new Response("{}", { status: 429, headers: { "retry-after": "30" } }),
    );
    const failure = await failureOf(postJson(baseRequest({ impl: limited })));
    expect(failure.reason).toBe("rate_limited");
    expect(failure.retryAfterSeconds).toBe(30);

    const { impl: down } = fakeFetch(() => new Response("{}", { status: 503 }));
    expect((await failureOf(postJson(baseRequest({ impl: down })))).reason).toBe("unavailable");
  });

  it("throws bad_response for a non-JSON answer", async () => {
    const { impl } = fakeFetch(() => new Response("not json", { status: 200 }));
    expect((await failureOf(postJson(baseRequest({ impl })))).reason).toBe("bad_response");
  });

  it("throws bad_response for a response larger than the cap", async () => {
    const { impl } = fakeFetch(
      () => new Response("{}", { status: 200, headers: { "content-length": "99999999" } }),
    );
    expect((await failureOf(postJson(baseRequest({ impl, maxBytes: 10 })))).reason).toBe(
      "bad_response",
    );
  });
});

describe("extractJson", () => {
  it("parses a clean JSON answer", () => {
    expect(extractJson('{"a":1}')).toEqual({ a: 1 });
  });

  it("extracts JSON wrapped in prose or a fenced code block", () => {
    expect(extractJson('Sure, here you go:\n```json\n{"a":1}\n```')).toEqual({ a: 1 });
  });

  it("throws on an answer with no JSON in it at all", () => {
    expect(() => extractJson("no json here")).toThrow(AiProviderError);
  });
});

const schema = z.object({ a: z.number() });
const request = (impl: typeof fetch, model?: string): AiCompleteRequest => ({
  system: "system",
  user: "user",
  schema,
  maxOutputTokens: 100,
  signal: new AbortController().signal,
  model,
});

describe("OpenAI-compatible adapters (Groq, OpenAI, DeepSeek)", () => {
  it("Groq: posts messages with json_object response_format and parses choices[0].message.content", async () => {
    const { impl, calls } = fakeFetch(() =>
      json({
        model: "llama-3.3-70b-versatile",
        choices: [{ message: { content: '{"a":1}' } }],
        usage: { prompt_tokens: 10, completion_tokens: 5 },
      }),
    );
    const provider = new GroqProvider({ apiKey: "gk", fetchImpl: impl });
    const result = await provider.complete(request(impl));

    expect(result).toEqual({
      data: { a: 1 },
      model: "llama-3.3-70b-versatile",
      usage: { input: 10, output: 5 },
    });
    const { url, init } = calls[0];
    expect(url.href).toBe("https://api.groq.com/openai/v1/chat/completions");
    expect(init.headers).toMatchObject({ authorization: "Bearer gk" });
    const body = JSON.parse(String(init.body));
    expect(body).toMatchObject({
      model: "llama-3.3-70b-versatile",
      response_format: { type: "json_object" },
      messages: [
        { role: "system", content: "system" },
        { role: "user", content: "user" },
      ],
    });
  });

  it("Groq: an explicit model overrides the adapter default", async () => {
    const { impl, calls } = fakeFetch(() => json({ choices: [{ message: { content: "{}" } }] }));
    const provider = new GroqProvider({ apiKey: "gk", fetchImpl: impl });
    await provider.complete(request(impl, "custom-model"));
    expect(JSON.parse(String(calls[0].init.body)).model).toBe("custom-model");
  });

  it("OpenAI: uses its own base URL and default model", async () => {
    const { impl, calls } = fakeFetch(() => json({ choices: [{ message: { content: "{}" } }] }));
    const provider = new OpenAiProvider({ apiKey: "ok", fetchImpl: impl });
    await provider.complete(request(impl));
    expect(calls[0].url.href).toBe("https://api.openai.com/v1/chat/completions");
  });

  it("DeepSeek: uses its own base URL and default model", async () => {
    const { impl, calls } = fakeFetch(() => json({ choices: [{ message: { content: "{}" } }] }));
    const provider = new DeepSeekProvider({ apiKey: "dk", fetchImpl: impl });
    await provider.complete(request(impl));
    expect(calls[0].url.href).toBe("https://api.deepseek.com/chat/completions");
  });

  it("throws bad_response when a choice has no content", async () => {
    const { impl } = fakeFetch(() => json({ choices: [{ message: {} }] }));
    const provider = new GroqProvider({ apiKey: "gk", fetchImpl: impl });
    await expect(provider.complete(request(impl))).rejects.toMatchObject({
      reason: "bad_response",
    });
  });
});

describe("AnthropicProvider", () => {
  it("sends the key as x-api-key, the system prompt at the top level, and parses the text block", async () => {
    const { impl, calls } = fakeFetch(() =>
      json({
        model: "claude-haiku-4-5-20251001",
        content: [{ type: "text", text: '{"a":1}' }],
        usage: { input_tokens: 8, output_tokens: 3 },
      }),
    );
    const provider = new AnthropicProvider({ apiKey: "ak", fetchImpl: impl });
    const result = await provider.complete(request(impl));

    expect(result).toEqual({
      data: { a: 1 },
      model: "claude-haiku-4-5-20251001",
      usage: { input: 8, output: 3 },
    });
    const { url, init } = calls[0];
    expect(url.href).toBe("https://api.anthropic.com/v1/messages");
    expect(init.headers).toMatchObject({ "x-api-key": "ak", "anthropic-version": "2023-06-01" });
    const body = JSON.parse(String(init.body));
    expect(body).toMatchObject({ system: "system" });
    expect(body.messages).toEqual([{ role: "user", content: "user" }]);
  });

  it("falls back to extracting JSON when Anthropic wraps the answer in prose", async () => {
    const { impl } = fakeFetch(() =>
      json({ content: [{ type: "text", text: 'Sure: {"a":1} — done.' }] }),
    );
    const provider = new AnthropicProvider({ apiKey: "ak", fetchImpl: impl });
    expect((await provider.complete(request(impl))).data).toEqual({ a: 1 });
  });
});

describe("OllamaProvider", () => {
  it("posts to /api/chat with format: json and stream: false, over plain http", async () => {
    const { impl, calls } = fakeFetch(() =>
      json({
        model: "llama3.1",
        message: { content: '{"a":1}' },
        eval_count: 5,
        prompt_eval_count: 20,
      }),
    );
    const provider = new OllamaProvider({ baseUrl: "http://127.0.0.1:11434", fetchImpl: impl });
    const result = await provider.complete(request(impl));

    expect(result).toEqual({ data: { a: 1 }, model: "llama3.1", usage: { input: 20, output: 5 } });
    const { url, init } = calls[0];
    expect(url.href).toBe("http://127.0.0.1:11434/api/chat");
    const body = JSON.parse(String(init.body));
    expect(body).toMatchObject({ format: "json", stream: false, model: "llama3.1" });
  });
});
