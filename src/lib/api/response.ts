import { NextResponse } from "next/server";

export type ApiErrorBody = {
  code: string;
  message: string;
  details?: unknown;
};

/** Every API route answers with this envelope so clients can rely on one shape. */
export type ApiEnvelope<T> =
  { success: true; data: T; error: null } | { success: false; data: null; error: ApiErrorBody };

export function ok<T>(data: T, init?: ResponseInit) {
  return NextResponse.json<ApiEnvelope<T>>({ success: true, data, error: null }, init);
}

export function fail(
  status: number,
  code: string,
  message: string,
  details?: unknown,
  headers?: HeadersInit,
) {
  const error: ApiErrorBody =
    details === undefined ? { code, message } : { code, message, details };
  return NextResponse.json<ApiEnvelope<never>>(
    { success: false, data: null, error },
    { status, headers },
  );
}
