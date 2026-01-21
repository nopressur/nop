// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import { getAdminRuntimeConfig } from "../config/runtime";
import { logAdminInfo, logAdminWarn } from "../logging/admin-logging";
import {
  FRAME_ACK,
  FRAME_AUTH_ERR,
  FRAME_AUTH_OK,
  FRAME_ERROR,
  FRAME_REQUEST,
  FRAME_RESPONSE,
  STREAM_FLAG_FINAL,
  FRAME_STREAM_CHUNK,
} from "../protocol/ws-protocol";
import type {
  AckFrame,
  RequestFrame,
  ResponseFrame,
  StreamChunkFrame,
  WsFrame,
} from "../protocol/ws-protocol";
import { WorkflowCounter } from "../protocol/wire";
import {
  SYSTEM_ACTION_PONG_ERROR,
  SYSTEM_DOMAIN_ID,
  decodeMessageResponse,
} from "../protocol/system";
import {
  clearBrowserTimeout,
  getLocationOrigin,
  setBrowserTimeout,
} from "../services/browser";
import { getCsrfToken } from "./csrf";
import { RestError, restJson } from "./restClient";
import { WsCoordinator } from "./ws-coordinator";

const AUTH_TIMEOUT_MS = 6000;
const REQUEST_TIMEOUT_MS = 10000;
const STREAM_ACK_TIMEOUT_MS = 15000;

type PendingRequest = {
  resolve: (frame: ResponseFrame) => void;
  reject: (error: Error) => void;
  timeoutId: number;
};

type PendingAck = {
  resolve: () => void;
  reject: (error: Error) => void;
  timeoutId: number;
};

const LOG_SCOPE = "AdminWS";

export class AdminWsClient {
  private coordinator = new WsCoordinator();
  private workflowCounter = new WorkflowCounter();
  private pending = new Map<number, PendingRequest>();
  private pendingAcks = new Map<string, PendingAck>();
  private authResolve?: () => void;
  private authReject?: (error: Error) => void;
  private authPromise: Promise<void>;
  private authCompleted = false;
  private connectPromise?: Promise<void>;
  private connected = false;

  constructor(private wsPath: string, private wsTicketPath: string) {
    this.authPromise = this.createAuthPromise();
    this.coordinator.onFrame((frame) => this.handleFrame(frame));
    this.coordinator.onClose((event) => this.handleSocketClose(event));
    this.coordinator.onError((error) => this.handleSocketError(error));
  }

  async connect(): Promise<void> {
    if (this.connected) {
      return;
    }
    if (!this.connectPromise) {
      this.connectPromise = this.doConnect().catch((error) => {
        this.connectPromise = undefined;
        throw error;
      });
    }
    return this.connectPromise;
  }

  async request(
    domainId: number,
    actionId: number,
    payload: Uint8Array,
  ): Promise<ResponseFrame> {
    await this.connect();

    const workflowId = this.workflowCounter.next();

    const frame: RequestFrame = {
      frameType: FRAME_REQUEST,
      domainId,
      actionId,
      workflowId,
      payload,
    };

    return new Promise((resolve, reject) => {
      const timeoutId = setBrowserTimeout(() => {
        this.pending.delete(workflowId);
        reject(new Error("Request timed out"));
      }, REQUEST_TIMEOUT_MS);

      this.pending.set(workflowId, { resolve, reject, timeoutId });
      logAdminInfo(LOG_SCOPE, "Request sent", { workflowId, domainId, actionId });
      this.coordinator.send(frame);
    });
  }

  async sendStreamChunk(
    streamId: number,
    seq: number,
    payload: Uint8Array,
    isFinal: boolean,
  ): Promise<void> {
    await this.connect();

    const frame: StreamChunkFrame = {
      frameType: FRAME_STREAM_CHUNK,
      streamId,
      seq,
      flags: isFinal ? STREAM_FLAG_FINAL : 0,
      payload,
    };

    const ackPromise = this.waitForAck(streamId, seq);
    this.coordinator.send(frame);
    await ackPromise;
  }

  async streamPayload(params: {
    streamId: number;
    payload: Uint8Array;
    chunkBytes: number;
    onProgress?: (loaded: number, total: number) => void;
  }): Promise<void> {
    if (params.chunkBytes <= 0) {
      throw new Error("chunkBytes must be positive");
    }
    const total = params.payload.length;
    let seq = 0;
    let loaded = 0;
    for (let offset = 0; offset < params.payload.length; offset += params.chunkBytes) {
      const end = Math.min(offset + params.chunkBytes, params.payload.length);
      const chunk = params.payload.subarray(offset, end);
      loaded = end;
      const isFinal = loaded === total;
      await this.sendStreamChunk(params.streamId, seq, chunk, isFinal);
      params.onProgress?.(loaded, total);
      seq += 1;
    }
  }

  private async doConnect(): Promise<void> {
    const wsUrl = buildWsUrl(this.wsPath);
    logAdminInfo(LOG_SCOPE, "Connecting to management WS", { wsUrl });

    const ticket = await fetchWsTicket(this.wsTicketPath);
    logAdminInfo(LOG_SCOPE, "Received WS ticket");

    const csrfToken = await getCsrfToken();
    logAdminInfo(LOG_SCOPE, "Loaded CSRF token");

    await this.coordinator.connect(wsUrl, ticket, csrfToken);
    await this.awaitAuth(AUTH_TIMEOUT_MS);
    this.connected = true;
    logAdminInfo(LOG_SCOPE, "Management WS authenticated");
  }

  private handleFrame(frame: WsFrame): void {
    switch (frame.frameType) {
      case FRAME_AUTH_OK:
        logAdminInfo(LOG_SCOPE, "Auth OK");
        this.markAuthResolved();
        return;
      case FRAME_AUTH_ERR:
        logAdminWarn(LOG_SCOPE, "Auth error", frame.message);
        this.markAuthRejected(new Error(frame.message));
        return;
      case FRAME_ERROR:
        logAdminWarn(LOG_SCOPE, "Error frame", frame.message);
        this.failAll(frame.message);
        return;
      case FRAME_RESPONSE:
        this.resolveRequest(frame);
        return;
      case FRAME_ACK:
        this.handleAck(frame);
        return;
      case FRAME_STREAM_CHUNK:
        this.ackStreamChunk(frame);
        return;
      default:
        logAdminWarn(LOG_SCOPE, "Unexpected frame", frame);
        return;
    }
  }

  private resolveRequest(frame: ResponseFrame): void {
    const pending = this.pending.get(frame.workflowId);
    if (!pending) {
      logAdminWarn(LOG_SCOPE, "Response without pending request", {
        workflowId: frame.workflowId,
        actionId: frame.actionId,
      });
      return;
    }
    clearBrowserTimeout(pending.timeoutId);
    this.pending.delete(frame.workflowId);
    if (
      frame.domainId === SYSTEM_DOMAIN_ID &&
      frame.actionId === SYSTEM_ACTION_PONG_ERROR
    ) {
      let message = "Request failed";
      try {
        message = decodeMessageResponse(frame.payload).message;
      } catch (error) {
        logAdminWarn(LOG_SCOPE, "Failed to decode error response", error);
      }
      pending.reject(new Error(message));
      return;
    }
    logAdminInfo(LOG_SCOPE, "Response received", {
      workflowId: frame.workflowId,
      actionId: frame.actionId,
    });
    pending.resolve(frame);
  }

  private failAll(message: string): void {
    const shouldNotify = this.pending.size > 0 || !this.authCompleted;
    for (const pending of this.pending.values()) {
      clearBrowserTimeout(pending.timeoutId);
      pending.reject(new Error(message));
    }
    this.pending.clear();
    for (const pending of this.pendingAcks.values()) {
      clearBrowserTimeout(pending.timeoutId);
      pending.reject(new Error(message));
    }
    this.pendingAcks.clear();
    if (shouldNotify) {
      logAdminWarn(LOG_SCOPE, "Request failed", message);
    }
  }

  private ackStreamChunk(frame: StreamChunkFrame): void {
    const ack: AckFrame = {
      frameType: FRAME_ACK,
      streamId: frame.streamId,
      seq: frame.seq,
    };
    this.coordinator.send(ack);
  }

  private handleAck(frame: AckFrame): void {
    const key = this.buildAckKey(frame.streamId, frame.seq);
    const pending = this.pendingAcks.get(key);
    if (!pending) {
      return;
    }
    clearBrowserTimeout(pending.timeoutId);
    this.pendingAcks.delete(key);
    pending.resolve();
  }

  private waitForAck(streamId: number, seq: number): Promise<void> {
    const key = this.buildAckKey(streamId, seq);
    return new Promise((resolve, reject) => {
      const timeoutId = setBrowserTimeout(() => {
        this.pendingAcks.delete(key);
        reject(new Error("Stream ack timed out"));
      }, STREAM_ACK_TIMEOUT_MS);
      this.pendingAcks.set(key, { resolve, reject, timeoutId });
    });
  }

  private buildAckKey(streamId: number, seq: number): string {
    return `${streamId}:${seq}`;
  }

  private async awaitAuth(timeoutMs: number): Promise<void> {
    let timeoutId = 0;
    const timeout = new Promise<void>((_, reject) => {
      timeoutId = setBrowserTimeout(() => {
        reject(new Error("WebSocket auth timed out"));
      }, timeoutMs);
    });
    try {
      await Promise.race([this.authPromise, timeout]);
    } finally {
      clearBrowserTimeout(timeoutId);
    }
  }

  private markAuthResolved(): void {
    if (this.authCompleted) {
      return;
    }
    this.authCompleted = true;
    this.authResolve?.();
    this.authResolve = undefined;
    this.authReject = undefined;
  }

  private markAuthRejected(error: Error): void {
    if (this.authCompleted) {
      return;
    }
    this.authCompleted = true;
    this.authReject?.(error);
    this.authResolve = undefined;
    this.authReject = undefined;
  }

  private handleSocketError(error: Error): void {
    logAdminWarn(LOG_SCOPE, "Socket error", error.message || error);
    this.markAuthRejected(error);
    this.failAll(error.message || "WebSocket error");
    this.resetConnectionState();
  }

  private handleSocketClose(event: CloseEvent): void {
    logAdminWarn(LOG_SCOPE, "Socket closed", {
      code: event.code,
      reason: event.reason,
      wasClean: event.wasClean,
    });
    const message =
      event.reason || "WebSocket closed before completing request";
    this.markAuthRejected(new Error(message));
    this.failAll(message);
    this.resetConnectionState();
  }

  private resetConnectionState(): void {
    this.connected = false;
    this.connectPromise = undefined;
    this.authPromise = this.createAuthPromise();
  }

  private createAuthPromise(): Promise<void> {
    return new Promise((resolve, reject) => {
      this.authResolve = resolve;
      this.authReject = reject;
      this.authCompleted = false;
    });
  }
}

function buildWsUrl(wsPath: string): string {
  const url = new URL(wsPath, getLocationOrigin());
  url.protocol = url.protocol === "https:" ? "wss:" : "ws:";
  return url.toString();
}

async function fetchWsTicket(wsTicketPath: string): Promise<string> {
  let data: { ticket?: string };
  try {
    data = await restJson<{ ticket?: string }>(wsTicketPath, {
      method: "POST",
    });
  } catch (error) {
    if (error instanceof RestError) {
      logAdminWarn(LOG_SCOPE, "Ticket request failed", error.status);
      throw new Error(`Failed to request WebSocket ticket (${error.status})`);
    }
    logAdminWarn(LOG_SCOPE, "Ticket request failed", error);
    throw error;
  }
  if (!data.ticket) {
    logAdminWarn(LOG_SCOPE, "Ticket response missing ticket");
    throw new Error("WebSocket ticket missing");
  }
  return data.ticket;
}

let sharedClient: AdminWsClient | null = null;

export function getAdminWsClient(): AdminWsClient {
  if (!sharedClient) {
    const config = getAdminRuntimeConfig();
    sharedClient = new AdminWsClient(config.wsPath, config.wsTicketPath);
  }
  return sharedClient;
}
