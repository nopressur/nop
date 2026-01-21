// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import {
  FRAME_AUTH,
  FRAME_AUTH_ERR,
  FRAME_AUTH_OK,
  FRAME_ERROR,
  FRAME_REQUEST,
  FRAME_RESPONSE,
  decodeFrame,
  encodeFrame,
} from "../protocol/ws-protocol";
import type {
  AuthErrFrame,
  AuthFrame,
  AuthOkFrame,
  ErrorFrame,
  RequestFrame,
  ResponseFrame,
  WsFrame,
} from "../protocol/ws-protocol";

type FrameHandler = (frame: WsFrame) => void;
type CloseHandler = (event: CloseEvent) => void;
type ErrorHandler = (error: Error) => void;

export class WsCoordinator {
  private socket: WebSocket | null = null;
  private handlers: FrameHandler[] = [];
  private closeHandlers: CloseHandler[] = [];
  private errorHandlers: ErrorHandler[] = [];
  private started = false;

  async connect(
    url: string,
    ticket: string,
    csrfToken: string,
  ): Promise<void> {
    if (this.socket) {
      if (
        this.socket.readyState === WebSocket.CLOSING ||
        this.socket.readyState === WebSocket.CLOSED
      ) {
        this.socket = null;
        this.started = false;
      } else {
        throw new Error("WebSocket already connected");
      }
    }

    this.socket = new WebSocket(url);
    this.socket.binaryType = "arraybuffer";
    this.start();

    await new Promise<void>((resolve, reject) => {
      if (!this.socket) {
        reject(new Error("WebSocket not initialized"));
        return;
      }

      const handleOpen = () => {
        cleanup();
        resolve();
      };

      const handleError = () => {
        cleanup();
        reject(new Error("WebSocket connection failed"));
      };

      const handleClose = (event: CloseEvent) => {
        cleanup();
        reject(new Error(`WebSocket closed (${event.code})`));
      };

      const cleanup = () => {
        this.socket?.removeEventListener("open", handleOpen);
        this.socket?.removeEventListener("error", handleError);
        this.socket?.removeEventListener("close", handleClose);
      };

      this.socket.addEventListener("open", handleOpen);
      this.socket.addEventListener("error", handleError);
      this.socket.addEventListener("close", handleClose);
    });

    const auth: AuthFrame = {
      frameType: FRAME_AUTH,
      ticket,
      csrfToken,
    };
    this.send(auth);
  }

  onFrame(handler: FrameHandler): void {
    this.handlers.push(handler);
  }

  onClose(handler: CloseHandler): void {
    this.closeHandlers.push(handler);
  }

  onError(handler: ErrorHandler): void {
    this.errorHandlers.push(handler);
  }

  start(): void {
    if (!this.socket) {
      throw new Error("WebSocket not connected");
    }
    if (this.started) {
      return;
    }
    this.started = true;
    const socket = this.socket;

    this.socket.onmessage = (event) => {
      if (this.socket !== socket) {
        return;
      }
      try {
        const data = new Uint8Array(event.data as ArrayBuffer);
        const frame = decodeFrame(data);
        this.handlers.forEach((handler) => handler(frame));
      } catch (error) {
        const err =
          error instanceof Error ? error : new Error("WebSocket decode failed");
        this.emitError(err);
      }
    };

    this.socket.onerror = () => {
      if (this.socket !== socket) {
        return;
      }
      this.socket = null;
      this.started = false;
      socket.close();
      this.emitError(new Error("WebSocket error"));
    };

    this.socket.onclose = (event) => {
      if (this.socket !== socket) {
        return;
      }
      this.socket = null;
      this.started = false;
      this.emitClose(event);
    };
  }

  send(frame: WsFrame): void {
    if (!this.socket) {
      throw new Error("WebSocket not connected");
    }
    const payload = encodeFrame(frame);
    this.socket.send(payload);
  }

  close(): void {
    if (this.socket) {
      this.socket.close();
      this.socket = null;
    }
    this.started = false;
  }

  private emitError(error: Error): void {
    this.errorHandlers.forEach((handler) => handler(error));
  }

  private emitClose(event: CloseEvent): void {
    this.closeHandlers.forEach((handler) => handler(event));
  }
}

export function isAuthOk(frame: WsFrame): frame is AuthOkFrame {
  return frame.frameType === FRAME_AUTH_OK;
}

export function isAuthErr(frame: WsFrame): frame is AuthErrFrame {
  return frame.frameType === FRAME_AUTH_ERR;
}

export function isErrorFrame(frame: WsFrame): frame is ErrorFrame {
  return frame.frameType === FRAME_ERROR;
}

export function isResponseFrame(frame: WsFrame): frame is ResponseFrame {
  return frame.frameType === FRAME_RESPONSE;
}

export function isRequestFrame(frame: WsFrame): frame is RequestFrame {
  return frame.frameType === FRAME_REQUEST;
}
