import {
    WasmRequest,
    WasmResponse,
} from "./wasmFunctions";
import {
    RequestInit,
    Response,
} from 'node-fetch';
import fetch from 'node-fetch';

export type Fetcher = (request: WasmRequest) => Promise<WasmResponse>;

async function wasmFromResponse(response: Response): Promise<WasmResponse> {
  return {
    body: Array.from(new Uint8Array(await response.arrayBuffer())),
    headers: Array.from(response.headers),
    status: response.status,
  };
}


export async function fetcher(request: WasmRequest) {
    const PAYLOAD_SIZE_LIMIT = 8000000;

    let requestInit: RequestInit = {
        headers: request.headers,
        method: request.method,
    };
    if (request.body.length > 0) {
        requestInit.body = Buffer.from(request.body);
    }
    const response = await fetch(request.url, requestInit);
    const body = await response.arrayBuffer();
    if (body.byteLength > PAYLOAD_SIZE_LIMIT) {
        throw `The size of payload exceeds the limit ${PAYLOAD_SIZE_LIMIT}`;
    }

    return await wasmFromResponse(new Response(Buffer.from(body), {
        headers: response.headers,
        status: response.status,
    }));
}