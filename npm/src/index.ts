import "crypto";

export interface BalanceResponseType {
  requests_left: number;
  expiration_date: Date;
}

export interface UploadResponseType {
  blake3Hash: string;
}

interface RawBalanceResponse {
  requests_left: number;
  expiration_date: string | number;
}

export interface StaticAnalysisDataType {
  fileName: string;
  date: Date;
  staticAnalysisDuration: number;
  tags: Tags[];
  sizeInBytes: number;
  configs?: JSON;
  blake3Hash: string;
  sha512Hash: string;
  sha256Hash: string;
  sha1Hash: string;
  mD5Hash: string;
  ssDeep: string;
}

interface Tags {
  name: string;
  heat: number;
}

/**
 * Fetches the remaining balance and expiration date
 *
 * @param apiKey - API Key
 */
export async function fetchBalance(
  apiKey: string,
): Promise<BalanceResponseType> {
  if (!apiKey) {
    throw new Error("Uncover it: API Key is required");
  }

  const url = `https://www.uncoverit.org/api/balance`;

  const response = await fetch(url, {
    method: "GET",
    headers: { Authorization: apiKey },
  });

  if (!response.ok) {
    let errorMessage = `Uncover it API Error: ${response.status} ${response.statusText}`;

    try {
      const errorBody = (await response.json()) as any;
      if (errorBody?.error) {
        errorMessage = errorBody.error;
      }
    } catch (e) {}

    throw new Error(errorMessage);
  }

  const data = (await response.json()) as RawBalanceResponse;

  return {
    requests_left: data.requests_left,
    expiration_date: new Date(data.expiration_date),
  };
}

/**
 * Check if a file is already uploaded to Uncover it.
 *
 * **IMPORTANT**: the { upload } function also already checks if a file is uploaded. You may only use that if needed.
 *
 * @returns boolean
 *
 * @param apiKey - API Key
 * @param file - The `File` or `Blob` object to check, or its SHA-256 hash string.
 *
 * @example
 * // Check using a File object
 * const exists = await exists("YOUR_API_KEY", myFileObject);
 *
 * @example
 * // Check using a SHA-256 hash
 * const exists = await exists("YOUR_API_KEY", "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e");
 */
export async function exists(
  apiKey: string,
  file: Blob | File | string,
): Promise<boolean> {
  if (!apiKey) {
    throw new Error("Uncover it: API Key is required");
  }

  let hash: string;

  if (typeof file === "string") {
    const sha256Regex = /^[a-fA-F0-9]{64}$/;
    if (sha256Regex.test(file)) {
      hash = file;
    } else {
      throw new Error("Uncover it: File hash must be a valid SHA-256 string");
    }
  } else if (typeof (file as any).arrayBuffer === "function") {
    const buffer = await file.arrayBuffer();
    const hashBuffer = await crypto.subtle.digest("SHA-256", buffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    hash = hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
  } else {
    throw new Error(
      "Uncover it: Invalid input: file must be a File/Blob object or a SHA-256 hash string",
    );
  }

  return new Promise((resolve, reject) => {
    const ws = new WebSocket(
      `wss://api.uncoverit.org/websocket?hash=${hash}&apikey=${apiKey}`,
    );

    const timeout = setTimeout(() => {
      ws.close();
      reject(new Error("Uncover it: WebSocket request timed out"));
    }, 10000);

    ws.onmessage = (event) => {
      clearTimeout(timeout);
      ws.onclose = null;
      ws.onerror = null;
      ws.close();

      if (event.data === "STATUS:UPLOAD_REQUIRED") {
        resolve(false);
      } else {
        resolve(true);
      }
    };

    ws.onerror = (event) => {
      clearTimeout(timeout);
      ws.onclose = null;
      ws.close();
      const msg = (event as any).message || "Connection refused";
      reject(new Error(`Uncover it: WebSocket connection failed: ${msg}`));
    };

    ws.onclose = (event) => {
      clearTimeout(timeout);
      if (!event.wasClean) {
        reject(
          new Error(`Uncover it: WebSocket closed unexpectedly: ${event.code}`),
        );
      }

      reject(new Error("Uncover it: WebSocket closed without response"));
    };
  });
}

/**
 * Upload a file to Uncover it
 *
 * @returns blake3Hash
 *
 * @param apiKey - API Key
 * @param file - The `File` or `Blob` object.
 *
 * @example
 * // Uploading a file
 * const requests = await upload("YOUR_API_KEY", myFileObject);
 */
export async function upload(
  apiKey: string,
  file: Blob | File,
): Promise<UploadResponseType> {
  if (file.size > 100 * 1024 * 1024) {
    throw new Error("Uncover it: File size exceeds the 100MB limit");
  }

  const validExtensions = [".exe", ".bin", ".elf"];

  const fileName = (file as any).name;

  if (!fileName) {
    throw new Error(
      "Uncover it: File name is missing. Please ensure you are passing a File object.",
    );
  }

  const fileExtension = "." + fileName.split(".").pop()?.toLowerCase();

  if (!validExtensions.includes(fileExtension)) {
    throw new Error(
      `Uncover it: Unsupported file type. Please upload a supported file (${validExtensions.join(
        ", ",
      )}).`,
    );
  }

  const isUploaded = await exists(apiKey, file);

  if (isUploaded) {
    throw new Error(
      "Uncover it: File already exists. Please fetch the analysis data instead.",
    );
  }

  const formData = new FormData();
  formData.append("file", file);

  const data = await fetch("https://api.uncoverit.org/private/upload", {
    method: "POST",
    headers: {
      authorization: apiKey,
    },
    body: formData,
  });

  const response = await data.json();

  if (!data.ok) {
    throw new Error(
      `Uncover it: Failed to upload file. ${data.status}: ${data.statusText}. ${response.error}`,
    );
  }

  return { blake3Hash: response.blake3Hash };
}

/**
 * Gets the the static report of a file from it's SHA-256, SHA-512 or BLAKE3 hash
 *
 * @param apiKey - API Key
 * @param hash - SHA-256, SHA-512 or BLAKE3 hash.
 *
 * @example
 * // Fetching a report
 * const data = await staticReport("YOUR_API_KEY", hash);
 */
export async function staticReport(
  apiKey: string,
  hash: string,
): Promise<StaticAnalysisDataType> {
  const regex = /\b([a-fA-F0-9]{64}|[a-fA-F0-9]{128})\b/;
  if (!regex.test(hash)) {
    throw new Error(
      "Uncover it: File hash must be a valid SHA-256 / SHA-512 / BLAKE3 string",
    );
  }

  const data = await fetch(`https://api.uncoverit.org/private/sample/${hash}`, {
    headers: {
      authorization: apiKey,
    },
    cache: "force-cache",
  });

  const response = await data.json();
  if (!data.ok) {
    throw new Error(
      `Uncover it: Failed to fetch static report. ${data.status}: ${data.statusText}. ${response.error}`,
    );
  }

  return response;
}
