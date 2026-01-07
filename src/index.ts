export interface BalanceResponse {
  requests_left: number;
  expiration_date: Date;
}

interface RawBalanceResponse {
  requests_left: number;
  expiration_date: string | number;
}

/**
 * Fetch the remaining balance and expiration date from API.
 *
 * @param apiKey - Uncover it API Key
 */
export async function fetchBalance(apiKey: string): Promise<BalanceResponse> {
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
