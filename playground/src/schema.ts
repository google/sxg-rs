export type CreateSignedExchangeRequest = {
  innerUrl: string;
};

export type CreateSignedExchangeResponse =
  | ['Ok', {outerUrl: string}]
  | [
      'Err',
      {
        message: string;
      }
    ];
