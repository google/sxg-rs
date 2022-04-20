export type CreateSignedExchangeRequest = {
  innerUrl: string;
};

export type CreateSignedExchangeResponse =
  | [
      'Ok',
      {
        outerUrl: string;
        info: {
          bodySize: number;
          subresourceUrls: string[];
        };
      }
    ]
  | [
      'Err',
      {
        message: string;
      }
    ];
