declare module "cc-transaction" {
  type ColoredCoinPayment = {
    input: number;
    output: number;
    amount: number;
    range: boolean;
    percent: boolean;
  };

  type ColoredCoinTransaction = {
    type: "issuance" | "transfer" | "burn";
    payments: ColoredCoinPayment[];
    lockStatus?: boolean;
    aggregationPolicy: "aggregatable" | "hybrid" | "dispersed";
    divisibility?: number;
    amount?: number;
  };

  const Transaction: {
    fromHex(data: Buffer): ColoredCoinTransaction;
  };

  export = Transaction;
}
