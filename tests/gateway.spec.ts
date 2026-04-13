import { expect } from "chai";
import { createHash } from "crypto";

const MAX_BPS = 100_000n;

type TokenFeeSettings = {
  senderToProvider: bigint;
  providerToAggregator: bigint;
  senderToAggregator: bigint;
  providerToAggregatorFx: bigint;
};

type Order = {
  sender: string;
  token: string;
  senderFeeRecipient: string;
  senderFee: bigint;
  protocolFee: bigint;
  isFulfilled: boolean;
  isRefunded: boolean;
  refundAddress: string;
  currentBps: bigint;
  amount: bigint;
};

class GatewayModel {
  readonly chainId: bigint;
  treasury: string;
  aggregator: string;
  paused = false;

  private userNonce = new Map<string, bigint>();
  private tokenSupported = new Map<string, boolean>();
  private tokenSettings = new Map<string, TokenFeeSettings>();
  private orders = new Map<string, Order>();
  private balances = new Map<string, bigint>();

  constructor(chainId: bigint, treasury: string, aggregator: string) {
    this.chainId = chainId;
    this.treasury = treasury;
    this.aggregator = aggregator;
  }

  setTokenSupported(token: string, supported: boolean): void {
    this.tokenSupported.set(token, supported);
  }

  setTokenFeeSettings(token: string, settings: TokenFeeSettings): void {
    if (!this.tokenSupported.get(token)) {
      throw new Error("TokenNotSupported");
    }
    this.tokenSettings.set(token, settings);
  }

  mint(user: string, amount: bigint): void {
    this.credit(user, amount);
  }

  balanceOf(user: string): bigint {
    return this.balances.get(user) ?? 0n;
  }

  createOrder(input: {
    sender: string;
    token: string;
    amount: bigint;
    rate: bigint;
    senderFeeRecipient: string;
    senderFee: bigint;
    refundAddress: string;
    messageHash: string;
  }): string {
    if (this.paused) throw new Error("Paused");
    if (!this.tokenSupported.get(input.token)) throw new Error("TokenNotSupported");
    if (input.amount === 0n) throw new Error("AmountIsZero");
    if (!input.refundAddress) throw new Error("ThrowZeroAddress");
    if (input.senderFee > 0n && !input.senderFeeRecipient) {
      throw new Error("InvalidSenderFeeRecipient");
    }
    if (!input.messageHash) throw new Error("InvalidMessageHash");

    let protocolFee = 0n;
    if (input.rate === 100n) {
      if (input.senderFee === 0n) throw new Error("SenderFeeIsZero");
    } else {
      const settings = this.getTokenSettings(input.token);
      if (settings.providerToAggregatorFx === 0n) {
        throw new Error("TokenFeeSettingsNotConfigured");
      }
      protocolFee = mulDiv(input.amount, settings.providerToAggregatorFx, MAX_BPS);
    }

    const nonce = (this.userNonce.get(input.sender) ?? 0n) + 1n;
    this.userNonce.set(input.sender, nonce);
    const orderId = computeOrderId(input.sender, nonce, this.chainId);
    if (this.orders.has(orderId)) throw new Error("OrderAlreadyExists");

    this.debit(input.sender, input.amount + input.senderFee);
    this.credit("gateway_vault", input.amount + input.senderFee);

    this.orders.set(orderId, {
      sender: input.sender,
      token: input.token,
      senderFeeRecipient: input.senderFeeRecipient,
      senderFee: input.senderFee,
      protocolFee,
      isFulfilled: false,
      isRefunded: false,
      refundAddress: input.refundAddress,
      currentBps: MAX_BPS,
      amount: input.amount,
    });
    return orderId;
  }

  settleOut(input: {
    caller: string;
    orderId: string;
    liquidityProvider: string;
    settlePercent: bigint;
    rebatePercent: bigint;
  }): void {
    if (input.caller !== this.aggregator) throw new Error("OnlyAggregator");
    if (input.rebatePercent > MAX_BPS) throw new Error("InvalidRebatePercent");

    const order = this.mustOrder(input.orderId);
    if (order.isFulfilled) throw new Error("OrderFulfilled");
    if (order.isRefunded) throw new Error("OrderRefunded");
    if (input.settlePercent <= 0n || input.settlePercent > order.currentBps) {
      throw new Error("InvalidSettlePercent");
    }

    const previousBps = order.currentBps;
    order.currentBps -= input.settlePercent;

    if (order.currentBps === 0n) {
      order.isFulfilled = true;
      if (order.senderFee !== 0n && order.protocolFee !== 0n) {
        this.handleFxSenderFeeSplit(order);
      }
    }

    if (order.senderFee !== 0n && order.protocolFee === 0n) {
      this.handleLocalSenderFeeSplit(order, input.liquidityProvider, input.settlePercent);
    }

    let liquidityProviderAmount = mulDiv(order.amount, input.settlePercent, previousBps);
    order.amount -= liquidityProviderAmount;

    if (order.protocolFee !== 0n) {
      const settings = this.getTokenSettings(order.token);
      let protocolFee = mulDiv(
        liquidityProviderAmount,
        settings.providerToAggregatorFx,
        MAX_BPS
      );
      liquidityProviderAmount -= protocolFee;

      if (input.rebatePercent !== 0n) {
        const rebateAmount = mulDiv(protocolFee, input.rebatePercent, MAX_BPS);
        protocolFee -= rebateAmount;
        liquidityProviderAmount += rebateAmount;
      }
      this.transferVault(this.treasury, protocolFee);
    }

    this.transferVault(input.liquidityProvider, liquidityProviderAmount);
  }

  settle(input: {
    caller: string;
    orderId: string;
    liquidityProvider: string;
    settlePercent: bigint;
    rebatePercent: bigint;
  }): void {
    // Backward-compatible alias to reflect on-chain API transition.
    this.settleOut(input);
  }

  settleIn(input: {
    caller: string;
    orderId: string;
    token: string;
    amount: bigint;
    senderFeeRecipient: string;
    senderFee: bigint;
    recipient: string;
    rate: bigint;
  }): void {
    if (this.paused) throw new Error("Paused");
    if (!this.tokenSupported.get(input.token)) throw new Error("TokenNotSupported");
    if (input.amount === 0n) throw new Error("AmountIsZero");
    if (!input.recipient) throw new Error("ThrowZeroAddress");
    if (this.orders.has(input.orderId)) throw new Error("OrderAlreadyExists");

    if (input.senderFee !== 0n && !input.senderFeeRecipient) {
      throw new Error("InvalidSenderFeeRecipient");
    }

    const totalAmount = input.amount + input.senderFee;
    this.debit(input.caller, totalAmount);
    this.credit("gateway_vault", totalAmount);

    let amountToSettle = input.amount;
    let aggregatorFee = 0n;

    if (input.rate === 100n) {
      if (input.senderFee === 0n) throw new Error("SenderFeeIsZero");
    } else {
      const settings = this.getTokenSettings(input.token);
      if (settings.providerToAggregatorFx === 0n) {
        throw new Error("TokenFeeSettingsNotConfigured");
      }
      aggregatorFee = mulDiv(input.amount, settings.providerToAggregatorFx, MAX_BPS);
      if (aggregatorFee > 0n) {
        amountToSettle -= aggregatorFee;
        this.transferVault(this.treasury, aggregatorFee);
      }
    }

    const order: Order = {
      sender: input.recipient,
      token: input.token,
      senderFeeRecipient: input.senderFeeRecipient,
      senderFee: input.senderFee,
      protocolFee: aggregatorFee,
      isFulfilled: true,
      isRefunded: false,
      refundAddress: "",
      currentBps: 0n,
      amount: amountToSettle,
    };
    this.orders.set(input.orderId, order);

    this.transferVault(input.recipient, amountToSettle);

    if (input.senderFee !== 0n) {
      if (aggregatorFee === 0n) {
        this.handleLocalSenderFeeSplit(order, input.caller, MAX_BPS);
      } else {
        this.handleFxSenderFeeSplit(order);
      }
    }
  }

  getAggregator(): string {
    return this.aggregator;
  }

  refund(input: { caller: string; orderId: string; fee: bigint }): void {
    if (input.caller !== this.aggregator) throw new Error("OnlyAggregator");
    const order = this.mustOrder(input.orderId);
    if (order.isFulfilled) throw new Error("OrderFulfilled");
    if (order.isRefunded) throw new Error("OrderRefunded");
    if (input.fee > order.protocolFee) throw new Error("FeeExceedsProtocolFee");

    if (input.fee > 0n) {
      this.transferVault(this.treasury, input.fee);
    }

    order.isRefunded = true;
    order.currentBps = 0n;

    const refundAmount = order.amount - input.fee;
    this.transferVault(order.refundAddress, refundAmount + order.senderFee);
  }

  getOrder(orderId: string): Order {
    return this.mustOrder(orderId);
  }

  private handleLocalSenderFeeSplit(
    order: Order,
    liquidityProvider: string,
    settlePercent: bigint
  ): void {
    const settings = this.getTokenSettings(order.token);
    const providerAmount = mulDiv(order.senderFee, settings.senderToProvider, MAX_BPS);
    const currentProviderAmount = mulDiv(providerAmount, settlePercent, MAX_BPS);
    const aggregatorAmount = mulDiv(
      currentProviderAmount,
      settings.providerToAggregator,
      MAX_BPS
    );
    const senderAmount = order.senderFee - providerAmount;

    if (senderAmount !== 0n && order.currentBps === 0n) {
      this.transferVault(order.senderFeeRecipient, senderAmount);
    }

    this.transferVault(this.treasury, aggregatorAmount);
    this.transferVault(liquidityProvider, currentProviderAmount - aggregatorAmount);
  }

  private handleFxSenderFeeSplit(order: Order): void {
    const settings = this.getTokenSettings(order.token);
    const senderAmount = mulDiv(
      order.senderFee,
      MAX_BPS - settings.senderToAggregator,
      MAX_BPS
    );
    const aggregatorAmount = order.senderFee - senderAmount;
    this.transferVault(order.senderFeeRecipient, senderAmount);
    this.transferVault(this.treasury, aggregatorAmount);
  }

  private transferVault(to: string, amount: bigint): void {
    if (amount === 0n) return;
    this.debit("gateway_vault", amount);
    this.credit(to, amount);
  }

  private credit(account: string, amount: bigint): void {
    this.balances.set(account, (this.balances.get(account) ?? 0n) + amount);
  }

  private debit(account: string, amount: bigint): void {
    const current = this.balanceOf(account);
    if (current < amount) {
      throw new Error("InsufficientBalance");
    }
    this.balances.set(account, current - amount);
  }

  private getTokenSettings(token: string): TokenFeeSettings {
    const settings = this.tokenSettings.get(token);
    if (!settings) throw new Error("TokenFeeSettingsNotConfigured");
    return settings;
  }

  private mustOrder(orderId: string): Order {
    const order = this.orders.get(orderId);
    if (!order) throw new Error("OrderNotFound");
    return order;
  }
}

const mulDiv = (amount: bigint, num: bigint, den: bigint): bigint => (amount * num) / den;

const computeOrderId = (sender: string, nonce: bigint, chainId: bigint): string => {
  const payload = `${sender}|${nonce.toString()}|${chainId.toString()}`;
  return createHash("sha256").update(payload).digest("hex");
};

describe("Gateway Solana parity tests", () => {
  const token = "USDT";
  const treasury = "treasury";
  const aggregator = "aggregator";
  const sender = "sender";
  const alice = "alice";
  const lp1 = "lp1";
  const lp2 = "lp2";
  const chainId = 1397n;

  const defaultSettings: TokenFeeSettings = {
    senderToProvider: 50_000n,
    providerToAggregator: 50_000n,
    senderToAggregator: 0n,
    providerToAggregatorFx: 500n,
  };

  const setup = () => {
    const g = new GatewayModel(chainId, treasury, aggregator);
    g.setTokenSupported(token, true);
    g.setTokenFeeSettings(token, defaultSettings);
    g.mint(sender, 27_000_000n);
    return g;
  };

  it("creates FX order with expected protocol fee", () => {
    const g = setup();
    const orderId = g.createOrder({
      sender,
      token,
      amount: 27_000_000n,
      rate: 750n,
      senderFeeRecipient: sender,
      senderFee: 0n,
      refundAddress: alice,
      messageHash: "0xhash",
    });
    const order = g.getOrder(orderId);
    expect(order.protocolFee).to.equal(135_000n);
    expect(order.currentBps).to.equal(MAX_BPS);
    expect(g.balanceOf("gateway_vault")).to.equal(27_000_000n);
  });

  it("settles full FX order and pays treasury/provider correctly", () => {
    const g = setup();
    const orderId = g.createOrder({
      sender,
      token,
      amount: 27_000_000n,
      rate: 750n,
      senderFeeRecipient: sender,
      senderFee: 0n,
      refundAddress: alice,
      messageHash: "0xhash",
    });

    g.settleOut({
      caller: aggregator,
      orderId,
      liquidityProvider: lp1,
      settlePercent: MAX_BPS,
      rebatePercent: 0n,
    });

    expect(g.balanceOf(lp1)).to.equal(26_865_000n);
    expect(g.balanceOf(treasury)).to.equal(135_000n);
    expect(g.balanceOf("gateway_vault")).to.equal(0n);
    expect(g.getOrder(orderId).isFulfilled).to.equal(true);
  });

  it("handles split FX settlement with rebate", () => {
    const g = setup();
    g.mint(sender, 1_000n);
    const orderId = g.createOrder({
      sender,
      token,
      amount: 27_000_000n,
      rate: 750n,
      senderFeeRecipient: sender,
      senderFee: 1_000n,
      refundAddress: alice,
      messageHash: "0xhash",
    });

    g.settleOut({
      caller: aggregator,
      orderId,
      liquidityProvider: lp1,
      settlePercent: 50_000n,
      rebatePercent: 25_000n,
    });
    g.settleOut({
      caller: aggregator,
      orderId,
      liquidityProvider: lp2,
      settlePercent: 50_000n,
      rebatePercent: 25_000n,
    });

    expect(g.balanceOf(sender)).to.equal(1_000n);
    expect(g.balanceOf(lp1)).to.equal(13_449_375n);
    expect(g.balanceOf(lp2)).to.equal(13_449_375n);
    expect(g.balanceOf(treasury)).to.equal(50_625n + 50_625n);
    expect(g.balanceOf("gateway_vault")).to.equal(0n);
  });

  it("handles local transfer sender-fee splitting parity", () => {
    const g = setup();
    g.mint(sender, 1_000n);
    const orderId = g.createOrder({
      sender,
      token,
      amount: 27_000_000n,
      rate: 100n,
      senderFeeRecipient: sender,
      senderFee: 1_000n,
      refundAddress: alice,
      messageHash: "0xhash",
    });

    g.settleOut({
      caller: aggregator,
      orderId,
      liquidityProvider: lp1,
      settlePercent: MAX_BPS,
      rebatePercent: 0n,
    });

    expect(g.balanceOf(sender)).to.equal(500n);
    expect(g.balanceOf(lp1)).to.equal(27_000_250n);
    expect(g.balanceOf(treasury)).to.equal(250n);
    expect(g.balanceOf("gateway_vault")).to.equal(0n);
  });

  it("refunds order and applies fee cap", () => {
    const g = setup();
    g.mint(sender, 1_000n);
    const orderId = g.createOrder({
      sender,
      token,
      amount: 27_000_000n,
      rate: 750n,
      senderFeeRecipient: sender,
      senderFee: 1_000n,
      refundAddress: alice,
      messageHash: "0xhash",
    });

    g.refund({ caller: aggregator, orderId, fee: 10_000n });
    expect(g.balanceOf(treasury)).to.equal(10_000n);
    expect(g.balanceOf(alice)).to.equal(26_991_000n);
    expect(g.getOrder(orderId).isRefunded).to.equal(true);
    expect(g.balanceOf("gateway_vault")).to.equal(0n);
  });

  it("rejects invalid operations", () => {
    const g = setup();
    const create = () =>
      g.createOrder({
        sender,
        token,
        amount: 1n,
        rate: 100n,
        senderFeeRecipient: sender,
        senderFee: 0n,
        refundAddress: alice,
        messageHash: "0xhash",
      });
    expect(create).to.throw("SenderFeeIsZero");

    const orderId = g.createOrder({
      sender,
      token,
      amount: 1_000n,
      rate: 750n,
      senderFeeRecipient: sender,
      senderFee: 0n,
      refundAddress: alice,
      messageHash: "0xhash",
    });

    expect(() =>
      g.settleOut({
        caller: "not-aggregator",
        orderId,
        liquidityProvider: lp1,
        settlePercent: MAX_BPS,
        rebatePercent: 0n,
      })
    ).to.throw("OnlyAggregator");

    expect(() =>
      g.settleOut({
        caller: aggregator,
        orderId,
        liquidityProvider: lp1,
        settlePercent: MAX_BPS,
        rebatePercent: MAX_BPS + 1n,
      })
    ).to.throw("InvalidRebatePercent");
  });

  it("processes settleIn FX flow parity", () => {
    const g = setup();
    g.mint(lp1, 50_000n);
    const orderId = "onramp-order-1";

    g.settleIn({
      caller: lp1,
      orderId,
      token,
      amount: 10_000n,
      senderFeeRecipient: sender,
      senderFee: 100n,
      recipient: alice,
      rate: 750n,
    });

    const order = g.getOrder(orderId);
    expect(order.isFulfilled).to.equal(true);
    expect(order.currentBps).to.equal(0n);
    expect(order.amount).to.equal(9_950n);
    expect(g.balanceOf(alice)).to.equal(9_950n);
    expect(g.balanceOf(sender)).to.equal(27_000_100n);
    expect(g.balanceOf(treasury)).to.equal(50n);
    expect(g.balanceOf(lp1)).to.equal(39_900n);
    expect(g.balanceOf("gateway_vault")).to.equal(0n);
  });

  it("processes settleIn local flow with sender-fee splitting", () => {
    const g = setup();
    g.mint(lp1, 50_000n);
    const orderId = "onramp-order-2";

    g.settleIn({
      caller: lp1,
      orderId,
      token,
      amount: 10_000n,
      senderFeeRecipient: sender,
      senderFee: 100n,
      recipient: alice,
      rate: 100n,
    });

    expect(g.balanceOf(alice)).to.equal(10_000n);
    expect(g.balanceOf(sender)).to.equal(27_000_050n);
    expect(g.balanceOf(lp1)).to.equal(39_925n);
    expect(g.balanceOf(treasury)).to.equal(25n);
    expect(g.balanceOf("gateway_vault")).to.equal(0n);
  });

  it("rejects settleIn when paused or local sender fee is zero", () => {
    const g = setup();
    g.mint(lp1, 50_000n);
    g.paused = true;
    expect(() =>
      g.settleIn({
        caller: lp1,
        orderId: "onramp-order-paused",
        token,
        amount: 10_000n,
        senderFeeRecipient: sender,
        senderFee: 100n,
        recipient: alice,
        rate: 750n,
      })
    ).to.throw("Paused");

    g.paused = false;
    expect(() =>
      g.settleIn({
        caller: lp1,
        orderId: "onramp-order-local",
        token,
        amount: 10_000n,
        senderFeeRecipient: sender,
        senderFee: 0n,
        recipient: alice,
        rate: 100n,
      })
    ).to.throw("SenderFeeIsZero");
  });

  it("rejects duplicate settleIn order IDs and exposes aggregator getter", () => {
    const g = setup();
    g.mint(lp1, 50_000n);
    const orderId = "onramp-order-3";

    g.settleIn({
      caller: lp1,
      orderId,
      token,
      amount: 10_000n,
      senderFeeRecipient: sender,
      senderFee: 100n,
      recipient: alice,
      rate: 750n,
    });

    expect(g.getAggregator()).to.equal(aggregator);
    expect(() =>
      g.settleIn({
        caller: lp1,
        orderId,
        token,
        amount: 10_000n,
        senderFeeRecipient: sender,
        senderFee: 100n,
        recipient: alice,
        rate: 750n,
      })
    ).to.throw("OrderAlreadyExists");
  });
});
