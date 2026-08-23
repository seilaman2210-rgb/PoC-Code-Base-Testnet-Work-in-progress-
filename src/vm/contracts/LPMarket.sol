// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract LPMarket {
    uint256 public constant SCALE = 1e18;

    struct Quote {
        bool active;
        uint256 bidRate;
        uint256 askRate;
        uint256 maxCc;
        uint256 maxQuote;
        uint256 feeBps;
        uint256 updatedAt;
        uint256 expiresAt;
        uint256 filledCc;
        uint256 filledQuote;
    }

    mapping(address => Quote) public quotes;
    address[] public lps;

    mapping(address => uint256) public liquidityCc;
    mapping(address => uint256) public liquidityQuote;

    struct Intent {
        bool active;
        address lp;
        address taker;
        uint256 ccAmount;
        uint256 quoteAmount;
        uint256 t1;
    }
    mapping(bytes32 => Intent) public intents;
    uint256 public totalIntents;

    struct Trade {
        address lp;
        address taker;
        uint256 ccAmount;
        uint256 quoteAmount;
        uint256 ratePerCc;
        uint256 at;
    }
    Trade[] public trades;

    uint256 public lastPricePerCc;
    uint256 public lastTradeAt;
    uint256 public lastTradeCc;
    uint256 public lastTradeQuote;
    uint256 public totalTrades;
    uint256 public totalCcVolume;
    uint256 public totalQuoteVolume;

    event QuotePosted(address indexed lp, uint256 bidRate, uint256 askRate, uint256 maxCc, uint256 maxQuote, uint256 expiresAt);
    event QuoteCancelled(address indexed lp);
    event IntentRegistered(bytes32 indexed hashlock, address indexed lp, address indexed taker, uint256 ccAmount, uint256 quoteAmount, uint256 t1);
    event TradeExecuted(address indexed lp, address indexed taker, uint256 ccAmount, uint256 quoteAmount, uint256 ratePerCc);
    event LiquidityChanged(address indexed lp, uint256 ccAdded, uint256 quoteRemoved, uint256 ccBalance, uint256 quoteBalance);

    function postQuote(
        uint256 bidRate, uint256 askRate, uint256 maxCc, uint256 maxQuote,
        uint256 feeBps, uint256 expiresAt
    ) external {
        require(bidRate > 0 && askRate > 0, 'rates must be > 0');
        require(askRate >= bidRate, 'ask < bid');
        require(maxCc > 0 || maxQuote > 0, 'no liquidity');
        require(liquidityCc[msg.sender] >= maxCc, 'no CC collateral');
        require(feeBps <= 10000, 'fee too high');
        require(expiresAt > block.timestamp, 'expires in the past');
        if (!quotes[msg.sender].active) lps.push(msg.sender);
        Quote storage q = quotes[msg.sender];
        q.active = true;
        q.bidRate = bidRate;
        q.askRate = askRate;
        q.maxCc = maxCc;
        q.maxQuote = maxQuote;
        q.feeBps = feeBps;
        q.updatedAt = block.timestamp;
        q.expiresAt = expiresAt;
        q.filledCc = 0;
        q.filledQuote = 0;
        liquidityQuote[msg.sender] = maxQuote;
        emit QuotePosted(msg.sender, bidRate, askRate, maxCc, maxQuote, expiresAt);
    }

    function cancelQuote() external {
        require(quotes[msg.sender].active, 'no active quote');
        quotes[msg.sender].active = false;
        emit QuoteCancelled(msg.sender);
    }

    function isQuoteActive(address lp) external view returns (bool) {
        Quote storage q = quotes[lp];
        return q.active && q.expiresAt >= block.timestamp;
    }

    function quoteOf(address lp) external view returns (
        bool active, uint256 bidRate, uint256 askRate, uint256 maxCc, uint256 maxQuote,
        uint256 feeBps, uint256 updatedAt, uint256 expiresAt, uint256 filledCc, uint256 filledQuote
    ) {
        Quote storage q = quotes[lp];
        return (q.active, q.bidRate, q.askRate, q.maxCc, q.maxQuote, q.feeBps, q.updatedAt, q.expiresAt, q.filledCc, q.filledQuote);
    }

    function depositCc() external payable {
        liquidityCc[msg.sender] += msg.value;
    }

    function withdrawCc(uint256 amount) external {
        require(liquidityCc[msg.sender] >= amount, 'not enough CC liquidity');
        liquidityCc[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
    }

    function registerSwapIntent(bytes32 hashlock, address lp, uint256 ccAmount, uint256 quoteAmount, uint256 t1) external {
        require(hashlock != bytes32(0), 'empty hashlock');
        require(ccAmount > 0 && quoteAmount > 0, 'invalid trade');
        require(t1 > block.timestamp, 't1 in the past');
        require(!intents[hashlock].active, 'intent already active');
        Quote storage q = quotes[lp];
        require(q.active, 'no active quote');
        require(ccAmount <= q.maxCc - q.filledCc, 'exceeds quote CC');
        require(quoteAmount <= q.maxQuote - q.filledQuote, 'exceeds quote');
        require(liquidityQuote[lp] >= quoteAmount, 'insufficient quote liquidity');
        intents[hashlock] = Intent(true, lp, msg.sender, ccAmount, quoteAmount, t1);
        totalIntents += 1;
        emit IntentRegistered(hashlock, lp, msg.sender, ccAmount, quoteAmount, t1);
    }

    function settleTrade(bytes32 hashlock, bytes32 secret) external {
        require(sha256(abi.encodePacked(secret)) == hashlock, 'secret != hashlock');
        Intent storage it = intents[hashlock];
        require(it.active, 'no active intent');
        require(msg.sender == it.lp, 'only the LP settles');
        require(block.timestamp < it.t1, 'past t1');
        Quote storage q = quotes[it.lp];
        require(q.active, 'no active quote');
        require(it.ccAmount <= q.maxCc - q.filledCc, 'exceeds quote CC');
        require(it.quoteAmount <= q.maxQuote - q.filledQuote, 'exceeds quote');
        uint256 ccAmount = it.ccAmount;
        uint256 quoteAmount = it.quoteAmount;
        uint256 rate = (quoteAmount * SCALE) / ccAmount;
        lastPricePerCc = rate;
        lastTradeAt = block.timestamp;
        lastTradeCc = ccAmount;
        lastTradeQuote = quoteAmount;
        totalTrades += 1;
        totalCcVolume += ccAmount;
        totalQuoteVolume += quoteAmount;
        liquidityQuote[it.lp] -= quoteAmount;
        liquidityCc[it.lp] -= ccAmount; // <-- FIX: release/consume CC collateral proportionally
        q.filledCc += ccAmount;
        q.filledQuote += quoteAmount;
        it.active = false;
        trades.push(Trade(it.lp, it.taker, ccAmount, quoteAmount, rate, block.timestamp));
        emit TradeExecuted(it.lp, it.taker, ccAmount, quoteAmount, rate);
        emit LiquidityChanged(it.lp, ccAmount, quoteAmount, liquidityCc[it.lp], liquidityQuote[it.lp]);
    }

    function bestBid() public view returns (uint256) {
        uint256 best = 0;
        for (uint256 i = 0; i < lps.length; i++) {
            Quote storage q = quotes[lps[i]];
            if (q.active && q.expiresAt >= block.timestamp && q.bidRate > best) best = q.bidRate;
        }
        return best;
    }

    function bestAsk() public view returns (uint256) {
        uint256 best = 0;
        for (uint256 i = 0; i < lps.length; i++) {
            Quote storage q = quotes[lps[i]];
            if (q.active && q.expiresAt >= block.timestamp) {
                if (best == 0 || q.askRate < best) best = q.askRate;
            }
        }
        return best;
    }

    function midPrice() public view returns (uint256) {
        uint256 bid = bestBid();
        uint256 ask = bestAsk();
        if (bid > 0 && ask > 0) return (bid + ask) / 2;
        return lastPricePerCc;
    }
}