// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IERC20Minimal {
    function balanceOf(address account) external view returns (uint256);
    function transferFrom(address sender, address recipient, uint256 amount) external returns (bool);
    function transfer(address recipient, uint256 amount) external returns (bool);
}

contract CcPool {
    uint256 public constant MIN_LIQUIDITY = 1000;
    uint256 public constant SCALE = 1e18;

    string public name;
    string public symbol;
    uint8 public constant decimals = 18;

    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;

    address public immutable token;
    uint256 public feeBps;

    uint256 public tokenReserve;
    uint256 public ccReserve;

    uint256 public totalTrades;
    uint256 public totalCcVolume;
    uint256 public totalTokenVolume;

    // Access control
    address public owner;
    modifier onlyOwner() {
        require(msg.sender == owner, 'not owner');
        _;
    }

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Mint(address indexed lp, uint256 lpAmount, uint256 tokenAmount, uint256 ccAmount);
    event Burn(address indexed lp, uint256 lpAmount, uint256 tokenAmount, uint256 ccAmount);
    event Swap(address indexed user, uint256 tokenIn, uint256 ccIn, uint256 tokenOut, uint256 ccOut);

    constructor(address token_, uint256 feeBps_) {
        token = token_;
        feeBps = feeBps_ <= 10000 ? feeBps_ : 30;
        name = 'CC-LP';
        symbol = 'CCLP';
        owner = msg.sender; // set owner to deployer
    }

    function _mint(address to, uint256 amount) internal {
        totalSupply += amount;
        balanceOf[to] += amount;
        emit Transfer(address(0), to, amount);
    }

    function _burn(address from, uint256 amount) internal {
        require(balanceOf[from] >= amount, 'no LP');
        balanceOf[from] -= amount;
        totalSupply -= amount;
        emit Transfer(from, address(0), amount);
    }

    function sqrt(uint256 y) internal pure returns (uint256 z) {
        if (y > 3) {
            z = y;
            uint256 x = y / 2 + 1;
            while (x < z) { z = x; x = (y / x + x) / 2; }
        } else if (y != 0) {
            z = 1;
        }
    }

    function addLiquidity(uint256 tokenAmount) external payable returns (uint256 lp) {
        require(msg.value > 0, 'no CC');
        uint256 before = IERC20Minimal(token).balanceOf(address(this));
        if (tokenAmount > 0) {
            IERC20Minimal(token).transferFrom(msg.sender, address(this), tokenAmount);
        }
        uint256 tokenAdded = IERC20Minimal(token).balanceOf(address(this)) - before;
        require(tokenAdded > 0, 'no token');
        uint256 ccAdded = msg.value;

        if (totalSupply == 0) {
            lp = sqrt(tokenAdded * ccAdded) - MIN_LIQUIDITY;
            _mint(address(0), MIN_LIQUIDITY);
        } else {
            uint256 lpByToken = (tokenAdded * totalSupply) / tokenReserve;
            uint256 lpByCc = (ccAdded * totalSupply) / ccReserve;
            lp = lpByToken < lpByCc ? lpByToken : lpByCc;
        }
        require(lp > 0, 'no LP minted');
        tokenReserve += tokenAdded;
        ccReserve += ccAdded;
        _mint(msg.sender, lp);
        emit Mint(msg.sender, lp, tokenAdded, ccAdded);
    }

    function removeLiquidity(uint256 lpAmount) external returns (uint256 tokenOut, uint256 ccOut) {
        tokenOut = (lpAmount * tokenReserve) / totalSupply;
        ccOut = (lpAmount * ccReserve) / totalSupply;
        require(tokenOut > 0 && ccOut > 0, 'zero out');
        _burn(msg.sender, lpAmount);
        tokenReserve -= tokenOut;
        ccReserve -= ccOut;
        require(IERC20Minimal(token).transfer(msg.sender, tokenOut), 'token transfer failed');
        payable(msg.sender).transfer(ccOut);
        emit Burn(msg.sender, lpAmount, tokenOut, ccOut);
    }

    function swapTokenForCc(uint256 tokenIn, uint256 minCcOut) external returns (uint256 ccOut) {
        require(tokenIn > 0, 'zero in');
        uint256 before = IERC20Minimal(token).balanceOf(address(this));
        IERC20Minimal(token).transferFrom(msg.sender, address(this), tokenIn);
        uint256 actualIn = IERC20Minimal(token).balanceOf(address(this)) - before;
        uint256 net = (actualIn * (10000 - feeBps)) / 10000;
        ccOut = (ccReserve * net) / (tokenReserve + net);
        require(ccOut > 0, 'zero out');
        require(ccOut >= minCcOut, 'slippage too high'); // slippage protection
        tokenReserve += actualIn;
        ccReserve -= ccOut;
        payable(msg.sender).transfer(ccOut);
        totalTrades += 1;
        totalCcVolume += ccOut;
        totalTokenVolume += actualIn;
        emit Swap(msg.sender, actualIn, 0, 0, ccOut);
    }

    function swapCcForToken(uint256 minTokenOut) external payable returns (uint256 tokenOut) {
        require(msg.value > 0, 'zero in');
        uint256 net = (msg.value * (10000 - feeBps)) / 10000;
        tokenOut = (tokenReserve * net) / (ccReserve + net);
        require(tokenOut > 0, 'zero out');
        require(tokenOut < tokenReserve, 'max');
        require(tokenOut >= minTokenOut, 'slippage too high'); // slippage protection
        ccReserve += msg.value;
        tokenReserve -= tokenOut;
        require(IERC20Minimal(token).transfer(msg.sender, tokenOut), 'token transfer failed');
        totalTrades += 1;
        totalCcVolume += msg.value;
        totalTokenVolume += tokenOut;
        emit Swap(msg.sender, 0, msg.value, tokenOut, 0);
    }

    function sync() external onlyOwner {
        tokenReserve = IERC20Minimal(token).balanceOf(address(this));
    }

    function priceCcPerToken() public view returns (uint256) {
        return (ccReserve * SCALE) / tokenReserve;
    }

    function priceTokenPerCc() public view returns (uint256) {
        return (tokenReserve * SCALE) / ccReserve;
    }

    function poolState() public view returns (
        uint256 _tokenReserve, uint256 _ccReserve, uint256 _lpSupply,
        uint256 _priceCcPerToken, uint256 _priceTokenPerCc
    ) {
        return (tokenReserve, ccReserve, totalSupply, priceCcPerToken(), priceTokenPerCc());
    }
}